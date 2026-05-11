//! pruv-lottery — Daily permissionless lottery with pruv node-consensus randomness.
//!
//! ## Instruction flow
//!
//! 1. `init_config`       — authority sets ticket price, shares, threshold (once).
//! 2. `update_node_count` — authority keeps active_node_count in sync.
//! 3. `initialize_round`  — permissionless; client reads config.current_round_id,
//!                          adds 1, passes it as `next_round_id`.
//! 4. `buy_ticket`        — user pays 0.01 SOL; SOL held in LotteryState PDA.
//! 5. `cast_draw_vote`    — each node derives winner from SlotHashes sysvar;
//!                          program re-derives and rejects any mismatch.
//! 6. `finalize_draw`     — permissionless once 2/3 threshold reached;
//!                          80% → winner, 15% → NodePrizePool, 5% → treasury.
//! 7. `claim_node_prize`  — each node that voted claims its equal share.

use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("FLot1111111111111111111111111111111111111111");

// ─── Constants ────────────────────────────────────────────────────────────────

pub const DEFAULT_TICKET_PRICE:         u64 = 10_000_000;  // 0.01 SOL
pub const DEFAULT_MAX_TICKETS_PER_WALLET: u8 = 10;
pub const DEFAULT_ROUND_DURATION_SLOTS: u64 = 216_000;     // ~24 h
pub const DEFAULT_NODE_SHARE_BPS:       u16 = 1_500;       // 15%
pub const DEFAULT_TREASURY_SHARE_BPS:   u16 = 500;         //  5%
pub const DEFAULT_THRESHOLD_BPS:        u64 = 6_667;       // ≥2/3
pub const SLOT_HASHES_CAPACITY:       usize = 512;
pub const SLOT_HASH_ENTRY_LEN:        usize = 40;          // 8 slot + 32 hash

// ─── Program ──────────────────────────────────────────────────────────────────

#[program]
pub mod pruv_lottery {
    use super::*;

    // ── 1. init_config ────────────────────────────────────────────────────────

    pub fn init_config(
        ctx: Context<InitConfig>,
        ticket_price_lamports: u64,
        max_tickets_per_wallet: u8,
        round_duration_slots: u64,
        node_share_bps: u16,
        treasury_share_bps: u16,
        threshold_bps: u64,
    ) -> Result<()> {
        require!(ticket_price_lamports > 0, LotteryError::InvalidParam);
        require!(max_tickets_per_wallet > 0, LotteryError::InvalidParam);
        require!(round_duration_slots > 0, LotteryError::InvalidParam);
        require!(
            (node_share_bps as u32) + (treasury_share_bps as u32) < 10_000,
            LotteryError::InvalidParam
        );
        require!(threshold_bps <= 10_000, LotteryError::InvalidParam);

        let cfg = &mut ctx.accounts.config;
        cfg.authority              = ctx.accounts.authority.key();
        cfg.treasury               = ctx.accounts.treasury.key();
        cfg.ticket_price_lamports  = ticket_price_lamports;
        cfg.max_tickets_per_wallet = max_tickets_per_wallet;
        cfg.round_duration_slots   = round_duration_slots;
        cfg.node_share_bps         = node_share_bps;
        cfg.treasury_share_bps     = treasury_share_bps;
        cfg.threshold_bps          = threshold_bps;
        cfg.active_node_count      = 1;
        cfg.current_round_id       = 0;
        cfg.bump = ctx.bumps.config;
        msg!("LotteryConfig initialised");
        Ok(())
    }

    // ── 2. update_node_count ──────────────────────────────────────────────────

    pub fn update_node_count(ctx: Context<UpdateNodeCount>, new_count: u32) -> Result<()> {
        require!(new_count > 0, LotteryError::InvalidParam);
        ctx.accounts.config.active_node_count = new_count;
        msg!("active_node_count → {}", new_count);
        Ok(())
    }

    // ── 3. initialize_round ───────────────────────────────────────────────────

    /// Client reads `config.current_round_id`, adds 1, passes as `next_round_id`.
    pub fn initialize_round(ctx: Context<InitializeRound>, next_round_id: u64) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(
            next_round_id == cfg.current_round_id.saturating_add(1),
            LotteryError::InvalidParam
        );

        let clock = Clock::get()?;
        cfg.current_round_id = next_round_id;

        let state = &mut ctx.accounts.lottery_state;
        state.round_id             = next_round_id;
        state.start_slot           = clock.slot;
        state.end_slot             = clock.slot.saturating_add(cfg.round_duration_slots);
        state.ticket_count         = 0;
        state.prize_pool_lamports  = 0;
        state.status               = LotteryStatus::Open as u8;
        state.winner               = Pubkey::default();
        state.committed_winner_index = 0;
        state.slot_hash_used       = [0u8; 32];
        state.vote_count           = 0;
        state.bump = ctx.bumps.lottery_state;

        emit!(RoundOpened { round_id: next_round_id, start_slot: state.start_slot, end_slot: state.end_slot });
        msg!("Round {} opened (ends slot {})", next_round_id, state.end_slot);
        Ok(())
    }

    // ── 4. buy_ticket ─────────────────────────────────────────────────────────

    /// `ticket_index` must equal `lottery_state.ticket_count` at call time.
    pub fn buy_ticket(ctx: Context<BuyTicket>, _round_id: u64, ticket_index: u64) -> Result<()> {
        let clock = Clock::get()?;
        let price        = ctx.accounts.config.ticket_price_lamports;
        let max_per_wallet = ctx.accounts.config.max_tickets_per_wallet;

        require!(ctx.accounts.lottery_state.status == LotteryStatus::Open as u8,
            LotteryError::RoundNotOpen);
        require!(clock.slot < ctx.accounts.lottery_state.end_slot, LotteryError::RoundEnded);
        require!(ticket_index == ctx.accounts.lottery_state.ticket_count,
            LotteryError::InvalidTicketIndex);
        require!(ctx.accounts.wallet_count.count < max_per_wallet,
            LotteryError::MaxTicketsExceeded);

        // SOL: buyer → LotteryState PDA (holds prize pool)
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.buyer.to_account_info(),
                    to:   ctx.accounts.lottery_state.to_account_info(),
                },
            ),
            price,
        )?;

        let round_id = ctx.accounts.lottery_state.round_id;

        let ticket = &mut ctx.accounts.ticket;
        ticket.round_id = round_id;
        ticket.buyer    = ctx.accounts.buyer.key();
        ticket.index    = ticket_index;
        ticket.bump     = ctx.bumps.ticket;

        ctx.accounts.wallet_count.count =
            ctx.accounts.wallet_count.count.saturating_add(1);
        ctx.accounts.lottery_state.ticket_count =
            ctx.accounts.lottery_state.ticket_count.saturating_add(1);
        ctx.accounts.lottery_state.prize_pool_lamports =
            ctx.accounts.lottery_state.prize_pool_lamports.saturating_add(price);

        emit!(TicketPurchased { round_id, buyer: ctx.accounts.buyer.key(), index: ticket_index });
        Ok(())
    }

    // ── 5. cast_draw_vote ─────────────────────────────────────────────────────

    /// Node calls this after `end_slot` passes. Program re-derives `winner_index`
    /// from SlotHashes; tx is rejected if node's value differs.
    pub fn cast_draw_vote(
        ctx: Context<CastDrawVote>,
        _round_id: u64,
        winner_index: u64,
    ) -> Result<()> {
        let clock = Clock::get()?;
        let status       = ctx.accounts.lottery_state.status;
        let end_slot     = ctx.accounts.lottery_state.end_slot;
        let ticket_count = ctx.accounts.lottery_state.ticket_count;
        let committed_sh = ctx.accounts.lottery_state.slot_hash_used;
        let round_id_val = ctx.accounts.lottery_state.round_id;
        let vote_count   = ctx.accounts.lottery_state.vote_count;

        require!(
            status == LotteryStatus::Open as u8 || status == LotteryStatus::Committing as u8,
            LotteryError::RoundNotOpen
        );
        require!(clock.slot >= end_slot,         LotteryError::RoundNotEnded);
        require!(ticket_count > 0,               LotteryError::NoTicketsSold);
        require!(winner_index < ticket_count,    LotteryError::InvalidWinnerIndex);

        let slot_hash_bytes = if status == LotteryStatus::Open as u8 {
            read_slot_hash_for_slot(&ctx.accounts.slot_hashes, end_slot)?
        } else {
            committed_sh
        };

        let expected = derive_winner_index(&slot_hash_bytes, round_id_val, ticket_count);
        require!(winner_index == expected, LotteryError::WinnerIndexMismatch);

        // Record vote
        let vote = &mut ctx.accounts.draw_vote;
        vote.round_id       = round_id_val;
        vote.node_pubkey    = ctx.accounts.node_operator.key();
        vote.winner_index   = winner_index;
        vote.slot_hash_used = slot_hash_bytes;
        vote.claimed        = false;
        vote.bump           = ctx.bumps.draw_vote;

        if status == LotteryStatus::Open as u8 {
            ctx.accounts.lottery_state.slot_hash_used = slot_hash_bytes;
            ctx.accounts.lottery_state.status         = LotteryStatus::Committing as u8;
        }
        ctx.accounts.lottery_state.committed_winner_index = winner_index;
        ctx.accounts.lottery_state.vote_count = vote_count.saturating_add(1);

        emit!(DrawVoteCast {
            round_id: round_id_val,
            node_pubkey: ctx.accounts.node_operator.key(),
            winner_index,
            vote_count: ctx.accounts.lottery_state.vote_count,
        });
        msg!("DrawVote: index={} votes={}", winner_index, ctx.accounts.lottery_state.vote_count);
        Ok(())
    }

    // ── 6. finalize_draw ──────────────────────────────────────────────────────

    pub fn finalize_draw(ctx: Context<FinalizeDraw>, round_id: u64) -> Result<()> {
        // ── Read all values first (avoid simultaneous &mut and & borrows) ──────
        let status         = ctx.accounts.lottery_state.status;
        let vote_count     = ctx.accounts.lottery_state.vote_count;
        let prize_pool     = ctx.accounts.lottery_state.prize_pool_lamports;
        let committed_idx  = ctx.accounts.lottery_state.committed_winner_index;
        let state_bump     = ctx.accounts.lottery_state.bump;
        let active_nodes   = ctx.accounts.config.active_node_count;
        let threshold_bps  = ctx.accounts.config.threshold_bps;
        let node_bps       = ctx.accounts.config.node_share_bps;
        let treasury_bps   = ctx.accounts.config.treasury_share_bps;

        require!(status == LotteryStatus::Committing as u8, LotteryError::RoundNotCommitting);

        let threshold_num = (active_nodes as u64).saturating_mul(threshold_bps);
        let actual_num    = (vote_count  as u64).saturating_mul(10_000);
        require!(actual_num >= threshold_num, LotteryError::ThresholdNotMet);

        let winner_pubkey = ctx.accounts.winner_ticket.buyer;
        require!(ctx.accounts.winner_ticket.index == committed_idx, LotteryError::WinnerTicketMismatch);

        // ── Compute shares ────────────────────────────────────────────────────
        let node_share     = prize_pool.saturating_mul(node_bps as u64) / 10_000;
        let treasury_share = prize_pool.saturating_mul(treasury_bps as u64) / 10_000;
        let winner_share   = prize_pool.saturating_sub(node_share).saturating_sub(treasury_share);

        // ── CPI transfers from LotteryState PDA ──────────────────────────────
        let round_id_bytes = round_id.to_le_bytes();
        let bump_arr       = [state_bump];
        let seeds: &[&[u8]] = &[b"lottery", &round_id_bytes, &bump_arr];
        let signer_seeds    = &[seeds];

        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.lottery_state.to_account_info(),
                    to:   ctx.accounts.winner_wallet.to_account_info(),
                },
                signer_seeds,
            ),
            winner_share,
        )?;

        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.lottery_state.to_account_info(),
                    to:   ctx.accounts.treasury.to_account_info(),
                },
                signer_seeds,
            ),
            treasury_share,
        )?;

        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.lottery_state.to_account_info(),
                    to:   ctx.accounts.node_prize_pool.to_account_info(),
                },
                signer_seeds,
            ),
            node_share,
        )?;

        // ── Update accounts ───────────────────────────────────────────────────
        ctx.accounts.lottery_state.winner               = winner_pubkey;
        ctx.accounts.lottery_state.status               = LotteryStatus::Closed as u8;
        ctx.accounts.lottery_state.prize_pool_lamports  = 0;

        ctx.accounts.node_prize_pool.round_id        = round_id;
        ctx.accounts.node_prize_pool.total_lamports  = node_share;
        ctx.accounts.node_prize_pool.vote_count      = vote_count;
        ctx.accounts.node_prize_pool.claimed_count   = 0;
        ctx.accounts.node_prize_pool.bump            = ctx.bumps.node_prize_pool;

        emit!(RoundFinalized {
            round_id, winner: winner_pubkey, winner_index: committed_idx,
            winner_share, node_share, treasury_share, vote_count,
        });
        msg!("Round {} finalized → winner {}", round_id, winner_pubkey);
        Ok(())
    }

    // ── 7. claim_node_prize ───────────────────────────────────────────────────

    pub fn claim_node_prize(ctx: Context<ClaimNodePrize>, _round_id: u64) -> Result<()> {
        require!(!ctx.accounts.draw_vote.claimed,            LotteryError::AlreadyClaimed);
        require!(ctx.accounts.node_prize_pool.vote_count > 0, LotteryError::InvalidParam);

        let share = ctx.accounts.node_prize_pool.total_lamports
            / (ctx.accounts.node_prize_pool.vote_count as u64);
        require!(share > 0, LotteryError::InvalidParam);

        let pool_round_bytes = ctx.accounts.node_prize_pool.round_id.to_le_bytes();
        let pool_bump_arr    = [ctx.accounts.node_prize_pool.bump];
        let pool_seeds: &[&[u8]] = &[b"node_prizes", &pool_round_bytes, &pool_bump_arr];
        let signer_seeds = &[pool_seeds];

        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.node_prize_pool.to_account_info(),
                    to:   ctx.accounts.node_operator.to_account_info(),
                },
                signer_seeds,
            ),
            share,
        )?;

        ctx.accounts.draw_vote.claimed = true;
        ctx.accounts.node_prize_pool.claimed_count =
            ctx.accounts.node_prize_pool.claimed_count.saturating_add(1);

        let r = ctx.accounts.node_prize_pool.round_id;
        emit!(NodePrizeClaimed { round_id: r, node_pubkey: ctx.accounts.node_operator.key(), amount: share });
        msg!("Node {} claimed {} lamports (round {})", ctx.accounts.node_operator.key(), share, r);
        Ok(())
    }
}

// ─── Randomness helpers ────────────────────────────────────────────────────────

/// Deterministic winner derivation:
///   mix = XOR-fold all 32 bytes of slot_hash into 8 bytes,
///         then XOR with round_id_le and ticket_count_le.
/// The slot hash already carries cryptographic entropy; we only need
/// a deterministic, collision-resistant mapping.
fn derive_winner_index(slot_hash: &[u8; 32], round_id: u64, ticket_count: u64) -> u64 {
    let rid = round_id.to_le_bytes();
    let tc  = ticket_count.to_le_bytes();
    let mut acc = [0u8; 8];
    for i in 0..8 {
        acc[i] = slot_hash[i]
            ^ slot_hash[i + 8]
            ^ slot_hash[i + 16]
            ^ slot_hash[i + 24]
            ^ rid[i]
            ^ tc[i];
    }
    u64::from_le_bytes(acc) % ticket_count
}

/// Parse SlotHashes sysvar (bincode LE: [u64 count] [u64 slot | [u8;32] hash]×n).
/// Returns the hash for `target_slot`, or the most-recent hash as a fallback.
fn read_slot_hash_for_slot(account: &AccountInfo, target_slot: u64) -> Result<[u8; 32]> {
    let data = account.try_borrow_data().map_err(|_| LotteryError::SlotHashesReadFailed)?;
    require!(data.len() >= 8, LotteryError::SlotHashesReadFailed);

    let count = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| LotteryError::SlotHashesReadFailed)?,
    ) as usize;

    let mut fallback: Option<[u8; 32]> = None;
    for i in 0..count.min(SLOT_HASHES_CAPACITY) {
        let off = 8 + i * SLOT_HASH_ENTRY_LEN;
        if off + SLOT_HASH_ENTRY_LEN > data.len() { break; }
        let slot = u64::from_le_bytes(
            data[off..off + 8].try_into().map_err(|_| LotteryError::SlotHashesReadFailed)?,
        );
        let hash: [u8; 32] = data[off + 8..off + SLOT_HASH_ENTRY_LEN]
            .try_into().map_err(|_| LotteryError::SlotHashesReadFailed)?;
        if fallback.is_none() { fallback = Some(hash); }
        if slot == target_slot { return Ok(hash); }
    }
    fallback.ok_or(LotteryError::SlotHashesReadFailed.into())
}

// ─── Account contexts ─────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(
        init, payer = authority,
        space = 8 + LotteryConfig::INIT_SPACE,
        seeds = [b"lottery_config"], bump,
    )]
    pub config: Account<'info, LotteryConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: treasury wallet — arbitrary system account
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateNodeCount<'info> {
    #[account(
        mut, seeds = [b"lottery_config"], bump = config.bump,
        has_one = authority @ LotteryError::Unauthorized,
    )]
    pub config: Account<'info, LotteryConfig>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(next_round_id: u64)]
pub struct InitializeRound<'info> {
    #[account(mut, seeds = [b"lottery_config"], bump = config.bump)]
    pub config: Account<'info, LotteryConfig>,

    #[account(
        init, payer = payer,
        space = 8 + LotteryState::INIT_SPACE,
        seeds = [b"lottery", next_round_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub lottery_state: Account<'info, LotteryState>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(round_id: u64, ticket_index: u64)]
pub struct BuyTicket<'info> {
    #[account(seeds = [b"lottery_config"], bump = config.bump)]
    pub config: Account<'info, LotteryConfig>,

    #[account(
        mut,
        seeds = [b"lottery", round_id.to_le_bytes().as_ref()],
        bump = lottery_state.bump,
    )]
    pub lottery_state: Account<'info, LotteryState>,

    #[account(
        init, payer = buyer,
        space = 8 + Ticket::INIT_SPACE,
        seeds = [b"ticket", round_id.to_le_bytes().as_ref(), ticket_index.to_le_bytes().as_ref()],
        bump,
    )]
    pub ticket: Account<'info, Ticket>,

    #[account(
        init_if_needed, payer = buyer,
        space = 8 + WalletTicketCount::INIT_SPACE,
        seeds = [b"wallet_tickets", round_id.to_le_bytes().as_ref(), buyer.key().as_ref()],
        bump,
    )]
    pub wallet_count: Account<'info, WalletTicketCount>,

    #[account(mut)]
    pub buyer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(round_id: u64)]
pub struct CastDrawVote<'info> {
    #[account(seeds = [b"lottery_config"], bump = config.bump)]
    pub config: Account<'info, LotteryConfig>,

    #[account(
        mut,
        seeds = [b"lottery", round_id.to_le_bytes().as_ref()],
        bump = lottery_state.bump,
    )]
    pub lottery_state: Account<'info, LotteryState>,

    #[account(
        init, payer = node_operator,
        space = 8 + DrawVote::INIT_SPACE,
        seeds = [b"draw_vote", round_id.to_le_bytes().as_ref(), node_operator.key().as_ref()],
        bump,
    )]
    pub draw_vote: Account<'info, DrawVote>,

    /// CHECK: SlotHashes sysvar
    #[account(address = anchor_lang::solana_program::sysvar::slot_hashes::id())]
    pub slot_hashes: UncheckedAccount<'info>,

    #[account(mut)]
    pub node_operator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(round_id: u64)]
pub struct FinalizeDraw<'info> {
    #[account(seeds = [b"lottery_config"], bump = config.bump)]
    pub config: Account<'info, LotteryConfig>,

    #[account(
        mut,
        seeds = [b"lottery", round_id.to_le_bytes().as_ref()],
        bump = lottery_state.bump,
    )]
    pub lottery_state: Account<'info, LotteryState>,

    /// Winner's Ticket PDA — proves wallet address for the winning index.
    #[account(
        seeds = [
            b"ticket",
            round_id.to_le_bytes().as_ref(),
            lottery_state.committed_winner_index.to_le_bytes().as_ref(),
        ],
        bump = winner_ticket.bump,
    )]
    pub winner_ticket: Account<'info, Ticket>,

    /// CHECK: winner's wallet — receives 80% of prize pool
    #[account(mut, address = winner_ticket.buyer)]
    pub winner_wallet: UncheckedAccount<'info>,

    #[account(
        init, payer = caller,
        space = 8 + NodePrizePool::INIT_SPACE,
        seeds = [b"node_prizes", round_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub node_prize_pool: Account<'info, NodePrizePool>,

    /// CHECK: treasury — must match config.treasury
    #[account(mut, address = config.treasury)]
    pub treasury: UncheckedAccount<'info>,

    #[account(mut)]
    pub caller: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(round_id: u64)]
pub struct ClaimNodePrize<'info> {
    #[account(
        mut,
        seeds = [b"draw_vote", round_id.to_le_bytes().as_ref(), node_operator.key().as_ref()],
        bump = draw_vote.bump,
        constraint = draw_vote.node_pubkey == node_operator.key() @ LotteryError::Unauthorized,
    )]
    pub draw_vote: Account<'info, DrawVote>,

    #[account(
        mut,
        seeds = [b"node_prizes", round_id.to_le_bytes().as_ref()],
        bump = node_prize_pool.bump,
    )]
    pub node_prize_pool: Account<'info, NodePrizePool>,

    #[account(mut)]
    pub node_operator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// ─── State ────────────────────────────────────────────────────────────────────

#[account]
#[derive(InitSpace)]
pub struct LotteryConfig {
    pub authority:              Pubkey,
    pub treasury:               Pubkey,
    pub ticket_price_lamports:  u64,
    pub max_tickets_per_wallet: u8,
    pub round_duration_slots:   u64,
    pub node_share_bps:         u16,
    pub treasury_share_bps:     u16,
    pub threshold_bps:          u64,
    pub active_node_count:      u32,
    pub current_round_id:       u64,
    pub bump:                   u8,
}

#[account]
#[derive(InitSpace)]
pub struct LotteryState {
    pub round_id:               u64,
    pub start_slot:             u64,
    pub end_slot:               u64,
    pub ticket_count:           u64,
    pub prize_pool_lamports:    u64,
    /// 0 = Open, 1 = Committing, 2 = Closed
    pub status:                 u8,
    pub winner:                 Pubkey,
    pub committed_winner_index: u64,
    /// Slot hash used as entropy — fixed on first cast_draw_vote
    pub slot_hash_used:         [u8; 32],
    pub vote_count:             u8,
    pub bump:                   u8,
}

#[account]
#[derive(InitSpace)]
pub struct Ticket {
    pub round_id: u64,
    pub buyer:    Pubkey,
    pub index:    u64,
    pub bump:     u8,
}

#[account]
#[derive(InitSpace)]
pub struct WalletTicketCount {
    pub count: u8,
    pub bump:  u8,
}

#[account]
#[derive(InitSpace)]
pub struct DrawVote {
    pub round_id:       u64,
    pub node_pubkey:    Pubkey,
    pub winner_index:   u64,
    pub slot_hash_used: [u8; 32],
    pub claimed:        bool,
    pub bump:           u8,
}

#[account]
#[derive(InitSpace)]
pub struct NodePrizePool {
    pub round_id:       u64,
    pub total_lamports: u64,
    pub vote_count:     u8,
    pub claimed_count:  u8,
    pub bump:           u8,
}

// ─── Enums ────────────────────────────────────────────────────────────────────

pub enum LotteryStatus {
    Open       = 0,
    Committing = 1,
    Closed     = 2,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event] pub struct RoundOpened   { pub round_id: u64, pub start_slot: u64, pub end_slot: u64 }
#[event] pub struct TicketPurchased { pub round_id: u64, pub buyer: Pubkey, pub index: u64 }
#[event] pub struct DrawVoteCast  { pub round_id: u64, pub node_pubkey: Pubkey, pub winner_index: u64, pub vote_count: u8 }
#[event] pub struct RoundFinalized {
    pub round_id:       u64,
    pub winner:         Pubkey,
    pub winner_index:   u64,
    pub winner_share:   u64,
    pub node_share:     u64,
    pub treasury_share: u64,
    pub vote_count:     u8,
}
#[event] pub struct NodePrizeClaimed { pub round_id: u64, pub node_pubkey: Pubkey, pub amount: u64 }

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum LotteryError {
    #[msg("Round is not open")]                         RoundNotOpen,
    #[msg("Round end slot has passed")]                 RoundEnded,
    #[msg("Round end slot not yet reached")]            RoundNotEnded,
    #[msg("Round not in Committing state")]             RoundNotCommitting,
    #[msg("ticket_index must equal ticket_count")]      InvalidTicketIndex,
    #[msg("Max tickets per wallet reached")]            MaxTicketsExceeded,
    #[msg("No tickets sold — cannot draw")]             NoTicketsSold,
    #[msg("winner_index mismatch with on-chain derivation")] WinnerIndexMismatch,
    #[msg("winner_index out of range")]                 InvalidWinnerIndex,
    #[msg("Failed to read SlotHashes sysvar")]          SlotHashesReadFailed,
    #[msg("Node threshold (2/3) not met")]              ThresholdNotMet,
    #[msg("Winner ticket index mismatch")]              WinnerTicketMismatch,
    #[msg("Prize already claimed")]                     AlreadyClaimed,
    #[msg("Invalid parameter")]                         InvalidParam,
    #[msg("Unauthorised")]                              Unauthorized,
}