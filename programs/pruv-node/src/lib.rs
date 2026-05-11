//! pruv-node — Node operator registration, PRUV token staking, slashing and rewards.
//!
//! Node operators stake PRUV tokens to join the attestation network.
//! Economic security: a node that signs a false attestation loses its stake (slashing).
//! Honest nodes earn protocol rewards distributed each epoch.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("HodePruv11111111111111111111111111111111111");

// ─── Constants ────────────────────────────────────────────────────────────────

/// Minimum stake required to operate a node (1 000 PRUV, assuming 9 decimals).
pub const MIN_STAKE: u64 = 1_000 * 1_000_000_000;

/// Slash amount for a proven false attestation (10% of stake).
pub const SLASH_BPS: u64 = 1_000; // basis points — 10%

/// Reputation bonus per successful attestation (capped at MAX_REPUTATION).
pub const REPUTATION_PER_ATTESTATION: u32 = 1;

/// Maximum achievable reputation score.
pub const MAX_REPUTATION: u32 = 1_000;

/// Unbonding period after calling `exit_node` (7 days in seconds).
pub const UNBONDING_PERIOD_SECS: i64 = 7 * 24 * 60 * 60;

// ─── Program ──────────────────────────────────────────────────────────────────

#[program]
pub mod pruv_node {
    use super::*;

    /// Initialise the global node-config singleton (called once by the protocol deployer).
    pub fn init_config(ctx: Context<InitConfig>, reward_rate_bps: u16) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.authority = ctx.accounts.authority.key();
        cfg.pruv_mint = ctx.accounts.pruv_mint.key();
        cfg.reward_pool = ctx.accounts.reward_pool.key();
        cfg.reward_rate_bps = reward_rate_bps;
        cfg.total_staked = 0;
        cfg.active_node_count = 0;
        cfg.epoch = 0;
        cfg.bump = ctx.bumps.config;
        msg!("NodeConfig initialised");
        Ok(())
    }

    /// Register as a node operator by staking PRUV tokens.
    pub fn register_node(ctx: Context<RegisterNode>, stake_amount: u64) -> Result<()> {
        require!(stake_amount >= MIN_STAKE, NodeError::InsufficientStake);

        // Transfer tokens from operator to the escrow vault.
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.operator_token_account.to_account_info(),
                    to: ctx.accounts.stake_vault.to_account_info(),
                    authority: ctx.accounts.operator.to_account_info(),
                },
            ),
            stake_amount,
        )?;

        let clock = Clock::get()?;
        let node = &mut ctx.accounts.node_entry;
        node.operator = ctx.accounts.operator.key();
        node.stake_amount = stake_amount;
        node.reputation_score = 0;
        node.attestations_signed = 0;
        node.slash_count = 0;
        node.status = NodeStatus::Active;
        node.joined_at = clock.unix_timestamp;
        node.exit_requested_at = 0;
        node.pending_rewards = 0;
        node.bump = ctx.bumps.node_entry;

        let cfg = &mut ctx.accounts.config;
        cfg.total_staked = cfg.total_staked.saturating_add(stake_amount);
        cfg.active_node_count = cfg.active_node_count.saturating_add(1);

        emit!(NodeRegistered {
            operator: node.operator,
            stake_amount,
        });

        Ok(())
    }

    /// Record a successful attestation contribution — increase reputation and
    /// accumulate reward shares. Called by pruv-attestation via CPI.
    pub fn record_attestation(ctx: Context<RecordAttestation>) -> Result<()> {
        let node = &mut ctx.accounts.node_entry;

        require!(node.status == NodeStatus::Active, NodeError::NodeNotActive);

        node.attestations_signed = node.attestations_signed.saturating_add(1);
        node.reputation_score = (node.reputation_score + REPUTATION_PER_ATTESTATION).min(MAX_REPUTATION);

        // Accrue reward: reward_rate_bps of the node's stake per attestation.
        let cfg = &ctx.accounts.config;
        let reward = node
            .stake_amount
            .saturating_mul(cfg.reward_rate_bps as u64)
            / 10_000;
        node.pending_rewards = node.pending_rewards.saturating_add(reward);

        Ok(())
    }

    /// Slash a misbehaving node. Requires protocol authority signature plus proof.
    /// In practice this is called by the DAO governance execution path.
    pub fn slash_node(ctx: Context<SlashNode>, evidence_cid: String) -> Result<()> {
        let node = &mut ctx.accounts.node_entry;

        require!(
            node.status == NodeStatus::Active || node.status == NodeStatus::Jailed,
            NodeError::NodeNotSlashable
        );

        let slash_amount = node.stake_amount.saturating_mul(SLASH_BPS) / 10_000;
        node.stake_amount = node.stake_amount.saturating_sub(slash_amount);
        node.slash_count = node.slash_count.saturating_add(1);
        node.status = NodeStatus::Jailed;

        // Reduce global stake counter.
        let cfg = &mut ctx.accounts.config;
        cfg.total_staked = cfg.total_staked.saturating_sub(slash_amount);

        // Slashed tokens go to the reward pool (benefit honest nodes).
        let cfg_bump = cfg.bump;
        let config_seeds: &[&[u8]] = &[b"config", &[cfg_bump]];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.stake_vault.to_account_info(),
                    to: ctx.accounts.reward_pool.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[config_seeds],
            ),
            slash_amount,
        )?;

        emit!(NodeSlashed {
            operator: node.operator,
            slash_amount,
            evidence_cid,
        });

        Ok(())
    }

    /// Begin the unbonding process. Tokens are locked for UNBONDING_PERIOD_SECS.
    pub fn exit_node(ctx: Context<ExitNode>) -> Result<()> {
        let node = &mut ctx.accounts.node_entry;

        require!(
            node.status == NodeStatus::Active,
            NodeError::NodeNotActive
        );

        let clock = Clock::get()?;
        node.status = NodeStatus::Exiting;
        node.exit_requested_at = clock.unix_timestamp;

        let cfg = &mut ctx.accounts.config;
        cfg.active_node_count = cfg.active_node_count.saturating_sub(1);

        emit!(NodeExiting {
            operator: node.operator,
            unlock_at: clock.unix_timestamp + UNBONDING_PERIOD_SECS,
        });

        Ok(())
    }

    /// Withdraw staked tokens after the unbonding period has elapsed.
    pub fn withdraw_stake(ctx: Context<WithdrawStake>) -> Result<()> {
        let node = &mut ctx.accounts.node_entry;

        require!(node.status == NodeStatus::Exiting, NodeError::NotExiting);

        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp >= node.exit_requested_at + UNBONDING_PERIOD_SECS,
            NodeError::UnbondingNotComplete
        );

        let amount = node.stake_amount;
        node.stake_amount = 0;
        node.status = NodeStatus::Exited;

        let cfg_bump = ctx.accounts.config.bump;
        let config_seeds: &[&[u8]] = &[b"config", &[cfg_bump]];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.stake_vault.to_account_info(),
                    to: ctx.accounts.operator_token_account.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[config_seeds],
            ),
            amount,
        )?;

        Ok(())
    }

    /// Claim accumulated attestation rewards.
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let node = &mut ctx.accounts.node_entry;
        let amount = node.pending_rewards;
        require!(amount > 0, NodeError::NoRewards);

        node.pending_rewards = 0;

        let cfg_bump = ctx.accounts.config.bump;
        let config_seeds: &[&[u8]] = &[b"config", &[cfg_bump]];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.reward_pool.to_account_info(),
                    to: ctx.accounts.operator_token_account.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[config_seeds],
            ),
            amount,
        )?;

        emit!(RewardsClaimed {
            operator: node.operator,
            amount,
        });

        Ok(())
    }
}

// ─── Accounts ─────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(
        init,
        payer = authority,
        space = NodeConfig::INIT_SPACE,
        seeds = [b"config"],
        bump,
    )]
    pub config: Account<'info, NodeConfig>,

    pub pruv_mint: Account<'info, Mint>,

    /// CHECK: Reward pool SPL token account — validated externally.
    pub reward_pool: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterNode<'info> {
    #[account(
        init,
        payer = operator,
        space = NodeEntry::INIT_SPACE,
        seeds = [b"node", operator.key().as_ref()],
        bump,
    )]
    pub node_entry: Account<'info, NodeEntry>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, NodeConfig>,

    /// Token account where staked PRUV tokens are escrowed.
    #[account(
        mut,
        constraint = stake_vault.mint == config.pruv_mint @ NodeError::WrongMint,
    )]
    pub stake_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = operator_token_account.owner == operator.key() @ NodeError::WrongOwner,
        constraint = operator_token_account.mint == config.pruv_mint @ NodeError::WrongMint,
    )]
    pub operator_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub operator: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RecordAttestation<'info> {
    #[account(
        mut,
        seeds = [b"node", node_entry.operator.as_ref()],
        bump = node_entry.bump,
    )]
    pub node_entry: Account<'info, NodeEntry>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, NodeConfig>,

    /// Only the pruv-attestation program (or protocol authority) may call this.
    #[account(
        constraint = authority.key() == config.authority @ NodeError::Unauthorized
    )]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SlashNode<'info> {
    #[account(
        mut,
        seeds = [b"node", node_entry.operator.as_ref()],
        bump = node_entry.bump,
    )]
    pub node_entry: Account<'info, NodeEntry>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority @ NodeError::Unauthorized,
    )]
    pub config: Account<'info, NodeConfig>,

    #[account(
        mut,
        constraint = stake_vault.mint == config.pruv_mint @ NodeError::WrongMint,
    )]
    pub stake_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = reward_pool.key() == config.reward_pool @ NodeError::WrongRewardPool,
    )]
    pub reward_pool: Account<'info, TokenAccount>,

    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ExitNode<'info> {
    #[account(
        mut,
        seeds = [b"node", operator.key().as_ref()],
        bump = node_entry.bump,
        has_one = operator @ NodeError::Unauthorized,
    )]
    pub node_entry: Account<'info, NodeEntry>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, NodeConfig>,

    pub operator: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawStake<'info> {
    #[account(
        mut,
        seeds = [b"node", operator.key().as_ref()],
        bump = node_entry.bump,
        has_one = operator @ NodeError::Unauthorized,
    )]
    pub node_entry: Account<'info, NodeEntry>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, NodeConfig>,

    #[account(
        mut,
        constraint = stake_vault.mint == config.pruv_mint @ NodeError::WrongMint,
    )]
    pub stake_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = operator_token_account.owner == operator.key() @ NodeError::WrongOwner,
    )]
    pub operator_token_account: Account<'info, TokenAccount>,

    pub operator: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(
        mut,
        seeds = [b"node", operator.key().as_ref()],
        bump = node_entry.bump,
        has_one = operator @ NodeError::Unauthorized,
    )]
    pub node_entry: Account<'info, NodeEntry>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, NodeConfig>,

    #[account(
        mut,
        constraint = reward_pool.key() == config.reward_pool @ NodeError::WrongRewardPool,
    )]
    pub reward_pool: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = operator_token_account.owner == operator.key() @ NodeError::WrongOwner,
    )]
    pub operator_token_account: Account<'info, TokenAccount>,

    pub operator: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

// ─── State ────────────────────────────────────────────────────────────────────

#[account]
#[derive(InitSpace)]
pub struct NodeConfig {
    /// Protocol authority — can slash nodes and update config.
    pub authority: Pubkey,
    /// PRUV SPL token mint.
    pub pruv_mint: Pubkey,
    /// Token account that holds tokens allocated for node rewards.
    pub reward_pool: Pubkey,
    /// Reward accrual rate in basis points (per attestation, relative to stake).
    pub reward_rate_bps: u16,
    /// Total PRUV tokens currently staked across all nodes.
    pub total_staked: u64,
    /// Number of nodes in Active status.
    pub active_node_count: u32,
    /// Current epoch counter (incremented by the protocol).
    pub epoch: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct NodeEntry {
    /// Node operator's wallet.
    pub operator: Pubkey,
    /// Current amount of PRUV tokens staked.
    pub stake_amount: u64,
    /// Reputation score (0–1 000).
    pub reputation_score: u32,
    /// Cumulative count of attestations this node has co-signed.
    pub attestations_signed: u64,
    /// Number of times this node has been slashed.
    pub slash_count: u32,
    /// Current lifecycle status.
    pub status: NodeStatus,
    /// Unix timestamp when the node joined.
    pub joined_at: i64,
    /// Unix timestamp when `exit_node` was called (0 if not exiting).
    pub exit_requested_at: i64,
    /// Accumulated rewards not yet claimed (in PRUV token smallest unit).
    pub pending_rewards: u64,
    pub bump: u8,
}

// ─── Enums ────────────────────────────────────────────────────────────────────

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq, InitSpace)]
pub enum NodeStatus {
    /// Actively participating in attestations.
    Active,
    /// Slashed and temporarily removed from the active set.
    Jailed,
    /// Unbonding period in progress.
    Exiting,
    /// Fully exited; stake has been withdrawn.
    Exited,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct NodeRegistered {
    pub operator: Pubkey,
    pub stake_amount: u64,
}

#[event]
pub struct NodeSlashed {
    pub operator: Pubkey,
    pub slash_amount: u64,
    pub evidence_cid: String,
}

#[event]
pub struct NodeExiting {
    pub operator: Pubkey,
    pub unlock_at: i64,
}

#[event]
pub struct RewardsClaimed {
    pub operator: Pubkey,
    pub amount: u64,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum NodeError {
    #[msg("Stake amount is below the minimum required (1 000 PRUV)")]
    InsufficientStake,
    #[msg("Node is not in Active status")]
    NodeNotActive,
    #[msg("Node cannot be slashed in its current status")]
    NodeNotSlashable,
    #[msg("Node is not in Exiting status")]
    NotExiting,
    #[msg("Unbonding period has not elapsed yet")]
    UnbondingNotComplete,
    #[msg("No pending rewards to claim")]
    NoRewards,
    #[msg("Caller is not authorised")]
    Unauthorized,
    #[msg("Token mint does not match PRUV mint")]
    WrongMint,
    #[msg("Token account owner mismatch")]
    WrongOwner,
    #[msg("Reward pool address mismatch")]
    WrongRewardPool,
}