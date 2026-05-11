//! Lottery participation module for pruv nodes.
//!
//! After each round's `end_slot` passes, every registered node calls
//! `cast_draw_vote` on-chain with the deterministically derived winner_index.
//! Once 2/3 threshold is met, any caller can call `finalize_draw`, and each
//! voting node can claim its prize share.

use crate::config::NodeConfig;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar,
    transaction::Transaction,
};
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing::{error, info, warn};

// ─── Program ID ───────────────────────────────────────────────────────────────

pub const LOTTERY_PROGRAM_ID: &str = "FLot1111111111111111111111111111111111111111";
pub const LOTTERY_POLL_INTERVAL_SECS: u64 = 30;

// ─── PDA helpers ─────────────────────────────────────────────────────────────

fn prog_id() -> Pubkey {
    LOTTERY_PROGRAM_ID.parse().expect("valid program id")
}

pub fn config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"lottery_config"], &prog_id())
}

pub fn lottery_state_pda(round_id: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"lottery", &round_id.to_le_bytes()], &prog_id())
}

pub fn draw_vote_pda(round_id: u64, node_pubkey: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"draw_vote", &round_id.to_le_bytes(), node_pubkey.as_ref()],
        &prog_id(),
    )
}

pub fn node_prize_pool_pda(round_id: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"node_prizes", &round_id.to_le_bytes()], &prog_id())
}

pub fn ticket_pda(round_id: u64, ticket_index: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"ticket", &round_id.to_le_bytes(), &ticket_index.to_le_bytes()],
        &prog_id(),
    )
}

pub fn node_claim_pda(round_id: u64, node_pubkey: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"node_claim", &round_id.to_le_bytes(), node_pubkey.as_ref()],
        &prog_id(),
    )
}

// ─── Deterministic winner derivation (mirrors on-chain logic) ─────────────────

/// XOR-fold all 32 bytes of `slot_hash` into 8 bytes, mix with `round_id` and
/// `ticket_count` — **must stay byte-for-byte identical to the on-chain Rust**.
pub fn derive_winner_index(slot_hash: &[u8; 32], round_id: u64, ticket_count: u64) -> u64 {
    if ticket_count == 0 {
        return 0;
    }
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

// ─── SlotHashes sysvar reader ─────────────────────────────────────────────────

/// Fetch the hash for `target_slot` from the SlotHashes sysvar.
/// Falls back to the most-recent entry if the exact slot is not listed.
pub async fn fetch_slot_hash_for_slot(
    rpc: &RpcClient,
    target_slot: u64,
) -> anyhow::Result<[u8; 32]> {
    let resp = rpc
        .get_account_with_commitment(&sysvar::slot_hashes::id(), CommitmentConfig::confirmed())
        .await?;
    let acc = resp
        .value
        .ok_or_else(|| anyhow::anyhow!("SlotHashes sysvar account not found"))?;

    let data = acc.data;
    if data.len() < 8 {
        anyhow::bail!("SlotHashes data too short ({} bytes)", data.len());
    }
    let count = u64::from_le_bytes(data[0..8].try_into()?) as usize;
    const ENTRY: usize = 40; // 8-byte slot + 32-byte hash

    let mut fallback: Option<[u8; 32]> = None;
    for i in 0..count.min(512) {
        let off = 8 + i * ENTRY;
        if off + ENTRY > data.len() {
            break;
        }
        let slot = u64::from_le_bytes(data[off..off + 8].try_into()?);
        let hash: [u8; 32] = data[off + 8..off + ENTRY].try_into()?;
        if fallback.is_none() {
            fallback = Some(hash);
        }
        if slot == target_slot {
            return Ok(hash);
        }
    }
    fallback.ok_or_else(|| anyhow::anyhow!("no slot hash found for slot {}", target_slot))
}

// ─── On-chain state snapshots ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LotteryStateSnapshot {
    pub round_id:               u64,
    pub end_slot:               u64,
    pub ticket_count:           u64,
    /// 0 = Open, 1 = Committing, 2 = Closed
    pub status:                 u8,
    pub committed_winner_index: u64,
    pub vote_count:             u8,
    pub winner:                 [u8; 32],
}

impl LotteryStateSnapshot {
    pub fn is_drawable(&self, current_slot: u64) -> bool {
        (self.status == 0 || self.status == 1)
            && current_slot >= self.end_slot
            && self.ticket_count > 0
    }
    pub fn is_closed(&self) -> bool {
        self.status == 2
    }
}

/// Parsed fields from `LotteryConfig` needed for `finalize_draw`.
#[derive(Debug, Clone)]
pub struct LotteryConfigSnapshot {
    pub treasury: Pubkey,
}

// ─── Long-running voter task ──────────────────────────────────────────────────

/// Spawnable async task: polls chain for drawable rounds, casts votes, and
/// claims node prizes. Runs until the process exits.
pub async fn run_lottery_voter(cfg: Arc<NodeConfig>, keypair: Arc<Keypair>) {
    info!("lottery_voter: started (node={})", keypair.pubkey());
    let rpc = RpcClient::new_with_commitment(
        cfg.solana_rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );
    let (cfg_pda, _) = config_pda();

    loop {
        sleep(Duration::from_secs(LOTTERY_POLL_INTERVAL_SECS)).await;

        // ── 1. Read current round id ──────────────────────────────────────────
        let current_round_id = match fetch_current_round_id(&rpc, &cfg_pda).await {
            Ok(id) => id,
            Err(e) => {
                warn!("lottery_voter: config fetch failed: {e}");
                continue;
            }
        };
        if current_round_id == 0 {
            continue; // no round opened yet
        }

        // ── 2. Read LotteryState for current round ────────────────────────────
        let (state_pda, _) = lottery_state_pda(current_round_id);
        let snapshot = match fetch_lottery_state(&rpc, &state_pda).await {
            Ok(s) => s,
            Err(e) => {
                warn!("lottery_voter: state fetch failed (round={current_round_id}): {e}");
                continue;
            }
        };

        // ── 3. Cast draw-vote if round has ended and we haven't voted ─────────
        let current_slot = match rpc.get_slot().await {
            Ok(s) => s,
            Err(e) => {
                warn!("lottery_voter: get_slot failed: {e}");
                continue;
            }
        };

        if snapshot.is_drawable(current_slot) {
            let (vote_pda, _) = draw_vote_pda(current_round_id, &keypair.pubkey());
            let already_voted = rpc.get_account(&vote_pda).await.is_ok();

            if !already_voted {
                match cast_vote(&rpc, &keypair, &snapshot).await {
                    Ok(sig) => info!(
                        "lottery_voter: cast_draw_vote round={} sig={}",
                        current_round_id, sig
                    ),
                    Err(e) => error!(
                        "lottery_voter: cast_draw_vote failed (round={}): {e}",
                        current_round_id
                    ),
                }
            }

            // ── 4. Attempt finalize (permissionless) ──────────────────────────
            if snapshot.status == 1 && snapshot.vote_count > 0 {
                // Read config to get treasury pubkey for the finalize instruction.
                let lottery_cfg = match fetch_lottery_config(&rpc, &cfg_pda).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("lottery_voter: config fetch for finalize failed: {e}");
                        continue;
                    }
                };
                match try_finalize(&rpc, &keypair, &snapshot, &lottery_cfg).await {
                    Ok(Some(sig)) => info!(
                        "lottery_voter: finalize_draw round={} sig={}",
                        current_round_id, sig
                    ),
                    Ok(None) => {}
                    Err(e) => warn!(
                        "lottery_voter: finalize_draw failed (round={}): {e}",
                        current_round_id
                    ),
                }
            }
        }

        // ── 5. Claim node prize if round closed ───────────────────────────────
        if snapshot.is_closed() {
            let (vote_pda, _) = draw_vote_pda(current_round_id, &keypair.pubkey());
            let (pool_pda, _) = node_prize_pool_pda(current_round_id);
            if let Err(e) =
                try_claim(&rpc, &keypair, current_round_id, &vote_pda, &pool_pda).await
            {
                let msg = e.to_string();
                if !msg.contains("AlreadyClaimed") && !msg.contains("account does not exist") {
                    warn!("lottery_voter: claim_node_prize failed (round={}): {e}", current_round_id);
                }
            }
        }
    }
}

// ─── RPC helpers ──────────────────────────────────────────────────────────────

/// Deserialize `LotteryConfig.current_round_id` from raw account data.
///
/// Layout (Anchor/Borsh, LE):
/// `[8 disc][32 authority][32 treasury][8 ticket_price][1 max_per_wallet]`
/// `[8 round_duration][2 node_bps][2 treasury_bps][8 threshold_bps]`
/// `[4 active_node_count][8 current_round_id][1 bump]`
///
/// Offset of `current_round_id` = 8+32+32+8+1+8+2+2+8+4 = 105
async fn fetch_current_round_id(rpc: &RpcClient, pda: &Pubkey) -> anyhow::Result<u64> {
    const OFFSET: usize = 105;
    let resp = rpc
        .get_account_with_commitment(pda, CommitmentConfig::confirmed())
        .await?;
    let data = resp
        .value
        .ok_or_else(|| anyhow::anyhow!("LotteryConfig not found"))?
        .data;
    if data.len() < OFFSET + 8 {
        anyhow::bail!("LotteryConfig data too short");
    }
    Ok(u64::from_le_bytes(data[OFFSET..OFFSET + 8].try_into()?))
}

/// Fetch treasury pubkey from `LotteryConfig`.
///
/// Layout: `[8 disc][32 authority][32 treasury]…`
/// Treasury is at bytes [8+32 .. 8+32+32] = [40..72]
async fn fetch_lottery_config(rpc: &RpcClient, pda: &Pubkey) -> anyhow::Result<LotteryConfigSnapshot> {
    let resp = rpc
        .get_account_with_commitment(pda, CommitmentConfig::confirmed())
        .await?;
    let data = resp
        .value
        .ok_or_else(|| anyhow::anyhow!("LotteryConfig not found"))?
        .data;
    if data.len() < 72 {
        anyhow::bail!("LotteryConfig data too short for treasury ({} bytes)", data.len());
    }
    let treasury = Pubkey::new_from_array(data[40..72].try_into()?);
    Ok(LotteryConfigSnapshot { treasury })
}

/// Deserialize a `LotteryState` account into a snapshot.
///
/// Layout:
/// `[8 disc][8 round_id][8 start_slot][8 end_slot][8 ticket_count]`
/// `[8 prize_pool][1 status][32 winner][8 committed_winner_index]`
/// `[32 slot_hash_used][1 vote_count][1 bump]`
async fn fetch_lottery_state(
    rpc: &RpcClient,
    pda: &Pubkey,
) -> anyhow::Result<LotteryStateSnapshot> {
    let resp = rpc
        .get_account_with_commitment(pda, CommitmentConfig::confirmed())
        .await?;
    let d = resp
        .value
        .ok_or_else(|| anyhow::anyhow!("LotteryState not found"))?
        .data;
    // Minimum: 8+8+8+8+8+8+1+32+8+32+1+1 = 123 bytes
    if d.len() < 123 {
        anyhow::bail!("LotteryState data too short ({} bytes)", d.len());
    }
    let round_id               = u64::from_le_bytes(d[8..16].try_into()?);
    let end_slot               = u64::from_le_bytes(d[24..32].try_into()?);
    let ticket_count           = u64::from_le_bytes(d[32..40].try_into()?);
    // prize_pool at [40..48], skip
    let status                 = d[48];
    let winner: [u8; 32]       = d[49..81].try_into()?;
    let committed_winner_index = u64::from_le_bytes(d[81..89].try_into()?);
    // slot_hash_used at [89..121], skip
    let vote_count             = d[121];

    Ok(LotteryStateSnapshot {
        round_id,
        end_slot,
        ticket_count,
        status,
        committed_winner_index,
        vote_count,
        winner,
    })
}

// ─── Instruction helpers ──────────────────────────────────────────────────────

/// Compute an Anchor instruction discriminator: SHA-256(namespace)[..8]
fn anchor_disc(namespace: &[u8]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(namespace);
    let mut d = [0u8; 8];
    d.copy_from_slice(&h[..8]);
    d
}

fn le_u64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

// ─── cast_draw_vote ───────────────────────────────────────────────────────────

/// Derive `winner_index` from chain data and submit the `cast_draw_vote` instruction.
async fn cast_vote(
    rpc: &RpcClient,
    keypair: &Keypair,
    snap: &LotteryStateSnapshot,
) -> anyhow::Result<String> {
    let slot_hash  = fetch_slot_hash_for_slot(rpc, snap.end_slot).await?;
    let winner_idx = derive_winner_index(&slot_hash, snap.round_id, snap.ticket_count);

    info!(
        "lottery_voter: cast_draw_vote round={} winner_index={} node={}",
        snap.round_id, winner_idx, keypair.pubkey()
    );

    let prog = prog_id();
    let node_key = keypair.pubkey();
    let (state_pda, _) = lottery_state_pda(snap.round_id);
    let (vote_pda, _)  = draw_vote_pda(snap.round_id, &node_key);

    // Discriminator for "global:cast_draw_vote"
    let disc = anchor_disc(b"global:cast_draw_vote");

    // Args: _round_id (u64 LE), winner_index (u64 LE)
    let mut data = disc.to_vec();
    data.extend_from_slice(&le_u64(snap.round_id));
    data.extend_from_slice(&le_u64(winner_idx));

    // Accounts (matches CastDrawVote struct in on-chain program):
    //   lottery_state  — mut
    //   draw_vote      — init + mut
    //   node_operator  — signer + mut
    //   slot_hashes    — readonly sysvar
    //   system_program — readonly
    let accounts = vec![
        AccountMeta::new(state_pda, false),
        AccountMeta::new(vote_pda, false),
        AccountMeta::new(node_key, true),
        AccountMeta::new_readonly(sysvar::slot_hashes::id(), false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];

    let ix = Instruction { program_id: prog, accounts, data };
    let sig = send_tx(rpc, keypair, &[ix]).await?;

    metrics::counter!("pruv_lottery_votes_cast_total").increment(1);
    Ok(sig)
}

// ─── finalize_draw ────────────────────────────────────────────────────────────

/// Attempt to finalize the draw. Returns `Ok(None)` if threshold not met or no
/// tickets were sold.
async fn try_finalize(
    rpc: &RpcClient,
    keypair: &Keypair,
    snap: &LotteryStateSnapshot,
    lottery_cfg: &LotteryConfigSnapshot,
) -> anyhow::Result<Option<String>> {
    // Sanity: round must be in Committing state with at least one ticket.
    if snap.status != 1 || snap.ticket_count == 0 {
        return Ok(None);
    }

    let prog     = prog_id();
    let node_key = keypair.pubkey();
    let round_id = snap.round_id;

    let (cfg_pda, _)   = config_pda();
    let (state_pda, _) = lottery_state_pda(round_id);
    let (pool_pda, _)  = node_prize_pool_pda(round_id);

    // Winner ticket PDA: seeds = [b"ticket", round_id.to_le_bytes(), winner_index.to_le_bytes()]
    let (winner_ticket_pda, _) = ticket_pda(round_id, snap.committed_winner_index);

    // Fetch winner ticket to get the buyer's wallet pubkey.
    let winner_wallet = fetch_ticket_buyer(rpc, &winner_ticket_pda).await?;

    let treasury = lottery_cfg.treasury;

    info!(
        "lottery_voter: finalize_draw round={} winner={} caller={}",
        round_id, winner_wallet, node_key
    );

    // Discriminator for "global:finalize_draw"
    let disc = anchor_disc(b"global:finalize_draw");

    // Args: round_id (u64 LE)
    let mut data = disc.to_vec();
    data.extend_from_slice(&le_u64(round_id));

    // Accounts (matches FinalizeDraw struct):
    //   config           — readonly
    //   lottery_state    — mut
    //   winner_ticket    — readonly
    //   winner_wallet    — mut
    //   treasury         — mut
    //   node_prize_pool  — init + mut
    //   caller           — signer + mut
    //   system_program   — readonly
    let accounts = vec![
        AccountMeta::new_readonly(cfg_pda, false),
        AccountMeta::new(state_pda, false),
        AccountMeta::new_readonly(winner_ticket_pda, false),
        AccountMeta::new(winner_wallet, false),
        AccountMeta::new(treasury, false),
        AccountMeta::new(pool_pda, false),
        AccountMeta::new(node_key, true),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];

    let ix  = Instruction { program_id: prog, accounts, data };
    let sig = send_tx(rpc, keypair, &[ix]).await?;

    metrics::counter!("pruv_lottery_finalize_attempts_total").increment(1);
    Ok(Some(sig))
}

/// Read the `buyer` pubkey from a `Ticket` account.
///
/// Ticket layout (Anchor/Borsh):
/// `[8 disc][8 round_id][32 buyer][8 index][1 bump]`
/// buyer starts at byte 16.
async fn fetch_ticket_buyer(rpc: &RpcClient, ticket_pda: &Pubkey) -> anyhow::Result<Pubkey> {
    let resp = rpc
        .get_account_with_commitment(ticket_pda, CommitmentConfig::confirmed())
        .await?;
    let data = resp
        .value
        .ok_or_else(|| anyhow::anyhow!("Ticket account {} not found", ticket_pda))?
        .data;
    // [8 disc][8 round_id][32 buyer] — buyer at [16..48]
    if data.len() < 48 {
        anyhow::bail!("Ticket account data too short ({} bytes)", data.len());
    }
    let buyer = Pubkey::new_from_array(data[16..48].try_into()?);
    Ok(buyer)
}

// ─── claim_node_prize ─────────────────────────────────────────────────────────

/// Claim the node prize for a closed round.
async fn try_claim(
    rpc: &RpcClient,
    keypair: &Keypair,
    round_id: u64,
    vote_pda: &Pubkey,
    pool_pda: &Pubkey,
) -> anyhow::Result<()> {
    let prog     = prog_id();
    let node_key = keypair.pubkey();

    let (state_pda, _) = lottery_state_pda(round_id);
    let (claim_pda, _) = node_claim_pda(round_id, &node_key);

    info!(
        "lottery_voter: claim_node_prize round={} node={}",
        round_id, node_key
    );

    // Discriminator for "global:claim_node_prize"
    let disc = anchor_disc(b"global:claim_node_prize");

    // Args: round_id (u64 LE)
    let mut data = disc.to_vec();
    data.extend_from_slice(&le_u64(round_id));

    // Accounts (matches ClaimNodePrize struct):
    //   lottery_state   — readonly
    //   node_prize_pool — readonly (lamport transfer done directly by program)
    //   claim           — init_if_needed + mut
    //   node            — signer + mut
    //   draw_vote       — readonly
    //   system_program  — readonly
    let accounts = vec![
        AccountMeta::new_readonly(state_pda, false),
        AccountMeta::new(*pool_pda, false),
        AccountMeta::new(claim_pda, false),
        AccountMeta::new(node_key, true),
        AccountMeta::new_readonly(*vote_pda, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];

    let ix = Instruction { program_id: prog, accounts, data };
    send_tx(rpc, keypair, &[ix]).await?;

    metrics::counter!("pruv_lottery_prizes_claimed_total").increment(1);
    Ok(())
}

// ─── Transaction helper ───────────────────────────────────────────────────────

/// Build, sign and send a transaction; return the signature string on success.
async fn send_tx(
    rpc: &RpcClient,
    keypair: &Keypair,
    instructions: &[Instruction],
) -> anyhow::Result<String> {
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow::anyhow!("get_latest_blockhash: {}", e))?;

    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&keypair.pubkey()),
        &[keypair],
        blockhash,
    );

    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow::anyhow!("send_and_confirm_transaction: {}", e))?;

    Ok(sig.to_string())
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winner_index_deterministic() {
        let h = [1u8; 32];
        assert_eq!(derive_winner_index(&h, 1, 100), derive_winner_index(&h, 1, 100));
    }

    #[test]
    fn winner_index_always_in_range() {
        let h = [0xABu8; 32];
        for n in [1u64, 2, 7, 50, 1_000, u32::MAX as u64] {
            let idx = derive_winner_index(&h, 42, n);
            assert!(idx < n, "idx={idx} not < ticket_count={n}");
        }
    }

    #[test]
    fn winner_index_zero_tickets_no_panic() {
        assert_eq!(derive_winner_index(&[0u8; 32], 0, 0), 0);
    }

    #[test]
    fn pda_derivation_stable() {
        let (pda1, _) = lottery_state_pda(1);
        let (pda2, _) = lottery_state_pda(1);
        assert_eq!(pda1, pda2);
        let (pda3, _) = lottery_state_pda(2);
        assert_ne!(pda1, pda3);
    }

    #[test]
    fn ticket_pda_unique_per_index() {
        let (a, _) = ticket_pda(1, 0);
        let (b, _) = ticket_pda(1, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn node_claim_pda_unique_per_node() {
        let k1 = Pubkey::new_unique();
        let k2 = Pubkey::new_unique();
        let (a, _) = node_claim_pda(1, &k1);
        let (b, _) = node_claim_pda(1, &k2);
        assert_ne!(a, b);
    }

    #[test]
    fn anchor_discriminator_cast_draw_vote() {
        // Sanity: discriminator must be 8 bytes and stable.
        let d1 = anchor_disc(b"global:cast_draw_vote");
        let d2 = anchor_disc(b"global:cast_draw_vote");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 8);
    }
}