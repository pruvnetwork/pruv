//! Attestor — collects peer signatures and submits `submit_attestation` on-chain.
//!
//! ## Improvements in this version
//! 1. `make_self_signature` signs SHA-256(program_id||program_hash||proof_hash)
//!    where proof_hash = SHA-256(proof_bytes) — matches on-chain `sign_message()`.
//! 2. `submit_attestation_tx` prepends an Ed25519Program ix so on-chain
//!    `verify_ed25519_sysvar` passes. Encodes proof_hash [u8;32] (not raw bytes).
//!    Adds the `instructions` sysvar account. Removes stray signatures field.
//! 3. Pending map entries now track `next_retry` (Instant) and `attempts` (u8)
//!    for exponential-backoff retries (30s → 60s → 120s → 300s).
//! 4. After `MAX_ATTEMPTS` failures the proof is written to the dead-letter
//!    queue (`retry_queue::RetryQueue`) so it is never silently discarded.
//! 5. TTL-expired entries (> 30 min) are also persisted to the DLQ before
//!    eviction, replacing the earlier warn-and-drop behaviour.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Signer,
    signer::keypair::Keypair,
    sysvar,
    transaction::Transaction,
};

use crate::{
    config::NodeConfig,
    p2p::{LastSlot, PeerSignature},
    prover::ProofResult,
    retry_queue::RetryQueue,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// How long to keep an unresolved entry before writing it to the DLQ.
const PENDING_TTL: Duration = Duration::from_secs(30 * 60);

/// How often to check for entries due for retry or TTL eviction.
/// Must be shorter than the smallest backoff step (30 s).
const RETRY_TICKER_INTERVAL: Duration = Duration::from_secs(15);

/// Maximum number of send attempts before writing to the dead-letter queue.
const MAX_ATTEMPTS: u8 = 4;

/// Exponential-backoff delays (seconds) between successive attempts.
/// Index 0 = delay before attempt 1, index 1 = before attempt 2, etc.
const RETRY_BACKOFF_SECS: [u64; 4] = [30, 60, 120, 300];

// ─── Internal pending-map entry ───────────────────────────────────────────────

struct PendingEntry {
    proof:      Option<ProofResult>,
    sigs:       Vec<PeerSignature>,
    created:    Instant,
    /// When (absolute Instant) the next retry should be attempted.
    next_retry: Instant,
    /// Number of failed submission attempts so far.
    attempts:   u8,
}

impl PendingEntry {
    fn new(proof: Option<ProofResult>, sigs: Vec<PeerSignature>) -> Self {
        let now = Instant::now();
        Self {
            proof,
            sigs,
            created: now,
            // First retry after RETRY_BACKOFF_SECS[0] seconds.
            next_retry: now + Duration::from_secs(RETRY_BACKOFF_SECS[0]),
            attempts: 1,
        }
    }

    /// Advance to the next retry window.
    fn schedule_next_retry(&mut self) {
        self.attempts += 1;
        let idx = ((self.attempts as usize).saturating_sub(1)).min(RETRY_BACKOFF_SECS.len() - 1);
        self.next_retry = Instant::now() + Duration::from_secs(RETRY_BACKOFF_SECS[idx]);
    }

    fn is_expired(&self) -> bool {
        self.created.elapsed() > PENDING_TTL
    }

    fn is_retry_due(&self) -> bool {
        Instant::now() >= self.next_retry
    }

    fn is_dlq_eligible(&self) -> bool {
        self.attempts >= MAX_ATTEMPTS
    }
}

// ─── Public entry point ───────────────────────────────────────────────────────

pub async fn start(
    cfg: Arc<NodeConfig>,
    mut proof_rx: mpsc::Receiver<ProofResult>,
    mut sig_rx: mpsc::Receiver<PeerSignature>,
    p2p_pub_tx: mpsc::Sender<PeerSignature>,
    last_slot: LastSlot,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let rpc = Arc::new(RpcClient::new_with_commitment(
        cfg.solana_rpc_url.clone(),
        CommitmentConfig::confirmed(),
    ));

    let dlq = Arc::new(
        RetryQueue::open(&cfg.retry_queue_db_path)
            .expect("Failed to open retry-queue DB"),
    );

    let handle = tokio::spawn(async move {
        info!("Attestor started");

        // key: hex(program_id) → PendingEntry
        let mut pending: HashMap<String, PendingEntry> = HashMap::new();

        let mut retry_ticker = tokio::time::interval(RETRY_TICKER_INTERVAL);
        retry_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // ── New proof produced by our prover ─────────────────────────
                Some(proof) = proof_rx.recv() => {
                    let key = hex::encode(proof.program_id);
                    info!("Attestor: received proof for {}", key);

                    let our_sig = make_self_signature(&cfg, &proof);
                    let _ = p2p_pub_tx.try_send(our_sig.clone());

                    // Re-use any peer sigs already buffered for this program.
                    let mut sigs = match pending.remove(&key) {
                        Some(e) => e.sigs,
                        None    => vec![],
                    };
                    if !sigs.iter().any(|s| s.signer == our_sig.signer) {
                        sigs.push(our_sig);
                    }

                    if try_submit(&cfg, &rpc, &proof, &sigs).await {
                        info!("Attestor: submitted for {}", key);
                        metrics::counter!("pruv_attestations_submitted_total").increment(1);
                        update_last_slot(&rpc, &last_slot).await;
                    } else {
                        // First failure — park in pending with backoff timer.
                        pending.insert(key, PendingEntry::new(Some(proof), sigs));
                    }
                }

                // ── Peer signature received over P2P ─────────────────────────
                Some(peer_sig) = sig_rx.recv() => {
                    let key = hex::encode(peer_sig.program_id);

                    match pending.get_mut(&key) {
                        Some(entry) => {
                            // Deduplicate.
                            if entry.sigs.iter().any(|s| s.signer == peer_sig.signer) {
                                continue;
                            }
                            entry.sigs.push(peer_sig);

                            // If we have the proof, try an immediate submit now
                            // that we have a new sig (threshold may be met).
                            if let Some(ref proof) = entry.proof.clone() {
                                let sigs = entry.sigs.clone();
                                if try_submit(&cfg, &rpc, proof, &sigs).await {
                                    info!("Attestor: peer-sig triggered submit for {}", key);
                                    metrics::counter!("pruv_attestations_submitted_total").increment(1);
                                    update_last_slot(&rpc, &last_slot).await;
                                    pending.remove(&key);
                                }
                                // else: already in pending, backoff timer unchanged
                            }
                        }
                        None => {
                            // Proof not arrived yet — buffer the sig.
                            warn!("Attestor: peer sig before proof for {} — buffering", key);
                            pending.insert(key, PendingEntry::new(None, vec![peer_sig]));
                        }
                    }
                }

                // ── Periodic retry + TTL eviction ────────────────────────────
                _ = retry_ticker.tick() => {
                    // Collect keys to process so we don't hold mutable refs.
                    let keys: Vec<String> = pending.keys().cloned().collect();

                    for key in keys {
                        let Some(entry) = pending.get_mut(&key) else { continue };

                        // ① TTL expired → DLQ regardless of attempt count.
                        if entry.is_expired() {
                            warn!("Attestor: TTL expired for {} — moving to dead-letter queue", key);
                            if let Some(ref proof) = entry.proof {
                                persist_to_dlq(&dlq, proof, entry.attempts);
                            }
                            pending.remove(&key);
                            continue;
                        }

                        // ② Too many attempts → DLQ.
                        if entry.is_dlq_eligible() {
                            error!(
                                "Attestor: max retries ({}) exhausted for {} — dead-letter queue",
                                MAX_ATTEMPTS, key
                            );
                            if let Some(ref proof) = entry.proof {
                                persist_to_dlq(&dlq, proof, entry.attempts);
                            }
                            pending.remove(&key);
                            continue;
                        }

                        // ③ Backoff timer due — attempt retry.
                        if entry.is_retry_due() {
                            if let Some(ref proof) = entry.proof.clone() {
                                let sigs = entry.sigs.clone();
                                if try_submit(&cfg, &rpc, proof, &sigs).await {
                                    info!(
                                        "Attestor: retry succeeded for {} (attempt {})",
                                        key, entry.attempts
                                    );
                                    metrics::counter!("pruv_attestations_submitted_total")
                                        .increment(1);
                                    metrics::counter!("pruv_attestations_retried_total")
                                        .increment(1);
                                    update_last_slot(&rpc, &last_slot).await;
                                    pending.remove(&key);
                                } else {
                                    let next_secs = RETRY_BACKOFF_SECS[
                                        (entry.attempts as usize).min(RETRY_BACKOFF_SECS.len() - 1)
                                    ];
                                    warn!(
                                        "Attestor: retry {} failed for {}, next in {}s",
                                        entry.attempts, key, next_secs
                                    );
                                    entry.schedule_next_retry();
                                }
                            }
                        }
                    }
                }

                _ = shutdown.recv() => {
                    info!("Attestor shutting down ({} pending entries)", pending.len());
                    break;
                }
            }
        }
    });

    Ok(handle)
}

// ─── DLQ helper ──────────────────────────────────────────────────────────────

fn persist_to_dlq(dlq: &RetryQueue, proof: &ProofResult, attempts: u8) {
    match dlq.enqueue(&proof.program_id, &proof.proof_bytes, attempts as u32) {
        Ok(()) => {
            metrics::counter!("pruv_attestations_dead_lettered_total").increment(1);
        }
        Err(e) => {
            error!("Attestor: failed to write dead-letter entry: {}", e);
        }
    }
}

// ─── Self-signature ───────────────────────────────────────────────────────────

/// Signs: SHA-256( program_id || program_hash || SHA-256(proof_bytes) )
/// Matches the on-chain `sign_message(dapp_program_id, program_hash, proof_hash)`.
fn make_self_signature(cfg: &NodeConfig, proof: &ProofResult) -> PeerSignature {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    let signing_key = cfg.signing_key();

    let proof_hash: [u8; 32] = Sha256::digest(&proof.proof_bytes).into();

    let mut h = Sha256::new();
    h.update(proof.program_id);
    h.update(proof.program_hash);
    h.update(proof_hash);
    let msg: [u8; 32] = h.finalize().into();

    let sig = signing_key.sign(&msg);

    PeerSignature {
        program_id:   proof.program_id,
        program_hash: proof.program_hash,
        signer:       cfg.operator_pubkey().to_bytes(),
        signature:    sig.to_bytes().to_vec(),
    }
}

// ─── Submission helpers ───────────────────────────────────────────────────────

async fn try_submit(
    cfg: &NodeConfig,
    rpc: &RpcClient,
    proof: &ProofResult,
    sigs: &[PeerSignature],
) -> bool {
    if proof.proof_bytes.is_empty() || sigs.is_empty() {
        return false;
    }
    match build_and_send(cfg, rpc, proof, sigs).await {
        Ok(sig) => {
            info!("Attestation tx: {}", sig);
            true
        }
        Err(e) => {
            error!("Attestation send failed: {}", e);
            false
        }
    }
}

async fn update_last_slot(rpc: &RpcClient, last_slot: &LastSlot) {
    if let Ok(slot) = rpc.get_slot().await {
        last_slot.store(slot, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Builds and sends a 2-instruction transaction:
///   ix[0] = Ed25519Program (N signatures)
///   ix[1] = submit_attestation Anchor instruction
async fn build_and_send(
    cfg: &NodeConfig,
    rpc: &RpcClient,
    proof: &ProofResult,
    sigs: &[PeerSignature],
) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    let attest_prog = cfg.attestation_program_id;
    let dapp_id = Pubkey::new_from_array(proof.program_id);

    // proof_hash = SHA-256(raw proof bytes)
    let proof_hash: [u8; 32] = Sha256::digest(&proof.proof_bytes).into();

    // sign_msg = SHA-256(dapp_id || program_hash || proof_hash) — matches on-chain
    let sign_msg: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(dapp_id.as_ref());
        h.update(proof.program_hash);
        h.update(proof_hash);
        h.finalize().into()
    };

    // Only keep sigs with a valid 64-byte payload.
    let valid: Vec<&PeerSignature> =
        sigs.iter().filter(|s| s.signature.len() == 64).collect();
    if valid.is_empty() {
        anyhow::bail!("no valid 64-byte signatures");
    }

    // ix[0]: Ed25519Program instruction
    let ed25519_ix = build_ed25519_instruction(&valid, &sign_msg);

    // Derive PDAs
    let (attestation_pda, _) =
        Pubkey::find_program_address(&[b"attestation", dapp_id.as_ref()], &attest_prog);
    let (config_pda, _) =
        Pubkey::find_program_address(&[b"attest_config"], &attest_prog);

    let keypair = Keypair::try_from(cfg.operator_keypair_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("keypair: {}", e))?;
    let submitter = keypair.pubkey();

    // Anchor discriminator for "submit_attestation"
    let discriminator = anchor_discriminator("global:submit_attestation");

    // Borsh-encode the Anchor args in declaration order:
    //   dapp_program_id: Pubkey       [32]
    //   program_hash:    [u8;32]      [32]
    //   attestation_type: u8 enum     [1]   (CodeIntegrity = 0)
    //   proof_hash:      [u8;32]      [32]
    //   signers:         Vec<Pubkey>  [4 + N*32]
    let mut ix_data = discriminator.to_vec();
    ix_data.extend_from_slice(dapp_id.as_ref());
    ix_data.extend_from_slice(&proof.program_hash);
    ix_data.push(0u8); // AttestationType::CodeIntegrity
    ix_data.extend_from_slice(&proof_hash);
    // signers Vec<Pubkey>
    let n_signers = valid.len() as u32;
    ix_data.extend_from_slice(&n_signers.to_le_bytes());
    for s in &valid {
        ix_data.extend_from_slice(&s.signer);
    }

    // Accounts:
    //  0. attestation PDA   (writable, not signer)
    //  1. config PDA        (writable, not signer)
    //  2. submitter         (writable, signer)
    //  3. clock sysvar      (readonly)
    //  4. instructions sysvar (readonly) ← REQUIRED by verify_ed25519_sysvar
    //  5. system_program    (readonly)
    let accounts = vec![
        AccountMeta::new(attestation_pda, false),
        AccountMeta::new(config_pda, false),
        AccountMeta::new(submitter, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ];

    let submit_ix = Instruction {
        program_id: attest_prog,
        accounts,
        data: ix_data,
    };

    let recent_blockhash = rpc.get_latest_blockhash().await?;
    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, submit_ix],
        Some(&submitter),
        &[&keypair],
        recent_blockhash,
    );

    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow::anyhow!("send_and_confirm: {}", e))?;

    Ok(sig.to_string())
}

// ─── Ed25519Program instruction builder ──────────────────────────────────────

/// Builds a Solana Ed25519Program instruction that verifies N signatures over
/// a shared 32-byte message.
///
/// Data layout:
///   [num_sigs: u16 LE]
///   N × Ed25519SignatureOffsets (7 × u16 LE = 14 bytes each)
///   N × signature (64 bytes each)
///   N × pubkey    (32 bytes each)
///   message       (32 bytes, shared by all sigs)
fn build_ed25519_instruction(sigs: &[&PeerSignature], message: &[u8; 32]) -> Instruction {
    const HEADER: usize = 2;   // num_sigs: u16
    const OFFSETS: usize = 14; // 7 × u16 per sig

    let n = sigs.len();
    let data_start = HEADER + n * OFFSETS;
    let sigs_start = data_start;
    let pks_start  = data_start + n * 64;
    let msg_start  = data_start + n * 64 + n * 32;

    let mut data: Vec<u8> = Vec::with_capacity(msg_start + 32);

    // num_sigs
    data.extend_from_slice(&(n as u16).to_le_bytes());

    // offset structs
    for i in 0..n {
        let sig_off = (sigs_start + i * 64) as u16;
        let pk_off  = (pks_start + i * 32) as u16;
        let msg_off = msg_start as u16;

        // Ed25519SignatureOffsets (all fields u16 LE):
        // signature_offset, signature_instruction_index (0xFFFF = same ix)
        data.extend_from_slice(&sig_off.to_le_bytes());
        data.extend_from_slice(&0xFFFFu16.to_le_bytes());
        // public_key_offset, public_key_instruction_index
        data.extend_from_slice(&pk_off.to_le_bytes());
        data.extend_from_slice(&0xFFFFu16.to_le_bytes());
        // message_data_offset, message_data_size, message_instruction_index
        data.extend_from_slice(&msg_off.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(&0xFFFFu16.to_le_bytes());
    }

    // signatures
    for sig in sigs {
        let bytes: [u8; 64] = sig.signature.as_slice().try_into().unwrap_or([0u8; 64]);
        data.extend_from_slice(&bytes);
    }

    // pubkeys
    for sig in sigs {
        data.extend_from_slice(&sig.signer);
    }

    // message (shared)
    data.extend_from_slice(message);

    Instruction {
        program_id: solana_sdk::ed25519_program::ID,
        accounts:   vec![],
        data,
    }
}

// ─── Anchor discriminator ─────────────────────────────────────────────────────

/// Computes the 8-byte Anchor instruction discriminator: SHA-256(name)[0..8]
fn anchor_discriminator(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(name.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}