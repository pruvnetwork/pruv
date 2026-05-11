//! ZK Prover — receives chain events, fetches on-chain bytecode and generates Halo2 proofs.
//!
//! ## Proof cache
//! Proofs are expensive (seconds of CPU time).  A SQLite database keyed on
//! `(program_id, program_hash)` lets the node survive restarts without
//! re-proving programs whose bytecode has not changed.  The DB path defaults
//! to `./proof_cache.db` and is overridden by the `PROOF_CACHE_PATH` env var.
//!
//! ## BPF Upgradeable Loader support
//! Most Solana programs use the BPFLoaderUpgradeable loader.  The ELF bytecode
//! is stored in a separate `ProgramData` account.  We follow the two-account
//! lookup:
//!   1. Read the `Program` account → extract `programdata_address`.
//!   2. Read the `ProgramData` account → skip the 45-byte header, rest is ELF.
//!
//! Legacy BPF programs (v1/v2) store bytecode directly in the program account.

use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{broadcast, mpsc, Semaphore};
use tracing::{error, info, warn};

use rusqlite::{params, Connection};
#[allow(deprecated)]
use solana_sdk::{
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    pubkey::Pubkey,
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;

use circuits::code_integrity::{
    compute_poseidon_commitment, prove as prove_code_integrity, sha256_native,
    CodeIntegrityPublicInputs, CodeIntegrityWitness,
};

use crate::{config::NodeConfig, monitor::{ChainEvent, FailedPrograms}};

/// Maximum number of ZK proofs that may be generated concurrently.
/// Each Halo2 proof at k=10 uses ~200-500 MB of RAM; we cap at half the
/// logical CPU count to avoid OOM under burst load.
fn max_concurrent_proofs() -> usize {
    (num_cpus::get() / 2).max(1)
}

// ─── Types ────────────────────────────────────────────────────────────────────

/// A completed ZK proof ready for attestation.
#[derive(Clone, Debug)]
pub struct ProofResult {
    pub program_id:    [u8; 32],
    pub program_hash:  [u8; 32],
    pub proof_bytes:   Vec<u8>,
    pub public_inputs: CodeIntegrityPublicInputs,
}

// ─── Proof cache ──────────────────────────────────────────────────────────────

/// SQLite-backed proof cache.
///
/// Thread-safety: `Connection` is `Send` but not `Sync`; we wrap in
/// `Arc<Mutex<…>>` so it can be cloned into `spawn_blocking` tasks.
#[derive(Clone)]
pub struct ProofCache {
    conn: Arc<Mutex<Connection>>,
}

impl ProofCache {
    /// Open (or create) the proof cache database.
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| anyhow::anyhow!("proof cache open '{}': {}", path, e))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous  = NORMAL;
             CREATE TABLE IF NOT EXISTS proof_cache (
                 program_id   BLOB NOT NULL,
                 program_hash BLOB NOT NULL,
                 proof_bytes  BLOB NOT NULL,
                 created_at   INTEGER NOT NULL,
                 PRIMARY KEY (program_id, program_hash)
             );",
        )
        .map_err(|e| anyhow::anyhow!("proof cache init: {}", e))?;

        info!("Proof cache opened at '{}'", path);
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Look up a cached proof.  Returns `None` on cache-miss.
    pub fn get(
        &self,
        program_id: &[u8; 32],
        program_hash: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let conn = self.conn.lock().ok()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT proof_bytes FROM proof_cache \
                 WHERE program_id = ?1 AND program_hash = ?2",
            )
            .ok()?;
        stmt.query_row(
            params![program_id.as_ref(), program_hash.as_ref()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok()
    }

    /// Store a proof in the cache (upsert).
    pub fn put(
        &self,
        program_id: &[u8; 32],
        program_hash: &[u8; 32],
        proof_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock()
            .map_err(|_| anyhow::anyhow!("proof cache lock poisoned"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO proof_cache \
             (program_id, program_hash, proof_bytes, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                program_id.as_ref(),
                program_hash.as_ref(),
                proof_bytes,
                now,
            ],
        )
        .map_err(|e| anyhow::anyhow!("proof cache put: {}", e))?;
        Ok(())
    }

    /// Return the number of cached proofs.
    pub fn len(&self) -> usize {
        let Ok(conn) = self.conn.lock() else { return 0 };
        conn.query_row("SELECT COUNT(*) FROM proof_cache", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    /// Return `true` when the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Start the prover task.
///
/// `failed_programs` is a shared set populated here on hash-mismatch failures.
/// The monitor reads it to skip infinite retry of programs with changed bytecode.
pub async fn start(
    cfg: Arc<NodeConfig>,
    mut event_rx: mpsc::Receiver<ChainEvent>,
    mut shutdown: broadcast::Receiver<()>,
    failed_programs: FailedPrograms,
) -> anyhow::Result<(tokio::task::JoinHandle<()>, mpsc::Receiver<ProofResult>)> {
    let cache = ProofCache::open(&cfg.proof_cache_db_path)?;
    info!("Proof cache ready — {} cached proofs", cache.len());

    let (proof_tx, proof_rx) = mpsc::channel::<ProofResult>(64);
    let srs_k   = cfg.srs_k;
    let rpc_url = cfg.solana_rpc_url.clone();

    // Shared RpcClient — reuse TCP connections across proofs.
    let rpc_client = Arc::new(RpcClient::new_with_commitment(
        rpc_url.clone(),
        CommitmentConfig::confirmed(),
    ));

    // Semaphore prevents OOM under burst load (each proof uses hundreds of MB).
    let max_concurrent = max_concurrent_proofs();
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    info!(
        "ZK Prover semaphore: max {} concurrent proofs (logical CPUs: {})",
        max_concurrent,
        num_cpus::get()
    );

    let handle = tokio::spawn(async move {
        info!("ZK Prover started (SRS k={})", srs_k);

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    match event {
                        ChainEvent::DappRegistered { program_id, program_hash }
                        | ChainEvent::AttestationExpiring {
                            program_id,
                            current_hash: program_hash,
                        } => {
                            info!(
                                "Proving program {}",
                                Pubkey::new_from_array(program_id)
                            );

                            let tx          = proof_tx.clone();
                            let cache_clone = cache.clone();
                            let rpc         = rpc_client.clone();
                            let sem         = semaphore.clone();
                            let fp          = Arc::clone(&failed_programs);

                            tokio::task::spawn(async move {
                                // Acquire semaphore slot before launching the
                                // blocking proof task so we bound RAM usage.
                                let _permit = sem.acquire_owned().await;
                                metrics::gauge!("pruv_proof_queue_depth")
                                    .set(0_f64); // slot acquired — queue depth decrements
                                tokio::task::spawn_blocking(move || {
                                    let t0 = Instant::now();
                                    match generate_proof_shared(
                                        program_id,
                                        program_hash,
                                        srs_k,
                                        &rpc,
                                        &cache_clone,
                                    ) {
                                        Ok(result) => {
                                            let elapsed_ms = t0.elapsed().as_millis() as f64;
                                            metrics::counter!("pruv_proofs_generated_total")
                                                .increment(1);
                                            metrics::histogram!("pruv_proof_duration_ms")
                                                .record(elapsed_ms);
                                            info!(
                                                "Proof ready in {:.0}ms for {}",
                                                elapsed_ms,
                                                Pubkey::new_from_array(result.program_id)
                                            );
                                            let _ = tx.blocking_send(result);
                                        }
                                        Err(e) => {
                                            metrics::counter!("pruv_proofs_failed_total")
                                                .increment(1);
                                            error!("Proof generation failed: {}", e);
                                            // If bytecode hash mismatch, blacklist the program so
                                            // the monitor does not keep re-queuing it on every poll.
                                            if e.to_string().contains("hash mismatch") {
                                                if let Ok(mut set) = fp.write() {
                                                    set.insert(program_id);
                                                    warn!(
                                                        "Prover: blacklisted {} (hash mismatch) — \
                                                         monitor will skip until node restart",
                                                        Pubkey::new_from_array(program_id)
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    // _permit dropped here → semaphore slot released
                                });
                            });

                            // Track pending items waiting for a semaphore slot.
                            metrics::gauge!("pruv_proof_queue_depth")
                                .increment(1_f64);
                        }
                        _ => {}
                    }
                }
                _ = shutdown.recv() => {
                    info!(
                        "Prover shutting down — waiting for in-flight proofs \
                         (semaphore: {}/{} slots free).",
                        semaphore.available_permits(),
                        max_concurrent
                    );
                    break;
                }
            }
        }
    });

    Ok((handle, proof_rx))
}

// ─── Proof generation ─────────────────────────────────────────────────────────

/// Generate a code integrity proof using a shared RpcClient (or replay from cache).
fn generate_proof_shared(
    program_id:      [u8; 32],
    registered_hash: [u8; 32],
    srs_k:           u32,
    rpc:             &RpcClient,
    cache:           &ProofCache,
) -> anyhow::Result<ProofResult> {
    let program_pubkey = Pubkey::new_from_array(program_id);

    // ── Cache lookup ──────────────────────────────────────────────────────────
    if let Some(cached_bytes) = cache.get(&program_id, &registered_hash) {
        info!(
            "Proof cache hit for {} ({} bytes) — skipping re-prove",
            program_pubkey,
            cached_bytes.len()
        );
        metrics::counter!("pruv_proofs_cached_total").increment(1);
        return Ok(ProofResult {
            program_id,
            program_hash: registered_hash,
            proof_bytes:  cached_bytes,
            public_inputs: CodeIntegrityPublicInputs {
                program_id_bytes:    program_id,
                program_hash:        registered_hash,
                poseidon_commitment: compute_poseidon_commitment(
                    &program_id,
                    &registered_hash,
                ),
            },
        });
    }

    // ── Fetch bytecode ────────────────────────────────────────────────────────
    let bytecode = fetch_program_bytecode_shared(rpc, &program_pubkey)?;

    // ── Verify hash ───────────────────────────────────────────────────────────
    let computed_hash = sha256_native(&bytecode);
    if computed_hash != registered_hash {
        warn!(
            "Hash mismatch for {}: registered={} actual={}",
            program_pubkey,
            hex::encode(registered_hash),
            hex::encode(computed_hash),
        );
        return Err(anyhow::anyhow!(
            "Program hash mismatch — bytecode has changed since registration"
        ));
    }

    info!(
        "Bytecode verified for {}: {} bytes, hash={}",
        program_pubkey,
        bytecode.len(),
        hex::encode(computed_hash)
    );

    // ── Generate ZK proof ─────────────────────────────────────────────────────
    let witness = CodeIntegrityWitness {
        bytecode,
        program_hash:     computed_hash,
        program_id_bytes: program_id,
    };

    let (proof_bytes, public_inputs) = prove_code_integrity(witness, srs_k)
        .map_err(|e| anyhow::anyhow!("Circuit prove error: {:?}", e))?;

    info!(
        "Proof generated: {} bytes for {}",
        proof_bytes.len(),
        program_pubkey
    );

    // ── Persist to cache ──────────────────────────────────────────────────────
    if let Err(e) = cache.put(&program_id, &computed_hash, &proof_bytes) {
        warn!("Failed to cache proof for {}: {}", program_pubkey, e);
    } else {
        info!("Proof cached for {}", program_pubkey);
    }

    Ok(ProofResult {
        program_id,
        program_hash: computed_hash,
        proof_bytes,
        public_inputs,
    })
}

// ─── Bytecode fetching ────────────────────────────────────────────────────────

/// Fetch the ELF bytecode for a Solana program using a shared RpcClient (blocking).
fn fetch_program_bytecode_shared(rpc: &RpcClient, program_pubkey: &Pubkey) -> anyhow::Result<Vec<u8>> {
    let program_account = rpc
        .get_account(program_pubkey)
        .map_err(|e| anyhow::anyhow!("Failed to fetch program account {}: {}", program_pubkey, e))?;

    // ── BPFLoaderUpgradeable ──────────────────────────────────────────────────
    if program_account.owner == bpf_loader_upgradeable::id() {
        let state: UpgradeableLoaderState = bincode::deserialize(&program_account.data)
            .map_err(|e| anyhow::anyhow!("UpgradeableLoaderState deser: {}", e))?;

        match state {
            UpgradeableLoaderState::Program { programdata_address } => {
                let programdata_account = rpc
                    .get_account(&programdata_address)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to fetch ProgramData {}: {}",
                            programdata_address,
                            e
                        )
                    })?;

                let header_len = UpgradeableLoaderState::size_of_programdata_metadata();
                if programdata_account.data.len() < header_len {
                    return Err(anyhow::anyhow!(
                        "ProgramData {} too small ({} bytes)",
                        programdata_address,
                        programdata_account.data.len()
                    ));
                }
                let bytecode = programdata_account.data[header_len..].to_vec();
                info!(
                    "Fetched {} bytes from ProgramData {}",
                    bytecode.len(),
                    programdata_address
                );
                return Ok(bytecode);
            }
            UpgradeableLoaderState::Buffer { .. } => {
                return Err(anyhow::anyhow!(
                    "Account {} is an upgrade buffer, not a deployed program",
                    program_pubkey
                ));
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unexpected UpgradeableLoaderState for {}",
                    program_pubkey
                ));
            }
        }
    }

    // ── Legacy BPF loaders (v1/v2) ────────────────────────────────────────────
    info!(
        "Fetched {} bytes (legacy loader) for {}",
        program_account.data.len(),
        program_pubkey
    );
    Ok(program_account.data)
}