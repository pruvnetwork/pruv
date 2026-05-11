//! Block monitor — watches Solana for dApp registration events and triggers proofs.
//!
//! ## Strategy: WS-first with polling fallback
//! 1. **Initial load** — `get_program_accounts` on startup so existing dApps are
//!    proven immediately after the node restarts.
//! 2. **WebSocket log subscription** — `logsSubscribe` filtered to mentions of the
//!    pruv-registry program ID.  Any confirmed, error-free transaction touching
//!    the registry triggers an incremental re-poll so we only re-fetch the minimal
//!    set of accounts rather than parsing raw Anchor event logs.
//! 3. **Polling fallback** — runs every `attestation_interval_secs` (default 1 h)
//!    in case the WS connection is disrupted for a long time.
//! 4. **Reconnect loop** — if the WS stream ends or errors, the task waits 5 s and
//!    re-connects with a fresh `PubsubClient`.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use borsh::BorshDeserialize as _;
use futures::StreamExt;
use solana_client::{
    nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient},
    rpc_config::{
        RpcAccountInfoConfig, RpcProgramAccountsConfig, RpcTransactionLogsConfig,
        RpcTransactionLogsFilter,
    },
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};

use crate::config::NodeConfig;

/// Shared, thread-safe set of program IDs that failed hash verification.
/// Populated by the prover; read by the monitor's poll function to skip re-queueing.
pub type FailedPrograms = Arc<RwLock<HashSet<[u8; 32]>>>;

// ─── Events ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum ChainEvent {
    DappRegistered {
        program_id:   [u8; 32],
        program_hash: [u8; 32],
    },
    AttestationExpiring {
        program_id:   [u8; 32],
        current_hash: [u8; 32],
    },
    ProposalCreated { proposal_id: u64 },
    EpochAdvanced   { epoch: u64 },
}

// ─── DAppEntry mirror ─────────────────────────────────────────────────────────

#[derive(borsh::BorshDeserialize, Debug)]
#[allow(dead_code)]
struct DAppEntryData {
    pub program_id:           [u8; 32],
    pub owner:                [u8; 32],
    pub name:                 String,
    pub uri:                  String,
    pub program_hash:         [u8; 32],
    pub status:               u8,    // 0 = Active
    pub attestation_count:    u32,
    pub registered_at:        i64,
    pub subscription_expiry:  i64,
    pub total_fees_paid:      u64,
    pub bump:                 u8,
}

const STATUS_ACTIVE:       u8  = 0;
const ATTESTATION_TTL_SEC: i64 = 24 * 60 * 60;
const WS_RECONNECT_DELAY:  u64 = 5;   // seconds

// ─── Public API ───────────────────────────────────────────────────────────────

pub async fn start(
    cfg: Arc<NodeConfig>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<(tokio::task::JoinHandle<()>, mpsc::Receiver<ChainEvent>, FailedPrograms)> {
    let (tx, rx) = mpsc::channel::<ChainEvent>(256);

    // Shared failed-programs set: prover writes, monitor reads.
    let failed_programs: FailedPrograms = Arc::new(RwLock::new(HashSet::new()));
    let failed_clone = Arc::clone(&failed_programs);

    let rpc_url          = cfg.solana_rpc_url.clone();
    let ws_url           = cfg.solana_ws_url.clone();
    let registry_id      = cfg.registry_program_id;
    let interval_secs    = cfg.attestation_interval_secs;

    let handle = tokio::spawn(async move {
        info!("Block monitor started (RPC: {}  WS: {})", rpc_url, ws_url);

        let rpc = RpcClient::new_with_commitment(
            rpc_url.clone(),
            CommitmentConfig::confirmed(),
        );

        // Use the shared failed_programs arc inside the task.
        let failed_programs = failed_clone;

        // ── Initial load ──────────────────────────────────────────────────
        // Clone the set before awaiting: std::sync::RwLockReadGuard is !Send,
        // so it must not be held across an .await boundary inside tokio::spawn.
        let fp_snap = failed_programs.read().unwrap_or_else(|e| e.into_inner()).clone();
        match poll_registered_dapps(&rpc, &registry_id, &tx, &fp_snap).await {
            Ok(n)  => info!("Monitor: emitted {} active dApp events (initial)", n),
            Err(e) => warn!("Monitor initial poll error: {}", e),
        }

        // ── Fallback polling ticker ───────────────────────────────────────
        let mut poll_interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        poll_interval.tick().await; // consume the immediate first tick

        // ── WS subscription loop (reconnects on drop) ─────────────────────
        loop {
            // Try to open the WS subscription.
            let pubsub_res = PubsubClient::new(&ws_url).await;

            match pubsub_res {
                Err(e) => {
                    warn!("Monitor: WS connect failed ({}), retrying in {}s", e, WS_RECONNECT_DELAY);
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(WS_RECONNECT_DELAY)) => {}
                        _ = shutdown.recv() => { info!("Block monitor shutting down."); return; }
                    }
                    continue;
                }
                Ok(pubsub) => {
                    let sub_res = pubsub
                        .logs_subscribe(
                            RpcTransactionLogsFilter::Mentions(vec![registry_id.to_string()]),
                            RpcTransactionLogsConfig {
                                commitment: Some(CommitmentConfig::confirmed()),
                            },
                        )
                        .await;

                    match sub_res {
                        Err(e) => {
                            warn!("Monitor: logsSubscribe failed ({}), retrying in {}s", e, WS_RECONNECT_DELAY);
                            tokio::select! {
                                _ = tokio::time::sleep(std::time::Duration::from_secs(WS_RECONNECT_DELAY)) => {}
                                _ = shutdown.recv() => { info!("Block monitor shutting down."); return; }
                            }
                        }
                        Ok((mut logs_stream, unsubscribe)) => {
                            info!("Monitor: WS logsSubscribe active for {}", registry_id);

                            loop {
                                tokio::select! {
                                    msg = logs_stream.next() => {
                                        match msg {
                                            Some(response) => {
                                                let logs_resp = response.value;
                                                if logs_resp.err.is_some() {
                                                    debug!("Monitor: skipping failed tx {}", logs_resp.signature);
                                                    continue;
                                                }
                                debug!(
                                    "Monitor: registry tx {} — re-polling accounts",
                                    logs_resp.signature
                                );
                                let fp_snap = failed_programs.read().unwrap_or_else(|e| e.into_inner()).clone();
                                match poll_registered_dapps(&rpc, &registry_id, &tx, &fp_snap).await {
                                    Ok(n)  => info!("Monitor: emitted {} active dApp events (WS trigger)", n),
                                    Err(e) => warn!("Monitor poll error: {}", e),
                                }
                                            }
                                            None => {
                                                warn!("Monitor: WS log stream ended, reconnecting…");
                                                unsubscribe().await;
                                                break; // reconnect outer loop
                                            }
                                        }
                                    }

                                    _ = poll_interval.tick() => {
                                        info!("Monitor: fallback poll tick");
                                        let fp_snap = failed_programs.read().unwrap_or_else(|e| e.into_inner()).clone();
                                        match poll_registered_dapps(&rpc, &registry_id, &tx, &fp_snap).await {
                                            Ok(n)  => info!("Monitor: emitted {} active dApp events (fallback)", n),
                                            Err(e) => warn!("Monitor fallback poll error: {}", e),
                                        }
                                    }

                                    _ = shutdown.recv() => {
                                        info!("Block monitor shutting down.");
                                        unsubscribe().await;
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    Ok((handle, rx, failed_programs))
}

// ─── Polling ──────────────────────────────────────────────────────────────────

async fn poll_registered_dapps(
    client:              &RpcClient,
    registry_program_id: &Pubkey,
    tx:                  &mpsc::Sender<ChainEvent>,
    failed_programs:     &HashSet<[u8; 32]>,
) -> anyhow::Result<usize> {
    info!("Polling DAppEntry accounts from registry {}", registry_program_id);

    let accounts = client
        .get_program_accounts_with_config(
            registry_program_id,
            RpcProgramAccountsConfig {
                filters:      None,
                account_config: RpcAccountInfoConfig {
                    // Base64 required — Solana RPC rejects base58 for accounts
                    // larger than ~128 bytes (the default when encoding is None).
                    encoding:         Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
                    data_slice:       None,
                    commitment:       Some(CommitmentConfig::confirmed()),
                    min_context_slot: None,
                },
                with_context: Some(false),
                sort_results: None,
            },
        )
        .await?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut active_count = 0usize;

    for (pubkey, account) in &accounts {
        if account.data.len() < 9 {
            continue;
        }
        let entry = match DAppEntryData::try_from_slice(&account.data[8..]) {
            Ok(e)  => e,
            Err(e) => { debug!("Skipping {} — not DAppEntry ({:?})", pubkey, e); continue; }
        };

        if entry.status != STATUS_ACTIVE { continue; }

        if entry.subscription_expiry < now_secs {
            warn!("dApp {} subscription expired — skipping", pubkey);
            continue;
        }

        // Skip programs that previously failed hash verification to avoid
        // infinite retry loops (re-check only after a full node restart).
        if failed_programs.contains(&entry.program_id) {
            debug!("Monitor: skipping {} — previously failed hash verification", pubkey);
            continue;
        }

        active_count += 1;

        let event = if entry.subscription_expiry - now_secs < ATTESTATION_TTL_SEC {
            ChainEvent::AttestationExpiring {
                program_id:   entry.program_id,
                current_hash: entry.program_hash,
            }
        } else {
            ChainEvent::DappRegistered {
                program_id:   entry.program_id,
                program_hash: entry.program_hash,
            }
        };

        info!("Monitor: emitting event for {}", Pubkey::new_from_array(entry.program_id));
        if tx.send(event).await.is_err() { break; }
    }

    Ok(active_count)
}