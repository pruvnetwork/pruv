//! Pruv Node Daemon — entry point.
//!
//! Starts all subsystems concurrently:
//!   • Block monitor   — watches Solana for new dApp registrations and
//!                       attestation requests.
//!   • ZK Prover       — generates Halo2 proofs for dApp code integrity.
//!   • Attestor        — coordinates multi-sig attestation and submits on-chain.
//!   • P2P layer       — libp2p gossipsub for peer discovery and sig sharing.
//!   • Metrics server  — axum HTTP endpoint at :9090/metrics.
//!   • Maintenance     — periodic proof-cache TTL pruning and DLQ cleanup.

use pruv_node::{attestor, config, lottery, monitor, p2p, prover, retry_queue};

use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logging ───────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("pruv_node=info".parse()?))
        .init();

    dotenv::dotenv().ok();
    info!("Pruv Node starting…");

    // ── Config ────────────────────────────────────────────────────────────────
    let cfg = Arc::new(config::NodeConfig::from_env()?);
    info!("Operator keypair: {}", cfg.operator_pubkey());
    info!("RPC endpoint    : {}", cfg.solana_rpc_url);
    info!("Cluster         : {}", cfg.cluster);

    // ── Shutdown broadcast ────────────────────────────────────────────────────
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // ── P2P layer ─────────────────────────────────────────────────────────────
    let (p2p_handle, sig_rx, p2p_pub_tx, last_attestation_slot) =
        p2p::start(cfg.clone(), shutdown_tx.subscribe()).await?;

    // ── Block monitor ─────────────────────────────────────────────────────────
    // `failed_programs` is shared: monitor reads it to skip retry, prover writes on mismatch.
    let (monitor_handle, event_rx, failed_programs) =
        monitor::start(cfg.clone(), shutdown_tx.subscribe()).await?;

    // ── ZK Prover ─────────────────────────────────────────────────────────────
    let (prover_handle, proof_rx) =
        prover::start(cfg.clone(), event_rx, shutdown_tx.subscribe(), failed_programs).await?;

    // ── Attestor ──────────────────────────────────────────────────────────────
    let attestor_handle =
        attestor::start(
            cfg.clone(),
            proof_rx,
            sig_rx,
            p2p_pub_tx,
            last_attestation_slot,
            shutdown_tx.subscribe(),
        )
        .await?;

    // ── Lottery voter ─────────────────────────────────────────────────────────
    // Build a solana_sdk::Keypair from the operator's Ed25519 bytes so the
    // lottery module can sign transactions independently.
    let operator_kp = {
        use solana_sdk::signer::keypair::Keypair as SolKeypair;
        Arc::new(
            SolKeypair::try_from(cfg.operator_keypair_bytes.as_slice())
                .expect("valid operator keypair bytes"),
        )
    };
    let lottery_handle = tokio::spawn(lottery::run_lottery_voter(cfg.clone(), operator_kp));

    // ── Metrics HTTP server ───────────────────────────────────────────────────
    let metrics_handle = tokio::spawn(metrics_server(cfg.metrics_port));

    // ── Maintenance task (proof-cache TTL + DLQ cleanup) ─────────────────────
    let maint_cfg = cfg.clone();
    let maintenance_handle = tokio::spawn(async move {
        // Run once per day.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            // Prune dead-letter queue entries older than proof_cache_ttl_days.
            match retry_queue::RetryQueue::open(&maint_cfg.retry_queue_db_path) {
                Ok(dlq) => {
                    match dlq.cleanup_older_than_days(maint_cfg.proof_cache_ttl_days) {
                        Ok(0) => {}
                        Ok(n) => info!("Maintenance: pruned {} stale DLQ entries", n),
                        Err(e) => warn!("Maintenance: DLQ cleanup error: {}", e),
                    }
                    match dlq.len() {
                        Ok(n) if n > 0 => warn!(
                            "Maintenance: {} attestation(s) remain in dead-letter queue — \
                             check {} for manual replay",
                            n, maint_cfg.retry_queue_db_path
                        ),
                        _ => {}
                    }
                }
                Err(e) => warn!("Maintenance: cannot open DLQ: {}", e),
            }
        }
    });

    // ── Shutdown: Ctrl-C  OR  SIGTERM ─────────────────────────────────────────
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { info!("Received Ctrl-C"); }
            _ = sigterm.recv()           => { info!("Received SIGTERM"); }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        info!("Received Ctrl-C");
    }
    info!("Shutting down…");
    let _ = shutdown_tx.send(());

    // Wait for all tasks.
    let _ = tokio::join!(
        p2p_handle,
        monitor_handle,
        prover_handle,
        attestor_handle,
        lottery_handle,
        metrics_handle,
        maintenance_handle,
    );

    info!("Pruv Node stopped.");
    Ok(())
}

/// Axum metrics + health endpoint backed by `metrics-exporter-prometheus`.
///
/// Counters registered across the codebase (via `metrics::counter!(...)`) are
/// automatically collected and served in the standard Prometheus text format at
/// GET /metrics.  A lightweight GET /health liveness probe is also provided.
async fn metrics_server(port: u16) {
    use axum::{routing::get, Router};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::net::SocketAddr;

    // ── Install the global Prometheus recorder ────────────────────────────────
    // `install_recorder()` registers the recorder globally and returns a handle
    // whose `render()` produces the Prometheus text exposition format.
    let recorder_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    // Register pre-declared metrics with descriptions so they appear in the
    // output even before the first observation.
    metrics::describe_counter!(
        "pruv_p2p_heartbeats_total",
        "Total gossip heartbeats published by this node"
    );
    metrics::describe_counter!(
        "pruv_p2p_sigs_published_total",
        "Total PeerSignature messages published to gossip"
    );
    metrics::describe_counter!(
        "pruv_p2p_sigs_received_total",
        "Total PeerSignature messages received from peers"
    );
    metrics::describe_counter!(
        "pruv_p2p_connections_total",
        "Total libp2p connections established"
    );
    metrics::describe_counter!(
        "pruv_proofs_generated_total",
        "Total ZK proofs generated by this node"
    );
    metrics::describe_counter!(
        "pruv_proofs_cached_total",
        "Total ZK proofs served from SQLite cache (no re-prove)"
    );
    metrics::describe_counter!(
        "pruv_attestations_submitted_total",
        "Total on-chain attestations submitted by this node"
    );
    metrics::describe_counter!(
        "pruv_attestations_retried_total",
        "Total attestations that required at least one retry before succeeding"
    );
    metrics::describe_counter!(
        "pruv_attestations_dead_lettered_total",
        "Total attestations written to the dead-letter queue after all retries failed"
    );
    metrics::describe_gauge!(
        "pruv_p2p_peers_connected",
        "Current number of connected libp2p peers"
    );
    metrics::describe_counter!(
        "pruv_rpc_requests_total",
        "Total RPC proxy requests handled"
    );
    metrics::describe_counter!(
        "pruv_lottery_votes_cast_total",
        "Total lottery draw-votes cast by this node"
    );
    metrics::describe_counter!(
        "pruv_lottery_finalize_attempts_total",
        "Total finalize_draw calls attempted by this node"
    );
    metrics::describe_counter!(
        "pruv_lottery_prizes_claimed_total",
        "Total lottery node prizes claimed by this node"
    );

    // ── Axum router (axum 0.7) ────────────────────────────────────────────────
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/metrics",
            get({
                let handle = recorder_handle.clone();
                move || {
                    let h = handle.clone();
                    async move { h.render() }
                }
            }),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Metrics server listening on {} — /health  /metrics", addr);

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Metrics server error: {}", e);
            }
        }
        Err(e) => error!("Metrics server bind error on {}: {}", addr, e),
    }
}
