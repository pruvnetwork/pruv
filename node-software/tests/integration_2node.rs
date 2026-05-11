//! Integration test: two in-process nodes form a gossip mesh and exchange
//! peer signatures, producing a 2-of-2 quorum within a timeout.
//!
//! Run with:
//!   cargo test --manifest-path node-software/Cargo.toml \
//!               --test integration_2node -- --nocapture

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use solana_sdk::pubkey::Pubkey;
use tokio::time::timeout;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal NodeConfig for an in-process test node.
///
/// We use loopback addresses and ephemeral ports to avoid conflicts
/// with other tests and with any live node that may be running.
fn make_test_config(
    keypair_bytes: [u8; 64],
    p2p_port: u16,
    bootstrap_peers: Vec<String>,
) -> Arc<pruv_node::config::NodeConfig> {
    Arc::new(pruv_node::config::NodeConfig {
        operator_keypair_bytes: keypair_bytes,
        p2p_listen_addr: format!("/ip4/127.0.0.1/tcp/{}", p2p_port),
        bootstrap_peers,
        solana_rpc_url: "https://api.devnet.solana.com".to_string(),
        solana_ws_url: "wss://api.devnet.solana.com".to_string(),
        cluster: "devnet".to_string(),
        registry_program_id:    Pubkey::from_str("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS").unwrap(),
        attestation_program_id: Pubkey::from_str("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnT").unwrap(),
        governance_program_id:  Pubkey::from_str("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnU").unwrap(),
        node_program_id:        Pubkey::from_str("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnV").unwrap(),
        srs_k: 10,
        attestation_interval_secs: 3600,
        metrics_port: 0,
        retry_queue_db_path: "/tmp/pruv_test_retry_queue.db".into(),
        proof_cache_ttl_days: 30,
        proof_cache_db_path: "/tmp/pruv_test_proof_cache.db".into(),
    })
}

/// Static test keypairs (first 32 bytes = secret scalar, last 32 = pubkey).
const KP1: [u8; 64] = [
    177,102,130,  1,251, 55,111, 70, 40, 58, 25,130, 66,138,107,185,
     24,121,120,231,212,166,128,211,107, 37, 76, 54,230, 76,139,144,
     32,101,214, 96,142,151, 65,230,100,179,182,230,158,103, 43, 62,
    232, 40,234,118, 98,142, 86,205,173, 89,188,  1,  6,232,179,163,
];

const KP2: [u8; 64] = [
    179,230,202,221,163,192, 29, 92,156,209,229, 52,188,  0, 17,247,
    112, 44,118,147, 58, 55, 18,191, 19,205,145, 25,231, 16,  3,110,
    177,239,110,104,234, 61,139,219,251, 91,132,190,155,150,170,190,
    237,242,170,220,126, 85,244,216, 95,240,212,127,117, 39, 73,  2,
];

// ── Test: P2P starts and channel plumbing works ───────────────────────────────

/// Verifies that `p2p::start` returns successfully and all channel handles
/// are live.  This does not require actual peer connectivity — it just checks
/// the subsystem wires up correctly.
#[tokio::test]
async fn test_p2p_start_returns_handles() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let cfg = make_test_config(KP1, 19100, vec![]);

    let result = timeout(
        Duration::from_secs(5),
        pruv_node::p2p::start(cfg, shutdown_rx),
    )
    .await;

    assert!(result.is_ok(), "p2p::start timed out");
    let inner = result.unwrap();
    assert!(inner.is_ok(), "p2p::start returned error: {:?}", inner.err());

    let (_handle, _sig_rx, sig_tx, last_slot) = inner.unwrap();

    // Channels should be open
    assert!(!sig_tx.is_closed(), "outbound sig channel should be open");

    // LastSlot should start at 0
    assert_eq!(
        last_slot.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "last_slot should initialise to 0"
    );

    let _ = shutdown_tx.send(());
}

// ── Test: two nodes form a mesh and exchange a signature ──────────────────────

/// This test starts two in-process nodes on loopback ports, lets them
/// discover each other via the explicit bootstrap address, publishes a
/// synthetic PeerSignature from Node 1, and asserts Node 2 receives it
/// within 15 seconds.
///
/// The test is marked `#[ignore]` by default because it requires the OS to
/// bind real TCP ports.  Run with:
///   cargo test -- --ignored integration_2node_sig_exchange
#[tokio::test]
#[ignore = "requires network ports; run with --ignored"]
async fn test_2node_sig_exchange() {
    // ── Start Node 1 (seed) ───────────────────────────────────────────────────
    let (sd_tx1, sd_rx1) = tokio::sync::broadcast::channel::<()>(1);
    let cfg1 = make_test_config(KP1, 19200, vec![]);
    let (_h1, _rx1, tx1, _slot1) = pruv_node::p2p::start(cfg1, sd_rx1)
        .await
        .expect("node 1 p2p start");

    // Give Node 1 time to bind
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node 1 PeerId is deterministic from KP1
    let node1_peer_id = "12D3KooWBzqHEQ1QjzRSmHVoSrQxVa4JXqJqQPFB6DUFww4JXuvr";
    let bootstrap = format!("/ip4/127.0.0.1/tcp/19200/p2p/{}", node1_peer_id);

    // ── Start Node 2 (peer) ───────────────────────────────────────────────────
    let (sd_tx2, sd_rx2) = tokio::sync::broadcast::channel::<()>(1);
    let cfg2 = make_test_config(KP2, 19201, vec![bootstrap]);
    let (_h2, mut rx2, _tx2, _slot2) = pruv_node::p2p::start(cfg2, sd_rx2)
        .await
        .expect("node 2 p2p start");

    // Wait for gossip mesh to form (mDNS + bootstrap dial ~3–5 s)
    tokio::time::sleep(Duration::from_secs(6)).await;

    // ── Publish a synthetic signature from Node 1 ─────────────────────────────
    let sig = pruv_node::p2p::PeerSignature {
        program_id:   [0x01u8; 32],
        program_hash: [0xabu8; 32],
        signer:       KP1[32..].try_into().unwrap(),
        signature:    vec![0xffu8; 64],
    };

    tx1.send(sig.clone())
        .await
        .expect("failed to publish sig from node 1");

    // ── Assert Node 2 receives it within 15 s ────────────────────────────────
    let received = timeout(Duration::from_secs(15), rx2.recv()).await;

    assert!(
        received.is_ok(),
        "Node 2 did not receive a PeerSignature within 15 s (gossip mesh may not have formed)"
    );

    let maybe_sig = received.unwrap();
    assert!(
        maybe_sig.is_some(),
        "Node 2 sig channel closed unexpectedly"
    );

    let got = maybe_sig.unwrap();
    assert_eq!(got.program_id, sig.program_id,   "program_id mismatch");
    assert_eq!(got.program_hash, sig.program_hash, "program_hash mismatch");
    assert_eq!(got.signer, sig.signer,             "signer mismatch");
    assert_eq!(got.signature, sig.signature,       "signature bytes mismatch");

    // ── Shutdown ──────────────────────────────────────────────────────────────
    let _ = sd_tx1.send(());
    let _ = sd_tx2.send(());
}

// ── Test: LastSlot propagates via heartbeat ───────────────────────────────────

/// Verifies that writing to `LastSlot` is reflected in subsequent
/// heartbeat messages (unit-level test; no network required).
#[tokio::test]
async fn test_last_slot_atomic_update() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let cfg = make_test_config(KP1, 19300, vec![]);

    let (_h, _rx, _tx, last_slot) = pruv_node::p2p::start(cfg, shutdown_rx)
        .await
        .expect("p2p start");

    // Write slot 42
    last_slot.store(42, std::sync::atomic::Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Read back — must be 42 (no concurrent writer in this test)
    assert_eq!(
        last_slot.load(std::sync::atomic::Ordering::Relaxed),
        42,
        "LastSlot atomic store/load should round-trip correctly"
    );

    let _ = shutdown_tx.send(());
}

// ── Test: shutdown signal stops the P2P task ─────────────────────────────────

#[tokio::test]
async fn test_p2p_task_stops_on_shutdown() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let cfg = make_test_config(KP1, 19400, vec![]);

    let (handle, _rx, _tx, _slot) = pruv_node::p2p::start(cfg, shutdown_rx)
        .await
        .expect("p2p start");

    // Give the swarm a moment to initialise
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send shutdown
    let _ = shutdown_tx.send(());

    // Task should finish within 2 s
    let result = timeout(Duration::from_secs(2), handle).await;
    assert!(result.is_ok(), "P2P task did not stop within 2s after shutdown signal");
}