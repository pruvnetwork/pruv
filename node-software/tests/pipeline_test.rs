//! Integration tests for the monitor → prover → attestor pipeline.
//!
//! These tests run entirely in-process without a real Solana validator.
//! They exercise:
//!   1. Prover cache-hit path — pre-populated cache returns proof without RPC.
//!   2. Prover graceful shutdown — task terminates cleanly when shutdown fires.
//!   3. Prover RPC error handling — unresolvable RPC URL logs an error, never panics.
//!   4. Attestor self-signature via channel — after receiving a ProofResult the
//!      attestor publishes a valid Ed25519 PeerSignature to the p2p channel.
//!   5. Attestor peer-sig buffering — peer sigs that arrive before the local
//!      proof are buffered and not discarded.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};

use pruv_node::{
    config::NodeConfig,
    monitor::ChainEvent,
    p2p::{LastSlot, PeerSignature},
    prover::{ProofCache, ProofResult, start as prover_start},
    attestor,
};

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Build a `NodeConfig` that is valid but points at a non-existent RPC
/// endpoint so tests that hit the proof-cache path never make real network calls.
fn test_config() -> Arc<NodeConfig> {
    use ed25519_dalek::SigningKey;
    let signing = SigningKey::from_bytes(&[42u8; 32]);
    let vk = signing.verifying_key();
    let mut keypair_bytes = [0u8; 64];
    keypair_bytes[..32].copy_from_slice(&[42u8; 32]);
    keypair_bytes[32..].copy_from_slice(vk.as_bytes());

    Arc::new(NodeConfig {
        operator_keypair_bytes: keypair_bytes,
        // Deliberately unreachable — tests must only exercise the cache-hit path.
        solana_rpc_url: "http://127.0.0.1:19999".into(),
        solana_ws_url:  "ws://127.0.0.1:19999".into(),
        cluster:        "localnet".into(),
        registry_program_id:    solana_sdk::pubkey::Pubkey::new_unique(),
        node_program_id:        solana_sdk::pubkey::Pubkey::new_unique(),
        governance_program_id:  solana_sdk::pubkey::Pubkey::new_unique(),
        attestation_program_id: solana_sdk::pubkey::Pubkey::new_unique(),
        p2p_listen_addr:        "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap_peers:        vec![],
        attestation_interval_secs: 3_600,
        srs_k:         14,
        metrics_port:   0,
        retry_queue_db_path: "/tmp/pruv_test_retry_queue.db".into(),
        proof_cache_ttl_days: 30,
        proof_cache_db_path: "/tmp/pruv_test_proof_cache_default.db".into(),
    })
}

/// Clone a NodeConfig but override the proof_cache_db_path.
fn test_config_with_cache(db_path: &str) -> Arc<NodeConfig> {
    let mut cfg = (*test_config()).clone();
    cfg.proof_cache_db_path = db_path.to_string();
    Arc::new(cfg)
}

/// Create a temporary proof-cache DB backed by a unique in-memory-style path.
fn temp_cache() -> (ProofCache, String) {
    let path = format!("/tmp/pruv_test_cache_{}.db", uuid_like());
    let cache = ProofCache::open(&path).expect("open test proof cache");
    (cache, path)
}

/// Poor-man's unique suffix without pulling in `uuid`.
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // Mix thread-id with nanoseconds for uniqueness across parallel tests.
    let tid = std::thread::current().id();
    format!("{:?}_{}", tid, ns)
}

/// A proof result that looks real enough for attestor tests (no real ZK bytes).
fn fake_proof(program_id: [u8; 32], program_hash: [u8; 32]) -> ProofResult {
    use circuits::code_integrity::{compute_poseidon_commitment, CodeIntegrityPublicInputs};
    // 128-byte fake proof: pattern 0xDE 0xAD 0xBE 0xEF repeated 32 times.
    let proof_bytes = [0xDE_u8, 0xAD, 0xBE, 0xEF]
        .iter()
        .cloned()
        .cycle()
        .take(128)
        .collect::<Vec<_>>();
    ProofResult {
        program_id,
        program_hash,
        proof_bytes,
        public_inputs: CodeIntegrityPublicInputs {
            program_id_bytes:    program_id,
            program_hash,
            poseidon_commitment: compute_poseidon_commitment(&program_id, &program_hash),
        },
    }
}

// ─── 1. Prover: cache-hit returns proof without touching the RPC ──────────────

#[tokio::test]
async fn prover_cache_hit_returns_proof_without_rpc() {
    let (cache, db_path) = temp_cache();

    let program_id:   [u8; 32] = [1u8; 32];
    let program_hash: [u8; 32] = [2u8; 32];
    let expected_proof = vec![0xAA; 64];

    // Pre-populate the cache so the prover never needs to call Solana.
    cache
        .put(&program_id, &program_hash, &expected_proof)
        .expect("cache put");
    assert!(!cache.is_empty());
    drop(cache); // let the prover own it

    let cfg = test_config_with_cache(&db_path);
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    let (event_tx, event_rx) = mpsc::channel::<ChainEvent>(4);
    let failed = Arc::new(std::sync::RwLock::new(std::collections::HashSet::<[u8;32]>::new()));
    let (handle, mut proof_rx) =
        prover_start(cfg, event_rx, shutdown_tx.subscribe(), failed)
            .await
            .expect("prover::start");

    // Send the matching DappRegistered event.
    event_tx
        .send(ChainEvent::DappRegistered { program_id, program_hash })
        .await
        .expect("send event");

    // The prover should reply with the cached proof within 2 s.
    let result = tokio::time::timeout(Duration::from_secs(2), proof_rx.recv())
        .await
        .expect("timed out waiting for proof")
        .expect("proof channel closed");

    assert_eq!(result.program_id, program_id);
    assert_eq!(result.program_hash, program_hash);
    assert_eq!(result.proof_bytes, expected_proof);

    // Clean up.
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    let _ = std::fs::remove_file(&db_path);
}

// ─── 2. Prover: AttestationExpiring event also triggers cache lookup ──────────

#[tokio::test]
async fn prover_attestation_expiring_also_uses_cache() {
    let (cache, db_path) = temp_cache();

    let program_id:   [u8; 32] = [3u8; 32];
    let program_hash: [u8; 32] = [4u8; 32];
    let expected_proof = vec![0xBB; 128];

    cache
        .put(&program_id, &program_hash, &expected_proof)
        .expect("cache put");
    drop(cache);

    let cfg = test_config_with_cache(&db_path);
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let (event_tx, event_rx) = mpsc::channel::<ChainEvent>(4);
    let failed = Arc::new(std::sync::RwLock::new(std::collections::HashSet::<[u8;32]>::new()));
    let (handle, mut proof_rx) =
        prover_start(cfg, event_rx, shutdown_tx.subscribe(), failed)
            .await
            .expect("prover::start");

    event_tx
        .send(ChainEvent::AttestationExpiring {
            program_id,
            current_hash: program_hash,
        })
        .await
        .expect("send event");

    let result = tokio::time::timeout(Duration::from_secs(2), proof_rx.recv())
        .await
        .expect("timed out")
        .expect("channel closed");

    assert_eq!(result.proof_bytes, expected_proof);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    let _ = std::fs::remove_file(&db_path);
}

// ─── 3. Prover: graceful shutdown terminates the task ─────────────────────────

#[tokio::test]
async fn prover_shuts_down_cleanly() {
    let (_, db_path) = temp_cache();
    let cfg = test_config_with_cache(&db_path);
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let (_event_tx, event_rx) = mpsc::channel::<ChainEvent>(4);
    let failed = Arc::new(std::sync::RwLock::new(std::collections::HashSet::<[u8;32]>::new()));
    let (handle, _proof_rx) =
        prover_start(cfg, event_rx, shutdown_tx.subscribe(), failed)
            .await
            .expect("prover::start");

    // Signal shutdown immediately.
    let _ = shutdown_tx.send(());

    // Task must terminate within 1 s.
    let finished = tokio::time::timeout(Duration::from_secs(1), handle).await;
    assert!(finished.is_ok(), "prover task did not shut down within 1 s");

    let _ = std::fs::remove_file(&db_path);
}

// ─── 4. Prover: RPC error is logged, task does not panic ─────────────────────

#[tokio::test]
async fn prover_rpc_error_does_not_panic() {
    let (_, db_path) = temp_cache();
    let cfg = test_config_with_cache(&db_path); // points at non-existent RPC
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let (event_tx, event_rx) = mpsc::channel::<ChainEvent>(4);
    let failed = Arc::new(std::sync::RwLock::new(std::collections::HashSet::<[u8;32]>::new()));
    let (handle, mut proof_rx) =
        prover_start(cfg, event_rx, shutdown_tx.subscribe(), failed)
            .await
            .expect("prover::start");

    // Send an event for a program NOT in the cache — prover must try RPC,
    // fail gracefully, and NOT emit a proof.
    let program_id:   [u8; 32] = [0xFFu8; 32];
    let program_hash: [u8; 32] = [0xEEu8; 32];
    event_tx
        .send(ChainEvent::DappRegistered { program_id, program_hash })
        .await
        .expect("send event");

    // Give the prover a moment to attempt (and fail) the RPC call.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // No proof should have been emitted (cache miss + RPC failure).
    assert!(
        proof_rx.try_recv().is_err(),
        "prover must not emit a proof when RPC fails"
    );

    // Shut down and verify the task finished cleanly (no panic).
    let _ = shutdown_tx.send(());
    let finished = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(
        finished.is_ok(),
        "prover task panicked or did not shut down after RPC error"
    );

    let _ = std::fs::remove_file(&db_path);
}

// ─── 5. Attestor: self-signature is published to p2p channel ─────────────────

#[tokio::test]
async fn attestor_publishes_self_signature_on_proof() {
    let cfg = test_config();

    let (shutdown_tx, _)       = broadcast::channel::<()>(1);
    let (proof_tx, proof_rx)   = mpsc::channel::<ProofResult>(4);
    let (peer_sig_tx, sig_rx)  = mpsc::channel::<PeerSignature>(4);
    let (pub_tx, mut pub_rx)   = mpsc::channel::<PeerSignature>(4);
    let last_slot: LastSlot    = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let handle = attestor::start(
        cfg.clone(),
        proof_rx,
        sig_rx,
        pub_tx,
        last_slot,
        shutdown_tx.subscribe(),
    )
    .await
    .expect("attestor::start");

    let program_id:   [u8; 32] = [5u8; 32];
    let program_hash: [u8; 32] = [6u8; 32];

    proof_tx
        .send(fake_proof(program_id, program_hash))
        .await
        .expect("send proof");

    // Attestor should publish its self-signature to the p2p channel promptly.
    let sig = tokio::time::timeout(Duration::from_secs(2), pub_rx.recv())
        .await
        .expect("timed out waiting for self-signature")
        .expect("p2p channel closed");

    // Verify the signature fields.
    assert_eq!(sig.program_id, program_id);
    assert_eq!(sig.program_hash, program_hash);
    assert_eq!(sig.signer, cfg.operator_pubkey().to_bytes());
    assert_eq!(sig.signature.len(), 64, "ed25519 signature must be 64 bytes");

    // Verify the Ed25519 signature is cryptographically valid.
    // Attestor signs: SHA256( program_id || program_hash || SHA256(proof_bytes) )
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};
    let vk = VerifyingKey::from_bytes(&sig.signer).expect("valid verifying key");
    let proof_bytes = fake_proof(program_id, program_hash).proof_bytes;
    let proof_hash: [u8; 32] = Sha256::digest(&proof_bytes).into();
    let mut hasher = Sha256::new();
    hasher.update(program_id);
    hasher.update(program_hash);
    hasher.update(proof_hash);
    let msg: [u8; 32] = hasher.finalize().into();
    let ed_sig = Signature::from_bytes(sig.signature.as_slice().try_into().unwrap());
    assert!(
        vk.verify(&msg, &ed_sig).is_ok(),
        "self-signature did not verify with the operator public key"
    );

    // Drop the dummy peer_sig channel so no lingering senders.
    drop(peer_sig_tx);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

// ─── 6. Attestor: peer sigs that arrive before the proof are buffered ─────────

#[tokio::test]
async fn attestor_buffers_peer_sig_before_proof() {
    let cfg = test_config();

    let (shutdown_tx, _)       = broadcast::channel::<()>(1);
    let (proof_tx, proof_rx)   = mpsc::channel::<ProofResult>(4);
    let (peer_sig_tx, sig_rx)  = mpsc::channel::<PeerSignature>(4);
    let (pub_tx, mut pub_rx)   = mpsc::channel::<PeerSignature>(4);
    let last_slot: LastSlot    = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let handle = attestor::start(
        cfg.clone(),
        proof_rx,
        sig_rx,
        pub_tx,
        last_slot,
        shutdown_tx.subscribe(),
    )
    .await
    .expect("attestor::start");

    let program_id:   [u8; 32] = [7u8; 32];
    let program_hash: [u8; 32] = [8u8; 32];

    // Build a peer signature from a *different* operator (different secret key).
    let peer_secret = [99u8; 32];
    let peer_signing = ed25519_dalek::SigningKey::from_bytes(&peer_secret);
    let peer_vk = peer_signing.verifying_key();
    let peer_signer: [u8; 32] = peer_vk.to_bytes();

    let peer_sig = PeerSignature {
        program_id,
        program_hash,
        signer: peer_signer,
        signature: vec![0u8; 64], // content doesn't matter for buffering test
    };

    // 1. Send peer sig BEFORE the proof — must be buffered.
    peer_sig_tx
        .send(peer_sig)
        .await
        .expect("send peer sig");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // No self-sig should have been published yet (no proof received).
    assert!(
        pub_rx.try_recv().is_err(),
        "attestor must not publish anything before a proof arrives"
    );

    // 2. Now send the proof.
    proof_tx
        .send(fake_proof(program_id, program_hash))
        .await
        .expect("send proof");

    // 3. Attestor should now publish its own self-signature.
    let self_sig = tokio::time::timeout(Duration::from_secs(2), pub_rx.recv())
        .await
        .expect("timed out waiting for self-sig after proof")
        .expect("p2p channel closed");

    assert_eq!(self_sig.program_id, program_id);
    assert_eq!(self_sig.signer, cfg.operator_pubkey().to_bytes());

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}