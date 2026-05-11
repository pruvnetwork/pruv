//! Unit tests for `NodeConfig` — env-var parsing, keypair formats,
//! default values, and helper methods.
//!
//! Each test sets / clears env vars behind a process-level mutex so parallel
//! `cargo test` threads cannot race each other.

use std::sync::Mutex;

use bs58;
use pruv_node::config::NodeConfig;

// Serialise all tests that touch env vars so they cannot race each other.
static ENV_LOCK: Mutex<()> = Mutex::new(());

// ─── Fixed test keypair ───────────────────────────────────────────────────────
//
// Ed25519: secret = [42u8; 32],  pubkey derived by dalek.
// Encoded once here so every test can reuse the same value.
fn test_keypair_bytes() -> [u8; 64] {
    use ed25519_dalek::SigningKey;
    let signing = SigningKey::from_bytes(&[42u8; 32]);
    let vk = signing.verifying_key();
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&[42u8; 32]);
    b[32..].copy_from_slice(vk.as_bytes());
    b
}

fn test_keypair_json() -> String {
    let b = test_keypair_bytes();
    let nums: Vec<String> = b.iter().map(|x| x.to_string()).collect();
    format!("[{}]", nums.join(","))
}

fn test_keypair_base58() -> String {
    bs58::encode(test_keypair_bytes()).into_string()
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Valid 32-byte-zero pubkey in base58 (Solana system program address).
const VALID_PUBKEY: &str = "11111111111111111111111111111111";

fn set_minimal_env(kp: &str) {
    unsafe {
        std::env::set_var("OPERATOR_KEYPAIR", kp);
        // Default program-IDs in config.rs may not decode to exactly 32 bytes
        // in all build environments, so always override them in tests.
        std::env::set_var("REGISTRY_PROGRAM_ID",    VALID_PUBKEY);
        std::env::set_var("NODE_PROGRAM_ID",         VALID_PUBKEY);
        std::env::set_var("GOVERNANCE_PROGRAM_ID",   VALID_PUBKEY);
        std::env::set_var("ATTESTATION_PROGRAM_ID",  VALID_PUBKEY);
    }
}

fn clear_test_env() {
    let vars = [
        "OPERATOR_KEYPAIR",
        "SOLANA_RPC_URL",
        "SOLANA_WS_URL",
        "CLUSTER",
        "REGISTRY_PROGRAM_ID",
        "NODE_PROGRAM_ID",
        "GOVERNANCE_PROGRAM_ID",
        "ATTESTATION_PROGRAM_ID",
        "P2P_LISTEN_ADDR",
        "P2P_PORT",
        "BOOTSTRAP_PEERS",
        "ATTESTATION_INTERVAL_SECS",
        "SRS_K",
        "METRICS_PORT",
    ];
    for v in vars {
        unsafe { std::env::remove_var(v); }
    }
}

// ─── lock helper — recovers from poison so one panicking test
// ─── doesn't cascade-fail every subsequent test.
macro_rules! env_lock {
    () => {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn keypair_json_array_is_accepted() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_json());

    let cfg = NodeConfig::from_env().expect("config must parse");
    assert_eq!(cfg.operator_keypair_bytes, test_keypair_bytes());
}

#[test]
fn keypair_base58_is_accepted() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_base58());

    let cfg = NodeConfig::from_env().expect("config must parse");
    assert_eq!(cfg.operator_keypair_bytes, test_keypair_bytes());
}

#[test]
fn defaults_are_sane() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_json());

    let cfg = NodeConfig::from_env().expect("config must parse");

    assert_eq!(cfg.solana_rpc_url, "https://api.devnet.solana.com");
    assert_eq!(cfg.solana_ws_url, "wss://api.devnet.solana.com");
    assert_eq!(cfg.cluster, "devnet");
    assert_eq!(cfg.p2p_listen_addr, "/ip4/0.0.0.0/tcp/6000");
    assert!(cfg.bootstrap_peers.is_empty());
    assert_eq!(cfg.attestation_interval_secs, 3_600);
    assert_eq!(cfg.srs_k, 14);
    assert_eq!(cfg.metrics_port, 9090);
}

#[test]
fn env_overrides_replace_defaults() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_json());
    unsafe {
        std::env::set_var("SOLANA_RPC_URL", "http://localhost:8899");
        std::env::set_var("SOLANA_WS_URL", "ws://localhost:8900");
        std::env::set_var("CLUSTER", "localnet");
        std::env::set_var("P2P_LISTEN_ADDR", "/ip4/0.0.0.0/tcp/7000");
        std::env::set_var("ATTESTATION_INTERVAL_SECS", "60");
        std::env::set_var("SRS_K", "10");
        std::env::set_var("METRICS_PORT", "9191");
    }

    let cfg = NodeConfig::from_env().expect("config must parse");

    assert_eq!(cfg.solana_rpc_url, "http://localhost:8899");
    assert_eq!(cfg.solana_ws_url, "ws://localhost:8900");
    assert_eq!(cfg.cluster, "localnet");
    assert_eq!(cfg.p2p_listen_addr, "/ip4/0.0.0.0/tcp/7000");
    assert_eq!(cfg.attestation_interval_secs, 60);
    assert_eq!(cfg.srs_k, 10);
    assert_eq!(cfg.metrics_port, 9191);
}

#[test]
fn p2p_port_shorthand_is_honoured() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_json());
    unsafe { std::env::set_var("P2P_PORT", "7777"); }

    let cfg = NodeConfig::from_env().expect("config must parse");
    assert_eq!(cfg.p2p_listen_addr, "/ip4/0.0.0.0/tcp/7777");
}

#[test]
fn bootstrap_peers_parsed_correctly() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_json());
    unsafe {
        std::env::set_var(
            "BOOTSTRAP_PEERS",
            "/ip4/1.2.3.4/tcp/6000/p2p/QmA,/ip4/5.6.7.8/tcp/6000/p2p/QmB",
        );
    }

    let cfg = NodeConfig::from_env().expect("config must parse");
    assert_eq!(cfg.bootstrap_peers.len(), 2);
    assert_eq!(cfg.bootstrap_peers[0], "/ip4/1.2.3.4/tcp/6000/p2p/QmA");
    assert_eq!(cfg.bootstrap_peers[1], "/ip4/5.6.7.8/tcp/6000/p2p/QmB");
}

#[test]
fn empty_bootstrap_peers_gives_empty_vec() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_json());
    unsafe { std::env::set_var("BOOTSTRAP_PEERS", ""); }

    let cfg = NodeConfig::from_env().expect("config must parse");
    assert!(cfg.bootstrap_peers.is_empty());
}

#[test]
fn operator_pubkey_is_deterministic() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_json());

    let cfg = NodeConfig::from_env().expect("config must parse");

    // Both calls must return the same pubkey.
    let pk1 = cfg.operator_pubkey();
    let pk2 = cfg.operator_pubkey();
    assert_eq!(pk1, pk2);

    // Verify against dalek directly.
    use ed25519_dalek::SigningKey;
    let expected_vk = SigningKey::from_bytes(&[42u8; 32]).verifying_key();
    assert_eq!(pk1.to_bytes(), expected_vk.to_bytes());
}

#[test]
fn signing_key_matches_keypair_bytes() {
    let _guard = env_lock!();
    clear_test_env();
    set_minimal_env(&test_keypair_json());

    let cfg = NodeConfig::from_env().expect("config must parse");
    let sk = cfg.signing_key();

    // The verifying key derived from signing_key() must equal operator_pubkey().
    let vk_bytes = sk.verifying_key().to_bytes();
    assert_eq!(vk_bytes, cfg.operator_pubkey().to_bytes());
}

#[test]
fn missing_operator_keypair_returns_error() {
    let _guard = env_lock!();
    clear_test_env(); // OPERATOR_KEYPAIR not set

    let result = NodeConfig::from_env();
    assert!(result.is_err(), "expected error when OPERATOR_KEYPAIR is missing");
}