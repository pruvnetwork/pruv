//! Node configuration — loaded from environment variables / .env file.
//!
//! ## Keypair loading precedence (most secure first)
//!
//! 1. **Encrypted keystore** — set both `OPERATOR_KEYSTORE_FILE` (path to JSON
//!    keystore) and `OPERATOR_KEYSTORE_PASSWORD`.  The keystore is AES-256-GCM
//!    encrypted, key derived via PBKDF2-SHA256 (100 000 iterations).
//!    Use `NodeConfig::create_keystore` to generate one from a raw keypair.
//!
//! 2. **Plain env var** — set `OPERATOR_KEYPAIR` to a base58 or JSON-array
//!    encoded keypair.  **A warning is emitted when the cluster is not `devnet`
//!    or `localnet`** because storing secrets in environment variables is risky
//!    on shared / cloud infrastructure.

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

/// All runtime configuration for a Pruv node operator.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    // ── Identity ──────────────────────────────────────────────────────────────
    /// Operator's Ed25519 signing key bytes (64 bytes: secret || public).
    pub operator_keypair_bytes: [u8; 64],

    // ── Solana ────────────────────────────────────────────────────────────────
    /// e.g. "https://api.devnet.solana.com"
    pub solana_rpc_url: String,
    /// e.g. "wss://api.devnet.solana.com"
    pub solana_ws_url: String,
    /// "mainnet" | "devnet" | "localnet"
    pub cluster: String,

    // ── On-chain program IDs ──────────────────────────────────────────────────
    pub registry_program_id: Pubkey,
    pub node_program_id: Pubkey,
    pub governance_program_id: Pubkey,
    pub attestation_program_id: Pubkey,

    // ── P2P ───────────────────────────────────────────────────────────────────
    /// TCP listen address for libp2p (e.g. "/ip4/0.0.0.0/tcp/6000")
    pub p2p_listen_addr: String,
    /// Comma-separated list of bootstrap peer multiaddrs.
    pub bootstrap_peers: Vec<String>,

    // ── Prover ────────────────────────────────────────────────────────────────
    /// How often to re-attest active dApps (seconds).
    pub attestation_interval_secs: u64,
    /// SRS K parameter for Halo2 circuits.
    pub srs_k: u32,

    // ── HTTP ──────────────────────────────────────────────────────────────────
    pub metrics_port: u16,

    // ── Storage ───────────────────────────────────────────────────────────────
    /// Path for the attestation dead-letter SQLite database.
    pub retry_queue_db_path: String,
    /// Proof cache TTL in days (proofs older than this are pruned).
    pub proof_cache_ttl_days: u32,
    /// Path to the SQLite proof-cache database.
    pub proof_cache_db_path: String,
}

impl NodeConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self> {
        let cluster = std::env::var("CLUSTER").unwrap_or_else(|_| "devnet".into());

        Ok(Self {
            operator_keypair_bytes: load_keypair_bytes(&cluster)?,
            solana_rpc_url: std::env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".into()),
            solana_ws_url: std::env::var("SOLANA_WS_URL")
                .unwrap_or_else(|_| "wss://api.devnet.solana.com".into()),
            cluster,
            registry_program_id:    parse_pubkey("REGISTRY_PROGRAM_ID",    "RegPruv111111111111111111111111111111111111")?,
            node_program_id:        parse_pubkey("NODE_PROGRAM_ID",        "NodePruv11111111111111111111111111111111111")?,
            governance_program_id:  parse_pubkey("GOVERNANCE_PROGRAM_ID",  "GovPruv111111111111111111111111111111111111")?,
            attestation_program_id: parse_pubkey("ATTESTATION_PROGRAM_ID", "AttsPruv11111111111111111111111111111111111")?,
            p2p_listen_addr: std::env::var("P2P_LISTEN_ADDR").unwrap_or_else(|_| {
                let port = std::env::var("P2P_PORT")
                    .ok()
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(6000);
                format!("/ip4/0.0.0.0/tcp/{}", port)
            }),
            bootstrap_peers: std::env::var("BOOTSTRAP_PEERS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            attestation_interval_secs: std::env::var("ATTESTATION_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3_600),
            srs_k: std::env::var("SRS_K")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(14),
            metrics_port: std::env::var("METRICS_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(9090),
            retry_queue_db_path: std::env::var("RETRY_QUEUE_DB_PATH")
                .unwrap_or_else(|_| "./attestation_retry.db".into()),
            proof_cache_ttl_days: std::env::var("PROOF_CACHE_TTL_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            proof_cache_db_path: std::env::var("PROOF_CACHE_PATH")
                .unwrap_or_else(|_| "./proof_cache.db".into()),
        })
    }

    /// Return the operator's Solana public key (from the Ed25519 verifying key).
    pub fn operator_pubkey(&self) -> Pubkey {
        let signing = SigningKey::from_keypair_bytes(&self.operator_keypair_bytes)
            .expect("invalid keypair bytes");
        let vk: VerifyingKey = signing.verifying_key();
        Pubkey::new_from_array(vk.to_bytes())
    }

    /// Return the operator's Ed25519 signing key.
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_keypair_bytes(&self.operator_keypair_bytes)
            .expect("invalid keypair bytes")
    }

    /// Create an AES-256-GCM encrypted keystore file from raw keypair bytes.
    ///
    /// ```
    /// # use pruv_node::config::NodeConfig;
    /// // Generate or load a keypair, then:
    /// // NodeConfig::create_keystore(&keypair_bytes, "my-strong-password", "/secure/operator.keystore")?;
    /// ```
    ///
    /// The resulting JSON file can be used by setting:
    ///   `OPERATOR_KEYSTORE_FILE=/secure/operator.keystore`
    ///   `OPERATOR_KEYSTORE_PASSWORD=my-strong-password`
    pub fn create_keystore(
        keypair_bytes: &[u8; 64],
        password: &str,
        output_path: &str,
    ) -> Result<()> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
        use rand::RngCore;

        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let aes_key = derive_key(password.as_bytes(), &salt);
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| anyhow::anyhow!("AES-GCM init: {e}"))?;
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, keypair_bytes.as_ref())
            .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {e}"))?;

        let ks = KeystoreFile {
            version:    1,
            salt:       hex::encode(salt),
            nonce:      hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
        };

        let json = serde_json::to_string_pretty(&ks).context("Keystore JSON serialise")?;
        std::fs::write(output_path, json)
            .with_context(|| format!("Cannot write keystore to: {output_path}"))?;

        Ok(())
    }
}

// ─── Keystore file format ─────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct KeystoreFile {
    version:    u8,
    /// Hex-encoded 32-byte PBKDF2 salt.
    salt:       String,
    /// Hex-encoded 12-byte AES-GCM nonce.
    nonce:      String,
    /// Hex-encoded AES-GCM ciphertext (64 bytes keypair + 16 bytes auth tag).
    ciphertext: String,
}

// ─── Key loading ──────────────────────────────────────────────────────────────

/// Resolve the operator keypair, preferring an encrypted keystore over a plain
/// env-var.  Emits a tracing warning when a plaintext keypair is used on a
/// non-development cluster.
fn load_keypair_bytes(cluster: &str) -> Result<[u8; 64]> {
    if let Ok(path) = std::env::var("OPERATOR_KEYSTORE_FILE") {
        let password = std::env::var("OPERATOR_KEYSTORE_PASSWORD").context(
            "OPERATOR_KEYSTORE_PASSWORD is required when OPERATOR_KEYSTORE_FILE is set",
        )?;
        return decrypt_keystore(&path, &password);
    }

    // Fall back to plain env var.
    let raw = std::env::var("OPERATOR_KEYPAIR")
        .context("Either OPERATOR_KEYSTORE_FILE or OPERATOR_KEYPAIR env var is required")?;

    let is_production = cluster != "devnet" && cluster != "localnet";
    if is_production {
        tracing::warn!(
            "⚠️  OPERATOR_KEYPAIR is set as plaintext on cluster '{cluster}'. \
             Consider using OPERATOR_KEYSTORE_FILE + OPERATOR_KEYSTORE_PASSWORD \
             for production deployments to avoid exposing private key material."
        );
    }

    parse_keypair_bytes(&raw)
}

/// Decrypt a JSON keystore file, returning the raw 64-byte keypair.
fn decrypt_keystore(path: &str, password: &str) -> Result<[u8; 64]> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

    let data = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read keystore file: {path}"))?;
    let ks: KeystoreFile = serde_json::from_str(&data).context("Invalid keystore JSON")?;

    anyhow::ensure!(ks.version == 1, "Unsupported keystore version: {}", ks.version);

    let salt       = hex::decode(&ks.salt).context("Keystore salt hex-decode")?;
    let nonce_raw  = hex::decode(&ks.nonce).context("Keystore nonce hex-decode")?;
    let ciphertext = hex::decode(&ks.ciphertext).context("Keystore ciphertext hex-decode")?;

    anyhow::ensure!(salt.len()      == 32, "Keystore salt must be 32 bytes");
    anyhow::ensure!(nonce_raw.len() == 12, "Keystore nonce must be 12 bytes");

    let aes_key: [u8; 32] = derive_key(password.as_bytes(), &salt);
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow::anyhow!("AES-GCM init: {e}"))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_raw);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("Keystore decryption failed — wrong password or corrupt file"))?;

    anyhow::ensure!(plaintext.len() == 64, "Decrypted keypair must be 64 bytes, got {}", plaintext.len());

    let mut arr = [0u8; 64];
    arr.copy_from_slice(&plaintext);
    Ok(arr)
}

/// PBKDF2-SHA256: derive a 32-byte AES key from `password` and `salt`.
/// Uses 100 000 iterations — takes ~100ms on a modern CPU which is acceptable
/// for a single startup operation.
fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, 100_000, &mut key);
    key
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn parse_pubkey(env_var: &str, default: &str) -> Result<Pubkey> {
    let s = std::env::var(env_var).unwrap_or_else(|_| default.into());
    Pubkey::from_str(&s).with_context(|| format!("Invalid pubkey in {}", env_var))
}

fn parse_keypair_bytes(s: &str) -> Result<[u8; 64]> {
    // Accept JSON array [n, n, …] or base58.
    if s.trim_start().starts_with('[') {
        let nums: Vec<u8> = serde_json::from_str(s).context("Keypair JSON parse error")?;
        anyhow::ensure!(nums.len() >= 64, "Keypair JSON array must have at least 64 elements");
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&nums[..64]);
        Ok(arr)
    } else {
        let bytes = bs58::decode(s).into_vec().context("Keypair base58 decode error")?;
        anyhow::ensure!(bytes.len() >= 64, "Keypair base58 must decode to at least 64 bytes");
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes[..64]);
        Ok(arr)
    }
}