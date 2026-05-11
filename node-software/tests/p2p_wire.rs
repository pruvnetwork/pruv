//! Integration tests for P2P message serialisation / deserialisation.
//!
//! `PeerSignature` fields (from p2p.rs):
//!   • program_id:   [u8; 32]
//!   • program_hash: [u8; 32]
//!   • signer:       [u8; 32]   — Ed25519 verifying key
//!   • signature:    Vec<u8>    — Ed25519 signature (64 bytes)

use pruv_node::p2p::PeerSignature;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn sample_sig() -> PeerSignature {
    PeerSignature {
        program_id:   [0xABu8; 32],
        program_hash: [0xCDu8; 32],
        signer:       [0x12u8; 32],
        signature:    vec![0x34u8; 64],
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[test]
fn peer_signature_roundtrip_bincode() {
    let original = sample_sig();
    let encoded: Vec<u8> = bincode::serialize(&original).expect("serialize");
    let decoded: PeerSignature = bincode::deserialize(&encoded).expect("deserialize");

    assert_eq!(decoded.program_id,   original.program_id);
    assert_eq!(decoded.program_hash, original.program_hash);
    assert_eq!(decoded.signer,       original.signer);
    assert_eq!(decoded.signature,    original.signature);
}

#[test]
fn peer_signature_roundtrip_serde_json() {
    let original = sample_sig();
    let json = serde_json::to_string(&original).expect("json serialize");
    let decoded: PeerSignature = serde_json::from_str(&json).expect("json deserialize");

    assert_eq!(decoded.program_id,   original.program_id);
    assert_eq!(decoded.program_hash, original.program_hash);
    assert_eq!(decoded.signer,       original.signer);
    assert_eq!(decoded.signature,    original.signature);
}

#[test]
fn bincode_size_is_deterministic() {
    // Fixed arrays (no length prefix) + Vec<u8> with 8-byte length prefix:
    // 32 + 32 + 32 + (8 + 64) = 168 bytes.
    let sig = sample_sig();
    let enc = bincode::serialize(&sig).expect("serialize");
    assert_eq!(enc.len(), 168, "wire size changed — update protocol docs");
}

#[test]
fn zero_sig_roundtrips() {
    let zero = PeerSignature {
        program_id:   [0u8; 32],
        program_hash: [0u8; 32],
        signer:       [0u8; 32],
        signature:    vec![0u8; 64],
    };
    let enc: Vec<u8>       = bincode::serialize(&zero).expect("serialize zero");
    let dec: PeerSignature = bincode::deserialize(&enc).expect("deserialize zero");
    assert_eq!(dec.program_id,   [0u8; 32]);
    assert_eq!(dec.signature.len(), 64);
    assert!(dec.signature.iter().all(|&b| b == 0));
}

#[test]
fn empty_signature_roundtrips() {
    let sig = PeerSignature {
        program_id:   [0xFFu8; 32],
        program_hash: [0x00u8; 32],
        signer:       [0xAAu8; 32],
        signature:    vec![],
    };
    let enc: Vec<u8>       = bincode::serialize(&sig).expect("serialize empty sig");
    let dec: PeerSignature = bincode::deserialize(&enc).expect("deserialize empty sig");
    assert!(dec.signature.is_empty());
}

#[test]
fn large_signature_roundtrips() {
    let sig = PeerSignature {
        program_id:   [0x01u8; 32],
        program_hash: [0x02u8; 32],
        signer:       [0x03u8; 32],
        signature:    (0u8..=255).cycle().take(512).collect(),
    };
    let enc: Vec<u8>       = bincode::serialize(&sig).expect("serialize large");
    let dec: PeerSignature = bincode::deserialize(&enc).expect("deserialize large");
    assert_eq!(dec.signature.len(), 512);
    assert_eq!(dec.signature, sig.signature);
}