//! Integration tests for the SQLite proof cache.
//!
//! These run against a temporary on-disk database to verify the full
//! open → put → get → upsert → len lifecycle.

use pruv_node::prover::ProofCache;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn tmp_db() -> (ProofCache, tempfile::NamedTempFile) {
    let file = tempfile::NamedTempFile::new().expect("temp file");
    let cache = ProofCache::open(file.path().to_str().unwrap()).expect("open cache");
    (cache, file)
}

fn program_id(b: u8) -> [u8; 32] { [b; 32] }
fn hash(b: u8)       -> [u8; 32] { [b; 32] }

// ─── tests ───────────────────────────────────────────────────────────────────

#[test]
fn open_creates_empty_db() {
    let (cache, _f) = tmp_db();
    assert_eq!(cache.len(), 0);
}

#[test]
fn put_then_get_returns_same_bytes() {
    let (cache, _f) = tmp_db();
    let pid   = program_id(0xAA);
    let ph    = hash(0xBB);
    let proof = vec![1u8, 2, 3, 4, 5];

    cache.put(&pid, &ph, &proof).expect("put");
    let got = cache.get(&pid, &ph).expect("get");
    assert_eq!(got, proof);
}

#[test]
fn cache_miss_returns_none() {
    let (cache, _f) = tmp_db();
    assert!(cache.get(&program_id(0x01), &hash(0x02)).is_none());
}

#[test]
fn len_increments_per_unique_key() {
    let (cache, _f) = tmp_db();
    assert_eq!(cache.len(), 0);

    cache.put(&program_id(1), &hash(1), b"proof-a").expect("put 1");
    assert_eq!(cache.len(), 1);

    cache.put(&program_id(2), &hash(2), b"proof-b").expect("put 2");
    assert_eq!(cache.len(), 2);

    // Same key → upsert, not insert.
    cache.put(&program_id(1), &hash(1), b"proof-a-v2").expect("put 3");
    assert_eq!(cache.len(), 2);
}

#[test]
fn upsert_overwrites_proof_bytes() {
    let (cache, _f) = tmp_db();
    let pid = program_id(0x10);
    let ph  = hash(0x20);

    cache.put(&pid, &ph, b"old-proof").expect("put v1");
    cache.put(&pid, &ph, b"new-proof").expect("put v2");

    let got = cache.get(&pid, &ph).expect("get");
    assert_eq!(got, b"new-proof");
}

#[test]
fn different_hash_same_program_id_is_different_entry() {
    let (cache, _f) = tmp_db();
    let pid = program_id(0x50);

    cache.put(&pid, &hash(0x01), b"proof-v1").expect("put v1");
    cache.put(&pid, &hash(0x02), b"proof-v2").expect("put v2");
    assert_eq!(cache.len(), 2);

    assert_eq!(cache.get(&pid, &hash(0x01)).unwrap(), b"proof-v1");
    assert_eq!(cache.get(&pid, &hash(0x02)).unwrap(), b"proof-v2");
}

#[test]
fn large_proof_roundtrip() {
    let (cache, _f) = tmp_db();
    let proof: Vec<u8> = (0u8..=255).cycle().take(65_536).collect();
    cache.put(&program_id(0xFF), &hash(0xEE), &proof).expect("put large");
    let got = cache.get(&program_id(0xFF), &hash(0xEE)).expect("get large");
    assert_eq!(got, proof);
}