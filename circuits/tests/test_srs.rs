//! Integration tests — SRS loader and in-memory cache (srs.rs).

use std::sync::Arc;
use pruv_circuits::srs;

#[test]
fn get_k4_returns_arc_with_k4() {
    let params = srs::get(4).expect("srs::get(4) must succeed");
    use halo2_proofs::poly::commitment::Params;
    assert_eq!(params.k(), 4, "returned params must have k=4");
    println!("[PASS] get_k4_returns_arc_with_k4  k={}", params.k());
}

#[test]
fn get_k5_returns_arc_with_k5() {
    let params = srs::get(5).expect("srs::get(5) must succeed");
    use halo2_proofs::poly::commitment::Params;
    assert_eq!(params.k(), 5, "returned params must have k=5");
    println!("[PASS] get_k5_returns_arc_with_k5  k={}", params.k());
}

#[test]
fn same_k_returns_same_arc() {
    let a = srs::get(4).expect("first get(4)");
    let b = srs::get(4).expect("second get(4)");
    assert!(Arc::ptr_eq(&a, &b), "second call must return the same Arc (cache hit)");
    println!("[PASS] same_k_returns_same_arc");
}

#[test]
fn different_k_returns_different_arc() {
    let a = srs::get(4).expect("get(4)");
    let b = srs::get(5).expect("get(5)");
    assert!(!Arc::ptr_eq(&a, &b), "distinct k must produce distinct cached Arc");
    println!("[PASS] different_k_returns_different_arc");
}

#[test]
fn concurrent_get_same_k_all_return_same_arc() {
    use std::thread;
    let handles: Vec<_> = (0..8)
        .map(|_| thread::spawn(|| srs::get(4).expect("concurrent get(4)")))
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let first = Arc::as_ptr(&results[0]);
    for (i, r) in results.iter().enumerate() {
        assert_eq!(Arc::as_ptr(r), first, "thread {i} got a different Arc");
    }
    println!("[PASS] concurrent_get_same_k_all_return_same_arc  ({} threads)", results.len());
}

#[test]
fn arc_is_valid_params() {
    use halo2_proofs::poly::commitment::Params;
    let params = srs::get(4).expect("get(4)");
    // Sanity: n = 2^k
    assert_eq!(params.n(), 1u64 << 4);
    println!("[PASS] arc_is_valid_params  n={}", params.n());
}