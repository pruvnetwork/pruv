//! End-to-end node startup integration test.
//!
//! Spawns the compiled `pruv-node` binary against a local `solana-test-validator`,
//! waits for the health endpoint to become live, then asserts /health and /metrics
//! respond correctly.  The test tears everything down on completion.
//!
//! **Prerequisites** (satisfied in CI and local dev):
//!   • `solana-test-validator` on PATH
//!   • `pruv-node` binary built at `target/release/pruv-node`
//!   • Ports 8899 (RPC), 8900 (validator WS), 6000 (P2P), 9090 (metrics) free

use std::{
    net::TcpStream,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

// ─── helpers ─────────────────────────────────────────────────────────────────

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) { let _ = self.0.kill(); }
}

fn wait_for_tcp(host: &str, port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect((host, port)).is_ok() { return true; }
        sleep(Duration::from_millis(200));
    }
    false
}

fn binary_path() -> std::path::PathBuf {
    // Works whether run via `cargo test` or directly.
    let mut p = std::env::current_exe().expect("current_exe");
    // current_exe is inside target/debug/deps or target/release/deps
    for _ in 0..3 { p.pop(); }
    p.push("release");
    p.push("pruv-node");
    p
}

// ─── test ────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires solana-test-validator on PATH and free ports 8899/6000/9090"]
fn node_starts_and_serves_health_and_metrics() {
    // 1. Start solana-test-validator
    let mut validator_cmd = Command::new("solana-test-validator");
    validator_cmd
        .args(["--reset", "--quiet"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let validator = Guard(validator_cmd.spawn().expect("start solana-test-validator"));

    // Wait for the validator RPC to be ready.
    assert!(
        wait_for_tcp("127.0.0.1", 8899, Duration::from_secs(20)),
        "solana-test-validator did not start within 20 s"
    );
    sleep(Duration::from_secs(3)); // let it stabilise

    // 2. Start the node daemon
    let bin = binary_path();
    assert!(bin.exists(), "pruv-node binary not found at {}", bin.display());

    let node = Guard(
        Command::new(&bin)
            .env("RUST_LOG", "pruv_node=info")
            .env("PROOF_CACHE_PATH", "/tmp/test_proof_cache.db")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start pruv-node"),
    );

    // 3. Wait for the metrics server (port 9090)
    assert!(
        wait_for_tcp("127.0.0.1", 9090, Duration::from_secs(15)),
        "pruv-node metrics port did not open within 15 s"
    );
    sleep(Duration::from_millis(500));

    // 4. /health → "ok"
    let health_body = ureq::get("http://127.0.0.1:9090/health")
        .call()
        .expect("GET /health failed")
        .into_string()
        .expect("body");
    assert_eq!(health_body.trim(), "ok");

    // 5. /metrics → contains expected counter names
    let metrics_body = ureq::get("http://127.0.0.1:9090/metrics")
        .call()
        .expect("GET /metrics failed")
        .into_string()
        .expect("body");

    for counter in &[
        "pruv_proofs_generated_total",
        "pruv_proofs_cached_total",
        "pruv_p2p_heartbeats_total",
        "pruv_attestations_submitted_total",
    ] {
        assert!(
            metrics_body.contains(counter),
            "/metrics missing counter: {}",
            counter
        );
    }

    // Guards drop here → processes killed.
    drop(node);
    drop(validator);
    let _ = std::fs::remove_file("/tmp/test_proof_cache.db");
}