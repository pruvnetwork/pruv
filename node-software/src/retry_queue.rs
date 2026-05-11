//! Dead-letter queue (DLQ) for failed attestation transactions.
//!
//! When `attestor` exhausts all retry attempts it writes the failed attestation
//! to this SQLite database so no proof is silently lost.  On the next node
//! restart the operator can inspect the queue and decide whether to replay or
//! discard entries.
//!
//! ## Schema
//!
//! ```text
//! failed_attestations(
//!     id          INTEGER PRIMARY KEY AUTOINCREMENT,
//!     program_id  TEXT    NOT NULL,   -- hex-encoded [u8;32]
//!     proof_blob  BLOB    NOT NULL,   -- raw ZK proof bytes
//!     created_at  INTEGER NOT NULL,   -- Unix timestamp (seconds)
//!     attempts    INTEGER NOT NULL    -- how many send attempts were made
//! )
//! ```

use anyhow::Context as _;
use rusqlite::{params, Connection};
use tracing::{info, warn};

// ─── Public types ─────────────────────────────────────────────────────────────

/// A single failed attestation stored in the DLQ.
#[derive(Debug, Clone)]
pub struct QueuedAttestation {
    pub id:          i64,
    pub program_id:  String,   // hex
    pub proof_blob:  Vec<u8>,
    pub created_at:  i64,      // Unix timestamp
    pub attempts:    u32,
}

// ─── RetryQueue ───────────────────────────────────────────────────────────────

/// Thin wrapper around a SQLite connection for the attestation dead-letter queue.
///
/// Each method opens and closes its own connection so the struct is `Send` +
/// `Sync` and can be cheaply cloned as `Arc<RetryQueue>`.
pub struct RetryQueue {
    db_path: String,
}

impl RetryQueue {
    /// Open (or create) the DLQ database at `db_path`.
    pub fn open(db_path: impl Into<String>) -> anyhow::Result<Self> {
        let path = db_path.into();
        // Create the table on first open.
        let conn = Connection::open(&path)
            .with_context(|| format!("Cannot open retry-queue DB at {path}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS failed_attestations (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 program_id TEXT    NOT NULL,
                 proof_blob BLOB    NOT NULL,
                 created_at INTEGER NOT NULL,
                 attempts   INTEGER NOT NULL DEFAULT 1
             );",
        )
        .context("Failed to initialise retry-queue schema")?;

        let q = Self { db_path: path };

        // Log pending count on startup so operators can see if there is a backlog.
        match q.len() {
            Ok(0)  => {}
            Ok(n)  => warn!("RetryQueue: {} unprocessed attestation(s) in dead-letter queue — inspect with `retry_queue.len()`", n),
            Err(e) => warn!("RetryQueue: could not query pending count: {}", e),
        }

        Ok(q)
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Persist a failed attestation to the DLQ.
    pub fn enqueue(
        &self,
        program_id: &[u8; 32],
        proof_blob: &[u8],
        attempts: u32,
    ) -> anyhow::Result<()> {
        let conn = Connection::open(&self.db_path)?;
        let now = unix_now();
        conn.execute(
            "INSERT INTO failed_attestations (program_id, proof_blob, created_at, attempts)
             VALUES (?1, ?2, ?3, ?4)",
            params![hex::encode(program_id), proof_blob, now, attempts],
        )
        .context("RetryQueue::enqueue")?;
        info!(
            "RetryQueue: enqueued failed attestation for {} (attempt #{})",
            hex::encode(program_id),
            attempts
        );
        Ok(())
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// Load all pending entries, ordered oldest-first.
    pub fn load_all(&self) -> anyhow::Result<Vec<QueuedAttestation>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT id, program_id, proof_blob, created_at, attempts
             FROM failed_attestations
             ORDER BY created_at ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(QueuedAttestation {
                    id:         row.get(0)?,
                    program_id: row.get(1)?,
                    proof_blob: row.get(2)?,
                    created_at: row.get(3)?,
                    attempts:   row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Number of entries currently in the queue.
    pub fn len(&self) -> anyhow::Result<usize> {
        let conn = Connection::open(&self.db_path)?;
        let n: i64 =
            conn.query_row("SELECT COUNT(*) FROM failed_attestations", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    pub fn is_empty(&self) -> anyhow::Result<bool> {
        Ok(self.len()? == 0)
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    /// Remove a single entry by id (e.g. after a successful manual replay).
    pub fn remove(&self, id: i64) -> anyhow::Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute("DELETE FROM failed_attestations WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Delete all entries older than `days` days.  Returns the number of rows
    /// deleted.  Called periodically to prevent unbounded growth.
    pub fn cleanup_older_than_days(&self, days: u32) -> anyhow::Result<usize> {
        let conn = Connection::open(&self.db_path)?;
        let cutoff = unix_now() - (days as i64 * 86_400);
        let n = conn.execute(
            "DELETE FROM failed_attestations WHERE created_at < ?1",
            params![cutoff],
        )?;
        if n > 0 {
            info!("RetryQueue: pruned {} entries older than {} days", n, days);
        }
        Ok(n)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}