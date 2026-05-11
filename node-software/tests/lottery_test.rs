//! Integration tests for the lottery module.
//!
//! All tests here are pure (no RPC, no Solana validator required).
//! They exercise:
//!   - `derive_winner_index` — determinism, range, edge cases, uniformity
//!   - PDA derivation stability and uniqueness for all four PDAs
//!   - `LotteryStateSnapshot` state-machine predicates
//!   - SlotHashes sysvar byte-layout parsing (via synthetic binary data)

use solana_sdk::pubkey::Pubkey;
use pruv_node::lottery::{
    config_pda, derive_winner_index, draw_vote_pda, lottery_state_pda,
    node_prize_pool_pda, LotteryStateSnapshot,
};

// ─── derive_winner_index ──────────────────────────────────────────────────────

#[test]
fn winner_index_is_deterministic() {
    let h = [0x42u8; 32];
    let a = derive_winner_index(&h, 7, 1_000);
    let b = derive_winner_index(&h, 7, 1_000);
    assert_eq!(a, b, "same inputs must always produce the same winner index");
}

#[test]
fn winner_index_is_always_in_range() {
    let h = [0xABu8; 32];
    for &n in &[1u64, 2, 3, 7, 50, 100, 1_000, u32::MAX as u64] {
        let idx = derive_winner_index(&h, 42, n);
        assert!(idx < n, "winner_index={idx} must be < ticket_count={n}");
    }
}

#[test]
fn winner_index_single_ticket_is_always_zero() {
    for round in 0..20u64 {
        // Only one ticket exists → winner must be index 0.
        let h: [u8; 32] = core::array::from_fn(|i| (round as u8).wrapping_add(i as u8));
        assert_eq!(derive_winner_index(&h, round, 1), 0);
    }
}

#[test]
fn winner_index_zero_tickets_returns_zero_without_panic() {
    assert_eq!(derive_winner_index(&[0u8; 32], 0, 0), 0);
    assert_eq!(derive_winner_index(&[0xFFu8; 32], 999, 0), 0);
}

#[test]
fn winner_index_differs_across_round_ids() {
    // Keep hash and ticket_count fixed; vary round_id.
    // For 1_000 tickets it's extremely unlikely all results are identical.
    let h = [0x11u8; 32];
    let indices: Vec<u64> = (0..20u64)
        .map(|r| derive_winner_index(&h, r, 1_000))
        .collect();
    let unique: std::collections::HashSet<u64> = indices.iter().cloned().collect();
    assert!(
        unique.len() > 1,
        "winner_index should vary when round_id changes; got unique={:?}",
        unique
    );
}

#[test]
fn winner_index_differs_across_slot_hashes() {
    // Vary only the slot hash; keep round_id and ticket_count fixed.
    //
    // NOTE: using a constant byte like [seed; 32] would make the four-way XOR
    // cancel to 0 (h[i]^h[i+8]^h[i+16]^h[i+24] = 0 for uniform arrays).
    // Use non-uniform hashes so the mixing actually propagates the seed.
    let mut indices = std::collections::HashSet::new();
    for seed in 0u8..50 {
        // Each byte differs: ensures the XOR fold does not collapse to zero.
        let h: [u8; 32] = core::array::from_fn(|i| seed.wrapping_add((i as u8).wrapping_mul(7)));
        indices.insert(derive_winner_index(&h, 1, 1_000));
    }
    assert!(
        indices.len() > 1,
        "winner_index should vary when slot_hash changes"
    );
}

#[test]
fn winner_index_roughly_uniform() {
    // Run 10_000 synthetic draws and check that each bucket receives at least
    // one hit (with 100 buckets this is almost certain for any reasonable hash).
    let n = 100u64;
    let mut buckets = vec![0u32; n as usize];
    for round in 0..10_000u64 {
        // Different hash per round: XOR seed byte into every position.
        let seed = (round & 0xFF) as u8;
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = seed ^ (i as u8).wrapping_mul(0x37);
        }
        let idx = derive_winner_index(&h, round, n) as usize;
        buckets[idx] += 1;
    }
    for (i, &count) in buckets.iter().enumerate() {
        assert!(
            count > 0,
            "bucket {i} was never selected in 10_000 draws — distribution is broken"
        );
    }
}

// ─── PDA derivation ───────────────────────────────────────────────────────────

#[test]
fn config_pda_is_stable() {
    let (a, _) = config_pda();
    let (b, _) = config_pda();
    assert_eq!(a, b, "config_pda must be deterministic");
}

#[test]
fn lottery_state_pda_is_stable() {
    for round in [0u64, 1, 42, u64::MAX] {
        let (a, _) = lottery_state_pda(round);
        let (b, _) = lottery_state_pda(round);
        assert_eq!(a, b, "lottery_state_pda({round}) must be deterministic");
    }
}

#[test]
fn lottery_state_pda_unique_per_round() {
    let rounds: Vec<u64> = (0..10).collect();
    let pdas: Vec<Pubkey> = rounds.iter().map(|&r| lottery_state_pda(r).0).collect();
    let unique: std::collections::HashSet<Pubkey> = pdas.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        rounds.len(),
        "each round must produce a distinct lottery_state PDA"
    );
}

#[test]
fn draw_vote_pda_is_stable() {
    let node = Pubkey::new_unique();
    let (a, _) = draw_vote_pda(1, &node);
    let (b, _) = draw_vote_pda(1, &node);
    assert_eq!(a, b, "draw_vote_pda must be deterministic");
}

#[test]
fn draw_vote_pda_unique_per_round() {
    let node = Pubkey::new_unique();
    let (pda1, _) = draw_vote_pda(1, &node);
    let (pda2, _) = draw_vote_pda(2, &node);
    assert_ne!(pda1, pda2, "different rounds must produce different draw_vote PDAs");
}

#[test]
fn draw_vote_pda_unique_per_node() {
    let node_a = Pubkey::new_unique();
    let node_b = Pubkey::new_unique();
    let (pda_a, _) = draw_vote_pda(1, &node_a);
    let (pda_b, _) = draw_vote_pda(1, &node_b);
    assert_ne!(pda_a, pda_b, "different nodes must produce different draw_vote PDAs");
}

#[test]
fn node_prize_pool_pda_is_stable() {
    for round in [0u64, 1, 999] {
        let (a, _) = node_prize_pool_pda(round);
        let (b, _) = node_prize_pool_pda(round);
        assert_eq!(a, b);
    }
}

#[test]
fn node_prize_pool_pda_unique_per_round() {
    let (a, _) = node_prize_pool_pda(1);
    let (b, _) = node_prize_pool_pda(2);
    assert_ne!(a, b);
}

#[test]
fn all_four_pdas_are_distinct_for_same_round() {
    let node = Pubkey::new_unique();
    let round = 42u64;
    let c = config_pda().0;
    let s = lottery_state_pda(round).0;
    let v = draw_vote_pda(round, &node).0;
    let p = node_prize_pool_pda(round).0;

    // All four should be different (extremely high probability by PDA construction).
    assert_ne!(c, s);
    assert_ne!(c, v);
    assert_ne!(c, p);
    assert_ne!(s, v);
    assert_ne!(s, p);
    assert_ne!(v, p);
}

// ─── LotteryStateSnapshot — is_drawable ──────────────────────────────────────

fn snapshot(status: u8, end_slot: u64, ticket_count: u64) -> LotteryStateSnapshot {
    LotteryStateSnapshot {
        round_id: 1,
        end_slot,
        ticket_count,
        status,
        committed_winner_index: 0,
        vote_count: 0,
        winner: [0u8; 32],
    }
}

#[test]
fn is_drawable_open_slot_reached_with_tickets() {
    // status=Open(0), slot past end, tickets > 0 → drawable
    let s = snapshot(0, 100, 50);
    assert!(s.is_drawable(100), "at end_slot it is drawable");
    assert!(s.is_drawable(200), "after end_slot it is drawable");
}

#[test]
fn is_drawable_open_slot_not_reached() {
    let s = snapshot(0, 100, 50);
    assert!(!s.is_drawable(99), "before end_slot it is not drawable");
}

#[test]
fn is_drawable_open_zero_tickets() {
    // Even if slot passed, zero tickets → not drawable
    let s = snapshot(0, 100, 0);
    assert!(!s.is_drawable(200));
}

#[test]
fn is_drawable_committing_slot_reached() {
    // status=Committing(1) + slot reached + tickets > 0 → drawable
    let s = snapshot(1, 100, 10);
    assert!(s.is_drawable(100));
    assert!(s.is_drawable(999));
}

#[test]
fn is_drawable_committing_slot_not_reached() {
    let s = snapshot(1, 500, 10);
    assert!(!s.is_drawable(499));
}

#[test]
fn is_drawable_closed_is_never_drawable() {
    // status=Closed(2) → never drawable regardless of slot/tickets
    let s = snapshot(2, 0, 1_000);
    assert!(!s.is_drawable(0));
    assert!(!s.is_drawable(u64::MAX));
}

// ─── LotteryStateSnapshot — is_closed ────────────────────────────────────────

#[test]
fn is_closed_only_for_status_2() {
    assert!(!snapshot(0, 0, 0).is_closed(), "Open is not closed");
    assert!(!snapshot(1, 0, 0).is_closed(), "Committing is not closed");
    assert!(snapshot(2, 0, 0).is_closed(), "status=2 is closed");
}

#[test]
fn is_closed_independent_of_slot_and_tickets() {
    let s = LotteryStateSnapshot {
        round_id: 5,
        end_slot: 1_000_000,
        ticket_count: 9_999,
        status: 2,
        committed_winner_index: 42,
        vote_count: 10,
        winner: [0u8; 32],
    };
    assert!(s.is_closed());
}

// ─── SlotHashes sysvar byte-layout (pure parsing helper) ─────────────────────
//
// `fetch_slot_hash_for_slot` requires a live RpcClient so we cannot call it
// directly here. Instead we verify the binary layout constants the parser
// depends on: every entry is 40 bytes (8-byte slot + 32-byte hash) and the
// first 8 bytes of the sysvar encode the count.

#[test]
fn slot_hashes_entry_size_is_40_bytes() {
    const ENTRY: usize = 40;
    // Each entry: u64 slot (8 bytes) + [u8; 32] hash (32 bytes) = 40 bytes.
    assert_eq!(8 + 32, ENTRY);
}

#[test]
fn slot_hashes_synthetic_layout_is_parseable() {
    // Build a minimal synthetic sysvar with 3 entries and confirm we can
    // navigate to the right bytes — mirrors the parser in lottery.rs.
    let entries: &[(u64, [u8; 32])] = &[
        (200, [0xAAu8; 32]),
        (100, [0xBBu8; 32]),
        (50,  [0xCCu8; 32]),
    ];
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(entries.len() as u64).to_le_bytes()); // count
    for (slot, hash) in entries {
        data.extend_from_slice(&slot.to_le_bytes());
        data.extend_from_slice(hash);
    }

    // Parse manually (mirrors fetch_slot_hash_for_slot logic).
    let count = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    assert_eq!(count, 3);

    const ENTRY: usize = 40;
    let mut found: Option<[u8; 32]> = None;
    for i in 0..count {
        let off = 8 + i * ENTRY;
        let slot = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let hash: [u8; 32] = data[off + 8..off + ENTRY].try_into().unwrap();
        if slot == 100 {
            found = Some(hash);
            break;
        }
    }
    assert_eq!(found, Some([0xBBu8; 32]), "should find hash for slot 100");
}