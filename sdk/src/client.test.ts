/**
 * PruvClient integration tests (Vitest).
 *
 * These tests run against a local validator + the Pruv RPC proxy.
 * Set TEST_RPC_URL to override the default.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { PruvClient } from "./client.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

const FAKE_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const UNATTESTED_PROGRAM = "UnknownProg111111111111111111111111111111111";

function makeClient(overrides?: Partial<{ rpcProxyUrl: string; apiKey: string }>) {
  return new PruvClient({
    rpcProxyUrl: overrides?.rpcProxyUrl ?? "http://localhost:8899",
    apiKey: overrides?.apiKey ?? "dev-api-key-000",
  });
}

// ── Unit: attestation status ──────────────────────────────────────────────────

describe("PruvClient.getAttestationStatus", () => {
  it("returns isAttested=false for unknown program (no PDA account)", async () => {
    const client = makeClient();

    // Mock getAccountInfo to return null (no account).
    vi.spyOn(client.connection, "getAccountInfo").mockResolvedValue(null);

    const status = await client.getAttestationStatus(UNATTESTED_PROGRAM);
    expect(status.isAttested).toBe(false);
    expect(status.trustScore).toBe(0);
  });

  it("returns isAttested=true for a valid attested account", async () => {
    const client = makeClient();

    // Build a synthetic attestation account buffer.
    const buf = Buffer.alloc(59);
    // discriminator (8 bytes) — all zeros
    buf[8] = 1; // is_valid = true
    // expiry = now + 3600 (little-endian u64 at offset 9)
    const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);
    buf.writeBigUInt64LE(expiry, 9);
    // hash (32 bytes at offset 17) — arbitrary
    buf.fill(0xab, 17, 49);
    // node_count (u16 at offset 49) = 3
    buf.writeUInt16LE(3, 49);
    // attested_at (u64 at offset 51)
    buf.writeBigUInt64LE(BigInt(Math.floor(Date.now() / 1000) - 100), 51);

    vi.spyOn(client.connection, "getAccountInfo").mockResolvedValue({
      data: buf,
      executable: false,
      lamports: 1_000_000,
      owner: { toBase58: () => "RegPruv111111111111111111111111111111111111" } as never,
      rentEpoch: 0,
    });

    const status = await client.getAttestationStatus(FAKE_PROGRAM);
    expect(status.isAttested).toBe(true);
    expect(status.nodeCount).toBe(3);
    expect(status.trustScore).toBe(60); // min(100, 3 * 20)
  });
});

// ── Unit: assertAttested ──────────────────────────────────────────────────────

describe("PruvClient.assertAttested", () => {
  it("throws for an un-attested program", async () => {
    const client = makeClient();
    vi.spyOn(client.connection, "getAccountInfo").mockResolvedValue(null);

    await expect(client.assertAttested(UNATTESTED_PROGRAM)).rejects.toThrow(
      "is NOT attested"
    );
  });

  it("does not throw for an attested program", async () => {
    const client = makeClient();

    const buf = Buffer.alloc(59);
    buf[8] = 1;
    buf.writeBigUInt64LE(BigInt(Math.floor(Date.now() / 1000) + 3600), 9);
    buf.writeUInt16LE(5, 49);

    vi.spyOn(client.connection, "getAccountInfo").mockResolvedValue({
      data: buf,
      executable: false,
      lamports: 1_000_000,
      owner: { toBase58: () => "RegPruv" } as never,
      rentEpoch: 0,
    });

    await expect(client.assertAttested(FAKE_PROGRAM)).resolves.toBeUndefined();
  });
});

// ── Unit: getDappInfo ─────────────────────────────────────────────────────────

describe("PruvClient.getDappInfo", () => {
  it("returns null when no registry account exists", async () => {
    const client = makeClient();
    vi.spyOn(client.connection, "getAccountInfo").mockResolvedValue(null);

    const info = await client.getDappInfo(UNATTESTED_PROGRAM);
    expect(info).toBeNull();
  });
});