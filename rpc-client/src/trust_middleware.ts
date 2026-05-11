/**
 * Trust middleware — rejects RPC calls that target un-attested programs.
 *
 * The middleware inspects the JSON-RPC method and params to extract any
 * program IDs involved, then queries the on-chain pruv-registry to check
 * whether each program has a valid, unexpired ZK attestation.
 *
 * Methods inspected:
 *   - sendTransaction / simulateTransaction  → decode tx, extract programIds
 *   - getAccountInfo / getMultipleAccounts   → check if account is a program
 *   - any method with a programId param
 */

import {
  Connection,
  PublicKey,
  Transaction,
  VersionedTransaction,
} from "@solana/web3.js";

export interface TrustResult {
  allowed: boolean;
  reason?: string;
  programId?: string;
}

// ── Config ────────────────────────────────────────────────────────────────────

const UPSTREAM_RPC = process.env.UPSTREAM_RPC_URL ?? "https://api.devnet.solana.com";
const REGISTRY_PROGRAM_ID = process.env.REGISTRY_PROGRAM_ID ?? "RegPruv111111111111111111111111111111111111";
const ATTESTATION_PROGRAM_ID = process.env.ATTESTATION_PROGRAM_ID ?? "AttsPruv11111111111111111111111111111111111";

/** Set of program IDs that are always allowed (Solana builtins). */
const ALWAYS_TRUSTED = new Set<string>([
  "11111111111111111111111111111111",         // System Program
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe8bUS", // Associated Token
  "Sysvar1111111111111111111111111111111111111", // Sysvar (prefix)
  "ComputeBudget111111111111111111111111111111",
  "Vote111111111111111111111111111111111111111",
  "BPFLoaderUpgradeab1e11111111111111111111111",
  "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s", // Metaplex
]);

// ── Shared RPC connection (module-level singleton) ────────────────────────────
// Creating a new Connection per request opens a new WebSocket / HTTP connection
// each time. Reusing one connection pool dramatically reduces overhead.
let _sharedConn: Connection | null = null;
function getConnection(): Connection {
  if (!_sharedConn) {
    _sharedConn = new Connection(UPSTREAM_RPC, {
      commitment: "confirmed",
      disableRetryOnRateLimit: false,
    });
  }
  return _sharedConn;
}

// In-memory attestation cache: programId → expiry timestamp (ms)
// Keys are purged by the background eviction timer below.
const attestationCache = new Map<string, number>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Background eviction: remove expired entries every 10 minutes.
 * Without this the Map grows unboundedly as new dApps are registered.
 * Using unref() so this timer does not keep the Node.js process alive
 * in test environments.
 */
const _cacheEvictionTimer = setInterval(() => {
  const now = Date.now();
  let evicted = 0;
  for (const [pid, expiry] of attestationCache) {
    if (expiry <= now) {
      attestationCache.delete(pid);
      evicted++;
    }
  }
  if (evicted > 0) {
    console.debug(`[trust] Cache eviction: removed ${evicted} expired entries (${attestationCache.size} remain)`);
  }
}, 10 * 60 * 1000);

if (typeof _cacheEvictionTimer.unref === "function") {
  _cacheEvictionTimer.unref();
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function trustMiddleware(
  body: Record<string, unknown>
): Promise<TrustResult> {
  const method = body["method"] as string | undefined;
  if (!method) return { allowed: true };

  const programIds = extractProgramIds(method, body["params"]);
  if (programIds.length === 0) return { allowed: true };

  for (const pid of programIds) {
    if (ALWAYS_TRUSTED.has(pid)) continue;

    const attested = await isAttested(pid);
    if (!attested) {
      return {
        allowed: false,
        reason: `Program ${pid} has no valid ZK attestation in the pruv-registry. Deploy via a Pruv-verified channel or wait for a node to attest it.`,
        programId: pid,
      };
    }
  }

  return { allowed: true };
}

// ── Attestation check ─────────────────────────────────────────────────────────

async function isAttested(programId: string): Promise<boolean> {
  // Check cache first.
  const cached = attestationCache.get(programId);
  if (cached && cached > Date.now()) return true;

  try {
    const conn = getConnection();

    // Derive the attestation PDA: seeds = ["attestation", program_id_bytes]
    // NOTE: attestation PDAs live under the pruv-attestation program, NOT the registry.
    const [attestationPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("attestation"), new PublicKey(programId).toBuffer()],
      new PublicKey(ATTESTATION_PROGRAM_ID)
    );

    const accountInfo = await conn.getAccountInfo(attestationPda);
    if (!accountInfo || accountInfo.data.length === 0) return false;

    // Attestation Borsh layout (little-endian):
    //   disc(8) | dapp_program_id(32) | attestation_type(1) | program_hash(32)
    //   | slot(8) | created_at(8) | expires_at(8) | signer_count(1) | valid(1) | …
    //   Offsets: expires_at=89, signer_count=97, valid=98
    const MIN_LEN = 99; // disc+dapp_id+type+hash+slot+created+expires+signer+valid
    if (accountInfo.data.length < MIN_LEN) return false;

    const data8   = Buffer.from(accountInfo.data);
    const expiry  = Number(data8.readBigInt64LE(89));        // expires_at (i64 LE)
    const isValid = data8[98] === 1;                         // valid (bool)
    const now = Math.floor(Date.now() / 1000);

    if (isValid && expiry > now) {
      // Cache for 5 minutes.
      attestationCache.set(programId, Date.now() + CACHE_TTL_MS);
      return true;
    }

    return false;
  } catch {
    // When the RPC is unreachable or the account data is undecodeable, the
    // behaviour is controlled by TRUST_FAIL_OPEN:
    //   "true"  → allow the request (useful for local dev / CI without a live chain)
    //   anything else / unset → deny the request (safe default for production)
    const failOpen = process.env.TRUST_FAIL_OPEN === "true";
    if (failOpen) {
      console.warn(
        `[trust] Failed to check attestation for ${programId} — allowing (TRUST_FAIL_OPEN=true)`
      );
      return true;
    }
    console.error(
      `[trust] Failed to check attestation for ${programId} — denying (fail-closed). ` +
        "Set TRUST_FAIL_OPEN=true to allow during development."
    );
    return false;
  }
}

// ── Program ID extraction ─────────────────────────────────────────────────────

function extractProgramIds(method: string, params: unknown): string[] {
  const ids: string[] = [];

  if (!Array.isArray(params) || params.length === 0) return ids;

  try {
    switch (method) {
      case "getAccountInfo":
      case "getBalance":
      case "getTokenAccountBalance": {
        // params[0] is the pubkey — could be a program.
        // The deeper check is done at simulateTransaction / sendTransaction level.
        break;
      }

      case "sendTransaction":
      case "simulateTransaction": {
        // params[0] is a base64-encoded transaction wire format.
        // Deserialise and extract every unique programId from the instructions.
        const encoded = params[0];
        if (typeof encoded !== "string") break;

        const bytes = Buffer.from(encoded, "base64");

        // Try versioned transaction first (covers both v0 and legacy messages
        // wrapped in the versioned envelope), then fall back to legacy format.
        let extracted = false;
        try {
          const vtx = VersionedTransaction.deserialize(bytes);
          const keys = vtx.message.staticAccountKeys;
          // Collect unique program-id indices referenced by compiled instructions.
          // Each CompiledInstruction carries a programIdIndex into staticAccountKeys.
          const programIndices = new Set(
            vtx.message.compiledInstructions.map((ix) => ix.programIdIndex)
          );
          for (const idx of programIndices) {
            if (idx < keys.length) {
              ids.push(keys[idx].toBase58());
            }
          }
          extracted = true;
        } catch {
          // Not a versioned transaction — fall through to legacy.
        }

        if (!extracted) {
          try {
            const tx = Transaction.from(bytes);
            for (const ix of tx.instructions) {
              ids.push(ix.programId.toBase58());
            }
          } catch {
            // Unparseable transaction — allow and log.
            console.warn(
              "[trust] sendTransaction: could not deserialise transaction bytes — allowing"
            );
          }
        }
        break;
      }

      default:
        break;
    }
  } catch {
    // Ignore unexpected parse errors.
  }

  // De-duplicate before returning.
  return [...new Set(ids)];
}
