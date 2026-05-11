/**
 * Billing middleware — per-request usage metering and API key gating.
 *
 * Billing model:
 *   - Each API key has a credit balance (stored in a lightweight KV store).
 *   - Each JSON-RPC method costs a configurable number of credits.
 *   - When balance reaches 0, requests are rejected with HTTP 402.
 *   - Operators earn a share of the credits consumed by their node.
 *
 * Storage backend: pluggable — defaults to in-memory (dev) or Redis (prod).
 */

import type { FastifyRequest } from "fastify";

export interface BillingResult {
  allowed: boolean;
  reason?: string;
  creditsRemaining?: number;
}

// ── Method costs (in credits) ─────────────────────────────────────────────────

const METHOD_COSTS: Record<string, number> = {
  sendTransaction: 10,
  simulateTransaction: 5,
  getAccountInfo: 1,
  getMultipleAccounts: 2,
  getProgramAccounts: 5,
  getTransaction: 2,
  getBlock: 3,
  getSignaturesForAddress: 3,
  getTokenAccountBalance: 1,
  getBalance: 1,
  // Default for unlisted methods:
  _default: 1,
};

// ── In-memory credit store (replace with Redis in production) ─────────────────

const creditStore = new Map<string, number>();

/** Seed a test API key with unlimited credits for development. */
creditStore.set("dev-api-key-000", 999_999);

const FREE_TIER_CREDITS = 10_000;
const BYPASS_AUTH = process.env.BYPASS_AUTH === "true";

if (BYPASS_AUTH) {
  console.warn(
    "[billing] WARNING: BYPASS_AUTH=true — all API key and credit checks are disabled. " +
      "Never run with this setting in production."
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function billingMiddleware(
  request: FastifyRequest
): Promise<BillingResult> {
  if (BYPASS_AUTH) return { allowed: true };

  const apiKey = extractApiKey(request);
  if (!apiKey) {
    return {
      allowed: false,
      reason: "Missing API key. Add X-API-Key header or ?api_key= query param.",
    };
  }

  // New key → grant free tier credits.
  if (!creditStore.has(apiKey)) {
    creditStore.set(apiKey, FREE_TIER_CREDITS);
  }

  const body = request.body as Record<string, unknown> | undefined;
  const method = (body?.["method"] as string) ?? "_default";
  const cost = METHOD_COSTS[method] ?? METHOD_COSTS["_default"]!;

  const balance = creditStore.get(apiKey)!;
  if (balance < cost) {
    return {
      allowed: false,
      reason: `Insufficient credits. Balance: ${balance}, required: ${cost}. Top up at https://pruv.io/billing`,
      creditsRemaining: balance,
    };
  }

  creditStore.set(apiKey, balance - cost);

  return { allowed: true, creditsRemaining: balance - cost };
}

// ── Credit management API (used by billing dashboard) ─────────────────────────

export function getBalance(apiKey: string): number {
  return creditStore.get(apiKey) ?? 0;
}

export function topUp(apiKey: string, credits: number): void {
  const current = creditStore.get(apiKey) ?? 0;
  creditStore.set(apiKey, current + credits);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractApiKey(request: FastifyRequest): string | null {
  // Priority: header → query param → bearer token.
  const header = request.headers["x-api-key"];
  if (typeof header === "string" && header.length > 0) return header;

  const query = (request.query as Record<string, string>)["api_key"];
  if (query) return query;

  const auth = request.headers["authorization"];
  if (typeof auth === "string" && auth.startsWith("Bearer ")) {
    return auth.slice(7);
  }

  return null;
}