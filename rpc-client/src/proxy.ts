/**
 * RPC proxy — forwards JSON-RPC requests to the upstream Solana node.
 *
 * Error handling:
 *   - HTTP 4xx/5xx from upstream: returned as a JSON-RPC error response
 *     with code -32002 (so the caller always gets a well-formed JSON-RPC body).
 *   - Network timeout / DNS failure: returned as -32603 without leaking the
 *     upstream URL.
 */

import axios, { AxiosError } from "axios";

const UPSTREAM_RPC =
  process.env.UPSTREAM_RPC_URL ?? "https://api.devnet.solana.com";

export async function proxyRpcRequest(
  body: Record<string, unknown>
): Promise<unknown> {
  try {
    const response = await axios.post(UPSTREAM_RPC, body, {
      headers: { "Content-Type": "application/json" },
      // Validate only network-level errors; Solana RPC returns HTTP 200 even
      // for JSON-RPC errors, so we never want to throw on 4xx/5xx.
      validateStatus: () => true,
      timeout: 30_000,
    });

    // If upstream returned a non-200 HTTP status (rare for Solana), wrap it
    // in a JSON-RPC error so callers always get a consistent shape.
    if (response.status < 200 || response.status >= 300) {
      return jsonRpcError(
        body["id"] ?? null,
        -32002,
        `Upstream RPC returned HTTP ${response.status}`
      );
    }

    return response.data;
  } catch (err) {
    // Catch network-level errors (timeout, DNS, TLS).  Do NOT include the
    // upstream URL in the message — it is internal infrastructure.
    const isTimeout =
      err instanceof AxiosError && err.code === "ECONNABORTED";
    const message = isTimeout
      ? "Upstream RPC request timed out"
      : "Upstream RPC is unreachable";
    return jsonRpcError(body["id"] ?? null, -32603, message);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function jsonRpcError(
  id: unknown,
  code: number,
  message: string
): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code, message },
  };
}