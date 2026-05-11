/**
 * Pruv RPC Client — Fastify proxy to Solana with trust middleware.
 *
 * Architecture:
 *   Client → [Pruv RPC Proxy] → Solana RPC
 *                  ↓
 *          Trust middleware: rejects calls to un-attested programs
 *                  ↓
 *          Billing middleware: per-method metered usage
 */

import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import dotenv from "dotenv";
import { trustMiddleware } from "./trust_middleware";
import { billingMiddleware } from "./billing";
import { proxyRpcRequest } from "./proxy";

dotenv.config();

const PORT = Number(process.env.PORT ?? 8899);
const HOST = process.env.HOST ?? "0.0.0.0";

const server = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? "info",
  },
});

// ── Plugins ──────────────────────────────────────────────────────────────────
await server.register(cors, { origin: "*" });
await server.register(rateLimit, {
  max: Number(process.env.RATE_LIMIT_MAX ?? 1000),
  timeWindow: "1 minute",
});

// ── Global error handler ──────────────────────────────────────────────────────
// Catches any unhandled exception from route handlers and returns a
// well-formed JSON-RPC error instead of a bare Fastify 500 HTML page.
server.setErrorHandler((error, request, reply) => {
  server.log.error({ err: error }, "Unhandled route error");
  const body = request.body as Record<string, unknown> | undefined;
  return reply.code(500).send({
    jsonrpc: "2.0",
    id: body?.["id"] ?? null,
    error: { code: -32603, message: "Internal server error" },
  });
});

// ── Health check ─────────────────────────────────────────────────────────────
server.get("/health", async () => ({ status: "ok", version: "0.1.0" }));

// ── Main JSON-RPC proxy endpoint ──────────────────────────────────────────────
server.post("/", async (request, reply) => {
  const body = request.body as Record<string, unknown>;

  // 1. Billing: record and gate by API key / credits.
  const billingResult = await billingMiddleware(request);
  if (!billingResult.allowed) {
    return reply.code(402).send({ error: "Payment Required", message: billingResult.reason });
  }

  // 2. Trust: reject interactions with un-attested programs.
  const trustResult = await trustMiddleware(body);
  if (!trustResult.allowed) {
    return reply.code(403).send({
      error: "Untrusted Program",
      message: trustResult.reason,
      programId: trustResult.programId,
    });
  }

  // 3. Proxy to upstream Solana RPC.
  // proxyRpcRequest never throws — it returns a JSON-RPC error object on
  // network failures.  The try/catch here is a defence-in-depth guard.
  try {
    const response = await proxyRpcRequest(body);
    return reply.code(200).send(response);
  } catch (err) {
    server.log.error({ err }, "Unexpected proxy error");
    return reply.code(502).send({
      jsonrpc: "2.0",
      id: body["id"] ?? null,
      error: { code: -32603, message: "Upstream RPC unavailable" },
    });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
try {
  await server.listen({ port: PORT, host: HOST });
  server.log.info(`Pruv RPC proxy listening on http://${HOST}:${PORT}`);
} catch (err) {
  server.log.error(err);
  process.exit(1);
}