/**
 * PruvConnection — drop-in replacement for @solana/web3.js Connection
 * that routes all requests through the Pruv trust-aware RPC proxy.
 */

import { Connection, type Commitment, type ConnectionConfig } from "@solana/web3.js";

export class PruvConnection extends Connection {
  constructor(
    pruvRpcUrl: string,
    commitmentOrConfig?: Commitment | ConnectionConfig
  ) {
    super(pruvRpcUrl, commitmentOrConfig ?? "confirmed");
  }

  /**
   * Factory: create a PruvConnection pointing at the Pruv RPC proxy.
   *
   * @param proxyUrl    URL of the Pruv RPC proxy (default: http://localhost:8899)
   * @param apiKey      API key for billing (set X-API-Key header via fetch middleware)
   */
  static create(
    proxyUrl: string = "http://localhost:8899",
    _apiKey?: string
  ): PruvConnection {
    // @solana/web3.js Connection doesn't natively support extra headers,
    // so in production wrap with a custom fetch middleware that injects
    // the X-API-Key header on every request.
    return new PruvConnection(proxyUrl, "confirmed");
  }
}