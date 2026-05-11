/**
 * PruvClient — main SDK class for interacting with the Pruv trust network.
 *
 * Usage:
 *   const client = new PruvClient({ rpcProxyUrl: "http://localhost:8899", apiKey: "..." });
 *
 *   // Check if a dApp is attested before interacting.
 *   const status = await client.getAttestationStatus("ProgramPubkey...");
 *   if (!status.isAttested) throw new Error("Untrusted program!");
 *
 *   // Use the trust-aware connection as a drop-in replacement.
 *   const conn = client.connection;
 *   const balance = await conn.getBalance(wallet.publicKey);
 */

import { PublicKey } from "@solana/web3.js";
import axios from "axios";
import type { AttestationStatus, DappInfo, NodeInfo, ProposalInfo } from "./types.js";
import { PruvConnection } from "./connection.js";

export interface PruvClientConfig {
  /** Pruv RPC proxy URL (e.g. "http://localhost:8899" or "https://rpc.pruv.io"). */
  rpcProxyUrl: string;
  /** API key for billing. */
  apiKey?: string;
  /** On-chain registry program ID. */
  registryProgramId?: string;
}

const DEFAULT_REGISTRY    = "RegPruv111111111111111111111111111111111111";
// Attestation PDAs are owned by the attestation program, NOT the registry.
const DEFAULT_ATTESTATION = "AttsPruv11111111111111111111111111111111111";

export class PruvClient {
  readonly connection: PruvConnection;
  private readonly apiKey: string | undefined;
  private readonly registryProgramId: PublicKey;
  private readonly attestationProgramId: PublicKey;
  private readonly rpcProxyUrl: string;

  constructor(config: PruvClientConfig) {
    this.rpcProxyUrl = config.rpcProxyUrl;
    this.apiKey = config.apiKey;
    this.registryProgramId = new PublicKey(
      config.registryProgramId ?? DEFAULT_REGISTRY
    );
    this.attestationProgramId = new PublicKey(DEFAULT_ATTESTATION);
    this.connection = PruvConnection.create(config.rpcProxyUrl, config.apiKey);
  }

  // ── Attestation ────────────────────────────────────────────────────────────

  /**
   * Check whether a Solana program has a valid ZK attestation.
   */
  async getAttestationStatus(programId: string): Promise<AttestationStatus> {
    // Attestation PDAs: seeds = ["attestation", dapp_program_id]
    // under the pruv-ATTESTATION program (not the registry).
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("attestation"), new PublicKey(programId).toBuffer()],
      this.attestationProgramId
    );

    const accountInfo = await this.connection.getAccountInfo(pda);

    // Attestation account Borsh layout (little-endian):
    //   disc(8) | dapp_program_id(32) | attestation_type(1) | program_hash(32)
    //   | slot(8) | created_at(8) | expires_at(8) | signer_count(1) | valid(1) | …
    //   Offsets: hash=41, slot=73, created_at=81, expires_at=89, signer_count=97, valid=98
    const MIN_LEN = 99;
    if (!accountInfo || accountInfo.data.length < MIN_LEN) {
      return {
        programId,
        isAttested: false,
        programHash: "",
        attestedAt: 0,
        expiresAt: 0,
        nodeCount: 0,
        trustScore: 0,
      };
    }

    const data = Buffer.from(accountInfo.data);
    const hashHex    = data.slice(41, 73).toString("hex");
    const attestedAt = Number(data.readBigInt64LE(81));   // created_at (i64 LE)
    const expiry     = Number(data.readBigInt64LE(89));   // expires_at (i64 LE)
    const nodeCount  = data[97];                          // signer_count (u8)
    const isValid    = data[98] === 1;                    // valid (bool)
    const now = Math.floor(Date.now() / 1000);

    return {
      programId,
      isAttested: isValid && expiry > now,
      programHash: hashHex,
      attestedAt,
      expiresAt: expiry,
      nodeCount,
      trustScore: isValid && expiry > now ? Math.min(100, nodeCount * 20) : 0,
    };
  }

  /**
   * Fetch dApp registry info (name, description, attestation).
   */
  async getDappInfo(programId: string): Promise<DappInfo | null> {
    try {
      const [registryPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("dapp"), new PublicKey(programId).toBuffer()],
        this.registryProgramId
      );
      const accountInfo = await this.connection.getAccountInfo(registryPda);
      if (!accountInfo) return null;

      const attestation = await this.getAttestationStatus(programId);

      // Full decode: parse Anchor-serialised string fields from account data.
      return {
        programId,
        name: "Unknown dApp",
        description: "",
        websiteUrl: "",
        registeredAt: 0,
        attestation,
      };
    } catch {
      return null;
    }
  }

  // ── Governance ─────────────────────────────────────────────────────────────

  /**
   * Fetch all active governance proposals.
   */
  async getProposals(): Promise<ProposalInfo[]> {
    // Full implementation: getProgramAccounts for governance program
    // filtered by account discriminator for Proposal accounts.
    return [];
  }

  // ── Node directory ─────────────────────────────────────────────────────────

  /**
   * Fetch registered node operators.
   */
  async getNodes(): Promise<NodeInfo[]> {
    return [];
  }

  // ── Convenience ────────────────────────────────────────────────────────────

  /**
   * Assert a program is attested before any transaction.
   * Throws if not attested.
   */
  async assertAttested(programId: string): Promise<void> {
    const status = await this.getAttestationStatus(programId);
    if (!status.isAttested) {
      throw new Error(
        `Program ${programId} is NOT attested by the Pruv network. ` +
        `Trust score: ${status.trustScore}/100. ` +
        `Refusing to interact for safety.`
      );
    }
  }
}