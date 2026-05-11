/** Shared types for the Pruv SDK. */

export interface AttestationStatus {
  programId: string;
  isAttested: boolean;
  programHash: string;
  attestedAt: number;       // Unix timestamp (seconds)
  expiresAt: number;        // Unix timestamp (seconds)
  nodeCount: number;        // Number of nodes that signed
  trustScore: number;       // 0–100 composite score
}

export interface DappInfo {
  programId: string;
  name: string;
  description: string;
  websiteUrl: string;
  registeredAt: number;
  attestation: AttestationStatus | null;
}

export interface NodeInfo {
  operatorPubkey: string;
  stakeAmount: bigint;
  reputation: number;
  totalAttestations: number;
  isActive: boolean;
}

export interface ProposalInfo {
  proposalId: bigint;
  title: string;
  description: string;
  voteDeadline: number;
  votesFor: bigint;
  votesAgainst: bigint;
  executed: boolean;
  passed: boolean | null;
}

export interface VoteProof {
  proposalId: bigint;
  nullifier: Uint8Array;
  voteCommitment: Uint8Array;
  memberTreeRoot: Uint8Array;
  proofBytes: Uint8Array;
}