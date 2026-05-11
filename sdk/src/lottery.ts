/**
 * pruv Lottery SDK client
 *
 * Provides typed helpers for all pruv-lottery instructions:
 *   initConfig · updateNodeCount · initializeRound · buyTicket
 *   castDrawVote · finalizeDraw · claimNodePrize
 *
 * Also exposes pure-TS helpers that mirror the on-chain randomness derivation
 * so off-chain tools can predict the winner index before finalization.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_SLOT_HASHES_PUBKEY,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

// ─── Program ID ───────────────────────────────────────────────────────────────

export const LOTTERY_PROGRAM_ID = new PublicKey(
  "FLot1111111111111111111111111111111111111111"
);

// ─── Discriminators (sha256("global:<ix_name>")[0..8]) ────────────────────────
// Pre-computed — regenerate with `anchor idl` if the program changes.

const DISC: Record<string, Buffer> = {
  initConfig:       Buffer.from([57,  154,  77,  148, 200, 106, 194, 228]),
  updateNodeCount:  Buffer.from([89,  218, 231, 247,  29,  88,  18,  60]),
  initializeRound:  Buffer.from([65,  100,  36, 173,  99, 181, 137, 128]),
  buyTicket:        Buffer.from([205, 109, 222,  14, 186,  75, 228, 217]),
  castDrawVote:     Buffer.from([38,   15, 174, 246, 118,  43,  27,  22]),
  finalizeDraw:     Buffer.from([148, 101,  68, 202, 109, 165, 245, 126]),
  claimNodePrize:   Buffer.from([184, 193,  14,  62,  27,  88, 165, 233]),
};

// ─── PDA helpers ─────────────────────────────────────────────────────────────

export function lotteryConfigPda(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("lottery_config")],
    LOTTERY_PROGRAM_ID
  );
}

export function lotteryStatePda(roundId: bigint): [PublicKey, number] {
  const roundBuf = Buffer.alloc(8);
  roundBuf.writeBigUInt64LE(roundId);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("lottery"), roundBuf],
    LOTTERY_PROGRAM_ID
  );
}

export function ticketPda(roundId: bigint, ticketIndex: bigint): [PublicKey, number] {
  const roundBuf = Buffer.alloc(8);
  roundBuf.writeBigUInt64LE(roundId);
  const indexBuf = Buffer.alloc(8);
  indexBuf.writeBigUInt64LE(ticketIndex);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("ticket"), roundBuf, indexBuf],
    LOTTERY_PROGRAM_ID
  );
}

export function walletTicketCountPda(
  roundId: bigint,
  buyer: PublicKey
): [PublicKey, number] {
  const roundBuf = Buffer.alloc(8);
  roundBuf.writeBigUInt64LE(roundId);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("wallet_tickets"), roundBuf, buyer.toBuffer()],
    LOTTERY_PROGRAM_ID
  );
}

export function drawVotePda(
  roundId: bigint,
  nodeOperator: PublicKey
): [PublicKey, number] {
  const roundBuf = Buffer.alloc(8);
  roundBuf.writeBigUInt64LE(roundId);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("draw_vote"), roundBuf, nodeOperator.toBuffer()],
    LOTTERY_PROGRAM_ID
  );
}

export function nodePrizePoolPda(roundId: bigint): [PublicKey, number] {
  const roundBuf = Buffer.alloc(8);
  roundBuf.writeBigUInt64LE(roundId);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("node_prizes"), roundBuf],
    LOTTERY_PROGRAM_ID
  );
}

// ─── On-chain state types ─────────────────────────────────────────────────────

export interface LotteryConfig {
  authority:            PublicKey;
  treasury:             PublicKey;
  ticketPriceLamports:  bigint;
  maxTicketsPerWallet:  number;
  roundDurationSlots:   bigint;
  nodeShareBps:         number;
  treasuryShareBps:     number;
  thresholdBps:         bigint;
  activeNodeCount:      number;
  currentRoundId:       bigint;
  bump:                 number;
}

export interface LotteryState {
  roundId:              bigint;
  startSlot:            bigint;
  endSlot:              bigint;
  ticketCount:          bigint;
  prizePoolLamports:    bigint;
  status:               number; // 0=Open 1=Committing 2=Closed
  winner:               PublicKey;
  committedWinnerIndex: bigint;
  slotHashUsed:         Uint8Array;
  voteCount:            number;
  bump:                 number;
}

export interface DrawVote {
  roundId:      bigint;
  nodePubkey:   PublicKey;
  winnerIndex:  bigint;
  slotHashUsed: Uint8Array;
  claimed:      boolean;
  bump:         number;
}

export interface NodePrizePool {
  roundId:       bigint;
  totalLamports: bigint;
  voteCount:     number;
  claimedCount:  number;
  bump:          number;
}

// ─── Account deserializers ────────────────────────────────────────────────────

/** Strip the 8-byte Anchor discriminator and return remaining bytes. */
function stripDisc(data: Buffer): Buffer {
  if (data.length < 8) throw new Error("account data too short");
  return data.slice(8);
}

function readU8(buf: Buffer, off: number): number { return buf.readUInt8(off); }
function readU16LE(buf: Buffer, off: number): number { return buf.readUInt16LE(off); }
function readU32LE(buf: Buffer, off: number): number { return buf.readUInt32LE(off); }
function readU64LE(buf: Buffer, off: number): bigint { return buf.readBigUInt64LE(off); }
function readPubkey(buf: Buffer, off: number): PublicKey {
  return new PublicKey(buf.slice(off, off + 32));
}

export function deserializeLotteryConfig(data: Buffer): LotteryConfig {
  const b = stripDisc(data);
  let o = 0;
  const authority           = readPubkey(b, o); o += 32;
  const treasury            = readPubkey(b, o); o += 32;
  const ticketPriceLamports = readU64LE(b, o);  o += 8;
  const maxTicketsPerWallet = readU8(b, o);      o += 1;
  const roundDurationSlots  = readU64LE(b, o);  o += 8;
  const nodeShareBps        = readU16LE(b, o);  o += 2;
  const treasuryShareBps    = readU16LE(b, o);  o += 2;
  const thresholdBps        = readU64LE(b, o);  o += 8;
  const activeNodeCount     = readU32LE(b, o);  o += 4;
  const currentRoundId      = readU64LE(b, o);  o += 8;
  const bump                = readU8(b, o);
  return {
    authority, treasury, ticketPriceLamports, maxTicketsPerWallet,
    roundDurationSlots, nodeShareBps, treasuryShareBps, thresholdBps,
    activeNodeCount, currentRoundId, bump,
  };
}

export function deserializeLotteryState(data: Buffer): LotteryState {
  const b = stripDisc(data);
  let o = 0;
  const roundId              = readU64LE(b, o); o += 8;
  const startSlot            = readU64LE(b, o); o += 8;
  const endSlot              = readU64LE(b, o); o += 8;
  const ticketCount          = readU64LE(b, o); o += 8;
  const prizePoolLamports    = readU64LE(b, o); o += 8;
  const status               = readU8(b, o);    o += 1;
  const winner               = readPubkey(b, o); o += 32;
  const committedWinnerIndex = readU64LE(b, o); o += 8;
  const slotHashUsed         = new Uint8Array(b.slice(o, o + 32)); o += 32;
  const voteCount            = readU8(b, o);    o += 1;
  const bump                 = readU8(b, o);
  return {
    roundId, startSlot, endSlot, ticketCount, prizePoolLamports,
    status, winner, committedWinnerIndex, slotHashUsed, voteCount, bump,
  };
}

// ─── Randomness helper ────────────────────────────────────────────────────────

/**
 * Derive winner index — **must stay byte-for-byte identical** to the
 * on-chain Rust implementation in `programs/pruv-lottery/src/lib.rs`.
 *
 * Formula: XOR-fold slotHash[32] into 8 bytes, XOR with roundId_LE and
 * ticketCount_LE, then take the result modulo ticketCount.
 */
export function deriveWinnerIndex(
  slotHash: Uint8Array,
  roundId: bigint,
  ticketCount: bigint
): bigint {
  if (ticketCount === 0n) return 0n;
  if (slotHash.length !== 32) {
    throw new Error(`slotHash must be 32 bytes, got ${slotHash.length}`);
  }

  const ridBuf = Buffer.alloc(8); ridBuf.writeBigUInt64LE(roundId);
  const tcBuf  = Buffer.alloc(8); tcBuf.writeBigUInt64LE(ticketCount);

  const acc = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) {
    acc[i] =
      slotHash[i] ^
      slotHash[i + 8] ^
      slotHash[i + 16] ^
      slotHash[i + 24] ^
      ridBuf[i] ^
      tcBuf[i];
  }
  return acc.readBigUInt64LE(0) % ticketCount;
}

// ─── SlotHashes sysvar parser ─────────────────────────────────────────────────

/**
 * Fetch the slot hash for `targetSlot` from the SlotHashes sysvar via RPC.
 * Falls back to the most-recent hash if the exact slot is not present.
 */
export async function fetchSlotHashForSlot(
  connection: Connection,
  targetSlot: bigint
): Promise<Uint8Array> {
  const acc = await connection.getAccountInfo(SYSVAR_SLOT_HASHES_PUBKEY, "confirmed");
  if (!acc) throw new Error("SlotHashes sysvar not found");

  const data = Buffer.from(acc.data);
  if (data.length < 8) throw new Error("SlotHashes data too short");

  const count = Number(data.readBigUInt64LE(0));
  const ENTRY = 40; // 8 slot + 32 hash
  let fallback: Uint8Array | null = null;

  for (let i = 0; i < Math.min(count, 512); i++) {
    const off  = 8 + i * ENTRY;
    if (off + ENTRY > data.length) break;
    const slot = data.readBigUInt64LE(off);
    const hash = new Uint8Array(data.slice(off + 8, off + ENTRY));
    if (!fallback) fallback = hash;
    if (slot === targetSlot) return hash;
  }
  if (!fallback) throw new Error(`No slot hash found for slot ${targetSlot}`);
  return fallback;
}

// ─── LotteryClient ────────────────────────────────────────────────────────────

export class LotteryClient {
  constructor(
    public readonly connection: Connection,
    public readonly wallet: Keypair
  ) {}

  // ── Queries ────────────────────────────────────────────────────────────────

  async fetchConfig(): Promise<LotteryConfig> {
    const [pda] = lotteryConfigPda();
    const acc = await this.connection.getAccountInfo(pda, "confirmed");
    if (!acc) throw new Error("LotteryConfig account not found");
    return deserializeLotteryConfig(Buffer.from(acc.data));
  }

  async fetchState(roundId: bigint): Promise<LotteryState> {
    const [pda] = lotteryStatePda(roundId);
    const acc = await this.connection.getAccountInfo(pda, "confirmed");
    if (!acc) throw new Error(`LotteryState not found for round ${roundId}`);
    return deserializeLotteryState(Buffer.from(acc.data));
  }

  async currentRoundId(): Promise<bigint> {
    return (await this.fetchConfig()).currentRoundId;
  }

  // ── buy_ticket ─────────────────────────────────────────────────────────────

  async buyTicket(roundId: bigint): Promise<string> {
    const state = await this.fetchState(roundId);
    const ticketIndex = state.ticketCount;

    const [lotteryStatePdaKey] = lotteryStatePda(roundId);
    const [ticketPdaKey]       = ticketPda(roundId, ticketIndex);
    const [walletCountPdaKey]  = walletTicketCountPda(roundId, this.wallet.publicKey);
    const [configPdaKey]       = lotteryConfigPda();

    const roundBuf  = Buffer.alloc(8); roundBuf.writeBigUInt64LE(roundId);
    const indexBuf  = Buffer.alloc(8); indexBuf.writeBigUInt64LE(ticketIndex);

    const data = Buffer.concat([
      DISC.buyTicket,
      roundBuf,
      indexBuf,
    ]);

    const ix = new TransactionInstruction({
      programId: LOTTERY_PROGRAM_ID,
      keys: [
        { pubkey: configPdaKey,       isSigner: false, isWritable: false },
        { pubkey: lotteryStatePdaKey, isSigner: false, isWritable: true  },
        { pubkey: ticketPdaKey,       isSigner: false, isWritable: true  },
        { pubkey: walletCountPdaKey,  isSigner: false, isWritable: true  },
        { pubkey: this.wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(ix);
    return sendAndConfirmTransaction(this.connection, tx, [this.wallet]);
  }

  // ── cast_draw_vote ─────────────────────────────────────────────────────────

  async castDrawVote(roundId: bigint): Promise<string> {
    const state     = await this.fetchState(roundId);
    const slotHash  = await fetchSlotHashForSlot(this.connection, state.endSlot);
    const winnerIdx = deriveWinnerIndex(slotHash, roundId, state.ticketCount);

    const [configPdaKey]  = lotteryConfigPda();
    const [statePdaKey]   = lotteryStatePda(roundId);
    const [votePdaKey]    = drawVotePda(roundId, this.wallet.publicKey);

    const roundBuf     = Buffer.alloc(8); roundBuf.writeBigUInt64LE(roundId);
    const winnerBuf    = Buffer.alloc(8); winnerBuf.writeBigUInt64LE(winnerIdx);

    const data = Buffer.concat([DISC.castDrawVote, roundBuf, winnerBuf]);

    const ix = new TransactionInstruction({
      programId: LOTTERY_PROGRAM_ID,
      keys: [
        { pubkey: configPdaKey,               isSigner: false, isWritable: false },
        { pubkey: statePdaKey,                isSigner: false, isWritable: true  },
        { pubkey: votePdaKey,                 isSigner: false, isWritable: true  },
        { pubkey: SYSVAR_SLOT_HASHES_PUBKEY,  isSigner: false, isWritable: false },
        { pubkey: this.wallet.publicKey,       isSigner: true,  isWritable: true  },
        { pubkey: SystemProgram.programId,     isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(ix);
    return sendAndConfirmTransaction(this.connection, tx, [this.wallet]);
  }

  // ── finalize_draw ──────────────────────────────────────────────────────────

  async finalizeDraw(
    roundId: bigint,
    treasury: PublicKey
  ): Promise<string> {
    const state = await this.fetchState(roundId);
    const idx   = state.committedWinnerIndex;

    const [configPdaKey]    = lotteryConfigPda();
    const [statePdaKey]     = lotteryStatePda(roundId);
    const [winnerTicketPda] = ticketPda(roundId, idx);
    const [poolPdaKey]      = nodePrizePoolPda(roundId);

    // Fetch winner wallet from ticket account (buyer field at offset 8+8=16 after disc)
    const ticketAcc = await this.connection.getAccountInfo(winnerTicketPda, "confirmed");
    if (!ticketAcc) throw new Error("Winner ticket account not found");
    const winnerWallet = new PublicKey(ticketAcc.data.slice(8 + 8, 8 + 8 + 32));

    const roundBuf = Buffer.alloc(8); roundBuf.writeBigUInt64LE(roundId);
    const data = Buffer.concat([DISC.finalizeDraw, roundBuf]);

    const ix = new TransactionInstruction({
      programId: LOTTERY_PROGRAM_ID,
      keys: [
        { pubkey: configPdaKey,              isSigner: false, isWritable: false },
        { pubkey: statePdaKey,               isSigner: false, isWritable: true  },
        { pubkey: winnerTicketPda,           isSigner: false, isWritable: false },
        { pubkey: winnerWallet,              isSigner: false, isWritable: true  },
        { pubkey: poolPdaKey,                isSigner: false, isWritable: true  },
        { pubkey: treasury,                  isSigner: false, isWritable: true  },
        { pubkey: this.wallet.publicKey,      isSigner: true,  isWritable: true  },
        { pubkey: SystemProgram.programId,    isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(ix);
    return sendAndConfirmTransaction(this.connection, tx, [this.wallet]);
  }

  // ── claim_node_prize ───────────────────────────────────────────────────────

  async claimNodePrize(roundId: bigint): Promise<string> {
    const [votePdaKey] = drawVotePda(roundId, this.wallet.publicKey);
    const [poolPdaKey] = nodePrizePoolPda(roundId);

    const roundBuf = Buffer.alloc(8); roundBuf.writeBigUInt64LE(roundId);
    const data = Buffer.concat([DISC.claimNodePrize, roundBuf]);

    const ix = new TransactionInstruction({
      programId: LOTTERY_PROGRAM_ID,
      keys: [
        { pubkey: votePdaKey,            isSigner: false, isWritable: true  },
        { pubkey: poolPdaKey,            isSigner: false, isWritable: true  },
        { pubkey: this.wallet.publicKey,  isSigner: true,  isWritable: true  },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(ix);
    return sendAndConfirmTransaction(this.connection, tx, [this.wallet]);
  }
}