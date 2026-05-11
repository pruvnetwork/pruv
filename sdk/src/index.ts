/**
 * @pruv/sdk — Pruv TypeScript SDK
 *
 * Primary entry point. Re-exports all public API surface.
 */

export { PruvClient, type PruvClientConfig } from "./client.js";
export { type AttestationStatus, type DappInfo } from "./types.js";
export { PruvConnection } from "./connection.js";

// ─── Lottery ──────────────────────────────────────────────────────────────────
export {
  LOTTERY_PROGRAM_ID,
  LotteryClient,
  lotteryConfigPda,
  lotteryStatePda,
  ticketPda,
  walletTicketCountPda,
  drawVotePda,
  nodePrizePoolPda,
  deriveWinnerIndex,
  fetchSlotHashForSlot,
  deserializeLotteryConfig,
  deserializeLotteryState,
  type LotteryConfig,
  type LotteryState,
  type DrawVote,
  type NodePrizePool,
} from "./lottery.js";
