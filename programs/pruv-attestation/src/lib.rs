//! pruv-attestation — Multi-signature trust attestation with Ed25519 verification.
//!
//! ## Production changes vs. prototype
//!
//! | Concern               | Prototype                          | Production (this file)              |
//! |-----------------------|------------------------------------|-------------------------------------|
//! | ZK proof storage      | `Vec<u8>` up to 1 024 B on-chain   | `[u8; 32]` Poseidon hash only       |
//! | Tx size budget        | Always exceeded Solana 1 232 B     | Constant-size instruction payload   |
//! | Signature verification| Stub (duplicate check only)        | Ed25519 native-program introspection|
//!
//! ## Ed25519 verification pattern
//!
//! Solana's built-in Ed25519 native program verifies all signatures **before**
//! our instruction executes.  If any signature is invalid the transaction is
//! rejected by the runtime and never reaches our program.
//!
//! Call convention (enforced in this program):
//!   1. The submitter adds an `Ed25519Instruction` at index 0 of the tx that
//!      covers every node signature with message = `sign_message(dapp, hash, slot)`.
//!   2. Our `submit_attestation` instruction reads the `Instructions` sysvar,
//!      locates the Ed25519 instruction, and confirms:
//!      a. All `signers` passed as arguments had their signature checked.
//!      b. The message used was exactly `sign_message(dapp, hash, slot)`.
//!
//! ## ZK proof lifecycle
//!
//! Raw Halo2 proof bytes (~1 KB) are stored **off-chain** by the submitting node
//! (local SQLite proof cache + optional IPFS/Arweave pin).  Only the
//! `proof_hash = SHA-256(proof_bytes)` is written on-chain — 32 bytes.
//! Any party can verify by fetching the raw proof from the off-chain store and
//! re-running `circuits::code_integrity::verify`.
//!
//! ## Flow
//!
//! 1. pruv nodes compute a ZK proof off-chain and gossip Ed25519 signatures (libp2p).
//! 2. Once ≥ 2/3 sign, any node builds a tx with:
//!      - ix[0]: Ed25519Program instruction (verifies all node sigs)
//!      - ix[1]: `submit_attestation` (this program) with proof_hash + signer list
//! 3. This program verifies threshold, confirms Ed25519 ix was present, stores hash.
//! 4. Hash mismatch → `invalidate_attestation` (simple majority + Ed25519 ix).
//! 5. Attestations expire after `ATTESTATION_TTL_SECS` (24 h).

use anchor_lang::prelude::*;
use solana_program::{
    ed25519_program,
    sysvar::instructions as ix_sysvar,
    hash::hashv,
};

declare_id!("AttsPruv11111111111111111111111111111111111");

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of node signatures per attestation.
pub const MAX_SIGNERS: usize = 32;

/// Minimum fraction of active nodes required (2/3, in basis points).
pub const THRESHOLD_BPS: u64 = 6_667;

/// Simple-majority threshold for invalidation (> 50%).
pub const MAJORITY_BPS: u64 = 5_001;

/// Attestation TTL: 24 hours.
pub const ATTESTATION_TTL_SECS: i64 = 24 * 60 * 60;

/// Ed25519 signature size.
pub const SIG_LEN: usize = 64;

/// Ed25519SignatureOffsets struct size (7 × u16).
const ED25519_OFFSETS_SIZE: usize = 14;

/// Offset in the Ed25519 instruction data where the offsets array starts.
/// Layout: [num_sigs: u16][padding: u16][offsets[0]: 14 bytes]...
const ED25519_HEADER_SIZE: usize = 2; // num_sigs only; Solana v2 has no padding u16

// ─── Sign-message helper ──────────────────────────────────────────────────────

/// Canonical message that every node Ed25519-signs for an attestation round.
///
/// message = SHA-256( dapp_program_id[32] ‖ program_hash[32] ‖ proof_hash[32] )
///
/// 96 bytes of preimage → 32 bytes of digest.
///
/// `proof_hash` (SHA-256 of raw Halo2 proof bytes) binds the signature to a
/// specific proof, preventing reuse of old signatures against a new proof.
/// No slot is included — the slot at tx execution time is unknowable at signing time.
pub fn sign_message(
    dapp_program_id: &Pubkey,
    program_hash: &[u8; 32],
    proof_hash: &[u8; 32],
) -> [u8; 32] {
    let h = hashv(&[
        dapp_program_id.as_ref(),
        program_hash.as_ref(),
        proof_hash.as_ref(),
    ]);
    h.to_bytes()
}

// ─── Program ──────────────────────────────────────────────────────────────────

#[program]
pub mod pruv_attestation {
    use super::*;

    // ── Configuration ─────────────────────────────────────────────────────────

    /// Initialise the global attestation config.
    pub fn init_config(
        ctx: Context<InitAttestationConfig>,
        active_node_count: u32,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.authority = ctx.accounts.authority.key();
        cfg.active_node_count = active_node_count;
        cfg.total_attestations_issued = 0;
        cfg.bump = ctx.bumps.config;
        msg!("AttestationConfig initialised — {} active nodes", active_node_count);
        Ok(())
    }

    /// Update the active node count (called after node register/exit).
    pub fn update_node_count(
        ctx: Context<UpdateNodeCount>,
        new_count: u32,
    ) -> Result<()> {
        ctx.accounts.config.active_node_count = new_count;
        msg!("Active node count updated to {}", new_count);
        Ok(())
    }

    // ── Attestation lifecycle ─────────────────────────────────────────────────

    /// Submit a new trust attestation for a registered dApp.
    ///
    /// # Arguments
    /// - `dapp_program_id` — the dApp being attested
    /// - `program_hash`    — SHA-256 of its on-chain bytecode
    /// - `attestation_type`— what property is being proved
    /// - `proof_hash`      — SHA-256 of the raw Halo2 proof bytes (stored off-chain)
    /// - `signers`         — ordered list of node operator pubkeys that signed
    ///
    /// # Prerequisites
    /// `ix[0]` of this transaction MUST be a Solana `Ed25519Program` instruction
    /// that verifies every pubkey in `signers` over `sign_message(dapp, hash, slot)`.
    pub fn submit_attestation(
        ctx: Context<SubmitAttestation>,
        dapp_program_id: Pubkey,
        program_hash: [u8; 32],
        attestation_type: AttestationType,
        proof_hash: [u8; 32],
        signers: Vec<Pubkey>,
    ) -> Result<()> {
        require!(
            !signers.is_empty() && signers.len() <= MAX_SIGNERS,
            AttestError::InvalidSignerCount
        );

        let cfg = &ctx.accounts.config;
        let clock = &ctx.accounts.clock;

        // ── 2/3 threshold check ───────────────────────────────────────────────
        check_threshold(signers.len(), cfg.active_node_count, THRESHOLD_BPS)?;

        // ── Ed25519 instruction introspection ─────────────────────────────────
        // Verify that all signers had their Ed25519 signature verified against
        // the canonical sign_message payload in this same transaction.
        let expected_msg = sign_message(&dapp_program_id, &program_hash, &proof_hash);
        verify_ed25519_sysvar(
            &ctx.accounts.instructions,
            &signers,
            &expected_msg,
        )?;

        // ── Write attestation record ──────────────────────────────────────────
        let attest = &mut ctx.accounts.attestation;
        attest.dapp_program_id  = dapp_program_id;
        attest.attestation_type = attestation_type.clone();
        attest.program_hash     = program_hash;
        attest.proof_hash       = proof_hash;
        attest.slot             = clock.slot;
        attest.created_at       = clock.unix_timestamp;
        attest.expires_at       = clock.unix_timestamp + ATTESTATION_TTL_SECS;
        attest.signer_count     = signers.len() as u8;
        attest.valid            = true;
        attest.bump             = ctx.bumps.attestation;

        let cfg = &mut ctx.accounts.config;
        cfg.total_attestations_issued = cfg.total_attestations_issued.saturating_add(1);

        emit!(AttestationSubmitted {
            dapp_program_id,
            program_hash,
            proof_hash,
            attestation_type,
            signer_count: attest.signer_count,
            expires_at: attest.expires_at,
        });

        msg!(
            "Attestation submitted: dapp={} signers={} slot={}",
            dapp_program_id,
            attest.signer_count,
            clock.slot,
        );
        Ok(())
    }

    /// Invalidate an existing attestation when a hash mismatch is detected.
    ///
    /// Requires a simple majority (> 50%) of node signatures.
    /// `ix[0]` MUST be an Ed25519Program instruction covering all `signers`
    /// over `sign_message(dapp_program_id, mismatch_hash, current_slot)`.
    pub fn invalidate_attestation(
        ctx: Context<InvalidateAttestation>,
        signers: Vec<Pubkey>,
        mismatch_hash: [u8; 32],
    ) -> Result<()> {
        require!(
            !signers.is_empty() && signers.len() <= MAX_SIGNERS,
            AttestError::InvalidSignerCount
        );

        let cfg = &ctx.accounts.config;
        let attest = &mut ctx.accounts.attestation;

        require!(attest.valid, AttestError::AlreadyInvalid);

        // Simple majority
        check_threshold(signers.len(), cfg.active_node_count, MAJORITY_BPS)?;

        // Ed25519 introspection — signers signed over (dapp_id, registered_hash, mismatch_hash).
        // sign_message = SHA-256(dapp_id[32] ‖ program_hash[32] ‖ proof_hash[32]).
        // Using the registered hash as program_hash and mismatch_hash as proof_hash
        // binds the signature to the specific discrepancy being reported.
        // No slot is mixed in — it is unknowable at off-chain signing time.
        let expected_msg = sign_message(&attest.dapp_program_id, &attest.program_hash, &mismatch_hash);
        verify_ed25519_sysvar(
            &ctx.accounts.instructions,
            &signers,
            &expected_msg,
        )?;

        attest.valid = false;

        emit!(AttestationInvalidated {
            dapp_program_id: attest.dapp_program_id,
            old_hash: attest.program_hash,
            detected_hash: mismatch_hash,
        });

        msg!("Attestation invalidated: dapp={}", attest.dapp_program_id);
        Ok(())
    }

    /// Refresh an expiring attestation (renews TTL, optionally updates hash).
    ///
    /// Same signing requirements as `submit_attestation`.
    pub fn refresh_attestation(
        ctx: Context<RefreshAttestation>,
        new_program_hash: [u8; 32],
        new_proof_hash: [u8; 32],
        signers: Vec<Pubkey>,
    ) -> Result<()> {
        require!(
            !signers.is_empty() && signers.len() <= MAX_SIGNERS,
            AttestError::InvalidSignerCount
        );

        let cfg = &ctx.accounts.config;
        let attest = &mut ctx.accounts.attestation;

        // refresh is allowed on both valid and invalid attestations (re-validation after mismatch)
        check_threshold(signers.len(), cfg.active_node_count, THRESHOLD_BPS)?;

        let clock = Clock::get()?;
        let expected_msg = sign_message(&attest.dapp_program_id, &new_program_hash, &new_proof_hash);
        verify_ed25519_sysvar(
            &ctx.accounts.instructions,
            &signers,
            &expected_msg,
        )?;

        attest.program_hash = new_program_hash;
        attest.proof_hash   = new_proof_hash;
        attest.slot         = clock.slot;
        attest.created_at   = clock.unix_timestamp;
        attest.expires_at   = clock.unix_timestamp + ATTESTATION_TTL_SECS;
        attest.signer_count = signers.len() as u8;
        attest.valid        = true; // re-validate if previously invalidated

        emit!(AttestationRefreshed {
            dapp_program_id: attest.dapp_program_id,
            new_hash: new_program_hash,
            new_proof_hash,
            new_expires_at: attest.expires_at,
        });

        Ok(())
    }
}

// ─── Ed25519 instruction introspection ───────────────────────────────────────

/// Verify that the current transaction contains an `Ed25519Program` instruction
/// that covers **all** pubkeys in `signers` over the exact `expected_message`.
///
/// Security properties:
/// - If the Ed25519 instruction is absent or malformed → `AttestError::MissingEd25519Ix`
/// - If any signer is not covered by the Ed25519 instruction → `AttestError::SignerNotVerified`
/// - If the message does not match → `AttestError::MessageMismatch`
/// - Duplicate signer pubkeys → `AttestError::DuplicateSigner`
///
/// This function does **not** re-verify the cryptographic signatures — the
/// Solana runtime already did that when it processed the Ed25519 instruction.
/// If the transaction is on-chain, the signatures were valid.
fn verify_ed25519_sysvar(
    instructions_sysvar: &UncheckedAccount,
    signers: &[Pubkey],
    expected_message: &[u8; 32],
) -> Result<()> {
    // ── Deduplicate signers ───────────────────────────────────────────────────
    {
        let mut seen = std::collections::BTreeSet::new();
        for pk in signers {
            require!(seen.insert(pk.to_bytes()), AttestError::DuplicateSigner);
        }
    }

    // ── Find the Ed25519Program instruction ───────────────────────────────────
    // We scan all instructions in the transaction (sysvar) to find one from the
    // Ed25519 native program.  Typically it is ix[0].
    let mut ed25519_ix_data: Option<Vec<u8>> = None;

    let num_ixs = ix_sysvar::load_current_index_checked(
        &instructions_sysvar.to_account_info()
    ).map_err(|_| error!(AttestError::InstructionSysvarError))? as usize;

    for idx in 0..=num_ixs {
        if let Ok(ix) = ix_sysvar::load_instruction_at_checked(
            idx,
            &instructions_sysvar.to_account_info(),
        ) {
            if ix.program_id == ed25519_program::ID {
                ed25519_ix_data = Some(ix.data.to_vec());
                break;
            }
        }
    }

    let data = ed25519_ix_data.ok_or(error!(AttestError::MissingEd25519Ix))?;

    // ── Parse Ed25519 instruction data ────────────────────────────────────────
    // Layout (Solana Ed25519 native program):
    //   [0..2]         num_signatures (u16 LE)
    //   [2..2+N*14]    N × Ed25519SignatureOffsets (14 bytes each)
    //   [...]          packed signature (64B) + pubkey (32B) + message data
    //
    // Ed25519SignatureOffsets (each field: u16 LE):
    //   signature_offset           — byte offset of the 64-byte signature
    //   signature_instruction_index— instruction index (0xFFFF = same ix)
    //   public_key_offset          — byte offset of the 32-byte public key
    //   public_key_instruction_index
    //   message_data_offset        — byte offset of the message
    //   message_data_size          — message length in bytes
    //   message_instruction_index

    require!(data.len() >= ED25519_HEADER_SIZE, AttestError::MalformedEd25519Ix);
    let num_sigs = u16::from_le_bytes([data[0], data[1]]) as usize;
    require!(num_sigs > 0, AttestError::MissingEd25519Ix);

    let offsets_end = ED25519_HEADER_SIZE + num_sigs * ED25519_OFFSETS_SIZE;
    require!(data.len() >= offsets_end, AttestError::MalformedEd25519Ix);

    // ── Collect verified (pubkey, message) pairs from the Ed25519 instruction ─
    let mut verified_pubkeys: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();

    for i in 0..num_sigs {
        let base = ED25519_HEADER_SIZE + i * ED25519_OFFSETS_SIZE;
        let offsets = &data[base..base + ED25519_OFFSETS_SIZE];

        // Parse offsets (all u16 LE)
        let pk_offset  = u16::from_le_bytes([offsets[4], offsets[5]]) as usize;
        let msg_offset = u16::from_le_bytes([offsets[8], offsets[9]]) as usize;
        let msg_size   = u16::from_le_bytes([offsets[10], offsets[11]]) as usize;

        // Extract public key (32 bytes)
        require!(
            pk_offset + 32 <= data.len(),
            AttestError::MalformedEd25519Ix
        );
        let pk_bytes: [u8; 32] = data[pk_offset..pk_offset + 32]
            .try_into()
            .map_err(|_| error!(AttestError::MalformedEd25519Ix))?;

        // Extract message and verify it matches expected_message
        require!(
            msg_offset + msg_size <= data.len(),
            AttestError::MalformedEd25519Ix
        );
        let msg_bytes = &data[msg_offset..msg_offset + msg_size];
        require!(
            msg_bytes == expected_message.as_ref(),
            AttestError::MessageMismatch
        );

        verified_pubkeys.insert(pk_bytes);
    }

    // ── Verify every signer was covered ──────────────────────────────────────
    for signer in signers {
        require!(
            verified_pubkeys.contains(&signer.to_bytes()),
            AttestError::SignerNotVerified
        );
    }

    Ok(())
}

// ─── Threshold helper ─────────────────────────────────────────────────────────

fn check_threshold(signer_count: usize, active_nodes: u32, threshold_bps: u64) -> Result<()> {
    let threshold_num = (active_nodes as u64).saturating_mul(threshold_bps);
    let actual_num    = (signer_count as u64).saturating_mul(10_000);
    require!(actual_num >= threshold_num, AttestError::ThresholdNotMet);
    Ok(())
}

// ─── Accounts ─────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitAttestationConfig<'info> {
    #[account(
        init,
        payer = authority,
        space = AttestationConfig::INIT_SPACE,
        seeds = [b"attest_config"],
        bump,
    )]
    pub config: Account<'info, AttestationConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateNodeCount<'info> {
    #[account(
        mut,
        seeds = [b"attest_config"],
        bump = config.bump,
        has_one = authority @ AttestError::Unauthorized,
    )]
    pub config: Account<'info, AttestationConfig>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(dapp_program_id: Pubkey)]
pub struct SubmitAttestation<'info> {
    #[account(
        init,
        payer = submitter,
        space = Attestation::INIT_SPACE,
        seeds = [b"attestation", dapp_program_id.as_ref()],
        bump,
    )]
    pub attestation: Account<'info, Attestation>,

    #[account(
        mut,
        seeds = [b"attest_config"],
        bump = config.bump,
    )]
    pub config: Account<'info, AttestationConfig>,

    #[account(mut)]
    pub submitter: Signer<'info>,

    pub clock: Sysvar<'info, Clock>,

    /// Instructions sysvar — used to introspect the preceding Ed25519 instruction.
    /// CHECK: read-only sysvar, validated by address constraint.
    #[account(address = ix_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InvalidateAttestation<'info> {
    #[account(
        mut,
        seeds = [b"attestation", attestation.dapp_program_id.as_ref()],
        bump = attestation.bump,
    )]
    pub attestation: Account<'info, Attestation>,

    #[account(
        seeds = [b"attest_config"],
        bump = config.bump,
    )]
    pub config: Account<'info, AttestationConfig>,

    /// Any active node operator may trigger invalidation.
    pub submitter: Signer<'info>,

    /// Instructions sysvar for Ed25519 verification.
    /// CHECK: read-only sysvar, validated by address constraint.
    #[account(address = ix_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct RefreshAttestation<'info> {
    #[account(
        mut,
        seeds = [b"attestation", attestation.dapp_program_id.as_ref()],
        bump = attestation.bump,
    )]
    pub attestation: Account<'info, Attestation>,

    #[account(
        seeds = [b"attest_config"],
        bump = config.bump,
    )]
    pub config: Account<'info, AttestationConfig>,

    pub submitter: Signer<'info>,

    /// Instructions sysvar for Ed25519 verification.
    /// CHECK: read-only sysvar, validated by address constraint.
    #[account(address = ix_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,
}

// ─── State ────────────────────────────────────────────────────────────────────

#[account]
#[derive(InitSpace)]
pub struct AttestationConfig {
    /// Authority that can update config (should be governance multisig).
    pub authority: Pubkey,
    /// Mirror of the pruv node registry active count.
    pub active_node_count: u32,
    /// Monotonically increasing counter of all attestations ever issued.
    pub total_attestations_issued: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Attestation {
    /// The dApp program being attested.
    pub dapp_program_id: Pubkey,
    /// What property this attestation proves.
    pub attestation_type: AttestationType,
    /// SHA-256 of the dApp's on-chain executable at the time of attestation.
    pub program_hash: [u8; 32],
    /// SHA-256 of the raw Halo2 proof bytes (proof itself stored off-chain).
    /// Use this to retrieve and re-verify the proof from the node's proof cache.
    pub proof_hash: [u8; 32],
    /// Solana slot at time of attestation.
    pub slot: u64,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Unix timestamp of expiry (created_at + ATTESTATION_TTL_SECS).
    pub expires_at: i64,
    /// Number of node signatures included.
    pub signer_count: u8,
    /// False once invalidated or expired and explicitly closed.
    pub valid: bool,
    pub bump: u8,
}

// ─── Enums ────────────────────────────────────────────────────────────────────

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq, InitSpace)]
pub enum AttestationType {
    /// SHA-256 bytecode hash matches the registered value.
    CodeIntegrity,
    /// Program vault holds the claimed token balances (custody proof).
    CustodyProof,
    /// Governance execution was performed honestly.
    GovernanceExecution,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct AttestationSubmitted {
    pub dapp_program_id:  Pubkey,
    pub program_hash:     [u8; 32],
    /// SHA-256 of the ZK proof — fetch from off-chain store to re-verify.
    pub proof_hash:       [u8; 32],
    pub attestation_type: AttestationType,
    pub signer_count:     u8,
    pub expires_at:       i64,
}

#[event]
pub struct AttestationInvalidated {
    pub dapp_program_id: Pubkey,
    pub old_hash:        [u8; 32],
    pub detected_hash:   [u8; 32],
}

#[event]
pub struct AttestationRefreshed {
    pub dapp_program_id: Pubkey,
    pub new_hash:        [u8; 32],
    pub new_proof_hash:  [u8; 32],
    pub new_expires_at:  i64,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum AttestError {
    #[msg("Signer count must be between 1 and MAX_SIGNERS")]
    InvalidSignerCount,
    #[msg("Active node threshold not met")]
    ThresholdNotMet,
    #[msg("Attestation is already invalid")]
    AlreadyInvalid,
    #[msg("Duplicate signer pubkey detected")]
    DuplicateSigner,
    #[msg("Transaction must include an Ed25519Program instruction at ix[0]")]
    MissingEd25519Ix,
    #[msg("Ed25519 instruction data is malformed")]
    MalformedEd25519Ix,
    #[msg("Ed25519 message does not match sign_message(dapp, hash, slot)")]
    MessageMismatch,
    #[msg("One or more signers were not covered by the Ed25519 instruction")]
    SignerNotVerified,
    #[msg("Failed to read instructions sysvar")]
    InstructionSysvarError,
    #[msg("Caller is not authorised")]
    Unauthorized,
}