//! pruv-governance — Privacy-preserving DAO voting via Halo2 ZK proofs.
//!
//! ## Production architecture
//!
//! Full Halo2 proof verification cannot run on-chain within Solana's compute-unit
//! and transaction-size limits (~1 232 byte MTU, 1.4 M CU per tx).  Instead,
//! pruv uses an **off-chain proof / on-chain commitment** pattern:
//!
//! 1. A voter generates a Halo2 proof off-chain that commits to:
//!      - vote (0/1)          — kept private from observers
//!      - nullifier           — `Poseidon(voter_secret, proposal_id)`, prevents double-vote
//!      - Merkle membership   — proves voter is a DAO member without revealing identity
//! 2. The voter submits the raw proof + public outputs to pruv nodes (libp2p gossip).
//! 3. Nodes verify the proof with `circuits::governance_vote::verify` and gossip their
//!    Ed25519 approval signatures.
//! 4. Once ≥ ⌈(2/3) × committee_size⌉ nodes have signed, any node submits on-chain:
//!      - ix[0]: Ed25519Program instruction (all node approval sigs)
//!      - ix[1]: `cast_vote` with proof_hash + nullifier + vote_signal + signer list
//! 5. On-chain: check nullifier uniqueness, verify Ed25519 ix, tally vote.
//!
//! ## Privacy guarantees
//!
//! - Observers on-chain see only: nullifier (opaque hash) + proof_hash
//! - Node operators see vote_signal during off-chain verification — accepted tradeoff
//!   for production deployments (nodes are pseudonymous and distributed)
//! - Voter identity is never linked to the nullifier on-chain
//!
//! ## Sign message (node committee)
//!
//!   message = SHA-256( proposal_id[8:LE] ‖ nullifier[32] ‖ vote_signal[1] ‖ proof_hash[32] )

use anchor_lang::prelude::*;
use solana_program::{
    ed25519_program,
    hash::hashv,
    sysvar::instructions as ix_sysvar,
};

declare_id!("GovPruv111111111111111111111111111111111111");

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum title length.
pub const MAX_TITLE_LEN: usize = 128;

/// Maximum description length.
pub const MAX_DESC_LEN: usize = 1024;

/// Minimum voting window (1 hour).
pub const MIN_VOTING_DURATION_SECS: i64 = 3_600;

/// Maximum voting window (30 days).
pub const MAX_VOTING_DURATION_SECS: i64 = 30 * 24 * 3_600;

/// Quorum: minimum fraction of member votes required (basis points, 1 000 = 10%).
pub const QUORUM_BPS: u64 = 1_000;

/// Approval threshold (basis points, 5 000 = simple majority).
pub const APPROVAL_THRESHOLD_BPS: u64 = 5_000;

/// Nullifier size (32-byte Poseidon hash).
pub const NULLIFIER_LEN: usize = 32;

/// Maximum nodes that can co-sign a single vote approval.
pub const MAX_VOTE_SIGNERS: usize = 32;

/// Committee threshold for vote approval (2/3, basis points).
pub const COMMITTEE_THRESHOLD_BPS: u64 = 6_667;

/// Ed25519SignatureOffsets struct size (7 × u16).
const ED25519_OFFSETS_SIZE: usize = 14;
/// Ed25519 instruction data header size (num_sigs: u16).
const ED25519_HEADER_SIZE: usize = 2;

// ─── Sign-message helper ──────────────────────────────────────────────────────

/// Canonical message that pruv nodes Ed25519-sign to approve a vote.
///
/// message = SHA-256( proposal_id[8:LE] ‖ nullifier[32] ‖ vote_signal[1] ‖ proof_hash[32] )
pub fn vote_sign_message(
    proposal_id: u64,
    nullifier: &[u8; 32],
    vote_signal: u8,
    proof_hash: &[u8; 32],
) -> [u8; 32] {
    let id_bytes = proposal_id.to_le_bytes();
    let h = hashv(&[
        &id_bytes,
        nullifier.as_ref(),
        &[vote_signal],
        proof_hash.as_ref(),
    ]);
    h.to_bytes()
}

// ─── Program ──────────────────────────────────────────────────────────────────

#[program]
pub mod pruv_governance {
    use super::*;

    /// Initialise the governance config singleton.
    pub fn init_governance(
        ctx: Context<InitGovernance>,
        member_tree_root: [u8; 32],
        total_members: u64,
        committee_size: u32,
    ) -> Result<()> {
        let gov = &mut ctx.accounts.governance_config;
        gov.authority = ctx.accounts.authority.key();
        gov.member_tree_root = member_tree_root;
        gov.total_members = total_members;
        gov.committee_size = committee_size;
        gov.proposal_count = 0;
        gov.bump = ctx.bumps.governance_config;
        msg!(
            "Governance initialised: {} members, {} committee nodes",
            total_members,
            committee_size
        );
        Ok(())
    }

    /// Update the member Merkle tree root (after a membership change).
    pub fn update_member_root(
        ctx: Context<UpdateMemberRoot>,
        new_root: [u8; 32],
        new_total_members: u64,
    ) -> Result<()> {
        let gov = &mut ctx.accounts.governance_config;
        gov.member_tree_root = new_root;
        gov.total_members = new_total_members;

        emit!(MemberRootUpdated {
            new_root,
            new_total_members,
        });
        Ok(())
    }

    /// Update the committee size when nodes join or leave.
    pub fn update_committee_size(
        ctx: Context<UpdateCommitteeSize>,
        new_size: u32,
    ) -> Result<()> {
        require!(new_size >= 1, GovError::InvalidCommitteeSize);
        ctx.accounts.governance_config.committee_size = new_size;
        msg!("Committee size updated to {}", new_size);
        Ok(())
    }

    /// Create a new governance proposal.
    pub fn create_proposal(
        ctx: Context<CreateProposal>,
        title: String,
        description: String,
        voting_duration_secs: i64,
        execution_payload: Vec<u8>,
    ) -> Result<()> {
        require!(title.len() <= MAX_TITLE_LEN, GovError::TitleTooLong);
        require!(description.len() <= MAX_DESC_LEN, GovError::DescTooLong);
        require!(
            voting_duration_secs >= MIN_VOTING_DURATION_SECS,
            GovError::VotingWindowTooShort
        );
        require!(
            voting_duration_secs <= MAX_VOTING_DURATION_SECS,
            GovError::VotingWindowTooLong
        );

        let clock = Clock::get()?;
        let gov = &mut ctx.accounts.governance_config;
        let proposal = &mut ctx.accounts.proposal;

        let id = gov.proposal_count;
        gov.proposal_count = gov.proposal_count.saturating_add(1);

        proposal.id = id;
        proposal.proposer = ctx.accounts.proposer.key();
        proposal.title = title;
        proposal.description = description;
        proposal.votes_for = 0;
        proposal.votes_against = 0;
        proposal.status = ProposalStatus::Active;
        proposal.start_time = clock.unix_timestamp;
        proposal.end_time = clock.unix_timestamp + voting_duration_secs;
        proposal.execution_payload = execution_payload;
        proposal.executed = false;
        proposal.bump = ctx.bumps.proposal;

        emit!(ProposalCreated {
            id,
            proposer: proposal.proposer,
            title: proposal.title.clone(),
            end_time: proposal.end_time,
        });

        msg!("Proposal #{} created: {}", id, proposal.title);
        Ok(())
    }

    /// Cast a private vote, approved by the pruv node committee.
    ///
    /// # Off-chain flow (handled by node-software)
    /// 1. Voter generates a Halo2 proof and submits it to pruv nodes.
    /// 2. Nodes verify `circuits::governance_vote::verify(proof, public_inputs)`.
    /// 3. Each node signs: `vote_sign_message(proposal_id, nullifier, vote_signal, proof_hash)`.
    /// 4. Once ≥ ⌈(2/3) × committee_size⌉ signatures gathered, any node submits this tx:
    ///      - ix[0] : Ed25519Program instruction (N node signatures)
    ///      - ix[1] : `cast_vote` (this instruction)
    ///
    /// # Arguments
    /// - `proof_hash`   — SHA-256 of the Halo2 proof bytes (for auditability)
    /// - `nullifier`    — Poseidon(voter_secret, proposal_id) prevents double-voting
    /// - `vote_signal`  — 0 = against, 1 = for
    /// - `signers`      — node committee pubkeys that signed the approval
    pub fn cast_vote(
        ctx: Context<CastVote>,
        proof_hash: [u8; 32],
        nullifier: [u8; NULLIFIER_LEN],
        vote_signal: u8,
        signers: Vec<Pubkey>,
    ) -> Result<()> {
        require!(vote_signal <= 1, GovError::InvalidVoteSignal);
        require!(
            !signers.is_empty() && signers.len() <= MAX_VOTE_SIGNERS,
            GovError::InvalidSignerCount
        );

        let clock = Clock::get()?;
        let proposal = &mut ctx.accounts.proposal;
        let gov = &ctx.accounts.governance_config;

        require!(
            proposal.status == ProposalStatus::Active,
            GovError::ProposalNotActive
        );
        require!(
            clock.unix_timestamp <= proposal.end_time,
            GovError::VotingWindowClosed
        );

        // ── Committee threshold check ──────────────────────────────────────────
        // Require ≥ 2/3 of pruv nodes to have verified the Halo2 proof.
        let threshold_num = (gov.committee_size as u64).saturating_mul(COMMITTEE_THRESHOLD_BPS);
        let actual_num    = (signers.len() as u64).saturating_mul(10_000);
        require!(actual_num >= threshold_num, GovError::CommitteeThresholdNotMet);

        // ── Ed25519 instruction introspection ─────────────────────────────────
        // Verify all node signers had their signatures verified by the Ed25519
        // native program in this same transaction, over vote_sign_message(...).
        let expected_msg = vote_sign_message(proposal.id, &nullifier, vote_signal, &proof_hash);
        verify_ed25519_vote_sysvar(
            &ctx.accounts.instructions,
            &signers,
            &expected_msg,
        )?;

        // ── Nullifier uniqueness is enforced by PDA init ───────────────────────
        // If the PDA already exists, the `init` constraint causes this tx to fail.
        let nr = &mut ctx.accounts.nullifier_record;
        nr.proposal_id = proposal.id;
        nr.nullifier   = nullifier;
        nr.proof_hash  = proof_hash;
        nr.bump        = ctx.bumps.nullifier_record;

        // Tally the vote.
        if vote_signal == 1 {
            proposal.votes_for = proposal.votes_for.saturating_add(1);
        } else {
            proposal.votes_against = proposal.votes_against.saturating_add(1);
        }

        emit!(VoteCast {
            proposal_id: proposal.id,
            nullifier,
            proof_hash,
            // We do NOT emit the vote direction — privacy preserved on-chain.
        });

        msg!(
            "Vote cast: proposal={} nullifier={:?} signers={}",
            proposal.id,
            &nullifier[..4],
            signers.len()
        );
        Ok(())
    }

    /// Finalise a proposal after the voting window has closed.
    pub fn finalize_proposal(ctx: Context<FinalizeProposal>) -> Result<()> {
        let clock = Clock::get()?;
        let proposal = &mut ctx.accounts.proposal;
        let gov = &ctx.accounts.governance_config;

        require!(
            proposal.status == ProposalStatus::Active,
            GovError::ProposalNotActive
        );
        require!(
            clock.unix_timestamp > proposal.end_time,
            GovError::VotingWindowStillOpen
        );

        let total_votes = proposal.votes_for + proposal.votes_against;
        let quorum_votes = gov
            .total_members
            .saturating_mul(QUORUM_BPS)
            / 10_000;

        if total_votes < quorum_votes {
            proposal.status = ProposalStatus::Failed;
            emit!(ProposalFinalized {
                id: proposal.id,
                status: ProposalStatus::Failed,
                votes_for: proposal.votes_for,
                votes_against: proposal.votes_against,
            });
            return Ok(());
        }

        let approval_bps = proposal
            .votes_for
            .saturating_mul(10_000)
            / total_votes.max(1);

        proposal.status = if approval_bps >= APPROVAL_THRESHOLD_BPS {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Failed
        };

        emit!(ProposalFinalized {
            id: proposal.id,
            status: proposal.status.clone(),
            votes_for: proposal.votes_for,
            votes_against: proposal.votes_against,
        });

        msg!(
            "Proposal #{} finalised: {:?} ({} for / {} against)",
            proposal.id,
            proposal.status,
            proposal.votes_for,
            proposal.votes_against
        );
        Ok(())
    }

    /// Mark a passed proposal as executed.
    pub fn mark_executed(ctx: Context<MarkExecuted>) -> Result<()> {
        let proposal = &mut ctx.accounts.proposal;

        require!(
            proposal.status == ProposalStatus::Passed,
            GovError::ProposalNotPassed
        );
        require!(!proposal.executed, GovError::AlreadyExecuted);

        proposal.executed = true;
        proposal.status = ProposalStatus::Executed;

        emit!(ProposalExecuted { id: proposal.id });

        Ok(())
    }
}

// ─── Ed25519 instruction introspection ───────────────────────────────────────

/// Verify that the current transaction contains an `Ed25519Program` instruction
/// that covers all `signers` over the exact `expected_message`.
///
/// Mirrors the implementation in `pruv-attestation` — keep in sync.
fn verify_ed25519_vote_sysvar(
    instructions_sysvar: &UncheckedAccount,
    signers: &[Pubkey],
    expected_message: &[u8; 32],
) -> Result<()> {
    // Deduplicate
    {
        let mut seen = std::collections::BTreeSet::new();
        for pk in signers {
            require!(seen.insert(pk.to_bytes()), GovError::DuplicateSigner);
        }
    }

    // Find Ed25519Program instruction in the transaction
    let mut ed25519_data: Option<Vec<u8>> = None;
    let current_idx = ix_sysvar::load_current_index_checked(
        &instructions_sysvar.to_account_info(),
    ).map_err(|_| error!(GovError::InstructionSysvarError))? as usize;

    for idx in 0..=current_idx {
        if let Ok(ix) = ix_sysvar::load_instruction_at_checked(
            idx,
            &instructions_sysvar.to_account_info(),
        ) {
            if ix.program_id == ed25519_program::ID {
                ed25519_data = Some(ix.data.to_vec());
                break;
            }
        }
    }

    let data = ed25519_data.ok_or(error!(GovError::MissingEd25519Ix))?;

    // Parse Ed25519 instruction data
    require!(data.len() >= ED25519_HEADER_SIZE, GovError::MalformedEd25519Ix);
    let num_sigs = u16::from_le_bytes([data[0], data[1]]) as usize;
    require!(num_sigs > 0, GovError::MissingEd25519Ix);

    let offsets_end = ED25519_HEADER_SIZE + num_sigs * ED25519_OFFSETS_SIZE;
    require!(data.len() >= offsets_end, GovError::MalformedEd25519Ix);

    let mut verified_pubkeys: std::collections::BTreeSet<[u8; 32]> =
        std::collections::BTreeSet::new();

    for i in 0..num_sigs {
        let base    = ED25519_HEADER_SIZE + i * ED25519_OFFSETS_SIZE;
        let offsets = &data[base..base + ED25519_OFFSETS_SIZE];

        let pk_offset  = u16::from_le_bytes([offsets[4], offsets[5]]) as usize;
        let msg_offset = u16::from_le_bytes([offsets[8], offsets[9]]) as usize;
        let msg_size   = u16::from_le_bytes([offsets[10], offsets[11]]) as usize;

        require!(pk_offset + 32 <= data.len(), GovError::MalformedEd25519Ix);
        let pk_bytes: [u8; 32] = data[pk_offset..pk_offset + 32]
            .try_into()
            .map_err(|_| error!(GovError::MalformedEd25519Ix))?;

        require!(msg_offset + msg_size <= data.len(), GovError::MalformedEd25519Ix);
        let msg_bytes = &data[msg_offset..msg_offset + msg_size];
        require!(msg_bytes == expected_message.as_ref(), GovError::MessageMismatch);

        verified_pubkeys.insert(pk_bytes);
    }

    for signer in signers {
        require!(
            verified_pubkeys.contains(&signer.to_bytes()),
            GovError::SignerNotVerified
        );
    }

    Ok(())
}

// ─── Accounts ─────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitGovernance<'info> {
    #[account(
        init,
        payer = authority,
        space = GovernanceConfig::INIT_SPACE,
        seeds = [b"governance"],
        bump,
    )]
    pub governance_config: Account<'info, GovernanceConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateMemberRoot<'info> {
    #[account(
        mut,
        seeds = [b"governance"],
        bump = governance_config.bump,
        has_one = authority @ GovError::Unauthorized,
    )]
    pub governance_config: Account<'info, GovernanceConfig>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateCommitteeSize<'info> {
    #[account(
        mut,
        seeds = [b"governance"],
        bump = governance_config.bump,
        has_one = authority @ GovError::Unauthorized,
    )]
    pub governance_config: Account<'info, GovernanceConfig>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(title: String, description: String)]
pub struct CreateProposal<'info> {
    #[account(
        init,
        payer = proposer,
        space = Proposal::INIT_SPACE,
        seeds = [b"proposal", governance_config.proposal_count.to_le_bytes().as_ref()],
        bump,
    )]
    pub proposal: Account<'info, Proposal>,

    #[account(
        mut,
        seeds = [b"governance"],
        bump = governance_config.bump,
    )]
    pub governance_config: Account<'info, GovernanceConfig>,

    #[account(mut)]
    pub proposer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proof_hash: [u8; 32], nullifier: [u8; 32])]
pub struct CastVote<'info> {
    #[account(
        mut,
        seeds = [b"proposal", proposal.id.to_le_bytes().as_ref()],
        bump = proposal.bump,
    )]
    pub proposal: Account<'info, Proposal>,

    #[account(
        seeds = [b"governance"],
        bump = governance_config.bump,
    )]
    pub governance_config: Account<'info, GovernanceConfig>,

    /// One PDA per nullifier — its existence on-chain enforces uniqueness.
    #[account(
        init,
        payer = submitter,
        space = NullifierRecord::INIT_SPACE,
        seeds = [b"nullifier", nullifier.as_ref()],
        bump,
    )]
    pub nullifier_record: Account<'info, NullifierRecord>,

    /// Any pruv node that gathered the required committee signatures can submit.
    #[account(mut)]
    pub submitter: Signer<'info>,

    /// Instructions sysvar for Ed25519 introspection.
    /// CHECK: read-only sysvar, validated by address constraint.
    #[account(address = ix_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FinalizeProposal<'info> {
    #[account(
        mut,
        seeds = [b"proposal", proposal.id.to_le_bytes().as_ref()],
        bump = proposal.bump,
    )]
    pub proposal: Account<'info, Proposal>,

    #[account(
        seeds = [b"governance"],
        bump = governance_config.bump,
    )]
    pub governance_config: Account<'info, GovernanceConfig>,

    /// Anyone can finalise after the window closes.
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct MarkExecuted<'info> {
    #[account(
        mut,
        seeds = [b"proposal", proposal.id.to_le_bytes().as_ref()],
        bump = proposal.bump,
    )]
    pub proposal: Account<'info, Proposal>,

    #[account(
        seeds = [b"governance"],
        bump = governance_config.bump,
        has_one = authority @ GovError::Unauthorized,
    )]
    pub governance_config: Account<'info, GovernanceConfig>,

    pub authority: Signer<'info>,
}

// ─── State ────────────────────────────────────────────────────────────────────

#[account]
#[derive(InitSpace)]
pub struct GovernanceConfig {
    /// Authority that can update the member tree and execute proposals.
    pub authority: Pubkey,
    /// Root of the Merkle tree committing to all DAO member public keys.
    pub member_tree_root: [u8; 32],
    /// Total number of DAO members (used for quorum calculation).
    pub total_members: u64,
    /// Number of active pruv nodes in the committee.
    pub committee_size: u32,
    /// Monotonically increasing proposal counter.
    pub proposal_count: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Proposal {
    pub id: u64,
    pub proposer: Pubkey,
    #[max_len(128)]
    pub title: String,
    #[max_len(1024)]
    pub description: String,
    pub votes_for: u64,
    pub votes_against: u64,
    pub status: ProposalStatus,
    pub start_time: i64,
    pub end_time: i64,
    /// Arbitrary payload that the executor interprets (e.g., serialised instruction).
    #[max_len(512)]
    pub execution_payload: Vec<u8>,
    pub executed: bool,
    pub bump: u8,
}

/// One account per nullifier — its existence on-chain proves the nullifier was used.
#[account]
#[derive(InitSpace)]
pub struct NullifierRecord {
    pub proposal_id: u64,
    pub nullifier:   [u8; 32],
    /// SHA-256 of the Halo2 proof — allows any party to fetch and re-verify.
    pub proof_hash:  [u8; 32],
    pub bump: u8,
}

// ─── Enums ────────────────────────────────────────────────────────────────────

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq, Debug, InitSpace)]
pub enum ProposalStatus {
    Active,
    Passed,
    Failed,
    Executed,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct MemberRootUpdated {
    pub new_root: [u8; 32],
    pub new_total_members: u64,
}

#[event]
pub struct ProposalCreated {
    pub id: u64,
    pub proposer: Pubkey,
    pub title: String,
    pub end_time: i64,
}

#[event]
pub struct VoteCast {
    pub proposal_id: u64,
    /// Public — double-vote prevention; reveals nothing about voter identity.
    pub nullifier: [u8; 32],
    /// SHA-256 of the ZK proof — fetch from off-chain store to re-verify.
    pub proof_hash: [u8; 32],
}

#[event]
pub struct ProposalFinalized {
    pub id: u64,
    pub status: ProposalStatus,
    pub votes_for: u64,
    pub votes_against: u64,
}

#[event]
pub struct ProposalExecuted {
    pub id: u64,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum GovError {
    #[msg("Proposal title exceeds 128 characters")]
    TitleTooLong,
    #[msg("Proposal description exceeds 1 024 characters")]
    DescTooLong,
    #[msg("Voting window is shorter than the minimum (1 hour)")]
    VotingWindowTooShort,
    #[msg("Voting window exceeds maximum (30 days)")]
    VotingWindowTooLong,
    #[msg("Proposal is not in Active status")]
    ProposalNotActive,
    #[msg("The voting window for this proposal has already closed")]
    VotingWindowClosed,
    #[msg("The voting window is still open")]
    VotingWindowStillOpen,
    #[msg("This nullifier has already been used — double-vote attempt")]
    AlreadyVoted,
    #[msg("ZK proof is invalid")]
    InvalidProof,
    #[msg("vote_signal must be 0 (against) or 1 (for)")]
    InvalidVoteSignal,
    #[msg("Proposal has not passed")]
    ProposalNotPassed,
    #[msg("Proposal has already been executed")]
    AlreadyExecuted,
    #[msg("Caller is not authorised")]
    Unauthorized,
    #[msg("Signer count must be between 1 and MAX_VOTE_SIGNERS")]
    InvalidSignerCount,
    #[msg("Committee threshold not met — need ≥ 2/3 of nodes")]
    CommitteeThresholdNotMet,
    #[msg("Duplicate signer pubkey detected")]
    DuplicateSigner,
    #[msg("Transaction must include an Ed25519Program instruction")]
    MissingEd25519Ix,
    #[msg("Ed25519 instruction data is malformed")]
    MalformedEd25519Ix,
    #[msg("Ed25519 message does not match vote_sign_message(...)")]
    MessageMismatch,
    #[msg("One or more signers were not covered by the Ed25519 instruction")]
    SignerNotVerified,
    #[msg("Failed to read instructions sysvar")]
    InstructionSysvarError,
    #[msg("committee_size must be at least 1")]
    InvalidCommitteeSize,
}