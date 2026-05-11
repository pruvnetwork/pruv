//! pruv-registry — dApp registration, code-hash tracking and subscription management.
//!
//! Any dApp on Solana can register here by paying a subscription fee (in SOL).
//! Once registered, pruv nodes continuously monitor the dApp's on-chain bytecode hash.
//! If the hash changes unexpectedly, the attestation is revoked automatically.

use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

// ─── Constants ────────────────────────────────────────────────────────────────

/// Monthly subscription cost in lamports (0.1 SOL).
pub const SUBSCRIPTION_FEE_LAMPORTS: u64 = 100_000_000;

/// Number of seconds in 30 days.
pub const SUBSCRIPTION_DURATION_SECS: i64 = 30 * 24 * 60 * 60;

/// Maximum length of a dApp name string.
pub const MAX_NAME_LEN: usize = 64;

/// Maximum length of a dApp website/doc URI.
pub const MAX_URI_LEN: usize = 200;

// ─── Program ──────────────────────────────────────────────────────────────────

#[program]
pub mod pruv_registry {
    use super::*;

    /// Register a new dApp and pay the first subscription period.
    ///
    /// The `program_hash` must be the SHA-256 hash of the dApp's current on-chain
    /// executable bytecode. pruv nodes will verify this on every epoch.
    pub fn register_dapp(
        ctx: Context<RegisterDapp>,
        name: String,
        uri: String,
        program_hash: [u8; 32],
    ) -> Result<()> {
        require!(name.len() <= MAX_NAME_LEN, RegistryError::NameTooLong);
        require!(uri.len() <= MAX_URI_LEN, RegistryError::UriTooLong);

        let clock = Clock::get()?;
        let entry = &mut ctx.accounts.dapp_entry;

        entry.owner = ctx.accounts.owner.key();
        entry.program_id = ctx.accounts.dapp_program.key();
        entry.name = name;
        entry.uri = uri;
        entry.program_hash = program_hash;
        entry.status = DAppStatus::Active;
        entry.attestation_count = 0;
        entry.registered_at = clock.unix_timestamp;
        entry.subscription_expiry = clock.unix_timestamp + SUBSCRIPTION_DURATION_SECS;
        entry.total_fees_paid = SUBSCRIPTION_FEE_LAMPORTS;
        entry.bump = ctx.bumps.dapp_entry;

        // Transfer subscription fee to the protocol treasury.
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.owner.to_account_info(),
                    to: ctx.accounts.treasury.to_account_info(),
                },
            ),
            SUBSCRIPTION_FEE_LAMPORTS,
        )?;

        emit!(DAppRegistered {
            program_id: entry.program_id,
            owner: entry.owner,
            name: entry.name.clone(),
            program_hash,
            subscription_expiry: entry.subscription_expiry,
        });

        msg!(
            "dApp registered: {} (program: {})",
            entry.name,
            entry.program_id
        );
        Ok(())
    }

    /// Renew the subscription for another 30-day period.
    pub fn renew_subscription(ctx: Context<RenewSubscription>) -> Result<()> {
        let clock = Clock::get()?;
        let entry = &mut ctx.accounts.dapp_entry;

        require!(
            entry.status != DAppStatus::Revoked,
            RegistryError::DAppRevoked
        );

        // If already expired, renew from now; otherwise extend from current expiry.
        let base = entry.subscription_expiry.max(clock.unix_timestamp);
        entry.subscription_expiry = base + SUBSCRIPTION_DURATION_SECS;
        entry.total_fees_paid = entry
            .total_fees_paid
            .saturating_add(SUBSCRIPTION_FEE_LAMPORTS);

        if entry.status == DAppStatus::Suspended {
            entry.status = DAppStatus::Active;
        }

        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.treasury.to_account_info(),
                },
            ),
            SUBSCRIPTION_FEE_LAMPORTS,
        )?;

        emit!(SubscriptionRenewed {
            program_id: entry.program_id,
            new_expiry: entry.subscription_expiry,
        });

        Ok(())
    }

    /// Owner-initiated hash update (e.g., after an intentional, announced upgrade).
    ///
    /// This does NOT revoke the attestation immediately; it queues a re-verification
    /// cycle. The hash change is emitted so nodes can re-verify within one epoch.
    pub fn update_program_hash(
        ctx: Context<UpdateProgramHash>,
        new_hash: [u8; 32],
    ) -> Result<()> {
        let entry = &mut ctx.accounts.dapp_entry;

        require!(
            entry.status == DAppStatus::Active,
            RegistryError::DAppNotActive
        );

        let old_hash = entry.program_hash;
        entry.program_hash = new_hash;

        emit!(ProgramHashUpdated {
            program_id: entry.program_id,
            old_hash,
            new_hash,
        });

        msg!("Program hash updated for {}", entry.program_id);
        Ok(())
    }

    /// Called by a pruv node (via CPI from pruv-attestation) when it detects
    /// that a dApp's on-chain bytecode no longer matches the registered hash.
    pub fn suspend_dapp(ctx: Context<AdminAction>) -> Result<()> {
        let entry = &mut ctx.accounts.dapp_entry;
        entry.status = DAppStatus::Suspended;

        emit!(DAppSuspended {
            program_id: entry.program_id,
            reason: SuspendReason::HashMismatch,
        });

        Ok(())
    }

    /// Permanently revoke a dApp (DAO governance decision).
    pub fn revoke_dapp(ctx: Context<AdminAction>) -> Result<()> {
        let entry = &mut ctx.accounts.dapp_entry;
        entry.status = DAppStatus::Revoked;

        emit!(DAppSuspended {
            program_id: entry.program_id,
            reason: SuspendReason::GovernanceDecision,
        });

        Ok(())
    }

    /// Reinstate a previously suspended dApp after the owner resolves the issue.
    pub fn reinstate_dapp(
        ctx: Context<ReinstateDapp>,
        verified_hash: [u8; 32],
    ) -> Result<()> {
        let entry = &mut ctx.accounts.dapp_entry;

        require!(
            entry.status == DAppStatus::Suspended,
            RegistryError::NotSuspended
        );

        entry.program_hash = verified_hash;
        entry.status = DAppStatus::Active;

        emit!(ProgramHashUpdated {
            program_id: entry.program_id,
            old_hash: entry.program_hash,
            new_hash: verified_hash,
        });

        Ok(())
    }

    /// Initialise the singleton treasury PDA that collects protocol fees.
    pub fn init_treasury(ctx: Context<InitTreasury>) -> Result<()> {
        let treasury = &mut ctx.accounts.treasury_state;
        treasury.authority = ctx.accounts.authority.key();
        treasury.bump = ctx.bumps.treasury_state;
        msg!("Treasury initialised");
        Ok(())
    }

    /// Withdraw accumulated fees to the authority wallet (multisig in production).
    pub fn withdraw_fees(ctx: Context<WithdrawFees>, amount: u64) -> Result<()> {
        let treasury_lamports = ctx.accounts.treasury.lamports();
        // Keep rent-exempt minimum in the account.
        let rent = Rent::get()?;
        let min_balance = rent.minimum_balance(TreasuryState::INIT_SPACE);
        require!(
            treasury_lamports.saturating_sub(amount) >= min_balance,
            RegistryError::InsufficientFunds
        );

        **ctx.accounts.treasury.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;

        msg!("Withdrew {} lamports from treasury", amount);
        Ok(())
    }
}

// ─── Accounts ─────────────────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(name: String, uri: String)]
pub struct RegisterDapp<'info> {
    #[account(
        init,
        payer = owner,
        space = DAppEntry::INIT_SPACE,
        seeds = [b"dapp", dapp_program.key().as_ref()],
        bump,
    )]
    pub dapp_entry: Account<'info, DAppEntry>,

    /// CHECK: We only store the program's public key — no data access needed.
    pub dapp_program: UncheckedAccount<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    /// CHECK: PDA treasury — validated by seeds.
    #[account(
        mut,
        seeds = [b"treasury"],
        bump,
    )]
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RenewSubscription<'info> {
    #[account(
        mut,
        seeds = [b"dapp", dapp_entry.program_id.as_ref()],
        bump = dapp_entry.bump,
    )]
    pub dapp_entry: Account<'info, DAppEntry>,

    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: PDA treasury.
    #[account(
        mut,
        seeds = [b"treasury"],
        bump,
    )]
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateProgramHash<'info> {
    #[account(
        mut,
        seeds = [b"dapp", dapp_entry.program_id.as_ref()],
        bump = dapp_entry.bump,
        has_one = owner @ RegistryError::Unauthorized,
    )]
    pub dapp_entry: Account<'info, DAppEntry>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(
        mut,
        seeds = [b"dapp", dapp_entry.program_id.as_ref()],
        bump = dapp_entry.bump,
    )]
    pub dapp_entry: Account<'info, DAppEntry>,

    /// The pruv admin / attestation program (checked via treasury authority).
    #[account(
        seeds = [b"treasury"],
        bump = treasury_state.bump,
        has_one = authority @ RegistryError::Unauthorized,
    )]
    pub treasury_state: Account<'info, TreasuryState>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReinstateDapp<'info> {
    #[account(
        mut,
        seeds = [b"dapp", dapp_entry.program_id.as_ref()],
        bump = dapp_entry.bump,
        has_one = owner @ RegistryError::Unauthorized,
    )]
    pub dapp_entry: Account<'info, DAppEntry>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitTreasury<'info> {
    #[account(
        init,
        payer = authority,
        space = TreasuryState::INIT_SPACE,
        seeds = [b"treasury"],
        bump,
    )]
    pub treasury_state: Account<'info, TreasuryState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawFees<'info> {
    #[account(
        seeds = [b"treasury"],
        bump = treasury_state.bump,
        has_one = authority @ RegistryError::Unauthorized,
    )]
    pub treasury_state: Account<'info, TreasuryState>,

    /// CHECK: PDA lamport account — validated by seeds above.
    #[account(
        mut,
        seeds = [b"treasury"],
        bump = treasury_state.bump,
    )]
    pub treasury: UncheckedAccount<'info>,

    /// CHECK: Recipient wallet — authority decides where funds go.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
}

// ─── State ────────────────────────────────────────────────────────────────────

#[account]
#[derive(InitSpace)]
pub struct DAppEntry {
    /// The dApp's Solana program address.
    pub program_id: Pubkey,
    /// The wallet that registered this dApp.
    pub owner: Pubkey,
    /// Human-readable name (max 64 chars).
    #[max_len(64)]
    pub name: String,
    /// Documentation / website URI (max 200 chars).
    #[max_len(200)]
    pub uri: String,
    /// SHA-256 hash of the dApp's on-chain executable at registration time.
    pub program_hash: [u8; 32],
    /// Current trust status.
    pub status: DAppStatus,
    /// How many valid attestations have been issued for this dApp.
    pub attestation_count: u32,
    /// Unix timestamp of registration.
    pub registered_at: i64,
    /// Unix timestamp after which the subscription expires.
    pub subscription_expiry: i64,
    /// Cumulative SOL fees paid (in lamports).
    pub total_fees_paid: u64,
    /// PDA bump seed.
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct TreasuryState {
    /// Authority that can withdraw fees (should be a multisig in production).
    pub authority: Pubkey,
    pub bump: u8,
}

// ─── Enums ────────────────────────────────────────────────────────────────────

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq, InitSpace)]
pub enum DAppStatus {
    /// Subscription active, hash verified, attestation valid.
    Active,
    /// Hash mismatch detected or subscription expired — attestation paused.
    Suspended,
    /// Permanently removed by DAO governance.
    Revoked,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq, InitSpace)]
pub enum SuspendReason {
    HashMismatch,
    SubscriptionExpired,
    GovernanceDecision,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct DAppRegistered {
    pub program_id: Pubkey,
    pub owner: Pubkey,
    pub name: String,
    pub program_hash: [u8; 32],
    pub subscription_expiry: i64,
}

#[event]
pub struct SubscriptionRenewed {
    pub program_id: Pubkey,
    pub new_expiry: i64,
}

#[event]
pub struct ProgramHashUpdated {
    pub program_id: Pubkey,
    pub old_hash: [u8; 32],
    pub new_hash: [u8; 32],
}

#[event]
pub struct DAppSuspended {
    pub program_id: Pubkey,
    pub reason: SuspendReason,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum RegistryError {
    #[msg("dApp name exceeds maximum length of 64 characters")]
    NameTooLong,
    #[msg("URI exceeds maximum length of 200 characters")]
    UriTooLong,
    #[msg("Caller is not authorised to perform this action")]
    Unauthorized,
    #[msg("dApp has been permanently revoked and cannot be renewed")]
    DAppRevoked,
    #[msg("dApp is not in Active status")]
    DAppNotActive,
    #[msg("dApp is not in Suspended status")]
    NotSuspended,
    #[msg("Insufficient treasury balance after rent reserve")]
    InsufficientFunds,
}