use anchor_lang::{
    prelude::*, 
    solana_program::clock, 
    solana_program::hash,
    solana_program::sysvar::instructions::{ID as IX_ID, load_instruction_at_checked},
    solana_program::instruction::Instruction
};
use anchor_spl::token::{
    self, /*CloseAccount, */ Mint, Token,
    TokenAccount, Transfer
};
use crate::utils::utils::verify_ed25519_ix;

#[path = "./utils.rs"]
mod utils;
#[path = "./txutils.rs"]
mod txutils;

declare_id!("AxE1wvXnceDMrappeMJWyh72YeEWaxcd984aVDSVBM1E");

pub fn now_ts() -> Result<u64> {
    Ok(clock::Clock::get()?.unix_timestamp.try_into().unwrap())
}

static KIND_LN: u8 = 0;
static KIND_CHAIN: u8 = 1;
static KIND_CHAIN_NONCED: u8 = 2;

pub mod verification_utils {
    use super::*;

    pub fn check_claim(account: &Box<Account<EscrowState>>, ix_sysvar: &AccountInfo, secret: &Vec<u8>) -> Result<()> {
        let current_timestamp = now_ts()?;

        require!(
            account.expiry >= current_timestamp,
            SwapErrorCode::AlreadyExpired
        );

        if account.kind==KIND_LN {
            let hash_result = hash::hash(&secret).to_bytes();

            require!(
                hash_result == account.hash,
                SwapErrorCode::InvalidSecret
            );
        }

        if account.kind==KIND_CHAIN || account.kind==KIND_CHAIN_NONCED {
            let output_index = u32::from_le_bytes(secret[0..4].try_into().unwrap());
            let tx = txutils::txutils::parse_transaction(&secret[4..]);
            let tx_output = &tx.tx_out[output_index as usize];

            let mut output_data = Vec::with_capacity(8+8+tx_output.script.len());
            output_data.extend_from_slice(&u64::to_le_bytes(account.nonce));
            output_data.extend_from_slice(&u64::to_le_bytes(tx_output.value));
            output_data.extend_from_slice(tx_output.script);

            let hash_result = hash::hash(&output_data).to_bytes();

            require!(
                hash_result == account.hash,
                SwapErrorCode::InvalidSecret
            );

            if account.kind==KIND_CHAIN_NONCED {
                let n_sequence = tx.tx_in[0].sequence & 0x00FFFFFF;
                for input in tx.tx_in.iter() {
                    require!(
                        n_sequence == (input.sequence & 0x00FFFFFF) && (input.sequence & 0xF0000000) == 0xF0000000,
                        SwapErrorCode::InvalidnSequence
                    );
                }
                let n_sequence_u64: u64 = (n_sequence as u64) & 0x00FFFFFF;
                let locktime_u64: u64 = (tx.locktime as u64)-500000000;
                let tx_nonce: u64 = (locktime_u64<<24) | n_sequence_u64;
                require!(
                    tx_nonce == account.nonce,
                    SwapErrorCode::InvalidNonce
                );
            }

            let ix: Instruction = load_instruction_at_checked(0, ix_sysvar)?;
            let verification_result = txutils::txutils::verify_tx_ix(&ix, &tx.hash, account.confirmations as u32)?;

            require!(
                verification_result != 10,
                SwapErrorCode::InvalidTxVerifyProgramId
            );
            require!(
                verification_result != 1,
                SwapErrorCode::InvalidTxVerifyIx
            );
            require!(
                verification_result != 2,
                SwapErrorCode::InvalidTxVerifyTxid
            );
            require!(
                verification_result != 3,
                SwapErrorCode::InvalidTxVerifyConfirmations
            );
        }

        Ok(())
    }
}

#[program]
pub mod test_anchor {
    use super::*;

    const AUTHORITY_SEED: &[u8] = b"authority";

    //Deposit to program balance
    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
    ) -> Result<()> {
        token::transfer(
            ctx.accounts.into_transfer_to_pda_context(),
            amount,
        )?;
        
        ctx.accounts.user_data.amount += amount;

        Ok(())
    }

    //Withdraw from program balance
    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
    ) -> Result<()> {
        let (_vault_authority, vault_authority_bump) =
            Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
        let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

        if amount>0 {
            token::transfer(
                ctx.accounts
                    .into_transfer_to_initializer_context()
                    .with_signer(&[&authority_seeds[..]]),
                amount,
            )?;
        }

        ctx.accounts.user_data.amount -= amount;

        Ok(())
    }

    //Initialize from wallet balance
    pub fn offerer_initialize_pay_in(
        ctx: Context<InitializePayIn>,
        initializer_amount: u64,
        expiry: u64,
        hash: [u8; 32],
        kind: u8,
        confirmations: u16,
        nonce: u64
    ) -> Result<()> {
        require!(
            kind <= 2,
            SwapErrorCode::KindUnknown
        );

        ctx.accounts.escrow_state.kind = kind;

        if kind==KIND_CHAIN_NONCED {
            ctx.accounts.escrow_state.nonce = nonce;
        }

        ctx.accounts.escrow_state.confirmations = confirmations;
        ctx.accounts.escrow_state.pay_in = true;
        ctx.accounts.escrow_state.initializer_key = *ctx.accounts.initializer.key;

        ctx.accounts.escrow_state.offerer = *ctx.accounts.initializer.key;
        ctx.accounts.escrow_state.claimer = *ctx.accounts.claimer.to_account_info().key;

        ctx.accounts.escrow_state.initializer_deposit_token_account = *ctx
            .accounts
            .initializer_deposit_token_account
            .to_account_info()
            .key;
        ctx.accounts.escrow_state.initializer_amount = initializer_amount;
        ctx.accounts.escrow_state.mint = *ctx.accounts.mint.to_account_info().key;

        ctx.accounts.escrow_state.expiry = expiry;
        ctx.accounts.escrow_state.hash = hash;

        token::transfer(
            ctx.accounts.into_transfer_to_pda_context(),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        emit!(InitializeEvent {
            hash: ctx.accounts.escrow_state.hash,
            nonce: ctx.accounts.escrow_state.nonce,
            kind: kind
        });

        Ok(())
    }

    //Initialize from program balance
    pub fn offerer_initialize(
        ctx: Context<Initialize>,
        nonce: u64,
        initializer_amount: u64,
        expiry: u64,
        hash: [u8; 32],
        kind: u8,
        confirmations: u16,
        escrow_nonce: u64,
        auth_expiry: u64,
        signature: [u8; 64]
    ) -> Result<()> {
        require!(
            kind <= 2,
            SwapErrorCode::KindUnknown
        );

        require!(
            auth_expiry > now_ts()?,
            SwapErrorCode::AlreadyExpired
        );

        require!(
            nonce > ctx.accounts.user_data.nonce,
            SwapErrorCode::AlreadyExpired
        );

        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        let mut msg = Vec::with_capacity(10+8+32+32+8+8+32+1+2+8);

        msg.extend_from_slice(b"initialize");
        msg.extend_from_slice(&nonce.to_le_bytes());
        msg.extend_from_slice(&ctx.accounts.mint.to_account_info().key.to_bytes());
        msg.extend_from_slice(&ctx.accounts.initializer.to_account_info().key.to_bytes());
        msg.extend_from_slice(&initializer_amount.to_le_bytes());
        msg.extend_from_slice(&expiry.to_le_bytes());
        msg.extend_from_slice(&hash);
        msg.extend_from_slice(&kind.to_le_bytes());
        msg.extend_from_slice(&confirmations.to_le_bytes());
        msg.extend_from_slice(&auth_expiry.to_le_bytes());

        // Check that ix is what we expect to have been sent
        let result = verify_ed25519_ix(&ix, &ctx.accounts.offerer.to_account_info().key.to_bytes(), &msg, &signature);

        require!(
            result == 0,
            SwapErrorCode::SignatureVerificationFailed
        );

        ctx.accounts.escrow_state.kind = kind;

        if kind==KIND_CHAIN_NONCED {
            ctx.accounts.escrow_state.nonce = escrow_nonce;
        }

        ctx.accounts.escrow_state.confirmations = confirmations;
        ctx.accounts.escrow_state.pay_in = false;
        ctx.accounts.escrow_state.initializer_key = *ctx.accounts.initializer.key;

        ctx.accounts.escrow_state.offerer = *ctx.accounts.offerer.to_account_info().key;
        ctx.accounts.escrow_state.claimer = *ctx.accounts.claimer.to_account_info().key;

        ctx.accounts.escrow_state.initializer_amount = initializer_amount;
        ctx.accounts.escrow_state.mint = *ctx.accounts.mint.to_account_info().key;

        ctx.accounts.escrow_state.expiry = expiry;
        ctx.accounts.escrow_state.hash = hash;

        ctx.accounts.user_data.amount -= initializer_amount;
        ctx.accounts.user_data.nonce = nonce;

        emit!(InitializeEvent {
            hash: ctx.accounts.escrow_state.hash,
            nonce: ctx.accounts.escrow_state.nonce,
            kind: kind
        });

        Ok(())
    }

    //Refund back to offerer once enough time has passed (withdrawing the tokens from the contract)
    pub fn offerer_refund_pay_out(ctx: Context<RefundPayOut>) -> Result<()> {
        require!(
            ctx.accounts.escrow_state.expiry < now_ts()?,
            SwapErrorCode::NotExpiredYet
        );

        let (_vault_authority, vault_authority_bump) =
            Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
        let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

        token::transfer(
            ctx.accounts
                .into_transfer_to_initializer_context()
                .with_signer(&[&authority_seeds[..]]),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        emit!(RefundEvent {
            hash: ctx.accounts.escrow_state.hash
        });

        Ok(())
    }

    //Refund back to offerer once enough time has passed (withdrawing the tokens from the contract)
    pub fn offerer_refund(ctx: Context<Refund>) -> Result<()> {
        require!(
            ctx.accounts.escrow_state.expiry < now_ts()?,
            SwapErrorCode::NotExpiredYet
        );

        ctx.accounts.user_data.amount += ctx.accounts.escrow_state.initializer_amount;

        emit!(RefundEvent {
            hash: ctx.accounts.escrow_state.hash
        });

        Ok(())
    }

    //Refund back to offerer with a valid refund signature from claimer
    pub fn offerer_refund_with_signature_pay_out(
        ctx: Context<RefundWithSignaturePayOut>,
        auth_expiry: u64,
        signature: [u8; 64]
    ) -> Result<()> {

        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        let mut msg = Vec::with_capacity(6+8+8+32+8);

        msg.extend_from_slice(b"refund");
        msg.extend_from_slice(&ctx.accounts.escrow_state.initializer_amount.to_le_bytes());
        msg.extend_from_slice(&ctx.accounts.escrow_state.expiry.to_le_bytes());
        msg.extend_from_slice(&ctx.accounts.escrow_state.hash);
        msg.extend_from_slice(&auth_expiry.to_le_bytes());

        // Check that ix is what we expect to have been sent
        let result = verify_ed25519_ix(&ix, &ctx.accounts.claimer.key.to_bytes(), &msg, &signature);

        require!(
            result == 0,
            SwapErrorCode::SignatureVerificationFailed
        );

        let (_vault_authority, vault_authority_bump) =
            Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
        let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

        token::transfer(
            ctx.accounts
                .into_transfer_to_initializer_context()
                .with_signer(&[&authority_seeds[..]]),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        emit!(RefundEvent {
            hash: ctx.accounts.escrow_state.hash
        });

        Ok(())
    }

    //Refund back to offerer with a valid refund signature from claimer
    pub fn offerer_refund_with_signature(
        ctx: Context<RefundWithSignature>,
        auth_expiry: u64,
        signature: [u8; 64]
    ) -> Result<()> {

        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        let mut msg = Vec::with_capacity(6+8+8+32+8);

        msg.extend_from_slice(b"refund");
        msg.extend_from_slice(&ctx.accounts.escrow_state.initializer_amount.to_le_bytes());
        msg.extend_from_slice(&ctx.accounts.escrow_state.expiry.to_le_bytes());
        msg.extend_from_slice(&ctx.accounts.escrow_state.hash);
        msg.extend_from_slice(&auth_expiry.to_le_bytes());

        // Check that ix is what we expect to have been sent
        let result = verify_ed25519_ix(&ix, &ctx.accounts.claimer.key.to_bytes(), &msg, &signature);

        require!(
            result == 0,
            SwapErrorCode::SignatureVerificationFailed
        );
        
        ctx.accounts.user_data.amount += ctx.accounts.escrow_state.initializer_amount;

        emit!(RefundEvent {
            hash: ctx.accounts.escrow_state.hash
        });

        Ok(())
    }

    //Refund back to payer
    // pub fn claimer_refund_payer(ctx: Context<RefundPayer>) -> Result<()> {
    //     let (_vault_authority, vault_authority_bump) =
    //         Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
    //     let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

    //     token::transfer(
    //         ctx.accounts
    //             .into_transfer_to_initializer_context()
    //             .with_signer(&[&authority_seeds[..]]),
    //         ctx.accounts.escrow_state.initializer_amount,
    //     )?;

    //     emit!(RefundEvent {
    //         hash: ctx.accounts.escrow_state.hash
    //     });
    //     //msg!("REFUND Hash: {}", hex::encode(ctx.accounts.escrow_state.hash));

    //     // token::close_account(
    //     //     ctx.accounts
    //     //         .into_close_context()
    //     //         .with_signer(&[&authority_seeds[..]]),
    //     // )?;

    //     Ok(())
    // }

    //Claim the swap
    pub fn claimer_claim_pay_out(ctx: Context<ClaimPayOut>, secret: Vec<u8>) -> Result<()> {
        verification_utils::check_claim(&ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &secret)?;

        let (_vault_authority, vault_authority_bump) =
            Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
        let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

        token::transfer(
            ctx.accounts
                .into_transfer_to_claimer_context()
                .with_signer(&[&authority_seeds[..]]),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        emit!(ClaimEvent {
            hash: ctx.accounts.escrow_state.hash,
            secret: secret
        });

        Ok(())
    }

    //Claim the swap
    pub fn claimer_claim(ctx: Context<Claim>, secret: Vec<u8>) -> Result<()> {
        verification_utils::check_claim(&ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &secret)?;

        ctx.accounts.user_data.amount += ctx.accounts.escrow_state.initializer_amount;

        emit!(ClaimEvent {
            hash: ctx.accounts.escrow_state.hash,
            secret: secret
        });

        Ok(())
    }

    //Claim the swap
    pub fn claimer_claim_pay_out_with_ext_data(ctx: Context<ClaimPayOutWithExtData>, reversed_tx_id: [u8; 32]) -> Result<()> {
        let (data_account_key, _block_header_bump) = Pubkey::find_program_address(&[b"data", &reversed_tx_id, ctx.accounts.claimer.to_account_info().key.as_ref()], &ctx.program_id);

        require!(
            data_account_key == *ctx.accounts.data.to_account_info().key,
            SwapErrorCode::InvalidDataAccount
        );

        verification_utils::check_claim(&ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &ctx.accounts.data.data)?;

        let (_vault_authority, vault_authority_bump) =
            Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
        let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

        token::transfer(
            ctx.accounts
                .into_transfer_to_claimer_context()
                .with_signer(&[&authority_seeds[..]]),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        emit!(ClaimEvent {
            hash: ctx.accounts.escrow_state.hash,
            secret: [0; 32].to_vec()
        });

        Ok(())
    }

    //Claim the swap
    pub fn claimer_claim_with_ext_data(ctx: Context<ClaimWithExtData>, reversed_tx_id: [u8; 32]) -> Result<()> {
        let (data_account_key, _block_header_bump) = Pubkey::find_program_address(&[b"data", &reversed_tx_id, ctx.accounts.claimer.to_account_info().key.as_ref()], &ctx.program_id);

        require!(
            data_account_key == *ctx.accounts.data.to_account_info().key,
            SwapErrorCode::InvalidDataAccount
        );

        verification_utils::check_claim(&ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &ctx.accounts.data.data)?;

        ctx.accounts.user_data.amount += ctx.accounts.escrow_state.initializer_amount;

        emit!(ClaimEvent {
            hash: ctx.accounts.escrow_state.hash,
            secret: [0; 32].to_vec()
        });

        Ok(())
    }

    pub fn write_data(ctx: Context<WriteData>, _reversed_tx_id: [u8; 32], size: u32, data: Vec<u8>) -> Result<()> {
        ctx.accounts.data.data.extend_from_slice(&data);

        Ok(())
    }

    pub fn close_data(_ctx: Context<CloseData>, _reversed_tx_id: [u8; 32]) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct Deposit<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: Signer<'info>,

    //Account of the token for initializer
    #[account(
         mut,
         constraint = initializer_deposit_token_account.amount >= amount
    )]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,

    //Account holding the tokens
    #[account(
        init_if_needed,
        seeds = [b"uservault".as_ref(), initializer.to_account_info().key.as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        payer = initializer,
        space = UserAccount::space()
    )]
    pub user_data: Account<'info, UserAccount>,

    //Account holding the tokens
    #[account(
        init_if_needed,
        seeds = [b"vault".as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        payer = initializer,
        token::mint = mint,
        token::authority = vault_authority,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account 
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    
    //Required data
    pub mint: Account<'info, Mint>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Program<'info, Token>
}

#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct Withdraw<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: Signer<'info>,

    //Account of the token for initializer
    #[account(mut)]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,

    //Account holding the tokens
    #[account(
        mut,
        seeds = [b"uservault".as_ref(), initializer.to_account_info().key.as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        constraint = user_data.amount >= amount
    )]
    pub user_data: Account<'info, UserAccount>,

    //Account holding the tokens
    #[account(
        mut,
        seeds = [b"vault".as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        token::mint = mint,
        token::authority = vault_authority,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,

    //Required data
    pub mint: Account<'info, Mint>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Program<'info, Token>
}

#[derive(Accounts)]
#[instruction(initializer_amount: u64, expiry: u64, escrow_seed: [u8; 32], kind: u8, confirmations: u16, escrow_nonce: u64)]
pub struct InitializePayIn<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: Signer<'info>,
    //Account of the token for initializer
    #[account(
         mut,
         constraint = initializer_deposit_token_account.amount >= initializer_amount
    )]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: AccountInfo<'info>,

    //Data storage account
    #[account(
        init,
        seeds = [b"state".as_ref(), escrow_seed.as_ref()],
        bump,
        payer = initializer,
        space = EscrowState::space()
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    //Account holding the tokens
    #[account(
        init_if_needed,
        seeds = [b"vault".as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        payer = initializer,
        token::mint = mint,
        token::authority = vault_authority,
    )]
    pub vault: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,

    //Required data
    pub mint: Account<'info, Mint>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Program<'info, Token>
}

#[derive(Accounts)]
#[instruction(nonce: u64, initializer_amount: u64, expiry: u64, escrow_seed: [u8; 32], kind: u8, confirmations: u16, auth_expiry: u64, signature: [u8; 64], escrow_nonce: u64)]
pub struct Initialize<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: Signer<'info>,

    //Account of the token for initializer
    #[account(
        mut,
        seeds = [b"uservault".as_ref(), offerer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        constraint = user_data.amount >= initializer_amount
    )]
    pub user_data: Account<'info, UserAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub offerer: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: AccountInfo<'info>,
    
    //Data storage account
    #[account(
        init,
        seeds = [b"state".as_ref(), escrow_seed.as_ref()],
        bump,
        payer = initializer,
        space = EscrowState::space()
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    //Required data
    pub mint: Account<'info, Mint>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    
    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>
}

#[derive(Accounts)]
pub struct RefundPayOut<'info> {
    #[account(mut)]
    pub offerer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Account<'info, TokenAccount>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    
    #[account(mut)]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = escrow_state.initializer_key == *initializer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.pay_in,
        constraint = escrow_state.initializer_deposit_token_account == *initializer_deposit_token_account.to_account_info().key,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Program<'info, Token>,
}


#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(mut)]
    pub offerer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    //Account of the token for initializer
    #[account(
        mut,
        seeds = [b"uservault".as_ref(), offerer.key.as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub user_data: Account<'info, UserAccount>,
    
    #[account(
        mut,
        constraint = escrow_state.initializer_key == *initializer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = !escrow_state.pay_in,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,
}

#[derive(Accounts)]
pub struct RefundWithSignaturePayOut<'info> {
    #[account(mut)]
    pub offerer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: AccountInfo<'info>,

    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Account<'info, TokenAccount>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    
    #[account(mut)]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = escrow_state.initializer_key == *initializer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = escrow_state.pay_in,
        constraint = escrow_state.initializer_deposit_token_account == *initializer_deposit_token_account.to_account_info().key,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Program<'info, Token>,
    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>
}

#[derive(Accounts)]
pub struct RefundWithSignature<'info> {
    #[account(mut)]
    pub offerer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: AccountInfo<'info>,

    //Account of the token for initializer
    #[account(
        mut,
        seeds = [b"uservault".as_ref(), offerer.key.as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub user_data: Account<'info, UserAccount>,
    
    #[account(
        mut,
        constraint = escrow_state.initializer_key == *initializer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = !escrow_state.pay_in,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>
}

#[derive(Accounts)]
pub struct ClaimPayOut<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: Signer<'info>,

    #[account(mut)]
    pub claimer_receive_token_account: Box<Account<'info, TokenAccount>>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub offerer: AccountInfo<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.initializer_key == *initializer.key,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,
    
    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Box<Account<'info, TokenAccount>>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Program<'info, Token>,
    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>
}

#[derive(Accounts)]
pub struct Claim<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub claimer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub offerer: AccountInfo<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    //Account of the token for initializer
    #[account(
        init_if_needed,
        seeds = [b"uservault".as_ref(), claimer.key.as_ref(), escrow_state.mint.as_ref()],
        bump,
        payer = claimer,
        space = UserAccount::space()
    )]
    pub user_data: Account<'info, UserAccount>,

    #[account(
        mut,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.initializer_key == *initializer.key,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub system_program: Program<'info, System>,
    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>
}

#[derive(Accounts)]
pub struct ClaimPayOutWithExtData<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: Signer<'info>,

    #[account(mut)]
    pub claimer_receive_token_account: Box<Account<'info, TokenAccount>>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub offerer: AccountInfo<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.initializer_key == *initializer.key,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,
    
    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Box<Account<'info, TokenAccount>>,
    
    #[account(
        mut,
        close = claimer
    )]
    pub data: Box<Account<'info, Data>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Program<'info, Token>,
    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>
}

#[derive(Accounts)]
pub struct ClaimWithExtData<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub claimer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub offerer: AccountInfo<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    //Account of the token for initializer
    #[account(
        init_if_needed,
        seeds = [b"uservault".as_ref(), claimer.key.as_ref(), escrow_state.mint.as_ref()],
        bump,
        payer = claimer,
        space = UserAccount::space()
    )]
    pub user_data: Account<'info, UserAccount>,

    #[account(
        mut,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.initializer_key == *initializer.key,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,
    
    #[account(
        mut,
        close = claimer
    )]
    pub data: Box<Account<'info, Data>>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub system_program: Program<'info, System>,
    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>
}

#[derive(Accounts)]
#[instruction(reversed_tx_id: [u8; 32], size: u32, start_index: u32, new_data: Vec<u8>)]
pub struct WriteData<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub signer: Signer<'info>,

    //Data storage account
    #[account(
        init_if_needed,
        seeds = [b"data".as_ref(), reversed_tx_id.as_ref(), signer.to_account_info().key.as_ref()],
        bump,
        payer = signer,
        space = Data::space(size as usize)
    )]
    pub data: Box<Account<'info, Data>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub system_program: Program<'info, System>
}

#[derive(Accounts)]
#[instruction(reversed_tx_id: [u8; 32])]
pub struct CloseData<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub signer: Signer<'info>,

    //Data storage account
    #[account(
        mut,
        seeds = [b"data".as_ref(), reversed_tx_id.as_ref(), signer.to_account_info().key.as_ref()],
        bump,
        close = signer
    )]
    pub data: Box<Account<'info, Data>>
}

#[account]
pub struct EscrowState {
    pub kind: u8,
    pub confirmations: u16,
    pub nonce: u64,
    pub hash: [u8; 32],

    pub initializer_key: Pubkey,
    pub pay_in: bool,
    
    pub offerer: Pubkey,
    pub claimer: Pubkey,
    
    pub initializer_deposit_token_account: Pubkey,
    pub initializer_amount: u64,
    pub mint: Pubkey,
    pub expiry: u64
}

#[account]
pub struct UserAccount {
    pub nonce: u64,
    pub amount: u64
}

#[account]
pub struct Data {
    pub data: Vec<u8>,
}

impl EscrowState {
    pub fn space() -> usize {
        8 + 1 + 2 + 8 + 192 + 8 + 8 + 1
    }
}

impl UserAccount {
    pub fn space() -> usize {
        8 + 8 + 8
    }
}

impl Data {
    pub fn space(size: usize) -> usize {
        8 + 4 + size
    }
}

impl<'info> Deposit<'info> {
    fn into_transfer_to_pda_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.initializer_deposit_token_account.to_account_info(),
            to: self.vault.to_account_info(),
            authority: self.initializer.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> Withdraw<'info> {
    fn into_transfer_to_initializer_context(
        &self,
    ) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.to_account_info(),
            to: self.initializer_deposit_token_account.to_account_info(),
            authority: self.vault_authority.clone(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> InitializePayIn<'info> {
    fn into_transfer_to_pda_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.initializer_deposit_token_account.to_account_info(),
            to: self.vault.to_account_info(),
            authority: self.initializer.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> RefundPayOut<'info> {
    fn into_transfer_to_initializer_context(
        &self,
    ) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.to_account_info(),
            to: self.initializer_deposit_token_account.to_account_info(),
            authority: self.vault_authority.clone(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> RefundWithSignaturePayOut<'info> {
    fn into_transfer_to_initializer_context(
        &self,
    ) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.to_account_info(),
            to: self.initializer_deposit_token_account.to_account_info(),
            authority: self.vault_authority.clone(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> ClaimPayOut<'info> {
    fn into_transfer_to_claimer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.to_account_info(),
            to: self.claimer_receive_token_account.to_account_info(),
            authority: self.vault_authority.clone(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> ClaimPayOutWithExtData<'info> {
    fn into_transfer_to_claimer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.to_account_info(),
            to: self.claimer_receive_token_account.to_account_info(),
            authority: self.vault_authority.clone(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

#[event]
pub struct InitializeEvent {
    pub hash: [u8; 32],
    pub nonce: u64,
    pub kind: u8
}

#[event]
pub struct RefundEvent {
    pub hash: [u8; 32]
}

#[event]
pub struct ClaimEvent {
    pub hash: [u8; 32],
    pub secret: Vec<u8>
}

#[error_code]
pub enum SwapErrorCode {
    #[msg("Request not expired yet.")]
    NotExpiredYet,
    #[msg("Request already expired.")]
    AlreadyExpired,
    #[msg("Invalid secret provided.")]
    InvalidSecret,
    #[msg("Not enough funds.")]
    InsufficientFunds,
    #[msg("Signature verification failed.")]
    SignatureVerificationFailed,
    #[msg("Unknown type of the contract.")]
    KindUnknown,
    #[msg("Invalid program id for transaction verification.")]
    InvalidTxVerifyProgramId,
    #[msg("Invalid instruction for transaction verification.")]
    InvalidTxVerifyIx,
    #[msg("Invalid txid for transaction verification.")]
    InvalidTxVerifyTxid,
    #[msg("Invalid confirmations for transaction verification.")]
    InvalidTxVerifyConfirmations,
    #[msg("Invalid nSequence in tx inputs")]
    InvalidnSequence,
    #[msg("Invalid nonce used")]
    InvalidNonce,
    #[msg("Invalid data account")]
    InvalidDataAccount
}