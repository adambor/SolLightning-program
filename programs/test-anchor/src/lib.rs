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

use errors::*;
use state::*;
use events::*;

#[path = "./utils.rs"]
mod utils;
#[path = "./txutils.rs"]
mod txutils;

pub mod errors;
pub mod state;
pub mod events;


declare_id!("6k1kyCtt2hTYHqS8s1QdkhY7mfFdFeYWfrzLjrzQRyaX");

pub fn now_ts() -> Result<u64> {
    Ok(clock::Clock::get()?.unix_timestamp.try_into().unwrap())
}

static KIND_LN: u8 = 0;
static KIND_CHAIN: u8 = 1;
static KIND_CHAIN_NONCED: u8 = 2;

pub mod verification_utils {
    use super::*;

    pub fn check_claim(account: &Box<Account<EscrowState>>, ix_sysvar: &AccountInfo, secret: &[u8]) -> Result<()> {
        // let current_timestamp = now_ts()?;
        //
        // require!(
        //     account.expiry >= current_timestamp,
        //     SwapErrorCode::AlreadyExpired
        // );

        if account.kind==KIND_LN {
            let hash_result = hash::hash(&secret).to_bytes();

            require!(
                hash_result == account.hash,
                SwapErrorCode::InvalidSecret
            );
        }

        if account.kind==KIND_CHAIN || account.kind==KIND_CHAIN_NONCED {
            let output_index = u32::from_le_bytes(secret[0..4].try_into().unwrap());
            let opt_tx = txutils::txutils::verify_transaction(&secret[4..], output_index.into(), account.kind==KIND_CHAIN_NONCED);

            require!(
                opt_tx.is_some(),
                SwapErrorCode::InvalidnSequence
            );

            let tx = opt_tx.unwrap();

            require!(
                tx.out.is_some(),
                SwapErrorCode::InvalidVout
            );

            let tx_output = tx.out.unwrap();

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
                let n_sequence_u64: u64 = (tx.n_sequence as u64) & 0x00FFFFFF;
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


static AUTHORITY_SEED: &[u8] = b"authority";
static USER_DATA_SEED: &[u8] = b"uservault";

#[program]
pub mod test_anchor {
    use super::*;

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
        nonce: u64,
        initializer_amount: u64,
        expiry: u64,
        hash: [u8; 32],
        kind: u8,
        confirmations: u16,
        auth_expiry: u64,
        escrow_nonce: u64,
        pay_out: bool,
        txo_hash: [u8; 32] //Only for on-chain
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
            nonce > ctx.accounts.user_data.claim_nonce,
            SwapErrorCode::AlreadyExpired
        );
        
        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        let mut msg;
        if pay_out {
            msg = Vec::with_capacity(16+8+32+8+8+32+1+2+8+1+32);
        } else {
            msg = Vec::with_capacity(16+8+32+8+8+32+1+2+8+1);
        }

        msg.extend_from_slice(b"claim_initialize");
        msg.extend_from_slice(&nonce.to_le_bytes()); //Nonce
        msg.extend_from_slice(&ctx.accounts.mint.to_account_info().key.to_bytes()); //Token
        msg.extend_from_slice(&initializer_amount.to_le_bytes()); //Amount
        msg.extend_from_slice(&expiry.to_le_bytes()); //Expiry
        msg.extend_from_slice(&hash); //Hash
        msg.extend_from_slice(&kind.to_le_bytes()); //Kind
        msg.extend_from_slice(&confirmations.to_le_bytes()); //Confirmations
        msg.extend_from_slice(&auth_expiry.to_le_bytes()); //Expiry
        if pay_out {
            msg.push(1); //Payout
            msg.extend_from_slice(&ctx.accounts.claimer_token_account.to_account_info().key.to_bytes());
        } else {
            msg.push(0); //Payout
        }

        // Check that ix is what we expect to have been sent
        let result = verify_ed25519_ix(&ix, &ctx.accounts.claimer.to_account_info().key.to_bytes(), &msg);

        require!(
            result == 0,
            SwapErrorCode::SignatureVerificationFailed
        );

        ctx.accounts.escrow_state.kind = kind;

        if kind==KIND_CHAIN_NONCED {
            ctx.accounts.escrow_state.nonce = escrow_nonce;
        }

        ctx.accounts.escrow_state.confirmations = confirmations;
        ctx.accounts.escrow_state.pay_in = true;
        ctx.accounts.escrow_state.pay_out = pay_out;
        ctx.accounts.escrow_state.initializer_key = *ctx.accounts.initializer.key;

        ctx.accounts.escrow_state.offerer = *ctx.accounts.initializer.key;
        ctx.accounts.escrow_state.claimer = *ctx.accounts.claimer.to_account_info().key;
        ctx.accounts.escrow_state.claimer_token_account = *ctx.accounts.claimer_token_account.to_account_info().key;

        ctx.accounts.escrow_state.initializer_deposit_token_account = *ctx
            .accounts
            .initializer_deposit_token_account
            .to_account_info()
            .key;
        ctx.accounts.escrow_state.initializer_amount = initializer_amount;
        ctx.accounts.escrow_state.mint = *ctx.accounts.mint.to_account_info().key;

        ctx.accounts.escrow_state.expiry = expiry;
        ctx.accounts.escrow_state.hash = hash;

        ctx.accounts.user_data.claim_nonce = nonce;

        token::transfer(
            ctx.accounts.into_transfer_to_pda_context(),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        emit!(InitializeEvent {
            hash: ctx.accounts.escrow_state.hash,
            txo_hash: txo_hash,
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
        pay_out: bool,
        txo_hash: [u8; 32] //Only for on-chain
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
        let result = verify_ed25519_ix(&ix, &ctx.accounts.offerer.to_account_info().key.to_bytes(), &msg);

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
        ctx.accounts.escrow_state.pay_out = pay_out;
        ctx.accounts.escrow_state.initializer_key = *ctx.accounts.initializer.key;

        ctx.accounts.escrow_state.offerer = *ctx.accounts.offerer.to_account_info().key;
        ctx.accounts.escrow_state.claimer = *ctx.accounts.claimer.to_account_info().key;
        ctx.accounts.escrow_state.claimer_token_account = *ctx.accounts.claimer_token_account.to_account_info().key;

        ctx.accounts.escrow_state.initializer_amount = initializer_amount;
        ctx.accounts.escrow_state.mint = *ctx.accounts.mint.to_account_info().key;

        ctx.accounts.escrow_state.expiry = expiry;
        ctx.accounts.escrow_state.hash = hash;

        ctx.accounts.user_data.amount -= initializer_amount;
        ctx.accounts.user_data.nonce = nonce;

        emit!(InitializeEvent {
            hash: ctx.accounts.escrow_state.hash,
            txo_hash: txo_hash,
            nonce: ctx.accounts.escrow_state.nonce,
            kind: kind
        });

        Ok(())
    }

    //Refund back to offerer once enough time has passed
    pub fn offerer_refund(ctx: Context<Refund>) -> Result<()> {
        require!(
            ctx.accounts.escrow_state.expiry < now_ts()?,
            SwapErrorCode::NotExpiredYet
        );

        if !ctx.accounts.escrow_state.pay_out {
            //Check the remainingAccounts
            let user_data_acc = &ctx.remaining_accounts[0];
            let (user_data_address, _user_data_bump) =
                Pubkey::find_program_address(&[USER_DATA_SEED, ctx.accounts.escrow_state.claimer.as_ref(), ctx.accounts.escrow_state.mint.as_ref()], ctx.program_id);
            
            require!(
                user_data_address==*user_data_acc.key,
                SwapErrorCode::InvalidUserData
            );

            require!(
                user_data_acc.is_writable,
                SwapErrorCode::InvalidUserData
            );

            let mut data = user_data_acc.try_borrow_mut_data()?;
            let mut user_data = UserAccount::try_deserialize(&mut &**data)?;

            user_data.fail_volume[usize::from(ctx.accounts.escrow_state.kind)] += ctx.accounts.escrow_state.initializer_amount;
            user_data.fail_count[usize::from(ctx.accounts.escrow_state.kind)] += 1;

            user_data.try_serialize(&mut *data)?;
        }

        if ctx.accounts.escrow_state.pay_in {
            let (_vault_authority, vault_authority_bump) =
                Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
            let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

            token::transfer(
                ctx.accounts
                    .into_transfer_to_initializer_context()
                    .with_signer(&[&authority_seeds[..]]),
                ctx.accounts.escrow_state.initializer_amount,
            )?;
        } else {
            let user_data = ctx.accounts.user_data.as_mut().unwrap();
            user_data.amount += ctx.accounts.escrow_state.initializer_amount;
        }

        emit!(RefundEvent {
            hash: ctx.accounts.escrow_state.hash
        });

        Ok(())
    }

    //Refund back to offerer with a valid refund signature from claimer
    pub fn offerer_refund_with_signature(
        ctx: Context<RefundWithSignature>,
        auth_expiry: u64
    ) -> Result<()> {

        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        let mut msg = Vec::with_capacity(6+8+8+32+8);

        msg.extend_from_slice(b"refund");
        msg.extend_from_slice(&ctx.accounts.escrow_state.initializer_amount.to_le_bytes());
        msg.extend_from_slice(&ctx.accounts.escrow_state.expiry.to_le_bytes());
        msg.extend_from_slice(&ctx.accounts.escrow_state.hash);
        msg.extend_from_slice(&auth_expiry.to_le_bytes());

        // Check that ix is what we expect to have been sent
        let result = verify_ed25519_ix(&ix, &ctx.accounts.claimer.key.to_bytes(), &msg);

        require!(
            result == 0,
            SwapErrorCode::SignatureVerificationFailed
        );

        if !ctx.accounts.escrow_state.pay_out {
            //Check the remainingAccounts
            let user_data_acc = &ctx.remaining_accounts[0];
            let (user_data_address, _user_data_bump) =
                Pubkey::find_program_address(&[USER_DATA_SEED, ctx.accounts.escrow_state.claimer.as_ref(), ctx.accounts.escrow_state.mint.as_ref()], ctx.program_id);
            
            require!(
                user_data_address==*user_data_acc.key,
                SwapErrorCode::InvalidUserData
            );

            require!(
                user_data_acc.is_writable,
                SwapErrorCode::InvalidUserData
            );

            let mut data = user_data_acc.try_borrow_mut_data()?;
            let mut user_data = UserAccount::try_deserialize(&mut &**data)?;

            user_data.coop_close_volume[usize::from(ctx.accounts.escrow_state.kind)] += ctx.accounts.escrow_state.initializer_amount;
            user_data.coop_close_count[usize::from(ctx.accounts.escrow_state.kind)] += 1;

            user_data.try_serialize(&mut *data)?;
        }

        if ctx.accounts.escrow_state.pay_in {
            let (_vault_authority, vault_authority_bump) =
                Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
            let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

            token::transfer(
                ctx.accounts
                    .into_transfer_to_initializer_context()
                    .with_signer(&[&authority_seeds[..]]),
                ctx.accounts.escrow_state.initializer_amount,
            )?;
        } else {
            let user_data = ctx.accounts.user_data.as_mut().unwrap();
            user_data.amount += ctx.accounts.escrow_state.initializer_amount;
        }

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
    pub fn claimer_claim_pay_out(ctx: Context<Claim>, secret: Vec<u8>) -> Result<()> {
        if ctx.accounts.data.is_some() {
            let data_acc = ctx.accounts.data.as_mut().unwrap();
            
            require!(
                data_acc.is_writable,
                SwapErrorCode::InvalidAccountWritability
            );

            {
                let acc_data = data_acc.try_borrow_data()?;
                require!(
                    acc_data[0..32]==ctx.accounts.signer.key.to_bytes(),
                    SwapErrorCode::InvalidUserData
                );
        
                verification_utils::check_claim(&ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &acc_data[32..])?;
            }
        } else {
            verification_utils::check_claim(&ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &secret)?;
        }

        if ctx.accounts.escrow_state.pay_out {
            let (_vault_authority, vault_authority_bump) =
                Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
            let authority_seeds = &[&AUTHORITY_SEED[..], &[vault_authority_bump]];

            token::transfer(
                ctx.accounts
                    .into_transfer_to_claimer_context()
                    .with_signer(&[&authority_seeds[..]]),
                ctx.accounts.escrow_state.initializer_amount,
            )?;
        } else {
            let user_data = ctx.accounts.user_data.as_mut().unwrap();
            user_data.amount += ctx.accounts.escrow_state.initializer_amount;
            user_data.success_volume[usize::from(ctx.accounts.escrow_state.kind)] += ctx.accounts.escrow_state.initializer_amount;
            user_data.success_count[usize::from(ctx.accounts.escrow_state.kind)] += 1;
        }

        if ctx.accounts.data.is_some() {
            let data_acc = ctx.accounts.data.as_mut().unwrap();
            
            let mut acc_balance = data_acc.try_borrow_mut_lamports()?;
            let balance: u64 = **acc_balance;
            **acc_balance = 0;

            let mut signer_balance = ctx.accounts.signer.try_borrow_mut_lamports()?;
            **signer_balance += balance;

            emit!(ClaimEvent {
                hash: ctx.accounts.escrow_state.hash,
                secret: [0; 32].to_vec()
            });
        } else {
            emit!(ClaimEvent {
                hash: ctx.accounts.escrow_state.hash,
                secret: secret
            });
        }


        Ok(())
    }

    pub fn init_data(ctx: Context<InitData>) -> Result<()> {
        require!(
            ctx.accounts.data.is_writable,
            SwapErrorCode::InvalidAccountWritability
        );

        let mut acc_data = ctx.accounts.data.try_borrow_mut_data()?;
        acc_data[0..32].copy_from_slice(&ctx.accounts.signer.key.to_bytes());

        Ok(())
    }

    pub fn write_data(ctx: Context<WriteDataAlt>, start: u32, data: Vec<u8>) -> Result<()> {
        require!(
            ctx.accounts.data.is_writable,
            SwapErrorCode::InvalidAccountWritability
        );

        let mut acc_data = ctx.accounts.data.try_borrow_mut_data()?;
        require!(
            acc_data[0..32]==ctx.accounts.signer.key.to_bytes(),
            SwapErrorCode::InvalidUserData
        );

        acc_data[((start+32) as usize)..(((start+32) as usize)+data.len())].copy_from_slice(&data);

        Ok(())
    }
    
    pub fn close_data(ctx: Context<CloseDataAlt>) -> Result<()> {
        require!(
            ctx.accounts.data.is_writable,
            SwapErrorCode::InvalidAccountWritability
        );

        let acc_data = ctx.accounts.data.try_borrow_data()?;
        require!(
            acc_data[0..32]==ctx.accounts.signer.key.to_bytes(),
            SwapErrorCode::InvalidUserData
        );

        let mut acc_balance = ctx.accounts.data.try_borrow_mut_lamports()?;
        let balance: u64 = **acc_balance;
        **acc_balance = 0;

        let mut signer_balance = ctx.accounts.signer.try_borrow_mut_lamports()?;
        **signer_balance += balance;

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
        seeds = [USER_DATA_SEED.as_ref(), initializer.to_account_info().key.as_ref(), mint.to_account_info().key.as_ref()],
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
        seeds = [USER_DATA_SEED.as_ref(), initializer.to_account_info().key.as_ref(), mint.to_account_info().key.as_ref()],
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
#[instruction(nonce: u64, initializer_amount: u64, expiry: u64, escrow_seed: [u8; 32], kind: u8, confirmations: u16, auth_expiry: u64, signature: [u8; 64], escrow_nonce: u64, pay_out: bool, txo_hash: [u8; 32])]
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
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer_token_account: AccountInfo<'info>,

    //Account of the token for claimer
    #[account(
        mut,
        seeds = [USER_DATA_SEED.as_ref(), claimer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump
    )]
    pub user_data: Account<'info, UserAccount>,

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
    pub token_program: Program<'info, Token>,
    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>
}

#[derive(Accounts)]
#[instruction(nonce: u64, initializer_amount: u64, expiry: u64, escrow_seed: [u8; 32], kind: u8, confirmations: u16, auth_expiry: u64, signature: [u8; 64], escrow_nonce: u64, pay_out: bool, txo_hash: [u8; 32])]
pub struct Initialize<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: Signer<'info>,

    //Account of the token for initializer
    #[account(
        mut,
        seeds = [USER_DATA_SEED.as_ref(), offerer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        constraint = user_data.amount >= initializer_amount
    )]
    pub user_data: Account<'info, UserAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub offerer: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer_token_account: AccountInfo<'info>,
    
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
pub struct Refund<'info> {
    ////////////////////////////////////////
    //Main data
    ////////////////////////////////////////
    #[account(mut)]
    pub offerer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = escrow_state.initializer_key == *initializer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = if escrow_state.pay_in { vault.is_some() && vault_authority.is_some() && initializer_deposit_token_account.is_some() && token_program.is_some() } else { user_data.is_some() },
        constraint = initializer_deposit_token_account.is_none() || escrow_state.initializer_deposit_token_account == *initializer_deposit_token_account.as_ref().unwrap().to_account_info().key,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    ////////////////////////////////////////
    //For Pay out
    ////////////////////////////////////////
    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Option<Account<'info, TokenAccount>>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: Option<AccountInfo<'info>>,
    
    #[account(mut)]
    pub initializer_deposit_token_account: Option<Account<'info, TokenAccount>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Option<Program<'info, Token>>,

    ////////////////////////////////////////
    //For NOT Pay out
    ////////////////////////////////////////
    //Account of the token for initializer
    #[account(
        mut,
        seeds = [USER_DATA_SEED.as_ref(), offerer.key.as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub user_data: Option<Account<'info, UserAccount>>
}

#[derive(Accounts)]
pub struct RefundWithSignature<'info> {
    ///////////////////////////////////////////
    //Main data
    ///////////////////////////////////////////
    #[account(mut)]
    pub offerer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: AccountInfo<'info>,
    
    #[account(
        mut,
        constraint = escrow_state.initializer_key == *initializer.key,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = if escrow_state.pay_in { vault.is_some() && vault_authority.is_some() && initializer_deposit_token_account.is_some() && token_program.is_some() } else { user_data.is_some() },
        constraint = initializer_deposit_token_account.is_none() || escrow_state.initializer_deposit_token_account == *initializer_deposit_token_account.as_ref().unwrap().to_account_info().key,
        close = initializer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,

    ///////////////////////////////////////////
    //For pay out
    ///////////////////////////////////////////
    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Option<Account<'info, TokenAccount>>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: Option<AccountInfo<'info>>,
    
    #[account(mut)]
    pub initializer_deposit_token_account: Option<Account<'info, TokenAccount>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Option<Program<'info, Token>>,

    ///////////////////////////////////////////
    //For NOT pay out
    ///////////////////////////////////////////
    //Account of the token for initializer
    #[account(
        mut,
        seeds = [USER_DATA_SEED.as_ref(), offerer.key.as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub user_data: Option<Account<'info, UserAccount>>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    ///////////////////////////////////////////
    //Main data
    ///////////////////////////////////////////
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        constraint = claimer_receive_token_account.is_none() || escrow_state.claimer_token_account == claimer_receive_token_account.as_ref().unwrap().key(),
        constraint = if escrow_state.pay_out { claimer_receive_token_account.is_some() && vault.is_some() && vault_authority.is_some() && token_program.is_some() } else { user_data.is_some() },
        close = signer
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,
    
    ///////////////////////////////////////////
    //For Pay out
    ///////////////////////////////////////////
    #[account(mut)]
    pub claimer_receive_token_account: Option<Box<Account<'info, TokenAccount>>>,

    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Option<Box<Account<'info, TokenAccount>>>,
    
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: Option<AccountInfo<'info>>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Option<Program<'info, Token>>,

    ///////////////////////////////////////////
    //For NOT Pay out
    ///////////////////////////////////////////
    //Account of the token for initializer
    #[account(
        mut,
        seeds = [USER_DATA_SEED.as_ref(), escrow_state.claimer.key().as_ref(), escrow_state.mint.as_ref()],
        bump
    )]
    pub user_data: Option<Box<Account<'info, UserAccount>>>,

    ///////////////////////////////////////////
    //For Using external data account
    ///////////////////////////////////////////
    #[account(mut)]
    pub data: Option<UncheckedAccount<'info>>,
}


#[derive(Accounts)]
pub struct InitData<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub signer: Signer<'info>,

    //Data storage account
    /// CHECK: We will handle this ourselves
    #[account(mut)]
    pub data: Signer<'info>
}

#[derive(Accounts)]
pub struct WriteDataAlt<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub signer: Signer<'info>,

    //Data storage account
    /// CHECK: We will handle this ourselves
    #[account(mut)]
    pub data: UncheckedAccount<'info>
}

#[derive(Accounts)]
pub struct CloseDataAlt<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub signer: Signer<'info>,

    //Data storage account
    /// CHECK: We will handle this ourselves
    #[account(mut)]
    pub data: UncheckedAccount<'info>
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

impl<'info> Refund<'info> {
    fn into_transfer_to_initializer_context(
        &self,
    ) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.as_ref().unwrap().to_account_info(),
            to: self.initializer_deposit_token_account.as_ref().unwrap().to_account_info(),
            authority: self.vault_authority.as_ref().unwrap().clone(),
        };
        CpiContext::new(self.token_program.as_ref().unwrap().to_account_info(), cpi_accounts)
    }
}

impl<'info> RefundWithSignature<'info> {
    fn into_transfer_to_initializer_context(
        &self,
    ) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.as_ref().unwrap().to_account_info(),
            to: self.initializer_deposit_token_account.as_ref().unwrap().to_account_info(),
            authority: self.vault_authority.as_ref().unwrap().clone(),
        };
        CpiContext::new(self.token_program.as_ref().unwrap().to_account_info(), cpi_accounts)
    }
}

impl<'info> Claim<'info> {
    fn into_transfer_to_claimer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.as_ref().unwrap().to_account_info(),
            to: self.claimer_receive_token_account.as_ref().unwrap().to_account_info(),
            authority: self.vault_authority.as_ref().unwrap().clone(),
        };
        CpiContext::new(self.token_program.as_ref().unwrap().to_account_info(), cpi_accounts)
    }
}
