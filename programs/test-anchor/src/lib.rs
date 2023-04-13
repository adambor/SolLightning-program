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
use instructions::*;

#[path = "./utils.rs"]
mod utils;
#[path = "./txutils.rs"]
mod txutils;

pub mod errors;
pub mod state;
pub mod events;
pub mod instructions;


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
        let result = verify_ed25519_ix(&ix, &ctx.accounts.claimer.to_account_info().key.to_bytes(), &hash::hash(&msg).to_bytes());

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
        let result = verify_ed25519_ix(&ix, &ctx.accounts.offerer.to_account_info().key.to_bytes(), &hash::hash(&msg).to_bytes());

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
    pub fn offerer_refund(ctx: Context<Refund>, auth_expiry: u64) -> Result<()> {
        if auth_expiry>0 {
            let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar.as_ref().unwrap())?;

            let mut msg = Vec::with_capacity(6+8+8+32+8);
    
            msg.extend_from_slice(b"refund");
            msg.extend_from_slice(&ctx.accounts.escrow_state.initializer_amount.to_le_bytes());
            msg.extend_from_slice(&ctx.accounts.escrow_state.expiry.to_le_bytes());
            msg.extend_from_slice(&ctx.accounts.escrow_state.hash);
            msg.extend_from_slice(&auth_expiry.to_le_bytes());
    
            // Check that ix is what we expect to have been sent
            let result = verify_ed25519_ix(&ix, &ctx.accounts.escrow_state.claimer.to_bytes(), &hash::hash(&msg).to_bytes());
    
            require!(
                result == 0,
                SwapErrorCode::SignatureVerificationFailed
            );
        } else {
            require!(
                ctx.accounts.escrow_state.expiry < now_ts()?,
                SwapErrorCode::NotExpiredYet
            );
        }

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

            if auth_expiry>0 {
                user_data.coop_close_volume[usize::from(ctx.accounts.escrow_state.kind)] += ctx.accounts.escrow_state.initializer_amount;
                user_data.coop_close_count[usize::from(ctx.accounts.escrow_state.kind)] += 1;
            } else {
                user_data.fail_volume[usize::from(ctx.accounts.escrow_state.kind)] += ctx.accounts.escrow_state.initializer_amount;
                user_data.fail_count[usize::from(ctx.accounts.escrow_state.kind)] += 1;
            }

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
