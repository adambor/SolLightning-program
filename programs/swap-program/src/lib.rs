use anchor_lang::{
    prelude::*, 
    solana_program::clock, 
    solana_program::hash,
    solana_program::sysvar::instructions::{ID as IX_ID, load_instruction_at_checked},
    solana_program::instruction::Instruction,
    system_program
};
use anchor_spl::token::{
    self, /*CloseAccount, */ Mint, Token,
    TokenAccount, Transfer
};
use std::cmp;

use enums::*;
use errors::*;
use state::*;
use events::*;
use instructions::*;

mod enums;
mod signatureutils;
mod txutils;
mod btcrelayutils;
mod errors;
mod state;
mod events;
mod instructions;


declare_id!("8vowxbBrrfDU6Dz1bBCL4W9K5pTwsBLVAd8kJPsgLiLR");

pub fn now_ts() -> Result<u64> {
    Ok(clock::Clock::get().unwrap().unix_timestamp.try_into().unwrap())
}

static AUTHORITY_SEED: &[u8] = b"authority";
static USER_DATA_SEED: &[u8] = b"uservault";
static BLOCKHEIGHT_EXPIRY_THRESHOLD: u64 = 1000000000; //If expiry is < BLOCKHEIGHT_EXPIRY_THRESHOLD it is considered as expressed in blockheight instead of timestamp

static BTCRELAY_PRUNING_FACTOR: u16 = 250;
static BTCRELAY_SAFETY_BUFFER: u16 = 50;
static MAX_CONFIRMATIONS: u16 = BTCRELAY_PRUNING_FACTOR - BTCRELAY_SAFETY_BUFFER;

pub mod refund_utils {
    use super::*;
    
    //Processes & checks refund (either via coop close signature, or timeout), updates reputation of the
    // claimer (if the swap was pay_out=false), emits ClaimEvent, throws on failure,
    // returns whether the refund was cooperative or not
    pub fn process_refund(auth_expiry: u64, escrow_state: &Account<EscrowState>, ix_sysvar: &Option<AccountInfo>, user_data_claimer: &mut Option<Account<UserAccount>>) -> Result<bool> {
        
        let is_cooperative = auth_expiry>0;

        if is_cooperative {
            refund_utils::verify_signature(auth_expiry, escrow_state, ix_sysvar.as_ref().unwrap())?;
        } else {
            refund_utils::verify_timeout(escrow_state, ix_sysvar)?;
        }

        //Update the on-chain reputation of claimer in case this was not pay_out swap
        if !escrow_state.pay_out {
            let user_data_claimer = user_data_claimer.as_mut().expect("Claimer UserData not provided for pay_out=false swap");

            if is_cooperative {
                user_data_claimer.coop_close_volume[escrow_state.kind as usize] = user_data_claimer.coop_close_volume[escrow_state.kind as usize].saturating_add(escrow_state.initializer_amount);
                user_data_claimer.coop_close_count[escrow_state.kind as usize] += 1;
            } else {
                user_data_claimer.fail_volume[escrow_state.kind as usize] = user_data_claimer.fail_volume[escrow_state.kind as usize].saturating_add(escrow_state.initializer_amount);
                user_data_claimer.fail_count[escrow_state.kind as usize] += 1;
            }
        }

        emit!(RefundEvent {
            hash: escrow_state.hash,
            sequence: escrow_state.sequence
        });

        Ok(is_cooperative)

    }

    //Verifies cooperative refund using the signature from claimer, throws on failure
    pub fn verify_signature(auth_expiry: u64, escrow_state: &Account<EscrowState>, ix_sysvar: &AccountInfo) -> Result<()> {
        //Load ed25519 verify instruction at 0-th index
        let ix: Instruction = load_instruction_at_checked(0, ix_sysvar)?;

        //Construct "refund" message
        let mut msg = Vec::with_capacity(6+8+8+8+32+8);
        msg.extend_from_slice(b"refund");
        msg.extend_from_slice(&escrow_state.initializer_amount.to_le_bytes());
        msg.extend_from_slice(&escrow_state.expiry.to_le_bytes());
        msg.extend_from_slice(&escrow_state.sequence.to_le_bytes());
        msg.extend_from_slice(&escrow_state.hash);
        msg.extend_from_slice(&auth_expiry.to_le_bytes());

        //Check that the ed25519 verify instruction verified the signature of the hash of the "refund" message
        //Throws on verify fail
        signatureutils::verify_ed25519_ix(&ix, &escrow_state.claimer.to_bytes(), &hash::hash(&msg).to_bytes())?;

        Ok(())
    }

    //Verifies timeout refund using timestamp or btc relay blockheight, throws on failure
    pub fn verify_timeout(escrow_state: &Account<EscrowState>, ix_sysvar: &Option<AccountInfo>) -> Result<()> {
        //Check if the contract is expired yet
        if escrow_state.expiry < BLOCKHEIGHT_EXPIRY_THRESHOLD {
            //Expiry is expressed in bitcoin blockheight
            
            //Check that there was a previous instruction verifying
            // blockheight of btcrelay program
            // btc_relay.blockheight > escrow_state.expiry
            let ix: Instruction = load_instruction_at_checked(0, ix_sysvar.as_ref().unwrap())?;

            //Throws on failure
            btcrelayutils::verify_blockheight_ix(&ix, escrow_state.expiry.try_into().unwrap(), 2)?;
        } else {
            //Expiry is expressed as UNIX timestamp in seconds
            require!(
                escrow_state.expiry < now_ts()?,
                SwapErrorCode::NotExpiredYet
            );
        }

        Ok(())
    }

    //Pays out security deposit to offerer & pays the rest back to initializer
    pub fn pay_security_deposit<'info>(escrow_state: &mut Account<'info, EscrowState>, offerer: &mut Signer<'info>, claimer: &mut AccountInfo<'info>, is_cooperative: bool) -> Result<()> {

        let initializer = if escrow_state.pay_in { offerer.to_account_info() } else { claimer.to_account_info() };
        if is_cooperative {
            //Coop closure, whole PDA amount (rent, security deposit & claimer bounty) is returned to initializer
            escrow_state.close(initializer).unwrap();
        } else {
            //Un-cooperative closure, security deposit goes to offerer, rest is paid out to the initializer
            if escrow_state.security_deposit>0 {
                let offerer_starting_lamports = offerer.to_account_info().lamports();
                let initializer_starting_lamports = initializer.lamports();
                let data_starting_lamports = escrow_state.to_account_info().lamports();

                **offerer.to_account_info().lamports.borrow_mut() = offerer_starting_lamports.checked_add(escrow_state.security_deposit).unwrap();
                **initializer.lamports.borrow_mut() = initializer_starting_lamports.checked_add(data_starting_lamports - escrow_state.security_deposit).unwrap();
                **escrow_state.to_account_info().lamports.borrow_mut() = 0;
            
                escrow_state.to_account_info().assign(&system_program::ID);
                escrow_state.to_account_info().realloc(0, false).unwrap();
            } else {
                escrow_state.close(initializer).unwrap();
            }
        }

        Ok(())
    }

}

pub mod claim_utils {
    use super::*;

    //Processes & checks the claim data - uses data from data_account if provided, otherwise uses data passed in secret param, emits ClaimEvent, throws on failure
    pub fn process_claim(signer: &Signer, escrow_state: &Account<EscrowState>, ix_sysvar: &AccountInfo, data_account: &mut Option<UncheckedAccount>, secret: &[u8]) -> Result<()> {

        let event_secret = match data_account {
            Some(data_acc) => {
                require!(
                    data_acc.is_writable,
                    SwapErrorCode::InvalidAccountWritability
                );
    
                let event_secret;
                {
                    let acc_data = data_acc.try_borrow_data()?;
                    require!(
                        acc_data[0..32]==signer.key.to_bytes(),
                        SwapErrorCode::InvalidUserData
                    );
            
                    event_secret = claim_utils::check_claim(escrow_state, ix_sysvar, &acc_data[32..])?;
                }
                
                let mut acc_balance = data_acc.try_borrow_mut_lamports()?;
                let balance: u64 = **acc_balance;
                **acc_balance = 0;
    
                let mut signer_balance = signer.try_borrow_mut_lamports()?;
                **signer_balance += balance;

                event_secret
            },
            None => claim_utils::check_claim(escrow_state, ix_sysvar, secret)?
        };

        emit!(ClaimEvent {
            hash: escrow_state.hash,
            secret: event_secret,
            sequence: escrow_state.sequence
        });
        
        Ok(())
    }

    //Verifies if the claim is claimable by the claimer, provided the secret data (tx data or preimage for HTLC), returns the preimage (for HTLC, or TXHASH for PTLC)
    pub fn check_claim(account: &Account<EscrowState>, ix_sysvar: &AccountInfo, secret: &[u8]) -> Result<[u8; 32]> {
        match account.kind {
            SwapType::Htlc => claim_utils::check_claim_htlc(account, secret),
            SwapType::Chain | SwapType::ChainNonced | SwapType::ChainTxhash => claim_utils::check_claim_chain(account, ix_sysvar, secret)
        }
    }

    //Verifies claim of HTLC by checking that a secret (the first 32 bytes of the secret) properly hash to escrow state hash, returns the 32 byte secret
    pub fn check_claim_htlc(account: &Account<EscrowState>, secret: &[u8]) -> Result<[u8; 32]> {
        //Check HTLC hash for lightning
        let hash_result = hash::hash(&secret[..32]).to_bytes();

        require!(
            hash_result == account.hash,
            SwapErrorCode::InvalidSecret
        );

        Ok(secret[..32].try_into().unwrap())
    }

    //Verifies claim of PTLC by verifying the tx_hash with btc relay program, returns the transaction hash
    pub fn check_claim_chain(account: &Account<EscrowState>, ix_sysvar: &AccountInfo, secret: &[u8]) -> Result<[u8; 32]> {
        //txhash to be checked with bitcoin relay program
        let tx_hash: [u8; 32] = match account.kind {
            SwapType::ChainTxhash => account.hash,
            SwapType::Chain | SwapType::ChainNonced => {
                //Extract output index from secret
                let output_index = u32::from_le_bytes(secret[0..4].try_into().unwrap());
                //Verify transaction, starting from byte 4 of the secret
                let opt_tx = txutils::verify_transaction(&secret[4..], output_index.into(), account.kind==SwapType::ChainNonced);
    
                //Has to be properly parsed
                require!(
                    opt_tx.is_some(),
                    SwapErrorCode::InvalidTx
                );
    
                let tx = opt_tx.unwrap();
    
                //Has to contain the required vout
                require!(
                    tx.out.is_some(),
                    SwapErrorCode::InvalidVout
                );
    
                let tx_output = tx.out.unwrap();
    
                //Extract data from the vout
                let mut output_data = Vec::with_capacity(8+8+tx_output.script.len());
                output_data.extend_from_slice(&u64::to_le_bytes(account.nonce));
                output_data.extend_from_slice(&u64::to_le_bytes(tx_output.value));
                output_data.extend_from_slice(tx_output.script);
    
                //Hash the nonce, output value and output script
                let hash_result = hash::hash(&output_data).to_bytes();
                require!(
                    hash_result == account.hash,
                    SwapErrorCode::InvalidSecret
                );
    
                if account.kind==SwapType::ChainNonced {
                    //For the transaction nonce, we utilize nSequence and timelock,
                    // this uniquelly identifies the transaction output, even if it's an address re-use
                    let n_sequence_u64: u64 = (tx.n_sequence as u64) & 0x00FFFFFF;
                    let locktime_u64: u64 = (tx.locktime as u64)-500000000;
                    let tx_nonce: u64 = (locktime_u64<<24) | n_sequence_u64;
                    require!(
                        tx_nonce == account.nonce,
                        SwapErrorCode::InvalidNonce
                    );
                }
    
                tx.hash
            },
            _ => panic!()
        };
    
        //Check that there was a previous instruction verifying
        // the transaction ID against btcrelay program
        let ix: Instruction = load_instruction_at_checked(0, ix_sysvar)?;
        
        //Throws on failure
        btcrelayutils::verify_tx_ix(&ix, &tx_hash, account.confirmations as u32)?;

        Ok(tx_hash)
    }

    //Handles payout of claimer bounty & paying the rest back to initializer
    pub fn pay_claimer_bounty<'info>(signer: &Signer, initializer: &AccountInfo<'info>, escrow_state: &Account<'info, EscrowState>) -> Result<()> {

        //Pay out claimer bounty to signer, rest goes back to initializer
        if escrow_state.claimer_bounty>0 {
            let data_starting_lamports = escrow_state.to_account_info().lamports();

            let signer_starting_lamports = signer.to_account_info().lamports();
            **signer.to_account_info().lamports.borrow_mut() = signer_starting_lamports.checked_add(escrow_state.claimer_bounty).unwrap();

            let initializer_starting_lamports = initializer.lamports();
            **initializer.lamports.borrow_mut() = initializer_starting_lamports.checked_add(data_starting_lamports - escrow_state.claimer_bounty).unwrap();
            
            **escrow_state.to_account_info().lamports.borrow_mut() = 0;
        
            escrow_state.to_account_info().assign(&system_program::ID);
            escrow_state.to_account_info().realloc(0, false).unwrap();
        } else {
            escrow_state.close(initializer.to_account_info()).unwrap();
        }

        Ok(())

    }

}

pub mod initialize_utils {
    use super::*;

    pub fn process_initialize(
        escrow_state: &mut Account<EscrowState>,
        bump: u8,
        offerer: &AccountInfo,
        claimer: &AccountInfo,
        claimer_token_account: &Option<Account<TokenAccount>>,
        mint: &Account<Mint>,

        initializer_amount: u64,
        expiry: u64,
        hash: [u8; 32],
        kind: SwapType,
        confirmations: u16,
        escrow_nonce: u64,
        auth_expiry: u64,
        pay_out: bool,
        txo_hash: [u8; 32], //Only for on-chain,
        sequence: u64
    ) -> Result<()> {
        require!(
            auth_expiry > now_ts()?,
            SwapErrorCode::AlreadyExpired
        );

        require!(
            confirmations <= MAX_CONFIRMATIONS,
            SwapErrorCode::TooManyConfirmations
        );

        escrow_state.kind = kind;

        if kind==SwapType::ChainNonced {
            escrow_state.nonce = escrow_nonce;
        }

        escrow_state.confirmations = confirmations;
        escrow_state.pay_in = true;
        escrow_state.pay_out = pay_out;

        escrow_state.offerer = *offerer.key;
        escrow_state.claimer = *claimer.to_account_info().key;

        if pay_out {
            let claimer_ata = claimer_token_account.as_ref().expect("Claimer ATA not provided for pay_out=true swap");
            escrow_state.claimer_token_account = *claimer_ata.to_account_info().key;
        }

        escrow_state.initializer_amount = initializer_amount;
        escrow_state.mint = *mint.to_account_info().key;

        escrow_state.expiry = expiry;
        escrow_state.hash = hash;
        escrow_state.sequence = sequence;

        escrow_state.bump = bump;

        emit!(InitializeEvent {
            hash: escrow_state.hash,
            txo_hash,
            nonce: escrow_state.nonce,
            kind,
            sequence
        });

        Ok(())
    }
}

#[program]
pub mod swap_program {
    use super::*;

    //Deposit to program balance
    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
    ) -> Result<()> {
        token::transfer(
            ctx.accounts.get_transfer_to_pda_context(),
            amount,
        )?;
        
        ctx.accounts.user_data.bump = ctx.bumps.user_data;
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
        let authority_seeds = &[AUTHORITY_SEED, &[vault_authority_bump]];

        if amount>0 {
            token::transfer(
                ctx.accounts
                    .get_transfer_to_initializer_context()
                    .with_signer(&[&authority_seeds[..]]),
                amount,
            )?;
        }

        ctx.accounts.user_data.amount -= amount;

        Ok(())
    }

    //Initialize from external source
    pub fn offerer_initialize_pay_in(
        ctx: Context<InitializePayIn>,
        initializer_amount: u64,
        expiry: u64,
        hash: [u8; 32],
        kind: SwapType,
        confirmations: u16,
        auth_expiry: u64,
        escrow_nonce: u64,
        pay_out: bool,
        txo_hash: [u8; 32], //Only for on-chain,
        sequence: u64
    ) -> Result<()> {

        initialize_utils::process_initialize(
            &mut ctx.accounts.escrow_state,
            ctx.bumps.escrow_state,
            &ctx.accounts.offerer.to_account_info(),
            &ctx.accounts.claimer,
            &ctx.accounts.claimer_token_account,
            &ctx.accounts.mint,
            initializer_amount,
            expiry,
            hash,
            kind,
            confirmations,
            escrow_nonce,
            auth_expiry,
            pay_out,
            txo_hash,
            sequence
        )?;

        ctx.accounts.escrow_state.initializer_deposit_token_account = *ctx.accounts.initializer_deposit_token_account.to_account_info().key;

        token::transfer(
            ctx.accounts.get_transfer_to_pda_context(),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        Ok(())
    }

    //Initialize from internal program balance.
    //Signer (claimer), must also deposit a required security_deposit,
    // in case he doesn't claim the swap in time and offerer has to refund,
    // offerer will get this deposit as a compensation for the time value
    // of funds locked up in a contract
    //Signer (claimer), may also deposit a claimer_bounty, to incentivize
    // watchtowers to claim this contract (only SwapType::Chain* swaps)
    pub fn offerer_initialize(
        ctx: Context<Initialize>,
        initializer_amount: u64,
        expiry: u64,
        hash: [u8; 32],
        kind: SwapType,
        confirmations: u16,
        escrow_nonce: u64,
        auth_expiry: u64,
        pay_out: bool,
        txo_hash: [u8; 32], //Only for on-chain
        security_deposit: u64,
        claimer_bounty: u64,
        sequence: u64
    ) -> Result<()> {

        initialize_utils::process_initialize(
            &mut ctx.accounts.escrow_state,
            ctx.bumps.escrow_state,
            &ctx.accounts.offerer.to_account_info(),
            &ctx.accounts.claimer,
            &ctx.accounts.claimer_token_account,
            &ctx.accounts.mint,
            initializer_amount,
            expiry,
            hash,
            kind,
            confirmations,
            escrow_nonce,
            auth_expiry,
            pay_out,
            txo_hash,
            sequence
        )?;

        //We can calculate only the maximum of the two, not a sum,
        // since only one of them can ever be paid out:
        // swap success - security_deposit goes back to claimer, claimer_bounty is paid to watchtower
        // swap failed - claimer_bounty goes back to claimer, security_deposit is paid to offerer
        let required_lamports = cmp::max(security_deposit, claimer_bounty);

        //There is already some amount of lamports in the PDA, required for rent exemption
        //Only deposit more if it's required
        let dst_starting_lamports = ctx.accounts.escrow_state.to_account_info().lamports();
        if dst_starting_lamports < required_lamports {
            let difference = required_lamports - dst_starting_lamports;
            let cpi_program = ctx.accounts.system_program.to_account_info();
            let transfer_lamports_instruction = system_program::Transfer{
                from: ctx.accounts.claimer.to_account_info(),
                to: ctx.accounts.escrow_state.to_account_info()
            };
            let cpi_ctx = CpiContext::new(cpi_program, transfer_lamports_instruction);
            system_program::transfer(cpi_ctx, difference)?;
        }

        ctx.accounts.user_data.amount -= initializer_amount;

        Ok(())
    }

    //Refund back to offerer once enough time has passed,
    // or by providing a "refund" message signed by claimer
    pub fn offerer_refund(ctx: Context<Refund>, auth_expiry: u64) -> Result<()> {
        let is_cooperative = refund_utils::process_refund(auth_expiry, &ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &mut ctx.accounts.user_data_claimer)?;

        //Refund to internal wallet
        ctx.accounts.user_data.amount += ctx.accounts.escrow_state.initializer_amount;

        refund_utils::pay_security_deposit(&mut ctx.accounts.escrow_state, &mut ctx.accounts.offerer, &mut ctx.accounts.claimer, is_cooperative)?;

        Ok(())
    }

    //Refund back to offerer once enough time has passed,
    // or by providing a "refund" message signed by claimer
    pub fn offerer_refund_pay_in(ctx: Context<RefundPayIn>, auth_expiry: u64) -> Result<()> {
        let is_cooperative = refund_utils::process_refund(auth_expiry, &ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &mut ctx.accounts.user_data_claimer)?;

        //Refund in token to external wallet
        let (_vault_authority, vault_authority_bump) =
            Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
        let authority_seeds = &[AUTHORITY_SEED, &[vault_authority_bump]];

        token::transfer(
            ctx.accounts
                .get_transfer_to_initializer_context()
                .with_signer(&[&authority_seeds[..]]),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        refund_utils::pay_security_deposit(&mut ctx.accounts.escrow_state, &mut ctx.accounts.offerer, &mut ctx.accounts.claimer, is_cooperative)?;

        Ok(())
    }

    //Claim the swap using the "secret", or data in the provided "data" account
    pub fn claimer_claim(ctx: Context<Claim>, secret: Vec<u8>) -> Result<()> {
        claim_utils::process_claim(&ctx.accounts.signer, &ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &mut ctx.accounts.data, &secret)?;

        let user_data = &mut ctx.accounts.user_data;
        user_data.amount += ctx.accounts.escrow_state.initializer_amount;
        user_data.success_volume[ctx.accounts.escrow_state.kind as usize] = user_data.success_volume[ctx.accounts.escrow_state.kind as usize].saturating_add(ctx.accounts.escrow_state.initializer_amount);
        user_data.success_count[ctx.accounts.escrow_state.kind as usize] += 1;

        claim_utils::pay_claimer_bounty(&ctx.accounts.signer, &ctx.accounts.initializer, &ctx.accounts.escrow_state)?;

        Ok(())
    }

    //Claim the swap using the "secret", or data in the provided "data" account
    pub fn claimer_claim_pay_out(ctx: Context<ClaimPayOut>, secret: Vec<u8>) -> Result<()> {
        claim_utils::process_claim(&ctx.accounts.signer, &ctx.accounts.escrow_state, &ctx.accounts.ix_sysvar, &mut ctx.accounts.data, &secret)?;

        let (_vault_authority, vault_authority_bump) =
        Pubkey::find_program_address(&[AUTHORITY_SEED], ctx.program_id);
        let authority_seeds = &[AUTHORITY_SEED, &[vault_authority_bump]];

        token::transfer(
            ctx.accounts
                .get_transfer_to_claimer_context()
                .with_signer(&[&authority_seeds[..]]),
            ctx.accounts.escrow_state.initializer_amount,
        )?;

        claim_utils::pay_claimer_bounty(&ctx.accounts.signer, &ctx.accounts.initializer, &ctx.accounts.escrow_state)?;

        Ok(())
    }

    //Initializes the data account, by writting signer's key to it
    pub fn init_data(ctx: Context<InitData>) -> Result<()> {
        require!(
            ctx.accounts.data.is_writable,
            SwapErrorCode::InvalidAccountWritability
        );

        let mut acc_data = ctx.accounts.data.try_borrow_mut_data()?;
        acc_data[0..32].copy_from_slice(&ctx.accounts.signer.key.to_bytes());

        Ok(())
    }

    //Initializes chunk of data to the data account
    pub fn write_data(ctx: Context<WriteDataAlt>, start: u32, data: Vec<u8>) -> Result<()> {
        require!(
            ctx.accounts.data.is_writable,
            SwapErrorCode::InvalidAccountWritability
        );

        //Check signer key matches
        let mut acc_data = ctx.accounts.data.try_borrow_mut_data()?;
        require!(
            acc_data[0..32]==ctx.accounts.signer.key.to_bytes(),
            SwapErrorCode::InvalidUserData
        );

        acc_data[((start+32) as usize)..(((start+32) as usize)+data.len())].copy_from_slice(&data);

        Ok(())
    }
    
    //Closes data account
    pub fn close_data(ctx: Context<CloseDataAlt>) -> Result<()> {
        require!(
            ctx.accounts.data.is_writable,
            SwapErrorCode::InvalidAccountWritability
        );

        //Check signer key matches
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
