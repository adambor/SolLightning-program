use anchor_lang::{
    prelude::*, 
    solana_program::clock
};
use anchor_spl::token::{
    Mint,
    TokenAccount
};

use crate::enums::*;
use crate::errors::*;
use crate::state::*;
use crate::events::*;

fn now_ts() -> Result<u64> {
    Ok(clock::Clock::get().unwrap().unix_timestamp.try_into().unwrap())
}

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
        confirmations <= crate::MAX_CONFIRMATIONS,
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