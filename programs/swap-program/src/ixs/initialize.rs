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
use crate::structs::*;

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

    swap_data: &SwapData,
    
    txo_hash: [u8; 32], //Only for on-chain,
    auth_expiry: u64
) -> Result<()> {
    require!(
        auth_expiry > now_ts()?,
        SwapErrorCode::AlreadyExpired
    );

    require!(
        swap_data.confirmations <= crate::MAX_CONFIRMATIONS,
        SwapErrorCode::TooManyConfirmations
    );

    if swap_data.kind != SwapType::ChainNonced {
        require!(
            swap_data.nonce == 0,
            SwapErrorCode::InvalidSwapDataNonce
        );
    }

    escrow_state.data = swap_data.clone();

    escrow_state.offerer = *offerer.key;
    escrow_state.claimer = *claimer.to_account_info().key;

    if swap_data.pay_out {
        let claimer_ata = claimer_token_account.as_ref().expect("Claimer ATA not provided for pay_out=true swap");
        escrow_state.claimer_token_account = *claimer_ata.to_account_info().key;
    }
    escrow_state.mint = *mint.to_account_info().key;

    escrow_state.bump = bump;

    emit!(InitializeEvent {
        hash: swap_data.hash,
        txo_hash,
        nonce: swap_data.nonce,
        kind: swap_data.kind,
        sequence: swap_data.sequence
    });

    Ok(())
}