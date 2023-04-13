use anchor_lang::prelude::*;

#[account]
pub struct EscrowState {
    pub kind: u8,
    pub confirmations: u16,
    pub nonce: u64,
    pub hash: [u8; 32],

    pub initializer_key: Pubkey,
    pub pay_in: bool,

    pub pay_out: bool,
    
    pub offerer: Pubkey,
    pub initializer_deposit_token_account: Pubkey,

    pub claimer: Pubkey,
    pub claimer_token_account: Pubkey,
    
    pub initializer_amount: u64,
    pub mint: Pubkey,
    pub expiry: u64
}

#[account]
pub struct UserAccount {
    pub nonce: u64,
    pub amount: u64,
    pub claim_nonce: u64,

    pub success_volume: [u64; 3],
    pub success_count: [u64; 3],
    pub fail_volume: [u64; 3],
    pub fail_count: [u64; 3],
    pub coop_close_volume: [u64; 3],
    pub coop_close_count: [u64; 3]
}

impl EscrowState {
    pub fn space() -> usize {
        8 + 1 + 2 + 8 + 192 + 8 + 8 + 1 + 32 + 1
    }
}

impl UserAccount {
    pub fn space() -> usize {
        8 + 8 + 8 + 8 + 144
    }
}
