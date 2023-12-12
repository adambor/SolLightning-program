use anchor_lang::prelude::*;

#[event]
pub struct InitializeEvent {
    pub txo_hash: [u8; 32],

    pub kind: u8, //Kind of the swap, KIND_*
    pub confirmations: u16, //On-chain confirmations required for swap (only on-chain swaps: KIND_CHAIN, KIND_CHAIN_NONCED)
    pub nonce: u64, //Nonce to prevent transaction replays (only KIND_CHAIN_NONCED swaps)
    
    //Locking hash for the swap
    // KIND_LN - payment hash
    // KIND_CHAIN & KIND_CHAIN_NONCED - txo hash
    // KIND_CHAIN_TXHASH - txhash
    pub hash: [u8; 32],

    //Whether the funds were deposited to the contract from external source
    //Used to determine if refund should be paid out to external wallet, or to the contract vault
    pub pay_in: bool,

    //Whether the funds should be paid out to external source
    //Used to determine if payout should be paid out to external wallet, or to the contract vault
    pub pay_out: bool,
    
    pub offerer: Pubkey, //Offerer, depositing funds into the swap contract
    pub initializer_deposit_token_account: Pubkey, //ATA of the offerer, left empty for non pay_in swaps

    pub claimer: Pubkey, //Claimer, able to claim the funds from the swap contract, when spend condition is met
    pub claimer_token_account: Pubkey, //ATA of the claimer, ignored for non pay_out swaps
    
    pub initializer_amount: u64, //Token amount
    pub mint: Pubkey, //Pubkey of the token mint
    pub expiry: u64, //UNIX seconds expiry timestamp, offerer can refund the swap after this timestamp

    //Bounty for the watchtower claiming the swap (only for KIND_CHAIN & KIND_CHAIN_NONCED).
    //Alway paid as native Solana, in Lamports
    pub claimer_bounty: u64,

    //Security deposit, paid out to offerer in case swap expires and needs to be refunded.
    //Used to cover transaction fee and compensate for time value of money locked up in the contract.
    //Alway paid as native Solana, in Lamports
    pub security_deposit: u64,

    //Uniquely identifies this swap PDA
    pub sequence: u64
}

#[event]
pub struct RefundEvent {
    pub hash: [u8; 32],
    pub sequence: u64
}

#[event]
pub struct ClaimEvent {
    pub hash: [u8; 32],
    pub secret: Vec<u8>,
    pub sequence: u64
}
