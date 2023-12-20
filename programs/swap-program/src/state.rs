use anchor_lang::prelude::*;
use crate::SwapType;
use crate::SWAP_TYPE_COUNT;

//Swap contract between offerer and claimer
// HTLC (hash-time locked contract) in case of KIND_LN
// PTLC (proof-time locked contract, where proof is transaction inclusion through bitcoin relay) in case of KIND_CHAIN_*
#[account]
pub struct EscrowState {
    pub kind: SwapType, //Kind of the swap, KIND_*
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
    pub sequence: u64,

    pub bump: u8
}

impl EscrowState {
    pub const SPACE: usize = 8 + 1 + 2 + 8 + 192 + 8 + 8 + 1 + 1 + 8 + 8 + 8 + 1;
}

//PDA format for storing user's (LP node's) balance and reputation
#[account]
pub struct UserAccount {
    //@deprecated, was used to prevent replay protection for initialization authorization
    pub nonce: u64,
    
    pub amount: u64, //Amount of tokens held by the user

    /////////////////////////
    // on-chain reputation //
    /////////////////////////
    //Volume of the successfully processed swaps, separate for every KIND_*
    pub success_volume: [u64; SWAP_TYPE_COUNT],
    //Count of the successfully processed swaps, separate for every KIND_*
    pub success_count: [u64; SWAP_TYPE_COUNT],

    //Volume of the failed swaps, separate for every KIND_*
    pub fail_volume: [u64; SWAP_TYPE_COUNT],
    //Count of the failed swaps, separate for every KIND_*
    pub fail_count: [u64; SWAP_TYPE_COUNT],

    //Volume of the cooperatively closed swaps, separate for every KIND_*
    pub coop_close_volume: [u64; SWAP_TYPE_COUNT],
    //Count of the cooperatively closed swaps, separate for every KIND_*
    pub coop_close_count: [u64; SWAP_TYPE_COUNT],
    
    pub bump: u8
}

impl UserAccount {
    pub const SPACE: usize = 8 + 8 + 8 + (8*6*SWAP_TYPE_COUNT) + 1;
}
