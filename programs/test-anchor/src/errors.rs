use anchor_lang::prelude::*;

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
    InvalidDataAccount,
    #[msg("Invalid user data account")]
    InvalidUserData,
    #[msg("Invalid vout of the output used")]
    InvalidVout,
    #[msg("Account cannot be written to")]
    InvalidAccountWritability
}