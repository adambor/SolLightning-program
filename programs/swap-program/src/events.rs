use anchor_lang::prelude::*;

#[event]
pub struct InitializeEvent {
    pub hash: [u8; 32],
    pub txo_hash: [u8; 32],
    pub nonce: u64,
    pub kind: u8,
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
