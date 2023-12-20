use anchor_lang::prelude::*;
use crate::*;
use crate::USER_DATA_SEED;

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
    
    pub rent: Sysvar<'info, Rent>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub token_program: Program<'info, Token>
}

#[derive(Accounts)]
#[instruction(initializer_amount: u64, expiry: u64, escrow_seed: [u8; 32], kind: u8, confirmations: u16, auth_expiry: u64, escrow_nonce: u64, pay_out: bool, txo_hash: [u8; 32])]
pub struct InitializePayIn<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub offerer: Signer<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer: Signer<'info>,

    //Account of the token for initializer
    #[account(
         mut,
         constraint = initializer_deposit_token_account.amount >= initializer_amount
    )]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer_token_account: AccountInfo<'info>,

    //Data storage account
    #[account(
        init,
        seeds = [b"state".as_ref(), escrow_seed.as_ref()],
        bump,
        payer = offerer,
        space = EscrowState::space(),
        //We need to verify existence of this PDA, so it can be properly provided in the possible refund()
        constraint = pay_out || user_data_claimer.is_some()
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    //Account holding the tokens
    #[account(
        init_if_needed,
        seeds = [b"vault".as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        payer = offerer,
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
    
    ////////////////////////////////////////
    //For NOT Pay out
    ////////////////////////////////////////
    #[account(
        seeds = [USER_DATA_SEED.as_ref(), claimer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump
    )]
    pub user_data_claimer: Option<Account<'info, UserAccount>>
}

#[derive(Accounts)]
#[instruction(initializer_amount: u64, expiry: u64, escrow_seed: [u8; 32], kind: u8, confirmations: u16, auth_expiry: u64, escrow_nonce: u64, pay_out: bool, txo_hash: [u8; 32])]
pub struct Initialize<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub claimer: Signer<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub offerer: Signer<'info>,

    //Account of the token for initializer
    #[account(
        mut,
        seeds = [USER_DATA_SEED.as_ref(), offerer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        constraint = user_data.amount >= initializer_amount
    )]
    pub user_data: Account<'info, UserAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub claimer_token_account: AccountInfo<'info>,
    
    //Data storage account
    #[account(
        init,
        seeds = [b"state".as_ref(), escrow_seed.as_ref()],
        bump,
        payer = claimer,
        space = EscrowState::space(),
        //We need to verify existence of this PDA, so it can be properly provided in the possible refund()
        constraint = pay_out || user_data_claimer.is_some()
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    //Required data
    pub mint: Account<'info, Mint>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,

    ////////////////////////////////////////
    //For NOT Pay out
    ////////////////////////////////////////
    #[account(
        seeds = [USER_DATA_SEED.as_ref(), claimer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump
    )]
    pub user_data_claimer: Option<Account<'info, UserAccount>>
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
    pub claimer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = if escrow_state.pay_in { vault.is_some() && vault_authority.is_some() && initializer_deposit_token_account.is_some() && token_program.is_some() } else { user_data.is_some() },
        constraint = initializer_deposit_token_account.is_none() || escrow_state.initializer_deposit_token_account == *initializer_deposit_token_account.as_ref().unwrap().to_account_info().key
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
    pub user_data: Option<Account<'info, UserAccount>>,

    ////////////////////////////////////////
    //For Refund with signature
    ////////////////////////////////////////
    /// CHECK: This is safe: https://github.com/GuidoDipietro/solana-ed25519-secp256k1-sig-verification/blob/master/programs/solana-ed25519-sig-verification/src/lib.rs
    #[account(address = IX_ID)]
    pub ix_sysvar: Option<AccountInfo<'info>>
}

#[derive(Accounts)]
pub struct Claim<'info> {
    ///////////////////////////////////////////
    //Main data
    ///////////////////////////////////////////
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub signer: Signer<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = claimer_receive_token_account.is_none() || escrow_state.claimer_token_account == claimer_receive_token_account.as_ref().unwrap().key(),
        constraint = if escrow_state.pay_out { claimer_receive_token_account.is_some() && vault.is_some() && vault_authority.is_some() && token_program.is_some() } else { user_data.is_some() },
        constraint = if escrow_state.pay_in { escrow_state.offerer == *initializer.key } else { escrow_state.claimer == *initializer.key },
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
    pub fn into_transfer_to_pda_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.initializer_deposit_token_account.to_account_info(),
            to: self.vault.to_account_info(),
            authority: self.initializer.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> Withdraw<'info> {
    pub fn into_transfer_to_initializer_context(
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
    pub fn into_transfer_to_pda_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.initializer_deposit_token_account.to_account_info(),
            to: self.vault.to_account_info(),
            authority: self.offerer.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> Refund<'info> {
    pub fn into_transfer_to_initializer_context(
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
    pub fn into_transfer_to_claimer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.as_ref().unwrap().to_account_info(),
            to: self.claimer_receive_token_account.as_ref().unwrap().to_account_info(),
            authority: self.vault_authority.as_ref().unwrap().clone(),
        };
        CpiContext::new(self.token_program.as_ref().unwrap().to_account_info(), cpi_accounts)
    }
}
