use anchor_lang::prelude::*;
use crate::*;
use crate::USER_DATA_SEED;
use crate::SwapType;

#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct Deposit<'info> {
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
        seeds = [USER_DATA_SEED, initializer.to_account_info().key.as_ref(), mint.to_account_info().key.as_ref()],
        bump,
        payer = initializer,
        space = UserAccount::SPACE
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

    /// CHECK: This account is not being read from, it is only an authority for the contract token vaults
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    
    //Required data
    pub mint: Account<'info, Mint>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>
}

#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub initializer: Signer<'info>,

    //Account of the token for initializer
    #[account(mut)]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,

    //Account holding the tokens
    #[account(
        mut,
        seeds = [USER_DATA_SEED, initializer.to_account_info().key.as_ref(), mint.to_account_info().key.as_ref()],
        bump = user_data.bump,
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

    /// CHECK: This account is not being read from, it is only an authority for the contract token vaults
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,

    //Required data
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>
}

#[derive(Accounts)]
#[instruction(initializer_amount: u64, expiry: u64, escrow_seed: [u8; 32], kind: SwapType, confirmations: u16, auth_expiry: u64, escrow_nonce: u64, pay_out: bool)]
pub struct InitializePayIn<'info> {
    #[account(mut)]
    pub offerer: Signer<'info>,
    pub claimer: Signer<'info>,

    //Account of the token for initializer
    #[account(
         mut,
         constraint = initializer_deposit_token_account.amount >= initializer_amount,
         token::mint = mint
    )]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,

    //Data storage account
    #[account(
        init,
        seeds = [b"state".as_ref(), escrow_seed.as_ref()],
        bump,
        payer = offerer,
        space = EscrowState::SPACE,
        //We need to verify existence of the recipient (either ATA or UserData PDA)
        constraint = if pay_out { claimer_token_account.is_some() } else { user_data_claimer.is_some() }
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

    /// CHECK: This account is not being read from, it is only an authority for the contract token vaults
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,

    //Required data
    pub mint: Account<'info, Mint>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    
    ////////////////////////////////////////
    //For NOT Pay out
    ////////////////////////////////////////
    #[account(
        seeds = [USER_DATA_SEED, claimer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump = user_data_claimer.bump
    )]
    pub user_data_claimer: Option<Account<'info, UserAccount>>,

    ////////////////////////////////////////
    //For pay out
    ////////////////////////////////////////
    #[account(
        token::mint = mint
    )]
    pub claimer_token_account: Option<Account<'info, TokenAccount>>,
}

#[derive(Accounts)]
#[instruction(initializer_amount: u64, expiry: u64, escrow_seed: [u8; 32], kind: SwapType, confirmations: u16, auth_expiry: u64, escrow_nonce: u64, pay_out: bool)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub claimer: Signer<'info>,
    pub offerer: Signer<'info>,

    //Account of the token for initializer
    #[account(
        mut,
        seeds = [USER_DATA_SEED, offerer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump = user_data.bump,
        constraint = user_data.amount >= initializer_amount
    )]
    pub user_data: Account<'info, UserAccount>,
    
    //Data storage account
    #[account(
        init,
        seeds = [b"state".as_ref(), escrow_seed.as_ref()],
        bump,
        payer = claimer,
        space = EscrowState::SPACE,
        //We need to verify existence of the recipient (either ATA or UserData PDA)
        constraint = if pay_out { claimer_token_account.is_some() } else { user_data_claimer.is_some() }
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    //Required data
    pub mint: Account<'info, Mint>,
    pub system_program: Program<'info, System>,

    ////////////////////////////////////////
    //For NOT Pay out
    ////////////////////////////////////////
    #[account(
        seeds = [USER_DATA_SEED, claimer.key.as_ref(), mint.to_account_info().key.as_ref()],
        bump = user_data_claimer.bump
    )]
    pub user_data_claimer: Option<Account<'info, UserAccount>>,
    
    ////////////////////////////////////////
    //For pay out
    ////////////////////////////////////////
    #[account(
        token::mint = mint
    )]
    pub claimer_token_account: Option<Account<'info, TokenAccount>>
}

#[derive(Accounts)]
pub struct Refund<'info> {
    ////////////////////////////////////////
    //Main data
    ////////////////////////////////////////
    #[account(mut)]
    pub offerer: Signer<'info>,

    /// CHECK: We are only transfering lamports to this account, we are not reading or writing data.
    #[account(mut)]
    pub claimer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = !escrow_state.data.pay_in,
        constraint = escrow_state.data.pay_out || user_data_claimer.is_some()
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    //User data account of the offerer, funds are refunded there
    #[account(
        mut,
        seeds = [USER_DATA_SEED, offerer.key.as_ref(), escrow_state.mint.as_ref()],
        bump = user_data.bump,
    )]
    pub user_data: Account<'info, UserAccount>,

    ////////////////////////////////////////
    //For NOT Pay out
    ////////////////////////////////////////
    //User data account of the claimer, used to lower his reputation
    #[account(
        mut,
        seeds = [USER_DATA_SEED, claimer.key.as_ref(), escrow_state.mint.as_ref()],
        bump = user_data_claimer.bump,
    )]
    pub user_data_claimer: Option<Account<'info, UserAccount>>,

    ////////////////////////////////////////
    //For Refund with signature
    ////////////////////////////////////////
    /// CHECK: We are not reading nor writing to this account, it is used to verify the previous IX in the transaction and its address is fixed to IX_ID
    #[account(address = IX_ID)]
    pub ix_sysvar: Option<AccountInfo<'info>>
}

#[derive(Accounts)]
pub struct RefundPayIn<'info> {
    ////////////////////////////////////////
    //Main data
    ////////////////////////////////////////
    #[account(mut)]
    pub offerer: Signer<'info>,

    /// CHECK: We are only transfering lamports to this account, we are not reading or writing data.
    #[account(mut)]
    pub claimer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = escrow_state.offerer == *offerer.key,
        constraint = escrow_state.claimer == *claimer.key,
        constraint = escrow_state.data.pay_in,
        constraint = escrow_state.initializer_deposit_token_account == *initializer_deposit_token_account.to_account_info().key,
        constraint = escrow_state.data.pay_out || user_data_claimer.is_some()
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Account<'info, TokenAccount>,
    
    /// CHECK: This account is not being read from, it is only an authority for the contract token vaults
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    
    #[account(mut)]
    pub initializer_deposit_token_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,

    ////////////////////////////////////////
    //For NOT Pay out
    ////////////////////////////////////////
    //User data account of the claimer, used to lower his reputation
    #[account(
        mut,
        seeds = [USER_DATA_SEED, claimer.key.as_ref(), escrow_state.mint.as_ref()],
        bump = user_data_claimer.bump,
    )]
    pub user_data_claimer: Option<Account<'info, UserAccount>>,

    ////////////////////////////////////////
    //For Refund with signature
    ////////////////////////////////////////
    /// CHECK: We are not reading nor writing to this account, it is used to verify the previous IX in the transaction and its address is fixed to IX_ID
    #[account(address = IX_ID)]
    pub ix_sysvar: Option<AccountInfo<'info>>
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    /// CHECK: We are only transfering lamports to this account, we are not reading or writing data.
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = !escrow_state.data.pay_out,
        constraint = if escrow_state.data.pay_in { escrow_state.offerer == *initializer.key } else { escrow_state.claimer == *initializer.key },
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    /// CHECK: We are not reading nor writing to this account, it is used to verify the previous IX in the transaction and its address is fixed to IX_ID
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,
    
    //Account of the claimer to claim the tokens to
    #[account(
        mut,
        seeds = [USER_DATA_SEED, escrow_state.claimer.key().as_ref(), escrow_state.mint.as_ref()],
        bump = user_data.bump
    )]
    pub user_data: Box<Account<'info, UserAccount>>,

    ///////////////////////////////////////////
    //For Using external data account
    ///////////////////////////////////////////
    #[account(mut)]
    pub data: Option<UncheckedAccount<'info>>,
}

#[derive(Accounts)]
pub struct ClaimPayOut<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    /// CHECK: We are only transfering lamports to this account, we are not reading or writing data.
    #[account(mut)]
    pub initializer: AccountInfo<'info>,

    #[account(
        mut,
        constraint = escrow_state.claimer_token_account == claimer_receive_token_account.key(),
        constraint = escrow_state.data.pay_out,
        constraint = if escrow_state.data.pay_in { escrow_state.offerer == *initializer.key } else { escrow_state.claimer == *initializer.key },
    )]
    pub escrow_state: Box<Account<'info, EscrowState>>,

    /// CHECK: We are not reading nor writing to this account, it is used to verify the previous IX in the transaction and its address is fixed to IX_ID
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,
    
    #[account(mut)]
    pub claimer_receive_token_account: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"vault".as_ref(), escrow_state.mint.as_ref()],
        bump,
    )]
    pub vault: Box<Account<'info, TokenAccount>>,
    
    /// CHECK: This account is not being read from, it is only an authority for the contract token vaults
    #[account(
        seeds = [b"authority".as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,

    ///////////////////////////////////////////
    //For Using external data account
    ///////////////////////////////////////////
    #[account(mut)]
    pub data: Option<UncheckedAccount<'info>>,
}

#[derive(Accounts)]
pub struct InitData<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    //Data storage account
    #[account(mut)]
    pub data: Signer<'info>
}

#[derive(Accounts)]
pub struct WriteDataAlt<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    //Data storage account
    /// CHECK: This is checked in the instruction logic, the signer key has to be the first 32 bytes of the account data
    #[account(mut)]
    pub data: UncheckedAccount<'info>
}

#[derive(Accounts)]
pub struct CloseDataAlt<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    //Data storage account
    /// CHECK: This is checked in the instruction logic, the signer key has to be the first 32 bytes of the account data
    #[account(mut)]
    pub data: UncheckedAccount<'info>
}

impl<'info> Deposit<'info> {
    pub fn get_transfer_to_pda_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.initializer_deposit_token_account.to_account_info(),
            to: self.vault.to_account_info(),
            authority: self.initializer.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> Withdraw<'info> {
    pub fn get_transfer_to_initializer_context(
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
    pub fn get_transfer_to_pda_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.initializer_deposit_token_account.to_account_info(),
            to: self.vault.to_account_info(),
            authority: self.offerer.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

impl<'info> RefundPayIn<'info> {
    pub fn get_transfer_to_initializer_context(
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

impl<'info> ClaimPayOut<'info> {
    pub fn get_transfer_to_claimer_context(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: self.vault.to_account_info(),
            to: self.claimer_receive_token_account.to_account_info(),
            authority: self.vault_authority.clone(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}
