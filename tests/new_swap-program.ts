
//Deposit
//SUCCESS:
//Deposit uninitialized vault
//Deposit initialized vault
//Deposit uninitialized user data
//Deposit initialized user data
//FAIL:
//Different signer
//Uninitialized ATA
//ATA for other mint
//ATA with not enough funds
//UserAccount of other signer
//UserAccount of other mint
//UserAccount of other signer & mint
//Bad mint vault
//Wrong vault authority

//Withdraw
//SUCCESS:
//Initialized user data and signer_ata
//FAIL:
//Different signer
//Uninitialized signer_ata
//signer_ata for other mint
//UserAccount with not enough funds
//UserAccount of other signer
//UserAccount of other mint
//UserAccount of other signer & mint
//Bad mint vault
//Wrong vault authority

//InitializePayIn
//SUCCESS:
//FAIL:
//data.pay_in = false
//Claimer not signed
//Offerer not signed
//Uninitialized offerer ATA
//offerer ATA for other mint
//offerer ATA with not enough funds
//Wrong escrow state
//Bad mint vault
//Wrong vault authority
//Auth expiry expired
//data.confirmations > 200
//data.kind!=nonced & nonce > 0
//#IF data.pay_out = true
//  Uninitialized claimer_ata
//  claimer_ata of other mint
//#ELSE
//  Uninitialized claimer_user_data
//  UserAccount of other signer
//  UserAccount of other mint
//  UserAccount of other signer & mint
//#END

//Initialize
//SUCCESS:
//FAIL:
//data.pay_in = true
//Claimer not signed
//Offerer not signed
//Uninitialized offerer_user_data
//offerer_user_data with not enough funds
//offerer_user_data of other signer
//offerer_user_data of other mint
//offerer_user_data of other signer & mint
//Wrong escrow state
//Auth expiry expired
//data.confirmations > 200
//data.kind!=nonced & nonce > 0
//#IF data.pay_out = true
//  Uninitialized claimer_ata
//  claimer_ata of other mint
//#ELSE
//  Uninitialized claimer_user_data
//  claimer_user_data of other signer
//  claimer_user_data of other mint
//  claimer_user_data of other signer & mint
//#END

//Refund
//SUCCESS:
//
//FAIL:
//Offerer not signed
//Wrong offerer
//Wrong claimer
//Wrong escrow_state (data.pay_in = true)
//Uninitialized offerer_user_data
//offerer_user_data with not enough funds
//offerer_user_data of other signer
//offerer_user_data of other mint
//offerer_user_data of other signer & mint
//#IF (data.pay_out = false)
//  Uninitialized claimer_user_data
//  claimer_user_data of other signer
//  claimer_user_data of other mint
//  claimer_user_data of other signer & mint
//#END
//#IF (auth_expiry != 0)
//  Wrong ix_sysvar
//  Expired auth
//  Data in verify sig IX is different than expected
//  Signer in verify sig IX is different than expected
//  Signer in verify sig IX is different than expected
//#ELSE
//  
//#END

