import * as anchor from "@project-serum/anchor";
import assert from "assert";
import { Program } from "@project-serum/anchor";
import { TOKEN_PROGRAM_ID, createMint, createAccount, mintTo, getAccount } from "@solana/spl-token";
import { TestAnchor } from "../target/types/test_anchor";
import { randomBytes, createHash } from "crypto";
import nacl from "tweetnacl";
import { BN } from "bn.js";
const { SystemProgram } = anchor.web3;
import { btcRelayIdl } from "./btc-relay-idl";


const program = anchor.workspace.TestAnchor as Program<TestAnchor>;
const commitment: anchor.web3.Commitment = "confirmed";
const provider = anchor.AnchorProvider.local();

const btcRelayProgram = new Program(btcRelayIdl as anchor.Idl, btcRelayIdl.metadata.address, provider);

const mainStateKeyBtcRelay = anchor.web3.PublicKey.findProgramAddressSync(
  [Buffer.from(anchor.utils.bytes.utf8.encode("state"))],
  btcRelayProgram.programId
)[0];


function programPaidBy(payer: anchor.web3.Keypair): anchor.Program {
  const newProvider = new anchor.AnchorProvider(provider.connection, new anchor.Wallet(payer), {});
  return new anchor.Program(program.idl as anchor.Idl, program.programId, newProvider)
}

const vaultSeed = "vault";
const userVaultSeed = "uservault";
const authoritySeed = "authority";
const mainStateSeed = "main_state";
const stateSeed = "state";

const blockHeader = {
  "chainWork": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,246,4,124,179,73,103,67,171,12,90,65],
  "header": {
      "version": 803938304,
      "reversedPrevBlockhash": [175,66,238,62,223,120,199,205,32,232,48,188,230,120,0,189,3,150,185,68,39,11,6,0,0,0,0,0,0,0,0,0],
      "merkleRoot": [130,200,49,239,89,214,161,244,158,191,18,204,232,15,241,32,124,19,126,237,112,109,120,208,200,20,169,77,164,91,45,92],
      "timestamp": 1677185675,
      "nbits": 386347065,
      "nonce": 3532953932
  },
  "lastDiffAdjustment": 1676188371,
  "blockheight": 778015,
  "prevBlockTimestamps": [1677181976,1677182599,1677183328,1677183851,1677183934,1677183999,1677184099,1677184431,1677185180,1677185276]
};

const txData = {
  "block_height":778015,
  "txId": "802158ec4fba58cdab1e4a2bbcc7e5f15a43fe6094fc626595b4a47dcad9b407",
  "merkle":["7a522f9be079d6dfca6643e7ba3f56baa0456abf4206dd8cbf827f0f025947cf","e0be523d916676659c6ed450926884a3d3cc9556ec6673338caadbb269dcf13d","0095710c38ae56e508300e336776e66d3d35dc3e526c1d997ba192f1482cf962","41b88230ff52158056e582501053d7dfd793c2d6c389cff0dab53ffc933530f3","4e83357a427367922e3744c734d08c65566c8af79d490f4a4eba6ab6182acb92","86f5a39c51ce7cc1323ef2c15308bc6fe78bb40da59c73fe4598166b75f8a1e4","da1fe8ea07a1dcdd701284763db3c3683c2aa38e7a93bda2bfb6ab2c4da43f0c","f579074af93f6fdddd9a26381377cd1a273a460879e53142a8bd54c66ff23cd0","d452f67c92a6af41a7984f5c1a274b095dda988e97a9d86becb2eaa41aceb5e1","03996a2a3b2baa176b4acfca05c353a2ae4efe03a514c1046e23bcd58abef7ef","6d1776e2269aaf068def21b3e829316a339a1598779a286c102d864b77fad7ac"],
  "pos":12,
  "rawTx": "02000000000101b3623a34555e2877ea449f82908f59a71d1fbcc8cde1dc9e134e05cefec702b00400000000fdffffff04e09b0b000000000017a91401795c0c6dc01d1630f1bb70055c822464380fe08788ed1b00000000001976a9141b140adf17bd53b6b9118b3275d5d28565b4f1f088ac3ee63a00000000001976a914a8059c8980d359515499db26a459caf4fd6aebc688ac8a5dbc2500000000160014f60834ef165253c571b11ce9fa74e46692fc5ec1024830450221008b77e7383dd82c6bdeb508d7ed351cc741ef65e7d94203c538df644f53ba219a0220262bf0c4a899830a0344de402bcd42a4b21846820b632f932bc837c53ea13abb0121026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea28600000000",
  "vout": 3,
  "amount": 633101706,
  "outputScript": "0014f60834ef165253c571b11ce9fa74e46692fc5ec1"
};

const hash2 = createHash("sha256").update(Buffer.concat([
  new BN(txData.amount).toBuffer("le", 8),
  Buffer.from(txData.outputScript, "hex")
])).digest();

const escrowStateKey2 = anchor.web3.PublicKey.findProgramAddressSync(
  [Buffer.from(anchor.utils.bytes.utf8.encode(stateSeed)), hash2],
  program.programId
)[0];


describe("test-anchor", () => {
  // Configure the client to use the local cluster.

  // Configure the client to use the local cluster.
  //anchor.setProvider(provider);

  const program = anchor.workspace.TestAnchor as Program<TestAnchor>;
  const publicKey = provider.wallet.publicKey;

  const payer = anchor.web3.Keypair.generate();
  const mintAuthority = anchor.web3.Keypair.generate();
  const initializer = anchor.web3.Keypair.generate();
  const claimer = anchor.web3.Keypair.generate();

  const secret = randomBytes(32);
  const hash = createHash("sha256").update(secret).digest();

  // Derive PDAs: escrowStateKey, vaultKey, vaultAuthorityKey
  const escrowStateKey = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from(anchor.utils.bytes.utf8.encode(stateSeed)), hash],
    program.programId
  )[0];

  const initializerAmount = 500;

  const deposit1Amount = 100;
  const deposit2Amount = 100;
  const initializePayInAmount = 100;
  const initializeAmount = 100;

  const mainStateKey = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from(anchor.utils.bytes.utf8.encode(mainStateSeed))],
    program.programId
  )[0];

  let vaultKey; 

  let userVaultKey;

  const vaultAuthorityKey = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from(anchor.utils.bytes.utf8.encode(authoritySeed))],
    program.programId
  )[0];

  let mintA: anchor.web3.PublicKey;
  let initializerTokenAccountA;
  let claimerTokenAccountA;

  it("Initialize program state", async () => {
    // 1. Airdrop 1 SOL to payer
    const signature = await provider.connection.requestAirdrop(payer.publicKey, 1000000000);
    const latestBlockhash = await provider.connection.getLatestBlockhash();
    await provider.connection.confirmTransaction(
      {
        signature,
        ...latestBlockhash,
      },
      commitment
    );

    // 2. Fund main roles: initializer and claimer
    const fundingTx = new anchor.web3.Transaction();
    fundingTx.add(
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: initializer.publicKey,
        lamports: 400000000,
      }),
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: claimer.publicKey,
        lamports: 400000000,
      })
    );

    await provider.sendAndConfirm(fundingTx, [payer]);

    // 3. Create dummy token mints: mintA and mintB
    mintA = await createMint(provider.connection, payer, mintAuthority.publicKey, null, 0);

    // 4. Create token accounts for dummy token mints and both main roles
    initializerTokenAccountA = await createAccount(provider.connection, initializer, mintA, initializer.publicKey);
    claimerTokenAccountA = await createAccount(provider.connection, claimer, mintA, claimer.publicKey);

    // 5. Mint dummy tokens to initializerTokenAccountA and claimerTokenAccountB
    await mintTo(provider.connection, initializer, mintA, initializerTokenAccountA, mintAuthority, initializerAmount);

    const fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);

    assert.ok(Number(fetchedInitializerTokenAccountA.amount) == initializerAmount);

    userVaultKey = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from(anchor.utils.bytes.utf8.encode(userVaultSeed)), initializer.publicKey.toBuffer(), mintA.toBuffer()],
      program.programId
    )[0];

    vaultKey = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from(anchor.utils.bytes.utf8.encode(vaultSeed)), mintA.toBuffer()],
      program.programId
    )[0];

  });

  it("Deposit 1 to program", async () => {
    let result = await programPaidBy(initializer).methods
      .deposit(new anchor.BN(deposit1Amount))
      .accounts({
        initializer: initializer.publicKey,
        userData: userVaultKey,
        mint: mintA,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        initializerDepositTokenAccount: initializerTokenAccountA,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([initializer])
      .transaction();

    const signature = await provider.sendAndConfirm(result, [initializer]);

    let fetchedVault = await program.account.userAccount.fetch(userVaultKey);
    const fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);

    // Check that the new owner is the PDA.
    //assert.ok(fetchedVault.owner.equals(vaultAuthorityKey));
    assert.ok(Number(fetchedVault.amount)===deposit1Amount);
  });

  it("Deposit 2 to program", async () => {
    let result = await programPaidBy(initializer).methods
      .deposit(new anchor.BN(deposit2Amount))
      .accounts({
        initializer: initializer.publicKey,
        userData: userVaultKey,
        mint: mintA,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        initializerDepositTokenAccount: initializerTokenAccountA,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([initializer])
      .transaction();

    const signature = await provider.sendAndConfirm(result, [initializer]);

    let fetchedVault = await program.account.userAccount.fetch(userVaultKey);
    const fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);

    // Check that the new owner is the PDA.
    //assert.ok(fetchedVault.owner.equals(vaultAuthorityKey));
    assert.ok(Number(fetchedVault.amount)===deposit1Amount+deposit2Amount);
  });

  it("Deposit/Withdraw to program", async () => {
    let result = await programPaidBy(initializer).methods
      .deposit(new anchor.BN(deposit2Amount))
      .accounts({
        initializer: initializer.publicKey,
        userData: userVaultKey,
        mint: mintA,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        initializerDepositTokenAccount: initializerTokenAccountA,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([initializer])
      .transaction();

    let signature = await provider.sendAndConfirm(result, [initializer]);

    let fetchedVault = await program.account.userAccount.fetch(userVaultKey);
    let fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);

    // Check that the new owner is the PDA.
    //assert.ok(fetchedVault.owner.equals(vaultAuthorityKey));
    assert.ok(Number(fetchedVault.amount)===deposit1Amount+deposit2Amount+deposit2Amount);
    assert.ok(Number(fetchedInitializerTokenAccountA.amount)===initializerAmount-deposit1Amount-deposit2Amount-deposit2Amount);
    
    result = await programPaidBy(initializer).methods
      .withdraw(new anchor.BN(deposit2Amount))
      .accounts({
        initializer: initializer.publicKey,
        userData: userVaultKey,
        mint: mintA,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        initializerDepositTokenAccount: initializerTokenAccountA,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([initializer])
      .transaction();

    signature = await provider.sendAndConfirm(result, [initializer]);
    
    fetchedVault = await program.account.userAccount.fetch(userVaultKey);
    fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);

    assert.ok(Number(fetchedVault.amount)===deposit1Amount+deposit2Amount);
    assert.ok(Number(fetchedInitializerTokenAccountA.amount)===initializerAmount-deposit1Amount-deposit2Amount);
  });

  /*it("Withdraw from program", async () => {
    let result = await programPaidBy(initializer).methods
      .withdraw(new anchor.BN(initializerAmount))
      .accounts({
        initializer: initializer.publicKey,
        uservault: userVaultKey,
        vaultAuthority: vaultAuthorityKey,
        mint: mintA,
        initializerDepositTokenAccount: initializerTokenAccountA,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([initializer])
      .transaction();

    const signature = await provider.sendAndConfirm(result, [initializer]);

    const fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);

    assert.ok(Number(fetchedInitializerTokenAccountA.amount) == initializerAmount);
  });*/

  const initWithoutSignatureOnchain = async (expiryTime?: number) => {
    if(expiryTime==null) expiryTime = Math.floor(Date.now()/1000)+(12*60*60);

    let result = await programPaidBy(initializer).methods
      .offererInitializePayIn(new anchor.BN(initializeAmount), new anchor.BN(expiryTime), hash2, new BN(1), new BN(3))
      .accounts({
        initializer: initializer.publicKey,
        initializerDepositTokenAccount: initializerTokenAccountA,
        claimer: claimer.publicKey,
        escrowState: escrowStateKey2,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,        
        mainState: mainStateKey,
        mint: mintA,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID
      })
      .signers([initializer])
      .instruction();

    const tx = new anchor.web3.Transaction();
    tx.add(result);

    await provider.sendAndConfirm(tx, [initializer], {
      skipPreflight: true
    });

    let fetchedEscrowState = await program.account.escrowState.fetch(escrowStateKey2);


    // Check that the values in the escrow account match what we expect.
    assert.ok(fetchedEscrowState.initializerKey.equals(initializer.publicKey));
    assert.ok(fetchedEscrowState.initializerAmount.toNumber() == initializeAmount);
    assert.ok(fetchedEscrowState.claimer.equals(claimer.publicKey));
    assert.ok(fetchedEscrowState.payIn);
    assert.ok(fetchedEscrowState.expiry.toNumber() == expiryTime);
    assert.ok(Buffer.from(fetchedEscrowState.hash).equals(hash2));

    return expiryTime;
  }

  const initWithoutSignature = async (expiryTime?: number) => {
    if(expiryTime==null) expiryTime = Math.floor(Date.now()/1000)+(12*60*60);

    
    let result = await programPaidBy(initializer).methods
      .offererInitializePayIn(new anchor.BN(initializeAmount), new anchor.BN(expiryTime), hash, new BN(0), new BN(0))
      .accounts({
        initializer: initializer.publicKey,
        initializerDepositTokenAccount: initializerTokenAccountA,
        claimer: claimer.publicKey,
        escrowState: escrowStateKey,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,        
        mainState: mainStateKey,
        mint: mintA,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID
      })
      .signers([initializer])
      .instruction();

    const tx = new anchor.web3.Transaction();
    tx.add(result);

    await provider.sendAndConfirm(tx, [initializer], {
      skipPreflight: true
    });

    let fetchedEscrowState = await program.account.escrowState.fetch(escrowStateKey);


    // Check that the values in the escrow account match what we expect.
    assert.ok(fetchedEscrowState.initializerKey.equals(initializer.publicKey));
    assert.ok(fetchedEscrowState.initializerAmount.toNumber() == initializeAmount);
    assert.ok(fetchedEscrowState.claimer.equals(claimer.publicKey));
    assert.ok(fetchedEscrowState.payIn);
    assert.ok(fetchedEscrowState.expiry.toNumber() == expiryTime);
    assert.ok(Buffer.from(fetchedEscrowState.hash).equals(hash));

    return expiryTime;
  }

  const initEscrowWithSignature = async (expiryTime?: number) => {
    if(expiryTime==null) expiryTime = Math.floor(Date.now()/1000)+(12*60*60);

    const authExpiry = Math.floor(Date.now()/1000)+(10*60);

    const fetchedAccount = await program.account.userAccount.fetch(userVaultKey);

    const nonce = fetchedAccount.nonce.add(new BN(1));

    const messageBuffers = [
      null,
      Buffer.alloc(8),
      null,
      null,
      Buffer.alloc(8),
      Buffer.alloc(8),
      null,
      Buffer.alloc(1),
      Buffer.alloc(2),
      Buffer.alloc(8)
    ];

    messageBuffers[0] = Buffer.from("initialize", "ascii");
    messageBuffers[1].writeBigUInt64LE(BigInt(nonce.toString(10)));
    messageBuffers[2] = mintA.toBuffer();
    messageBuffers[3] = claimer.publicKey.toBuffer();
    messageBuffers[4].writeBigUInt64LE(BigInt(initializeAmount));
    messageBuffers[5].writeBigUInt64LE(BigInt(expiryTime));
    messageBuffers[6] = hash;
    messageBuffers[7].writeUint8(0);
    messageBuffers[8].writeUint16LE(0);
    messageBuffers[9].writeBigUInt64LE(BigInt(authExpiry));

    const messageBuffer = Buffer.concat(messageBuffers);
    
    const signature = nacl.sign.detached(messageBuffer, initializer.secretKey);

    let result = await programPaidBy(initializer).methods
      .offererInitialize(nonce, new anchor.BN(initializeAmount), new anchor.BN(expiryTime), hash, new BN(0), new BN(0), new anchor.BN(authExpiry), Buffer.from(signature))
      .accounts({
        initializer: claimer.publicKey,
        offerer: initializer.publicKey,
        claimer: claimer.publicKey,
        mint: mintA,
        mainState: mainStateKey,
        userData: userVaultKey,
        escrowState: escrowStateKey,
        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      })
      .signers([initializer])
      .instruction();

    const signatureVerificationInstruction = anchor.web3.Ed25519Program.createInstructionWithPublicKey({
      message: messageBuffer,
      publicKey: initializer.publicKey.toBuffer(),
      signature
    });

    // console.log(signatureVerificationInstruction);

    const tx = new anchor.web3.Transaction();
    tx.add(signatureVerificationInstruction);
    tx.add(result);

    // console.log(tx);
    // console.log(tx.instructions);

    await provider.sendAndConfirm(tx, [claimer], {
      skipPreflight: true
    });

    let fetchedVault = await getAccount(provider.connection, vaultKey);
    let fetchedEscrowState = await program.account.escrowState.fetch(escrowStateKey);

    // Check that the new owner is the PDA.
    assert.ok(fetchedVault.owner.equals(vaultAuthorityKey));

    // Check that the values in the escrow account match what we expect.
    assert.ok(fetchedEscrowState.initializerKey.equals(claimer.publicKey));
    assert.ok(fetchedEscrowState.initializerAmount.toNumber() == initializeAmount);
    assert.ok(fetchedEscrowState.claimer.equals(claimer.publicKey));
    assert.ok(!fetchedEscrowState.payIn);
    assert.ok(fetchedEscrowState.expiry.toNumber() == expiryTime);
    assert.ok(Buffer.from(fetchedEscrowState.hash).equals(hash));

    return expiryTime;
  };

  it("Initialize escrow without signature and claim on-chain", async () => {
    await initWithoutSignatureOnchain();

    console.log("Verify TX: ", btcRelayProgram.methods);

    const reversedTxId = Buffer.from(txData.txId, "hex").reverse();
    const rawTx = Buffer.from(txData.rawTx, "hex");

    const txDataKey = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from(anchor.utils.bytes.utf8.encode("data")), reversedTxId, claimer.publicKey.toBuffer()],
      program.programId
    )[0];

    try {
      const fetchedDataAccount = await program.account.data.fetch(txDataKey);
      //Exists
      const eraseTx = await programPaidBy(claimer).methods
        .closeData(reversedTxId)
        .accounts({
          signer: claimer.publicKey,
          data: txDataKey
        })
        .signers([claimer])
        .rpc({
          skipPreflight: true
        });
    
      console.log("Prev TX data erased: ", eraseTx);
    } catch (e) {

    }

    const txDataTx = await programPaidBy(claimer).methods
      .writeData(reversedTxId, new BN(4+rawTx.length), Buffer.concat([
        new BN(txData.vout).toBuffer("le", 4),
        rawTx
      ]))
      .accounts({
        signer: claimer.publicKey,
        data: txDataKey,
        systemProgram: SystemProgram.programId
      })
      .signers([claimer])
      .rpc({
        skipPreflight: true
      });

    console.log("TX data save account created: ", txDataTx);

    const verifyIx = await btcRelayProgram.methods
      .verifyTransaction(
        reversedTxId,
        3,
        txData.pos,
        txData.merkle.map(e => Buffer.from(e, "hex").reverse()),
        blockHeader
      )
      .accounts({
        signer: claimer.publicKey,
        mainState: mainStateKeyBtcRelay
      })
      .signers([claimer])
      .instruction();

    const ix = await programPaidBy(claimer).methods
      .claimerClaimPayOutWithExtData(reversedTxId)
      .accounts({
        claimer: claimer.publicKey,
        claimerReceiveTokenAccount: claimerTokenAccountA,
        offerer: initializer.publicKey,
        initializer: initializer.publicKey,
        escrowState: escrowStateKey2,
        vault: vaultKey,
        data: txDataKey,
        vaultAuthority: vaultAuthorityKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      })
      .signers([claimer])
      .instruction();

    const tx = new anchor.web3.Transaction();
    tx.add(verifyIx);
    tx.add(ix);
    tx.feePayer = claimer.publicKey;
    tx.recentBlockhash = (await provider.connection.getRecentBlockhash()).blockhash;

    tx.sign(claimer);

    const solTxData = tx.serialize();

    await provider.connection.sendRawTransaction(solTxData, {
      skipPreflight: true
    });

    console.log(tx);
    console.log(solTxData.length);

    let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);

    assert.ok(Number(fetchedTakerTokenAccountA.amount) == initializeAmount);
  });

  return;

  it("Initialize escrow without signature and claim", async () => {
    await initWithoutSignature();

    const signature = await programPaidBy(claimer).methods
      .claimerClaimPayOut(secret)
      .accounts({
        claimer: claimer.publicKey,
        claimerReceiveTokenAccount: claimerTokenAccountA,
        offerer: initializer.publicKey,
        initializer: initializer.publicKey,
        escrowState: escrowStateKey,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      })
      .rpc();

    let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);

    assert.ok(Number(fetchedTakerTokenAccountA.amount) == initializeAmount);

    console.log("Current signature: ", signature);
    let signatures;
    while(signatures==null || !signatures.find(e => e.signature===signature)) {
      signatures = await provider.connection.getSignaturesForAddress(escrowStateKey, null, "confirmed");
      console.log(signatures);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    const coder = new anchor.BorshCoder(program.idl);
    const eventParser = new anchor.EventParser(program.programId, coder);

    const tx = await provider.connection.getTransaction(signature, {
      commitment: "confirmed"
    });

    console.log(tx.meta.logMessages);
    const events = eventParser.parseLogs(tx.meta.logMessages);
    console.log(events);

    for(let event of events) {
      console.log(event);
    }
  });

  it("Initialize escrow with signature and claim", async () => {
    await initEscrowWithSignature();

    const signature = await programPaidBy(claimer).methods
      .claimerClaimPayOut(secret)
      .accounts({
        claimer: claimer.publicKey,
        claimerReceiveTokenAccount: claimerTokenAccountA,
        offerer: initializer.publicKey,
        initializer: claimer.publicKey,
        escrowState: escrowStateKey,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      })
      .rpc();

    let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);

    assert.ok(Number(fetchedTakerTokenAccountA.amount) == initializeAmount);

    console.log("Current signature: ", signature);
    let signatures;
    while(signatures==null || !signatures.find(e => e.signature===signature)) {
      signatures = await provider.connection.getSignaturesForAddress(escrowStateKey, null, "confirmed");
      console.log(signatures);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    const coder = new anchor.BorshCoder(program.idl);
    const eventParser = new anchor.EventParser(program.programId, coder);

    const tx = await provider.connection.getTransaction(signature, {
      commitment: "confirmed"
    });

    console.log(tx.meta.logMessages);
    const events = eventParser.parseLogs(tx.meta.logMessages);
    console.log(events);

    for(let event of events) {
      console.log(event);
    }
  });

  // it("Initialize escrow with signature and refund payer", async () => {
  //   await initEscrowWithSignature();

  //   await programPaidBy(claimer).methods
  //     .claimerRefundPayer()
  //     .accounts({
  //       claimer: claimer.publicKey,
  //       initializerDepositTokenAccount: userVaultKey,
  //       offerer: initializer.publicKey,
  //       initializer: claimer.publicKey,
  //       escrowState: escrowStateKey,
  //       vault: vaultKey,
  //       vaultAuthority: vaultAuthorityKey,
  //       tokenProgram: TOKEN_PROGRAM_ID,
  //     })
  //     .rpc();

  //   let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);
  //   let fetchedUserVault = await getAccount(provider.connection, userVaultKey);

  //   assert.ok(Number(fetchedUserVault.amount) == deposit1Amount+deposit2Amount-initializeAmount);
  //   assert.ok(Number(fetchedTakerTokenAccountA.amount) == initializeAmount);
  // });

  it("Initialize escrow with signature and refund payer with signature", async () => {
    const expiryTime = await initEscrowWithSignature();

    const authExpiry = Math.floor(Date.now()/1000)+(10*60);

    const messageBuffers = [
      null,
      Buffer.alloc(8),
      Buffer.alloc(8),
      null,
      Buffer.alloc(8)
    ];

    messageBuffers[0] = Buffer.from("refund", "ascii");
    messageBuffers[1].writeBigUInt64LE(BigInt(initializeAmount));
    messageBuffers[2].writeBigUInt64LE(BigInt(expiryTime));
    messageBuffers[3] = hash;
    messageBuffers[4].writeBigUInt64LE(BigInt(authExpiry));

    const messageBuffer = Buffer.concat(messageBuffers);
    
    const signature = nacl.sign.detached(messageBuffer, claimer.secretKey);

    const signatureVerificationInstruction = anchor.web3.Ed25519Program.createInstructionWithPublicKey({
      message: messageBuffer,
      publicKey: claimer.publicKey.toBuffer(),
      signature
    });

    const result = await programPaidBy(initializer).methods
      .offererRefundWithSignature(new anchor.BN(authExpiry), Buffer.from(signature))
      .accounts({
        claimer: claimer.publicKey,
        userData: userVaultKey,
        offerer: initializer.publicKey,
        initializer: claimer.publicKey,
        escrowState: escrowStateKey,
        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      })
      .instruction();

    const tx = new anchor.web3.Transaction();
    tx.add(signatureVerificationInstruction);
    tx.add(result);
    await provider.sendAndConfirm(tx, [initializer], {
      skipPreflight: true
    });

    let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);
    let fetchedUserVault = await program.account.userAccount.fetch(userVaultKey);

    assert.ok(Number(fetchedUserVault.amount) == deposit1Amount+deposit2Amount-initializeAmount);
    assert.ok(Number(fetchedTakerTokenAccountA.amount) == initializeAmount);
  });

  it("Initialize escrow with signature and refund (timed out)", async () => {
    await initEscrowWithSignature(Math.floor(Date.now()/1000)-1200); //Already expired

    await programPaidBy(initializer).methods
      .offererRefund()
      .accounts({
        offerer: initializer.publicKey,
        initializer: claimer.publicKey,
        userData: userVaultKey,
        escrowState: escrowStateKey
      })
      .rpc();

    let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);
    let fetchedUserVault = await program.account.userAccount.fetch(userVaultKey);

    assert.ok(Number(fetchedUserVault.amount) == deposit1Amount+deposit2Amount-initializeAmount);
    assert.ok(Number(fetchedTakerTokenAccountA.amount) == initializeAmount);
  });

  it("Initialize escrow with signature and refund (not timed out yet)", async () => {
    await initEscrowWithSignature();

    let failed = false;
    try {
      await programPaidBy(initializer).methods
        .offererRefund()
        .accounts({
          offerer: initializer.publicKey,
          initializer: claimer.publicKey,
          userData: userVaultKey,
          escrowState: escrowStateKey
        })
        .rpc();
    } catch (e) {
      failed = true;
    }

    assert.ok(failed);
  });

  /*it("Initialize escrow", async () => {
    const expiryTime = Math.floor(Date.now()/1000)-300;

    let result = await programPaidBy(initializer).methods
      .offererInitializePayIn(new anchor.BN(initializerAmount), new anchor.BN(expiryTime), hash)
      .accounts({
        initializer: initializer.publicKey,
        claimer: claimer.publicKey,
        vault: vaultKey,
        mint: mintA,
        initializerDepositTokenAccount: initializerTokenAccountA,
        escrowState: escrowStateKey,
        systemProgram: anchor.web3.SystemProgram.programId,
        vaultAuthority: vaultAuthorityKey,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([initializer])
      .transaction();

    const signature = await provider.sendAndConfirm(result, [initializer]);

    let fetchedVault = await getAccount(provider.connection, vaultKey);
    let fetchedEscrowState = await program.account.escrowState.fetch(escrowStateKey);

    // Check that the new owner is the PDA.
    assert.ok(fetchedVault.owner.equals(vaultAuthorityKey));

    // Check that the values in the escrow account match what we expect.
    assert.ok(fetchedEscrowState.initializerKey.equals(initializer.publicKey));
    assert.ok(fetchedEscrowState.initializerAmount.toNumber() == initializerAmount);
    assert.ok(fetchedEscrowState.claimer.equals(claimer.publicKey));
    assert.ok(fetchedEscrowState.initializerDepositTokenAccount.equals(initializerTokenAccountA));
    assert.ok(fetchedEscrowState.expiry.toNumber() == expiryTime);
    assert.ok(Buffer.from(fetchedEscrowState.hash).equals(hash));
  });*/

  /*it("Exchange escrow state", async () => {
    await programPaidBy(claimer).methods
      .claimerClaim(secret)
      .accounts({
        claimer: claimer.publicKey,
        claimerReceiveTokenAccount: claimerTokenAccountA,
        offerer: initializer.publicKey,
        initializer: claimer.publicKey,
        escrowState: escrowStateKey,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();

    let fetchedVaultAccount = await getAccount(provider.connection, vaultKey);
    let fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);
    let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);

    assert.ok(Number(fetchedTakerTokenAccountA.amount) == initializerAmount);
    assert.ok(Number(fetchedInitializerTokenAccountA.amount) == 0);
    assert.ok(Number(fetchedVaultAccount.amount) == 0);
  });*/

  /*it("Cancel escrow state", async () => {
    await programPaidBy(initializer).methods
      .offererRefund()
      .accounts({
        initializer: initializer.publicKey,
        initializerDepositTokenAccount: initializerTokenAccountA,
        escrowState: escrowStateKey,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();

    let fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);
    let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);

    assert.ok(Number(fetchedInitializerTokenAccountA.amount) == initializerAmount);
    assert.ok(Number(fetchedTakerTokenAccountA.amount) == 0);
  });*/

  /*it("Cancel claimer escrow state", async () => {
    await programPaidBy(claimer).methods
      .claimerRefundPayer()
      .accounts({
        claimer: claimer.publicKey,
        initializer: initializer.publicKey,
        initializerDepositTokenAccount: initializerTokenAccountA,
        escrowState: escrowStateKey,
        vault: vaultKey,
        vaultAuthority: vaultAuthorityKey,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();

    let fetchedInitializerTokenAccountA = await getAccount(provider.connection, initializerTokenAccountA);
    let fetchedTakerTokenAccountA = await getAccount(provider.connection, claimerTokenAccountA);

    assert.ok(Number(fetchedInitializerTokenAccountA.amount) == initializerAmount);
    assert.ok(Number(fetchedTakerTokenAccountA.amount) == 0);
  });*/

  /*it("Is initialized!", async () => {
    // Add your test here.

    //const myAccount = anchor.web3.Keypair.generate();

    const hash = "test3";

    const [PDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from(hash)],
      program.programId
    );

    console.log("PDA: ", PDA);

    await program.methods
      .remove(hash)
      .accounts({
        escrow: PDA,
        signer: publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  
    const account = await program.account.myAccount.fetch(PDA);

    console.log("Account: ", account)

    assert.ok(account.data.eq(new anchor.BN(20)));

    // Store the account for the next test.
    //_myAccount = myAccount;
  });*/

});
