import { Keypair, SystemProgram, PublicKey, SignatureResult, SYSVAR_INSTRUCTIONS_PUBKEY, Transaction, Ed25519Program } from "@solana/web3.js";
import { AnchorProvider, EventParser, Program, workspace, Event, IdlEvents } from "@coral-xyz/anchor";
import { SwapProgram } from "../../target/types/swap_program";
import BN from "bn.js";
import nacl from "tweetnacl";
import { TokenMint, getNewMint } from "../utils/tokens";
import { RandomPDA, SwapEscrowState, SwapUserVault, SwapVault, SwapVaultAuthority } from "../utils/accounts";
import { Account, TOKEN_PROGRAM_ID, getAccount } from "@solana/spl-token";
import { assert } from "chai";
import { getInitializedUserData } from "../utils/userData";
import { randomBytes, createHash } from "crypto";
import { EscrowStateType, SwapData, SwapType, SwapTypeEnum, getInitializeDefaultDataNotPayIn, getInitializeDefaultDataPayIn, getInitializedEscrowState as _getInitializedEscrowState, initializeDefaultAmount, initializeExecuteNotPayIn, initializeExecutePayIn } from "../utils/escrowState";
import { BtcRelayMainState, btcRelayProgram } from "../btcrelay/accounts";
import { ParalelizedTest } from "../utils";

const program = workspace.SwapProgram as Program<SwapProgram>;
const provider: AnchorProvider = AnchorProvider.local();
const eventParser = new EventParser(program.programId, program.coder);

//Pay out can be: true, false
//Kind can be: htlc, chain, chainNonced, chainTxhash
//Claim type can be: ix, dataAccount

