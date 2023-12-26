import { Keypair, PublicKey } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createMint, createAccount, mintTo, getAccount, getOrCreateAssociatedTokenAccount, getAssociatedTokenAddressSync } from "@solana/spl-token";
import { AnchorProvider, BN } from "@coral-xyz/anchor";

const provider = AnchorProvider.local();

export class TokenMint {

    mint: PublicKey;
    mintAuthority: Keypair;

    constructor(mint: PublicKey, mintAuthority: Keypair) {
        this.mint = mint;
        this.mintAuthority = mintAuthority;
    }

    async mintTo(dst: PublicKey, amount: BN): Promise<PublicKey> {
        const dstAta = await getOrCreateAssociatedTokenAccount(provider.connection, this.mintAuthority, this.mint, dst);
        await mintTo(provider.connection, this.mintAuthority, this.mint, dstAta.address, this.mintAuthority, BigInt(amount.toString()));
        return dstAta.address;
    }

    getATA(dst: PublicKey): PublicKey {
        return getAssociatedTokenAddressSync(this.mint, dst);
    }

};

export async function getNewMint(): Promise<TokenMint> {
    const mintAuthority = Keypair.generate();
  
    const signature = await provider.connection.requestAirdrop(mintAuthority.publicKey, 1000000000);
    await provider.connection.confirmTransaction(signature);

    const mint = await createMint(provider.connection, mintAuthority, mintAuthority.publicKey, null, 0);

    return new TokenMint(
        mint,
        mintAuthority
    );
}
