import * as anchor from '@coral-xyz/anchor';
import { Program } from '@coral-xyz/anchor';
import { Signatures } from '../target/types/signatures';
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import * as ethUtil from '@ethereumjs/util';

describe('Ethereum recovery', () => {
    // Configure the client to use the local cluster.
    const provider = anchor.AnchorProvider.local('http://127.0.0.1:8899');
    anchor.setProvider(provider);

    const program = anchor.workspace.Signatures as Program<Signatures>;

    before(async () => {});

    it('recovery', async () => {
        const privateKey = ethUtil.hexToBytes(
            '0x1111111111111111111111111111111111111111111111111111111111111111'
        );
        const publicKey = ethUtil.privateToPublic(privateKey);

        const msgForActivation = new TextEncoder().encode('DePIN'); // activation msg
        const hashedMsgForActivation = keccak256(msgForActivation);

        const { r, s, v } = ethUtil.ecsign(hashedMsgForActivation, privateKey);
        const signature = Uint8Array.from([...r, ...s]);
        const recoveryId = Number(ethUtil.calculateSigRecovery(v));

        // anchor.web3.Secp256k1Program.publicKeyToEthAddress(pubKey)
        const tx = await program.methods
            .secp256K1RecoverIns({
                // idl secp256k1RecoverIns => secp256K1RecoverIns
                publicKey: publicKey,
                message: Buffer.from(msgForActivation),
                signature: signature,
                recoveryId: recoveryId,
            })
            .rpc();
    });
});
