//! Very reduced Solana program that indirectly validates
//! Ed25519/Secp256k1 signatures by using instruction introspection
//!
//! Made for learning / teaching / example purposes.
//!

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{keccak, secp256k1_recover::secp256k1_recover};
use libsecp256k1;
use solana_program::instruction::Instruction;
use solana_program::sysvar::instructions::{load_instruction_at_checked, ID as IX_ID};

pub mod error;
pub mod utils;

declare_id!("6eX3sxexs8Ct67xdxjjGJ4HLybK7YR6QkcWmaMhwgTcS");

/// Main module
#[program]
pub mod signatures {
    use super::*;

    /// External instruction that only gets executed if
    /// an `Ed25519Program.createInstructionWithPublicKey`
    /// instruction was sent in the same transaction.
    pub fn verify_ed25519(
        ctx: Context<Verify>,
        pubkey: [u8; 32],
        msg: Vec<u8>,
        sig: [u8; 64],
    ) -> Result<()> {
        // Get what should be the Ed25519Program instruction
        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        // Check that ix is what we expect to have been sent
        utils::verify_ed25519_ix(&ix, &pubkey, &msg, &sig)?;

        // Do other stuff

        Ok(())
    }

    /// External instruction that only gets executed if
    /// a `Secp256k1Program.createInstructionWithEthAddress`
    /// instruction was sent in the same transaction.
    pub fn secp256k1_verify_ins(
        ctx: Context<Verify>,
        eth_address: [u8; 20],
        msg: Vec<u8>,
        sig: [u8; 64],
        recovery_id: u8,
    ) -> Result<()> {
        // Get what should be the Secp256k1Program instruction
        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        // Check that ix is what we expect to have been sent
        utils::verify_secp256k1_ix(&ix, &eth_address, &msg, &sig, recovery_id)?;

        // Do other stuff

        Ok(())
    }

    pub fn secp256k1_recover_ins(
        _ctx: Context<Secp256k1Recover>,
        args: Secp256k1RecoverArgs,
    ) -> Result<()> {
        let message_hash = {
            let mut hasher = keccak::Hasher::default();
            hasher.hash(&args.message);
            hasher.result()
        };

        {
            let signature = libsecp256k1::Signature::parse_standard_slice(&args.signature)
                .map_err(|_| ProgramError::InvalidArgument)
                .unwrap();

            if signature.s.is_high() {
                msg!("signature with high-s value");
            }
        }

        let recovered_pubkey =
            // https://docs.rs/solana-program/latest/solana_program/secp256k1_recover/fn.secp256k1_recover.html
            secp256k1_recover(&message_hash.0, args.recovery_id, &args.signature)
                .map_err(|_| ProgramError::InvalidArgument)?;

        require!(
            recovered_pubkey.0 == args.public_key,
            RecoverErr::InvalidPublicKey
        );

        Ok(())
    }
}

/// Context accounts
#[derive(Accounts)]
pub struct Verify<'info> {
    pub sender: Signer<'info>,

    /// CHECK: The address check is needed because otherwise
    /// the supplied Sysvar could be anything else.
    /// The Instruction Sysvar has not been implemented
    /// in the Anchor framework yet, so this is the safe approach.
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Secp256k1Recover<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(AnchorDeserialize, AnchorSerialize, Clone)]
pub struct Secp256k1RecoverArgs {
    pub public_key: [u8; 64],
    pub message: Vec<u8>,
    pub signature: [u8; 64],
    pub recovery_id: u8,
}

#[error_code]
pub enum RecoverErr {
    #[msg("Publick key is invalid!")]
    InvalidPublicKey,
}
