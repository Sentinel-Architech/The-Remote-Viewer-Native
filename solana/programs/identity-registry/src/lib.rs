//! TRV VerificationRegistry — deployable Solana program.
//!
//! This is the **thin on-chain adapter** for the pure-Rust identity logic in
//! `trv-solana` (`solana/src/identity.rs`). It does three things and nothing
//! more:
//!
//! 1. Deserializes the instruction data into [`AdapterInstruction`].
//! 2. Loads the PDA attestation-record account, verifies it is the correct
//!    PDA, and deserializes it via [`AttestationRecord::from_bytes`].
//! 3. Calls the pure [`process_instruction`] from `trv-solana` and writes the
//!    updated record bytes back into the PDA.
//!
//! All business logic (registration rules, rate limits, revocation,
//! signer checks) lives in `trv-solana` and is tested offline with
//! `cargo test`. This adapter adds no logic of its own — it only bridges
//! Solana accounts to that logic.
//!
//! # Accounts
//!
//! * Account 0 — the attestation-record PDA (writable). Seeds:
//!   `[b"trv-attestation", device_key]`. The adapter verifies the PDA
//!   derivation and rejects anything else.
//! * Account 1 — the device signer (must sign; its key must equal the
//!   `device_key` in the instruction).
//!
//! # Instruction data (compact binary, little-endian where noted)
//!
//! * Tag `0` — RegisterAttestation (106 bytes):
//!   `0 || device_key(32) || attestation_hash(64) || level(1) ||
//!    expires_at(8 LE)`. The `now` timestamp comes from the on-chain
//!   `Clock`, not from the instruction.
//! * Tag `1` — RevokeAttestation (33 bytes):
//!   `1 || device_key(32)`. `now` comes from the on-chain `Clock`.
//!
//! # Program ID
//!
//! `EHbJGKAEUJLYq2BJ6Htj9aAZHKfwroA6VAonRdXL4USv` — from
//! `program-keypair.json` next to this crate. Unfunded: the keypair is a
//! build artifact (an address), not a wallet. It holds no SOL until the
//! user funds deployment.

// The `entrypoint!` macro from solana-program 4.1.0 emits `cfg`
// conditions (custom-heap, custom-panic, solana) that this newer
// rustc flags as unexpected. They are benign and come from the
// dependency's macro expansion, not from this crate's code.
#![allow(unexpected_cfgs)]

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};
use trv_solana::identity::{
    process_instruction, AttestationRecord, IdentityAccounts, IdentityError, IdentityInstruction,
    IdentityOutput,
};

solana_program::declare_id!("EHbJGKAEUJLYq2BJ6Htj9aAZHKfwroA6VAonRdXL4USv");

/// PDA seed prefix for attestation records.
pub const ATTESTATION_SEED: &[u8] = b"trv-attestation";

/// On-chain instruction, deserialized from the raw instruction data.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AdapterInstruction {
    Register {
        device_key: [u8; 32],
        attestation_hash: [u8; 64],
        level: u8,
        expires_at: u64,
    },
    Revoke {
        device_key: [u8; 32],
    },
}

fn parse_instruction(data: &[u8]) -> Result<AdapterInstruction, ProgramError> {
    if data.is_empty() {
        msg!("missing instruction tag");
        return Err(ProgramError::InvalidInstructionData);
    }
    match data[0] {
        0 => {
            // 1 + 32 + 64 + 1 + 8 = 106 bytes
            if data.len() != 106 {
                msg!("register: expected 106 bytes, got {}", data.len());
                return Err(ProgramError::InvalidInstructionData);
            }
            let mut device_key = [0u8; 32];
            let mut attestation_hash = [0u8; 64];
            device_key.copy_from_slice(&data[1..33]);
            attestation_hash.copy_from_slice(&data[33..97]);
            let level = data[97];
            let mut b8 = [0u8; 8];
            b8.copy_from_slice(&data[98..106]);
            Ok(AdapterInstruction::Register {
                device_key,
                attestation_hash,
                level,
                expires_at: u64::from_le_bytes(b8),
            })
        }
        1 => {
            // 1 + 32 = 33 bytes
            if data.len() != 33 {
                msg!("revoke: expected 33 bytes, got {}", data.len());
                return Err(ProgramError::InvalidInstructionData);
            }
            let mut device_key = [0u8; 32];
            device_key.copy_from_slice(&data[1..33]);
            Ok(AdapterInstruction::Revoke { device_key })
        }
        t => {
            msg!("unknown instruction tag {}", t);
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

fn map_error(e: IdentityError) -> ProgramError {
    msg!("identity error: {}", e);
    // Map each scaffold error to a distinct custom code so clients can
    // distinguish them. Codes 0-8 mirror the IdentityError variants.
    let code = match e {
        IdentityError::BadAttestationEncoding => 0,
        IdentityError::InvalidLevel => 1,
        IdentityError::AttestationExpired => 2,
        IdentityError::DuplicateRegistration => 3,
        IdentityError::RateLimited => 4,
        IdentityError::NotRegistered => 5,
        IdentityError::AlreadyRevoked => 6,
        IdentityError::NotDeviceSigner => 7,
    };
    ProgramError::Custom(code)
}

entrypoint!(process_instruction_entry);

/// Real on-chain entrypoint. Bridges Solana accounts to the pure logic.
pub fn process_instruction_entry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let ix = parse_instruction(instruction_data)?;

    let accounts_iter = &mut accounts.iter();
    let record_ai = next_account_info(accounts_iter)?;
    let signer_ai = next_account_info(accounts_iter)?;

    // The device key comes from the instruction; both paths need it.
    let device_key: [u8; 32] = match &ix {
        AdapterInstruction::Register { device_key, .. } => *device_key,
        AdapterInstruction::Revoke { device_key } => *device_key,
    };

    // Verify the record account is the PDA we expect. No one can slip in
    // a lookalike account: the PDA must derive from our program id.
    let (expected_pda, _bump) =
        Pubkey::find_program_address(&[ATTESTATION_SEED, &device_key], program_id);
    if record_ai.key != &expected_pda {
        msg!("record account is not the expected PDA");
        return Err(ProgramError::InvalidSeeds);
    }
    if !record_ai.is_writable {
        msg!("record account must be writable");
        return Err(ProgramError::InvalidAccountData);
    }

    // The signer must be the device key itself.
    if !signer_ai.is_signer {
        msg!("device must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    if signer_ai.key.to_bytes() != device_key {
        msg!("signer is not the device key");
        return Err(map_error(IdentityError::NotDeviceSigner));
    }

    // Load the record: fresh PDAs are zero-filled (uninitialized).
    let record_data = record_ai.try_borrow_data()?;
    if record_data.len() < 135 {
        msg!("record account too small: {} bytes", record_data.len());
        return Err(ProgramError::InvalidAccountData);
    }
    let mut raw = [0u8; 135];
    raw.copy_from_slice(&record_data[0..135]);
    drop(record_data);
    let mut record = AttestationRecord::from_bytes(&raw);

    // On-chain time from the Clock sysvar — the scaffold's `now`
    // parameter is filled here, never trusted from the client.
    let clock = Clock::get()?;
    if clock.unix_timestamp < 0 {
        msg!("clock before unix epoch");
        return Err(ProgramError::InvalidAccountData);
    }
    let now = clock.unix_timestamp as u64;

    // Build the scaffold instruction and forward to the pure logic.
    // This is the ONLY logic call: everything else here is bridging.
    let scaffold_ix = match ix {
        AdapterInstruction::Register {
            device_key,
            attestation_hash,
            level,
            expires_at,
        } => IdentityInstruction::RegisterAttestation {
            device_key,
            attestation_hash,
            level,
            expires_at,
            now,
        },
        AdapterInstruction::Revoke { device_key } => {
            IdentityInstruction::RevokeAttestation { device_key, now }
        }
    };
    let mut scaffold_accts = IdentityAccounts {
        record: Some(&mut record),
        is_signer: true,
        signer_key: device_key,
    };
    let output = process_instruction(scaffold_ix, &mut scaffold_accts).map_err(map_error)?;

    // Write the updated record back to the PDA.
    let mut record_data = record_ai.try_borrow_mut_data()?;
    let out = record.to_bytes();
    record_data[0..135].copy_from_slice(&out);

    match output {
        IdentityOutput::Registered { registered_at } => {
            msg!("attestation registered at {}", registered_at)
        }
        IdentityOutput::Revoked { revoked_at } => msg!("attestation revoked at {}", revoked_at),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_register_round_trip() {
        let mut data = vec![0u8; 106];
        data[0] = 0;
        data[1..33].copy_from_slice(&[7u8; 32]);
        data[33..97].copy_from_slice(&[9u8; 64]);
        data[97] = 2;
        data[98..106].copy_from_slice(&2_000_000_000u64.to_le_bytes());
        match parse_instruction(&data).unwrap() {
            AdapterInstruction::Register {
                device_key,
                attestation_hash,
                level,
                expires_at,
            } => {
                assert_eq!(device_key, [7u8; 32]);
                assert_eq!(attestation_hash, [9u8; 64]);
                assert_eq!(level, 2);
                assert_eq!(expires_at, 2_000_000_000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_revoke_round_trip() {
        let mut data = vec![0u8; 33];
        data[0] = 1;
        data[1..33].copy_from_slice(&[3u8; 32]);
        match parse_instruction(&data).unwrap() {
            AdapterInstruction::Revoke { device_key } => assert_eq!(device_key, [3u8; 32]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_rejects_bad_tag() {
        assert!(parse_instruction(&[9u8]).is_err());
    }

    #[test]
    fn parse_rejects_wrong_lengths() {
        assert!(parse_instruction(&vec![0u8; 100]).is_err());
        assert!(parse_instruction(&vec![1u8; 40]).is_err());
        assert!(parse_instruction(&[]).is_err());
    }

    #[test]
    fn pda_derivation_is_deterministic() {
        let program_id = id();
        let device_key = [42u8; 32];
        let (pda1, _) =
            Pubkey::find_program_address(&[ATTESTATION_SEED, &device_key], &program_id);
        let (pda2, _) =
            Pubkey::find_program_address(&[ATTESTATION_SEED, &device_key], &program_id);
        assert_eq!(pda1, pda2);
        // Different device keys give different PDAs.
        let (pda3, _) =
            Pubkey::find_program_address(&[ATTESTATION_SEED, &[43u8; 32]], &program_id);
        assert_ne!(pda1, pda3);
    }
}
