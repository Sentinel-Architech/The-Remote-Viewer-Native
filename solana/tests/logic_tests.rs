//! End-to-end logic tests for the TRV Solana programs.
//!
//! These exercise the instruction dispatcher the way an on-chain
//! client would: initialize mint, mint supply, transfer with the
//! hook, stake through a full lock, and verify every policy edge.

use trv_solana::program::{
    Accounts, Instruction, InstructionOutput, MintAccount, ProgramError, StakeAccountRecord,
    TreasuryRecord,
};
use trv_solana::staking::{StakeAccount, StakingError, STAKE_LOCK_SECS};
use trv_solana::token::{MintError, MintState, TRV_TOTAL_SUPPLY};
use trv_solana::transfer_hook::{TransferRequest, WalletKind};
use trv_solana::TRANSFER_FEE_BPS;

fn setup() -> (MintAccount, StakeAccountRecord, TreasuryRecord) {
    (
        MintAccount {
            state: MintState::initialize([1u8; 32]),
        },
        StakeAccountRecord {
            stake: StakeAccount::empty(),
        },
        TreasuryRecord { balance: 0 },
    )
}

fn accts<'a>(
    m: &'a mut MintAccount,
    s: &'a mut StakeAccountRecord,
    t: &'a mut TreasuryRecord,
) -> Accounts<'a> {
    Accounts {
        mint: Some(m),
        stake: Some(s),
        treasury: Some(t),
        is_signer: true,
    }
}

#[test]
fn token_economics_end_to_end() {
    let (mut m, mut s, mut t) = setup();
    let mut a = accts(&mut m, &mut s, &mut t);

    // Mint half the supply.
    let half = TRV_TOTAL_SUPPLY / 2;
    let out = trv_solana::program::process_instruction(
        Instruction::MintTo { caller: [1u8; 32], amount: half },
        &mut a,
    )
    .unwrap();
    assert_eq!(out, InstructionOutput::Minted { new_total: half });

    // Over-mint rejected; state untouched.
    let err = trv_solana::program::process_instruction(
        Instruction::MintTo { caller: [1u8; 32], amount: half + 1 },
        &mut a,
    )
    .unwrap_err();
    assert_eq!(err, ProgramError::Token(MintError::SupplyCapExceeded));

    // Fee constants match the workspace policy (25%).
    assert_eq!(TRANSFER_FEE_BPS, 2_500);
}

#[test]
fn transfer_hook_policy_matrix() {
    let (mut m, mut s, mut t) = setup();
    let mut a = accts(&mut m, &mut s, &mut t);

    let xfer = |a: &mut Accounts, amount: u64, to: WalletKind, ar: bool| {
        match trv_solana::program::process_instruction(
            Instruction::TransferWithHook(TransferRequest {
                amount,
                from: WalletKind::Network,
                to,
                ar_earned: ar,
            }),
            a,
        )
        .unwrap()
        {
            InstructionOutput::Transfer(r) => r,
            _ => panic!("expected transfer receipt"),
        }
    };

    // In-network: free.
    let r = xfer(&mut a, 10_000, WalletKind::Network, false);
    assert_eq!((r.net, r.fee, r.burned), (10_000, 0, 0));

    // Outside: 25% to treasury.
    let r = xfer(&mut a, 10_000, WalletKind::Outside, false);
    assert_eq!((r.net, r.fee, r.burned), (7_500, 2_500, 0));

    // AR soulbound cash-out: dust.
    let r = xfer(&mut a, 10_000, WalletKind::Outside, true);
    assert_eq!((r.net, r.fee, r.burned), (0, 0, 10_000));

    // Release the account borrows before inspecting the treasury.
    drop(a);
    assert_eq!(t.balance, 2_500);
}

#[test]
fn staking_full_lifecycle_no_early_exit() {
    let (mut m, mut s, mut t) = setup();
    let mut a = accts(&mut m, &mut s, &mut t);
    let px = trv_solana::program::process_instruction;

    px(Instruction::Stake { owner: [5u8; 32], amount: 100_000, now: 0 }, &mut a).unwrap();

    // Every early exit attempt fails, at several points in the lock.
    for now in [1, 1_000_000, STAKE_LOCK_SECS - 1] {
        let err = px(Instruction::Unstake { caller: [5u8; 32], now }, &mut a).unwrap_err();
        assert!(
            matches!(err, ProgramError::Staking(StakingError::StillLocked { .. })),
            "now={now}"
        );
    }

    // At expiry: principal + proportional reward, account closed.
    let out = px(
        Instruction::Unstake { caller: [5u8; 32], now: STAKE_LOCK_SECS },
        &mut a,
    )
    .unwrap();
    match out {
        InstructionOutput::Unstaked { principal, rewards } => {
            assert_eq!(principal, 100_000);
            assert_eq!(rewards, 5_000); // 5% of 100k
        }
        _ => panic!("expected unstake output"),
    }

    // Double-unstake fails: account is closed.
    let err = px(
        Instruction::Unstake { caller: [5u8; 32], now: STAKE_LOCK_SECS },
        &mut a,
    )
    .unwrap_err();
    assert_eq!(err, ProgramError::Staking(StakingError::NotStaked));
}
