#![cfg(any(test, feature = "runtime-benchmarks"))]

use frame_benchmarking::sp_std::convert::TryFrom;
use sp_std::fmt::Debug;

pub fn get_signer<'a, AccountId>(pubkey: &'a [u8]) -> AccountId
where
    AccountId: TryFrom<&'a [u8]>,
    <AccountId as TryFrom<&'a [u8]>>::Error: Debug,
{
    AccountId::try_from(pubkey).unwrap()
}
