#![cfg(any(test, feature = "runtime-benchmarks"))]

use frame_benchmarking::sp_std::convert::TryFrom;

pub fn get_signer<'a, AccountId>(pubkey: &'a [u8]) -> AccountId
where

	AccountId: TryFrom<&'a [u8]>,
	// Todo: Check what's up with this weird trait bounds
	<AccountId as TryFrom<&'a [u8]>>::Error: std::fmt::Debug
{
	AccountId::try_from(pubkey).unwrap()
}