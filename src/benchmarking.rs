/*
    Copyright 2021 Integritee AG and Supercomputing Systems AG

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

*/

//! Teerex pallet benchmarking

#![cfg(feature = "runtime-benchmarks")]

use super::*;

use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;

use sp_runtime::traits::CheckedConversion;

use crate::test_utils::{consts::URL, ias::IAS_SETUPS};
use crate::Pallet as Teerex;

pub fn get_signer<AccountId: From<[u8; 32]>>(pubkey: &[u8; 32]) -> AccountId {
    AccountId::from(*pubkey)
}

benchmarks! {
    where_clause {  where T::AccountId: From<[u8; 32]> }
    register_enclave {
        let i in 0 .. IAS_SETUPS.len() as u32;
        let setup = IAS_SETUPS[i as usize];

        timestamp::Pallet::<T>::set_timestamp(setup.timestamp.checked_into().unwrap());
        let signer: T::AccountId = get_signer(setup.signer_pub);

    }: _(RawOrigin::Signed(signer), setup.cert.to_vec(), URL.to_vec())
    verify {
        assert_eq!(Teerex::<T>::enclave_count(), 1);
    }
}

// Todo: I am currently unsure when to use the below

#[cfg(test)]
use crate::{Config, Module as PalletModule};

#[cfg(test)]
frame_benchmarking::impl_benchmark_test_suite!(
    PalletModule,
    crate::mock::new_test_ext(),
    crate::mock::Test,
);
