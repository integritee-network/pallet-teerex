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

#![cfg(any(test, feature = "runtime-benchmarks"))]

use super::*;

use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;

use sp_core::crypto::UncheckedFrom;
use sp_runtime::traits::CheckedConversion;

use crate::test_utils::{consts::URL, get_signer, ias::IAS_SETUPS};
use crate::Pallet as Teerex;

fn ensure_not_skipping_ra_check() {
    if cfg!(feature = "skip-ias-check") {
        panic!("Benchmark does not allow the `skip-ias-check` flag.");
    };
}

fn add_enclaves_to_registry<T: Config>(amount: u8) -> Vec<T::AccountId>
where
    T::AccountId: UncheckedFrom<H256>,
{
    let accounts: Vec<T::AccountId> = (0..amount)
        .map(|_n| T::AccountId::unchecked_from(H256::random()))
        .collect();

    for a in accounts.iter() {
        Teerex::<T>::add_enclave(
            a,
            &Enclave::new(
                a.clone(),
                Default::default(),
                Default::default(),
                Default::default(),
            ),
        )
        .unwrap()
    }
    accounts
}

benchmarks! {
    // Benchmark `register` enclave with the worst possible conditions
    // * remote attestation is valid
    // * enclave already exists
    //
    // Note: The storage-map structure has the following complexity for updating a value:
    //   DB Reads: O(1) Encoding: O(1) DB Writes: O(1)
    //
    // Hence, it does not matter how many other enclaves already exist.
    where_clause {  where T::AccountId: From<[u8; 32]> }
    register_enclave {
        let i in 0 .. (IAS_SETUPS.len() as u32 - 1);
        let setup = IAS_SETUPS[i as usize];

        ensure_not_skipping_ra_check();

        timestamp::Pallet::<T>::set_timestamp(setup.timestamp.checked_into().unwrap());
        let signer: T::AccountId = get_signer(setup.signer_pub);

        // simply register the enclave before to make sure it already
        // exists when running the benchmark
        Teerex::<T>::register_enclave(
            RawOrigin::Signed(signer.clone()).into(),
            setup.cert.to_vec(),
            URL.to_vec()
        ).unwrap();

    }: _(RawOrigin::Signed(signer), setup.cert.to_vec(), URL.to_vec())
    verify {
        assert_eq!(Teerex::<T>::enclave_count(), 1);
    }
}

#[cfg(test)]
use crate::{Config, Module as PalletModule};

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;

#[cfg(test)]
impl_benchmark_test_suite!(PalletModule, crate::mock::new_test_ext(), crate::mock::Test,);
