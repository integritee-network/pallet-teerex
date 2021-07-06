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

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite};
use frame_system::RawOrigin;

use crate::{Pallet, Config};
use crate::mock::{IAS_SETUPS, Timestamp, SubstrateeRegistry, consts::URL};
use crate::test_utils::get_signer;

use crate::Pallet as PalletTeerex;

benchmarks! {
	where_clause {  where T::AccountId: From<&'static [u8]> }
	register_enclave {
		let i in 0 .. IAS_SETUPS.len() as u32;
		let setup = IAS_SETUPS[i as usize];

		Timestamp::set_timestamp(setup.timestamp);
		let signer: T::AccountId = get_signer(setup.signer_pub);

	}: _(RawOrigin::Signed(signer), setup.cert.to_vec(), URL.to_vec())
	verify {
		assert_eq!(SubstrateeRegistry::enclave_count(), 1);
	}
}

impl_benchmark_test_suite!(
	PalletTeerex,
	crate::mock::new_test_ext(),
	crate::mock::Test,
);