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

use codec::Decode;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, account};
use frame_system::RawOrigin;

use sp_core::sr25519;

use crate::{Pallet, Config};
use crate::mock::{IAS_SETUPS, Timestamp, SubstrateeRegistry, consts::URL};

use crate::Pallet as PalletTeerex;

benchmarks! {
	where_clause {  where T::AccountId: From<sr25519::Public> }
	register_enclave {
		let i in 0 .. IAS_SETUPS.len() as u32;
		Timestamp::set_timestamp(IAS_SETUPS[i as usize].timestamp);
		let signer: T::AccountId = sr25519::Public::decode(
			&mut &IAS_SETUPS[i as usize].signer_pub[..]
		).unwrap().into();
	}: _(RawOrigin::Signed(signer), IAS_SETUPS[i as usize].cert.to_vec(), URL.to_vec())
	verify {
		assert_eq!(SubstrateeRegistry::enclave_count(), 1);
	}
}

impl_benchmark_test_suite!(
	PalletTeerex,
	crate::mock::new_test_ext(),
	crate::mock::Test,
);