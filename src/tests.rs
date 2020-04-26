/*
    Copyright 2019 Supercomputing Systems AG

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
use super::*;
use crate::{Error, mock::*};
use frame_support::{assert_ok, assert_noop, IterableStorageMap };
use codec::{Decode, Encode};
use sp_core::{sr25519, Blake2Hasher, Pair, Public, H256};
use sp_runtime::traits::IdentifyAccount;
use hex_literal::hex;

// reproduce with "substratee_worker dump_ra"
const TEST4_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST4.der");
const TEST5_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST5.der");
const TEST6_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST6.der");
const TEST7_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST7.der");

// reproduce with substratee-worker signing-key
const TEST4_SIGNER_PUB: &[u8] = include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST4.bin");  
// equal to TEST4! because of MRSIGNER policy it was possible to change the MRENCLAVE but keep the secret
const TEST5_SIGNER_PUB: &[u8] = include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST5.bin");        
const TEST6_SIGNER_PUB: &[u8] = include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST6.bin");        
const TEST7_SIGNER_PUB: &[u8] = include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST7.bin");        

// reproduce with "make mrenclave" in worker repo root
// MRSIGNER is always 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
const TEST4_MRENCLAVE: [u8; 32] = hex!("7a3454ec8f42e265cb5be7dfd111e1d95ac6076ed82a0948b2e2a45cf17b62a0");
const TEST5_MRENCLAVE: [u8; 32] = hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
const TEST6_MRENCLAVE: [u8; 32] = hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
const TEST7_MRENCLAVE: [u8; 32] = hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");

// unix epoch. must be later than this
const TEST4_TIMESTAMP: i64 = 1587899785i64;
const TEST5_TIMESTAMP: i64 = 1587900013i64;
const TEST6_TIMESTAMP: i64 = 1587900233i64;
const TEST7_TIMESTAMP: i64 = 1587900450i64;

const URL: &[u8] = &[
	119, 115, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 57, 57, 57, 49,
];


fn get_signer(pubkey : &[u8]) -> AccountId {
	AccountId::from(sr25519::Public::decode(&mut &pubkey[..]).unwrap())
			.into_account()
}

fn list_enclaves() -> Vec<(u64, Enclave<AccountId, Vec<u8>>)> {
	<EnclaveRegistry<TestRuntime>>::iter()
		.collect::<Vec<(u64, Enclave<AccountId, Vec<u8>>)>>()
}

#[test]
fn add_enclave_works() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert_ok!(Registry::register_enclave(
			Origin::signed(signer),
			TEST4_CERT.to_vec(),
			URL.to_vec()
		));
		assert_eq!(Registry::enclave_count(), 1);
	})
}

#[test]
fn add_and_remove_enclave_works() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert_ok!(Registry::register_enclave(
			Origin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			URL.to_vec()
		));
		assert_eq!(Registry::enclave_count(), 1);
		assert_ok!(Registry::unregister_enclave(Origin::signed(signer)));
		assert_eq!(Registry::enclave_count(), 0);
		assert_eq!(list_enclaves(), vec![])
	})
}

#[test]
fn list_enclaves_works() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST4_SIGNER_PUB);
		let e_1: Enclave<AccountId, Vec<u8>> = Enclave {
			pubkey: signer.clone(),
			mr_enclave: TEST4_MRENCLAVE,
			timestamp: TEST4_TIMESTAMP,
			url: URL.to_vec(),
		};
		assert_ok!(Registry::register_enclave(
			Origin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			URL.to_vec()
		));
		assert_eq!(Registry::enclave_count(), 1);
		let enclaves = list_enclaves();
		assert_eq!(enclaves[0].1.pubkey, signer)
	})
}

#[test]
fn remove_middle_enclave_works() {
	new_test_ext().execute_with(|| {
		let signer5 = get_signer(TEST5_SIGNER_PUB);
		let signer6 = get_signer(TEST6_SIGNER_PUB);
		let signer7 = get_signer(TEST7_SIGNER_PUB);

		// add enclave 1
		let e_1: Enclave<AccountId, Vec<u8>> = Enclave {
			pubkey: signer5.clone(),
			mr_enclave: TEST5_MRENCLAVE,
			timestamp: TEST5_TIMESTAMP,
			url: URL.to_vec(),
		};

		let e_2: Enclave<AccountId, Vec<u8>> = Enclave {
			pubkey: signer6.clone(),
			mr_enclave: TEST6_MRENCLAVE,
			timestamp: TEST6_TIMESTAMP,
			url: URL.to_vec(),
		};

		let e_3: Enclave<AccountId, Vec<u8>> = Enclave {
			pubkey: signer7.clone(),
			mr_enclave: TEST7_MRENCLAVE,
			timestamp: TEST7_TIMESTAMP,
			url: URL.to_vec(),
		};

		assert_ok!(Registry::register_enclave(
			Origin::signed(signer5.clone()),
			TEST5_CERT.to_vec(),
			URL.to_vec()
		));
		assert_eq!(Registry::enclave_count(), 1);
		assert_eq!(list_enclaves(), vec![(1, e_1.clone())]);

		// add enclave 2
		assert_ok!(Registry::register_enclave(
			Origin::signed(signer6.clone()),
			TEST6_CERT.to_vec(),
			URL.to_vec()
		));
		assert_eq!(Registry::enclave_count(), 2);
		let enclaves = list_enclaves();
		assert!(enclaves.contains(&(1, e_1.clone())));
		assert!(enclaves.contains(&(2, e_2.clone())));
		
		// add enclave 3
		assert_ok!(Registry::register_enclave(
			Origin::signed(signer7.clone()),
			TEST7_CERT.to_vec(),
			URL.to_vec()
		));
		assert_eq!(Registry::enclave_count(), 3);
		let enclaves = list_enclaves();
		assert!(enclaves.contains(&(1, e_1.clone())));
		assert!(enclaves.contains(&(2, e_2.clone())));
		assert!(enclaves.contains(&(3, e_3.clone())));

		// remove enclave 2
		assert_ok!(Registry::unregister_enclave(Origin::signed(signer6)));
		assert_eq!(Registry::enclave_count(), 2);
		let enclaves = list_enclaves();
		assert!(enclaves.contains(&(1, e_1.clone())));
		assert!(enclaves.contains(&(2, e_3.clone())));
	})
}

#[test]
fn register_enclave_with_different_signer_fails() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST7_SIGNER_PUB);
		assert!(
			Registry::register_enclave(
				Origin::signed(signer),
				TEST5_CERT.to_vec(),
				URL.to_vec()
			)
			.is_err()
		);
	})
}

#[test]
fn update_enclave_url_works() {
	new_test_ext().execute_with(|| {
		let signer = get_signer(TEST4_SIGNER_PUB);
		let url2 = "my fancy url".as_bytes();
		let e_1: Enclave<AccountId, Vec<u8>> = Enclave {
			pubkey: signer.clone(),
			mr_enclave: TEST4_MRENCLAVE,
			timestamp: TEST4_TIMESTAMP,
			url: url2.to_vec(),
		};

		assert_ok!(Registry::register_enclave(
			Origin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			URL.to_vec()
		));
		assert_eq!(Registry::enclave(1).url, URL.to_vec());

		assert_ok!(Registry::register_enclave(
			Origin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			url2.to_vec()
		));
		assert_eq!(Registry::enclave(1).url, url2.to_vec());
		let enclaves = list_enclaves();
		assert_eq!(enclaves[0].1.pubkey, signer)
	})
}

#[test]
fn update_ipfs_hash_works() {
	new_test_ext().execute_with(|| {
		let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
		let shard = H256::default();
		let request_hash = vec![];
		let signer = get_signer(TEST4_SIGNER_PUB);

		assert_ok!(Registry::register_enclave(
			Origin::signed(signer.clone()),
			TEST4_CERT.to_vec(),
			URL.to_vec()
		));
		assert_eq!(Registry::enclave_count(), 1);
		assert_ok!(Registry::confirm_call(
			Origin::signed(signer.clone()),
			shard.clone(),
			request_hash.clone(),
			ipfs_hash.as_bytes().to_vec()
		));
		assert_eq!(
			str::from_utf8(&Registry::latest_ipfs_hash(shard.clone())).unwrap(),
			ipfs_hash
		);
		assert_eq!(Registry::worker_for_shard(shard.clone()), 1u64);

		let expected_event = TestEvent::registry(RawEvent::UpdatedIpfsHash(
			shard.clone(),
			1,
			ipfs_hash.as_bytes().to_vec(),
		));
		assert!(System::events().iter().any(|a| a.event == expected_event));

		let expected_event =
			TestEvent::registry(RawEvent::CallConfirmed(signer.clone(), request_hash));
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}

#[test]
fn ipfs_update_from_unregistered_enclave_fails() {
	new_test_ext().execute_with(|| {
		let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert!(Registry::confirm_call(
			Origin::signed(signer),
			H256::default(),
			vec![],
			ipfs_hash.as_bytes().to_vec()
		)
		.is_err());
	})
}

#[test]
fn call_worker_works() {
	new_test_ext().execute_with(|| {
		let req = Request {
			shard: ShardIdentifier::default(),
			cyphertext: vec![0u8, 1, 2, 3, 4],
		};
		// don't care who signs
		let signer = get_signer(TEST4_SIGNER_PUB);
		assert!(Registry::call_worker(Origin::signed(signer), req.clone()).is_ok());
		let expected_event = TestEvent::registry(RawEvent::Forwarded(req));
		println!("events:{:?}", System::events());
		assert!(System::events().iter().any(|a| a.event == expected_event));
	})
}


