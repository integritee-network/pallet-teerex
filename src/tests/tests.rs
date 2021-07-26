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

//use super::*;
use crate::mock::*;
use crate::test_utils::consts::*;
use crate::{ConfirmedCalls, Enclave, EnclaveRegistry, Error, RawEvent, Request, ShardIdentifier};
use frame_support::{assert_err, assert_ok, IterableStorageMap, StorageMap};
use sp_core::H256;
use sp_keyring::AccountKeyring;

fn list_enclaves() -> Vec<(u64, Enclave<AccountId, Vec<u8>>)> {
    <EnclaveRegistry<Test>>::iter().collect::<Vec<(u64, Enclave<AccountId, Vec<u8>>)>>()
}

// give get_signer a concrete type
fn get_signer(pubkey: &[u8; 32]) -> AccountId {
    crate::test_utils::get_signer(pubkey)
}

#[test]
fn add_enclave_works() {
    new_test_ext().execute_with(|| {
        // set the now in the runtime such that the remote attestation reports are within accepted range (24h)
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer = get_signer(TEST4_SIGNER_PUB);
        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer),
            TEST4_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave_count(), 1);
    })
}

#[test]
fn add_and_remove_enclave_works() {
    new_test_ext().execute_with(|| {
        let _ = env_logger::init();
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer = get_signer(TEST4_SIGNER_PUB);
        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave_count(), 1);
        assert_ok!(SubstrateeRegistry::unregister_enclave(Origin::signed(
            signer
        )));
        assert_eq!(SubstrateeRegistry::enclave_count(), 0);
        assert_eq!(list_enclaves(), vec![])
    })
}

#[test]
fn list_enclaves_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer = get_signer(TEST4_SIGNER_PUB);
        let _e_1: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer.clone(),
            mr_enclave: TEST4_MRENCLAVE,
            timestamp: TEST4_TIMESTAMP,
            url: URL.to_vec(),
        };
        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave_count(), 1);
        let enclaves = list_enclaves();
        assert_eq!(enclaves[0].1.pubkey, signer)
    })
}

#[test]
fn remove_middle_enclave_works() {
    new_test_ext().execute_with(|| {
        // use the newest timestamp, is as now such that all reports are valid
        Timestamp::set_timestamp(TEST7_TIMESTAMP);

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

        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer5.clone()),
            TEST5_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave_count(), 1);
        assert_eq!(list_enclaves(), vec![(1, e_1.clone())]);

        // add enclave 2
        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer6.clone()),
            TEST6_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave_count(), 2);
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_1.clone())));
        assert!(enclaves.contains(&(2, e_2.clone())));

        // add enclave 3
        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer7.clone()),
            TEST7_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave_count(), 3);
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_1.clone())));
        assert!(enclaves.contains(&(2, e_2.clone())));
        assert!(enclaves.contains(&(3, e_3.clone())));

        // remove enclave 2
        assert_ok!(SubstrateeRegistry::unregister_enclave(Origin::signed(
            signer6
        )));
        assert_eq!(SubstrateeRegistry::enclave_count(), 2);
        let enclaves = list_enclaves();
        assert!(enclaves.contains(&(1, e_1.clone())));
        assert!(enclaves.contains(&(2, e_3.clone())));
    })
}

#[test]
fn register_enclave_with_different_signer_fails() {
    new_test_ext().execute_with(|| {
        let signer = get_signer(TEST7_SIGNER_PUB);
        assert_err!(
            SubstrateeRegistry::register_enclave(
                Origin::signed(signer),
                TEST5_CERT.to_vec(),
                URL.to_vec()
            ),
            Error::<Test>::SenderIsNotAttestedEnclave
        );
    })
}

#[test]
fn register_enclave_with_to_old_attestation_report_fails() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST7_TIMESTAMP + TWENTY_FOUR_HOURS + 1);
        let signer = get_signer(TEST7_SIGNER_PUB);
        assert_err!(
            SubstrateeRegistry::register_enclave(
                Origin::signed(signer),
                TEST7_CERT.to_vec(),
                URL.to_vec(),
            ),
            Error::<Test>::RemoteAttestationTooOld
        );
    })
}

#[test]
fn register_enclave_with_almost_too_old_report_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST7_TIMESTAMP + TWENTY_FOUR_HOURS - 1);
        let signer = get_signer(TEST7_SIGNER_PUB);
        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer),
            TEST7_CERT.to_vec(),
            URL.to_vec()
        ));
    })
}

#[test]
fn update_enclave_url_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);

        let signer = get_signer(TEST4_SIGNER_PUB);
        let url2 = "my fancy url".as_bytes();
        let _e_1: Enclave<AccountId, Vec<u8>> = Enclave {
            pubkey: signer.clone(),
            mr_enclave: TEST4_MRENCLAVE,
            timestamp: TEST4_TIMESTAMP,
            url: url2.to_vec(),
        };

        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave(1).url, URL.to_vec());

        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            url2.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave(1).url, url2.to_vec());
        let enclaves = list_enclaves();
        assert_eq!(enclaves[0].1.pubkey, signer)
    })
}

#[test]
fn update_ipfs_hash_works() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);

        let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
        let shard = H256::default();
        let request_hash = H256::default();
        let signer = get_signer(TEST4_SIGNER_PUB);

        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave_count(), 1);
        assert_ok!(SubstrateeRegistry::confirm_call(
            Origin::signed(signer.clone()),
            shard.clone(),
            request_hash.clone(),
            ipfs_hash.as_bytes().to_vec()
        ));
        assert_eq!(
            SubstrateeRegistry::latest_ipfs_hash(shard.clone()),
            ipfs_hash.as_bytes().to_vec()
        );
        assert_eq!(SubstrateeRegistry::worker_for_shard(shard.clone()), 1u64);

        let expected_event = Event::SubstrateeRegistry(RawEvent::UpdatedIpfsHash(
            shard.clone(),
            1,
            ipfs_hash.as_bytes().to_vec(),
        ));
        assert!(System::events().iter().any(|a| a.event == expected_event));

        let expected_event =
            Event::SubstrateeRegistry(RawEvent::CallConfirmed(signer.clone(), request_hash));
        assert!(System::events().iter().any(|a| a.event == expected_event));
    })
}

#[test]
fn ipfs_update_from_unregistered_enclave_fails() {
    new_test_ext().execute_with(|| {
        let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
        let signer = get_signer(TEST4_SIGNER_PUB);
        assert!(SubstrateeRegistry::confirm_call(
            Origin::signed(signer),
            H256::default(),
            H256::default(),
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
        assert!(SubstrateeRegistry::call_worker(Origin::signed(signer), req.clone()).is_ok());
        let expected_event = Event::SubstrateeRegistry(RawEvent::Forwarded(req.shard));
        println!("events:{:?}", System::events());
        assert!(System::events().iter().any(|a| a.event == expected_event));
    })
}

#[test]
fn unshield_is_only_executed_once_for_the_same_call_hash() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(TEST4_TIMESTAMP);
        let signer = get_signer(TEST4_SIGNER_PUB);
        let call_hash: H256 = H256::from([1u8; 32]);

        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(signer.clone()),
            TEST4_CERT.to_vec(),
            URL.to_vec()
        ));

        assert_ok!(Balances::transfer(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            signer.clone(),
            1 << 50
        ));

        assert!(SubstrateeRegistry::unshield_funds(
            Origin::signed(signer.clone()),
            AccountKeyring::Alice.to_account_id(),
            50,
            signer.clone(),
            call_hash.clone()
        )
        .is_ok());

        assert!(SubstrateeRegistry::unshield_funds(
            Origin::signed(signer.clone()),
            AccountKeyring::Alice.to_account_id(),
            50,
            signer,
            call_hash.clone()
        )
        .is_ok());

        assert_eq!(<ConfirmedCalls>::get(call_hash), 2)
    })
}