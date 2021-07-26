use crate::mock::*;
use crate::test_utils::consts::*;
use frame_support::assert_ok;
use sp_keyring::AccountKeyring;

#[test]
fn register_with_skip_ias_works() {
    new_test_ext().execute_with(|| {
        // set the now in the runtime such that the remote attestation reports are within accepted range (24h)
        assert_ok!(SubstrateeRegistry::register_enclave(
            Origin::signed(AccountKeyring::Alice.to_account_id()),
            Vec::new(),
            URL.to_vec()
        ));
        assert_eq!(SubstrateeRegistry::enclave_count(), 1);
    })
}
