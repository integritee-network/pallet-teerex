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

// Creating mock runtime here
use crate as substratee_registry;
use frame_support::parameter_types;
use frame_system as system;
use sp_core::{sr25519, H256};
use sp_keyring::AccountKeyring;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup, Verify},
};
use substratee_registry::Config;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

use consts::*;

#[derive(Copy, Clone)]
pub struct IasSetup {
    pub cert: &'static [u8],
    pub signer_pub: &'static [u8],
    pub mrenclave: [u8; 32],
    pub timestamp: u64
}

pub const IAS_SETUPS: [IasSetup; 4] = [TEST4_SETUP, TEST5_SETUP, TEST6_SETUP, TEST7_SETUP];

pub const TEST4_SETUP: IasSetup = IasSetup {
    cert: TEST4_CERT,
    signer_pub: TEST4_SIGNER_PUB,
    mrenclave: TEST4_MRENCLAVE,
    timestamp: TEST4_TIMESTAMP
};

pub const TEST5_SETUP: IasSetup = IasSetup {
    cert: TEST5_CERT,
    signer_pub: TEST5_SIGNER_PUB,
    mrenclave: TEST5_MRENCLAVE,
    timestamp: TEST5_TIMESTAMP
};

pub const TEST6_SETUP: IasSetup = IasSetup {
    cert: TEST6_CERT,
    signer_pub: TEST6_SIGNER_PUB,
    mrenclave: TEST6_MRENCLAVE,
    timestamp: TEST6_TIMESTAMP
};

pub const TEST7_SETUP: IasSetup = IasSetup {
    cert: TEST7_CERT,
    signer_pub: TEST7_SIGNER_PUB,
    mrenclave: TEST7_MRENCLAVE,
    timestamp: TEST7_TIMESTAMP
};

pub mod consts {
    use hex_literal::hex;

    // reproduce with "substratee_worker dump_ra"
    pub const TEST4_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST4.der");
    pub const TEST5_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST5.der");
    pub const TEST6_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST6.der");
    pub const TEST7_CERT: &[u8] = include_bytes!("../ias-verify/test/ra_dump_cert_TEST7.der");

    // reproduce with substratee-worker signing-key
    pub const TEST4_SIGNER_PUB: &[u8] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST4.bin");
    // equal to TEST4! because of MRSIGNER policy it was possible to change the MRENCLAVE but keep the secret
    pub const TEST5_SIGNER_PUB: &[u8] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST5.bin");
    pub const TEST6_SIGNER_PUB: &[u8] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST6.bin");
    pub const TEST7_SIGNER_PUB: &[u8] =
        include_bytes!("../ias-verify/test/enclave-signing-pubkey-TEST7.bin");

    // reproduce with "make mrenclave" in worker repo root
    // MRSIGNER is always 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
    pub const TEST4_MRENCLAVE: [u8; 32] =
        hex!("7a3454ec8f42e265cb5be7dfd111e1d95ac6076ed82a0948b2e2a45cf17b62a0");
    pub const TEST5_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
    pub const TEST6_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
    pub const TEST7_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");

    // unix epoch. must be later than this
    pub const TEST4_TIMESTAMP: u64 = 1587899785000;
    pub const TEST5_TIMESTAMP: u64 = 1587900013000;
    pub const TEST6_TIMESTAMP: u64 = 1587900233000;
    pub const TEST7_TIMESTAMP: u64 = 1587900450000;

    #[cfg(test)]
    pub const TWENTY_FOUR_HOURS: u64 = 60 * 60 * 24 * 1000;

    pub const URL: &[u8] = &[
        119, 115, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 57, 57, 57, 49,
    ];
}

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        Timestamp: timestamp::{Pallet, Call, Storage, Inherent},
        SubstrateeRegistry: substratee_registry::{Pallet, Call, Storage, Event<T>},
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
}
impl frame_system::Config for Test {
    type BaseCallFilter = ();
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Index = u64;
    type Call = Call;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
}

pub type Balance = u64;

parameter_types! {
    pub const ExistentialDeposit: u64 = 1;
}

impl pallet_balances::Config for Test {
    type MaxLocks = ();
    type Balance = u64;
    type DustRemoval = ();
    type Event = Event;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxReserves = ();
    type ReserveIdentifier = ();
}

parameter_types! {
        pub const MinimumPeriod: u64 = 6000 / 2;
}

pub type Moment = u64;

impl timestamp::Config for Test {
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

parameter_types! {
    pub const MomentsPerDay: u64 = 86_400_000; // [ms/d]
}

impl Config for Test {
    type Event = Event;
    type Currency = Balances;
    type MomentsPerDay = MomentsPerDay;
}

// Easy access alias
//pub type Registry = Module<Test>;
//pub type System = system::Module<TestRuntime>;
//pub type Balances = balances::Module<TestRuntime>;
//pub type Timestamp = timestamp::Module<TestRuntime>;

// This function basically just builds a genesis storage key/value store according to
// our desired mockup.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(AccountKeyring::Alice.public(), 1 << 60)],
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let mut ext: sp_io::TestExternalities = t.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// The signature type used by accounts/transactions.
pub type Signature = sr25519::Signature;
/// An identifier for an account on this system.
pub type AccountId = <Signature as Verify>::Signer;
