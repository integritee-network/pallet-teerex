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
