// Creating mock runtime here

use crate::{Module, Trait};
use sp_core::{sr25519, H256};
use frame_support::{impl_outer_origin, impl_outer_event, parameter_types, weights::Weight};
use frame_system as system;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup, Verify},
    testing::Header, 
    Perbill,
};

impl_outer_origin! {
	pub enum Origin for TestRuntime {}
}

#[derive(Clone, Eq, PartialEq)]
pub struct TestRuntime;
parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
}
impl system::Trait for TestRuntime {
	type Origin = Origin;
	type Call = ();
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = TestEvent;
	type BlockHashCount = BlockHashCount;
	type MaximumBlockWeight = MaximumBlockWeight;
	type DbWeight = ();
	type BlockExecutionWeight = ();
	type ExtrinsicBaseWeight = ();
	type MaximumBlockLength = MaximumBlockLength;
	type AvailableBlockRatio = AvailableBlockRatio;
	type Version = ();
	type ModuleToIndex = ();
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
}
impl Trait for TestRuntime {
	type Event = TestEvent;
}

// Easy access alias
pub type Registry = Module<TestRuntime>;
pub type System = system::Module<TestRuntime>;

// This function basically just builds a genesis storage key/value store according to
// our desired mockup.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = system::GenesisConfig::default()
        .build_storage::<TestRuntime>()
        .unwrap();
    let mut ext: sp_io::TestExternalities = t.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// The signature type used by accounts/transactions.
pub type Signature = sr25519::Signature;
/// An identifier for an account on this system.
pub type AccountId = <Signature as Verify>::Signer;

mod registry {
	pub use crate::Event;
}

impl_outer_event! {
	pub enum TestEvent for TestRuntime {
		registry<T>,
		system<T>,
	}
}
