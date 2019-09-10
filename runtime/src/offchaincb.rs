/// A runtime module template with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references


/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/srml/example/src/lib.rs

use support::{decl_module, decl_event, dispatch::Result};
use system::ensure_signed;
use core::convert::TryInto;

/// The module's configuration trait.
pub trait Trait: system::Trait {
	/// A dispatchable call type.
	type Call: From<Call<Self>>;

	/// The overarching event type.f
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event> + From<<Self as system::Trait>::Event> + TryInto<Event<Self>>;
}

// The module's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// Initializing events
		// this is needed only if you are using events in your module
		fn deposit_event() = default;

		// Just a dummy entry point.
		// function that can be called by the external world as an extrinsics call
		// takes a parameter of the type `AccountId`, stores it and emits an event
		pub fn ping(origin, something: u32) -> Result {
			let who = ensure_signed(origin)?;

			// here we are raising the Something event
			Self::deposit_event(RawEvent::Ping(something, who));
			Ok(())
		}

		pub fn pong(origin, something: u32, who: T::AccountId) -> Result {
			let _author = ensure_signed(origin)?;

			// here we are raising the Something event
			Self::deposit_event(RawEvent::Ack(something, who));
			Ok(())
		}

		// Runs after every block.q
		fn offchain_worker(_now: T::BlockNumber) {
			if runtime_io::is_validator() {
				Self::offchain();
			}
		}
	}
}


impl<T: Trait> Module<T> {
	fn offchain() {
		runtime_io::print("Offchain triggered");
		// On
		for e in <system::Module<T>>::events() {
			let evt: <T as Trait>::Event = e.event.into();
			if let Ok(Event::<T>::Ping(something, who)) = evt.try_into() {
				runtime_io::print("Received ping, sending pong");
				let call = <T as Trait>::Call::from(Call::pong(something, who));
                let extrinsic = prepare_transaction::<T>(call);
				runtime_io::submit_transaction(&extrinsic);
			}
		}
	}
}

// This should convert a runtime-wide `Call` into runtime-wide `Extrinsic` type.
// And that's exactly what `srml_system::offchain::SubmitTransaction` extension is
// attempting to simplify.
fn prepare_transaction<T: Trait>(call: <T as Trait>::Call) -> impl codec::Encode {
    unimplemented!()
}

decl_event!(
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		// Just a dummy event.
		// Event `Something` is declared with a parameter of the type `u32` and `AccountId`
		// To emit this event, we call the deposit funtion, from our runtime funtions
		Ping(u32, AccountId),
		// When we received a Pong, we also Ack it.
		Ack(u32, AccountId),
	}
);

/// tests for this module
#[cfg(test)]
mod tests {
	use super::*;

	use runtime_io::with_externalities;
	use primitives::{H256, Blake2Hasher};
	use support::{impl_outer_origin, assert_ok, parameter_types, impl_outer_event};
	use sr_primitives::{traits::{BlakeTwo256, IdentityLookup}, testing::Header};
	use sr_primitives::weights::Weight;
	use sr_primitives::Perbill;

	impl_outer_origin! {
		pub enum Origin for Test {}
	}

    use crate::template as module;
    impl_outer_event! {
		pub enum TestEvent for Test {
			module<T>,
		}
	}

	// For testing the module, we construct most of a mock runtime. This means
	// first constructing a configuration type (`Test`) which `impl`s each of the
	// configuration traits of modules we want to use.
	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;
	parameter_types! {
		pub const BlockHashCount: u64 = 250;
		pub const MaximumBlockWeight: Weight = 1024;
		pub const MaximumBlockLength: u32 = 2 * 1024;
		pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
	}
	impl system::Trait for Test {
		type Origin = Origin;
		type Call = ();
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type AccountId = u64;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Header = Header;
		type WeightMultiplierUpdate = ();
		type Event = TestEvent;
		type BlockHashCount = BlockHashCount;
		type MaximumBlockWeight = MaximumBlockWeight;
		type MaximumBlockLength = MaximumBlockLength;
		type AvailableBlockRatio = AvailableBlockRatio;
		type Version = ();
	}
	impl Trait for Test {
		type Event = TestEvent;
	}
	type TemplateModule = Module<Test>;
	type SystemModule = system::Module<Test>;

	// This function basically just builds a genesis storage key/value store according to
	// our desired mockup.
	fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
		system::GenesisConfig::default().build_storage::<Test>().unwrap().into()
	}

	#[test]
	fn it_works_for_default_value() {
		with_externalities(&mut new_test_ext(), || {
			// Just a dummy test for the dummy funtion `do_something`
			// calling the `do_something` function with a value 42
			assert_ok!(TemplateModule::ping(Origin::signed(1), 42));

			// check the entry was signalled
			assert_eq!(SystemModule::events()[0].event, RawEvent::Ping(42, 1).into());
		});
	}
}
