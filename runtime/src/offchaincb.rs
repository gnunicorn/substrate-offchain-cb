 // Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use rstd::prelude::*;
use app_crypto::RuntimeAppPublic;
use support::{decl_module, decl_event, decl_storage, StorageValue, dispatch::Result};
use system::{ensure_signed, ensure_root};
use system::offchain::SubmitSignedTransaction;
use core::convert::TryInto;

pub const KEY_TYPE: app_crypto::KeyTypeId = app_crypto::KeyTypeId(*b"ofcb");

/// The module's configuration trait.
pub trait Trait: system::Trait  {
	/// A dispatchable call type.
	type Call: From<Call<Self>>;
	/// The overarching event type
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event> + From<<Self as system::Trait>::Event> + TryInto<Event<Self>>;
	/// The way through which we submit signed transactions
	type SubmitTransaction: SubmitSignedTransaction<Self, <Self as Trait>::Call>;
    /// A key type for offchaincb.
    type KeyType: RuntimeAppPublic + From<Self::AccountId> + Into<Self::AccountId> + Clone;
}

decl_storage! {
	trait Store for Module<T: Trait> as OffchainCb {
		/// The current set of keys that may submit pongs
		Authorities get(authorities): Vec<T::AccountId>;
	}
}

// The module's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// Initializing events
		// this is needed only if you are using events in your module
		fn deposit_event() = default;

		// This will trigger the ping to the offchain worker
		pub fn ping(origin, something: u32) -> Result {
			let who = ensure_signed(origin)?;

			// Let's send the ping event out
			Self::deposit_event(RawEvent::Ping(something, who));
			Ok(())
		}

		// Function called from the offchain worker to respond to a ping
		pub fn pong(origin, something: u32) -> Result {
			// Must be signed
			let author = ensure_signed(origin)?;
			// And a valid authorities, we accept offchain-worker calls from
			if Self::is_authority(&author) {
				// Then we act
				Self::deposit_event(RawEvent::Ack(something, author));
			}
			// Else we just consume their transcation fee without any reaction

			Ok(())
		}

		// Add a new authority
		pub fn add_authority(origin, who: T::AccountId) {
			let _me = ensure_root(origin)?;

			if !Self::is_authority(&who){
				<Authorities<T>>::mutate(|l| l.push(who));
			}

		}

		// Runs after every block.q
		fn offchain_worker(_now: T::BlockNumber) {
			Self::offchain();
		}
	}
}


impl<T: Trait> Module<T> {

	fn is_authority(who: &T::AccountId) -> bool {
		Self::authorities().into_iter().find(|i| i == who).is_some()
	}

	fn authority_id() -> Option<T::AccountId> {
		let local_keys = T::KeyType::all().iter().map(
				|i| (*i).clone().into()
			).collect::<Vec<T::AccountId>>();

		Self::authorities().into_iter().find_map(|authority| {
			if local_keys.contains(&authority) {
				Some(authority)
			} else {
				None
			}
		})
	}

	fn offchain() {
		if let Some(key) = Self::authority_id() {
			runtime_io::print("Offchain triggered");
			for e in <system::Module<T>>::events() {
				let evt: <T as Trait>::Event = e.event.into();
				if let Ok(Event::<T>::Ping(something, _who)) = evt.try_into() {
					runtime_io::print("Received ping, sending pong");
					let call = Call::pong(something);
					let _ = T::SubmitTransaction::sign_and_submit(call, key.clone().into());
				}
			}
		} else {
			runtime_io::print("Skipped Offchain Worker, we aren't a valid authority");
		}
	}
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
