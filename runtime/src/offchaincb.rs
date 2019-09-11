/// A runtime module template with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references


/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/srml/example/src/lib.rs

use rstd::prelude::*;
use support::{decl_module, decl_event, decl_storage, dispatch::Result};
use system::ensure_signed;
use system::offchain::SubmitUnsignedTransaction;
use session;

use core::convert::TryInto;

/// The module's configuration trait.
pub trait Trait: system::Trait {
	/// A dispatchable call type.
	type Call: From<Call<Self>>;

	/// The overarching event type
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event> + From<<Self as system::Trait>::Event> + TryInto<Event<Self>>;
	/// The way through which we submit signed transactions
	type SubmitTransaction = SubmitUnsignedTransaction<Self, <Self as Trait>::Call>;
}

decl_storage! {
	trait Store for Module<T: Trait> as OffchainCb {
		/// The current set of keys that may submit pongs
		Keys get(keys): Vec<T::AccountId>;
	}
	add_extra_genesis {
		config(keys): Vec<T::AccountId>;
		build(|config| Module::<T>::initialize_keys(&config.keys))
	}
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

		pub fn pong(origin, index: u32, something: u32, who: T::AccountId) -> Result {
			let author = ensure_signed(origin)?;
			if Some(author) = Keys::<T>::get().get(index) {
				// here we are raising the Something event
				Self::deposit_event(RawEvent::Ack(something, author));
			}

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

		let (index, key) = match {
			let authorities = Keys::<T>::get();
			let mut local_keys = T::AccountId::all();
			local_keys.sort();

			authorities.into_iter()
				.enumerate()
				.filter_map(|(index, authority)| {
					local_keys.binary_search(&authority)
						.ok()
						.map(|location| (index as u32, &local_keys[location]))
				}).next()
			} {
			Some((index, key)) => (index, key),
			_ => {
				runtime_io::print("No acceptable key found, not running offchain worker");
				return;
			}
		};

		// On
		for e in <system::Module<T>>::events() {
			let evt: <T as Trait>::Event = e.event.into();
			if let Ok(Event::<T>::Ping(something, who)) = evt.try_into() {
				runtime_io::print("Received ping, sending pong");
				let call = <T as Trait>::Call::from(Call::pong(index, something, who));
				Self::SubmitTransaction::sign_and_submit(call, key);
			}
		}
	}

	fn initialize_keys(keys: &[T::AccountId]) {
		if !keys.is_empty() {
			assert!(Keys::<T>::get().is_empty(), "Keys are already initialized!");
			Keys::<T>::put_ref(keys);
		}
	}
}

impl<T: Trait> session::OneSessionHandler<T::AccountId> for Module<T> {

	type Key = T::AccountId;

	fn on_genesis_session<'a, I: 'a>(validators: I)
		where I: Iterator<Item=(&'a T::AccountId, T::AccountId)>
	{
		let keys = validators.map(|x| x.1).collect::<Vec<_>>();
		Self::initialize_keys(&keys);
	}

	fn on_new_session<'a, I: 'a>(_changed: bool, validators: I, _queued_validators: I)
		where I: Iterator<Item=(&'a T::AccountId, T::AccountId)>
	{
		// Remember who the authorities are for the new session.
		Keys::<T>::put(validators.map(|x| x.1).collect::<Vec<_>>());
	}

	fn on_before_session_ending() {
		Keys::<T>::kill();
	}

	fn on_disabled(_i: usize) {
		Keys::<T>::kill();
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
