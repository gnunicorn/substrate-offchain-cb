//! # Offchain Worker Callback Example 
//!
//! This is a minimal example module to show case how the runtime can and should
//! interact with an offchain worker asynchronously.
//!
//! This example plays simple ping-pong with authenticated off-chain workers:
//! Once a signed transaction to `ping` is submitted, the runtime emits the `Ping`
//! event. After every block the offchain worker is triggered. If it sees the `Ping`
//! event in the current block, it reacts by sending a signed transaction to call
//! `pong`.  When `pong` is called, it emits an `Ack` event so it easy to track
//! with existing UIs whether the Ping-Pong-Ack happened. The offchain worker does
//! not react on `Ack`.
//!
//! However, because the `pong` contains trusted information (the `nonce`) the runtime
//! can't verify by itself - the key reason why we have the offchain worker in the
//! first place, we can't allow just anyone to call `pong`. Instead the runtime has a
//! local list of `authorities`-keys that allowed to evoke `pong`. In this simple example
//! this list can only be extended via a root call (e.g. `sudo`). In practice more
//! complex management models and session based key rotations should be conidered, but 
//! this is out of the scope of this example

// Ensure we're `no_std` when compiling for Wasm. Otherwise our `Vec` and operations
// on it will fail with `invalid`.
#![cfg_attr(not(feature = "std"), no_std)]

// We have to import a few things
use rstd::prelude::*;
use app_crypto::RuntimeAppPublic;
use support::{decl_module, decl_event, decl_storage, StorageValue, dispatch::Result};
use system::{ensure_signed, ensure_root};
use system::offchain::SubmitSignedTransaction;
use core::convert::TryInto;

/// Our local KeyType.
///
/// For security reasons the offchain worker doesn't have direct access to tohe keys
/// but only to app-specific subkeys, which are defined and grouped  by their KeyTypeId.
/// We define it here as `ofcb` (for `offchain callback`). Yours should be specific to
/// the module you are actually building.
pub const KEY_TYPE: app_crypto::KeyTypeId = app_crypto::KeyTypeId(*b"ofcb");

/// The module's main configuration trait.
pub trait Trait: system::Trait  {
	/// The regular events type.
	/// Extended by a few `TryInto` and other traits so we can match this back
	/// with our localised event from within the offchain worker after it was emitted.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event> + From<<Self as system::Trait>::Event> + TryInto<Event<Self>>;

	/// A dispatchable call type. We need to define it for the offchain worker to 
	/// reference the `pong` function it wants to call.
	type Call: From<Call<Self>>;

	/// Let's define the helper we use to create signed transactions with
	type SubmitTransaction: SubmitSignedTransaction<Self, <Self as Trait>::Call>;

	/// The local keytype
	type KeyType: RuntimeAppPublic + From<Self::AccountId> + Into<Self::AccountId> + Clone;
}


// Then we need some events. The runtime and offchain worker can't talk to one another directly,
// but the runtime can emit events that the offchain worker then react upon. In
decl_event!(
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		/// Emitted when someone asks us to ping
		Ping(u8, AccountId),
		/// When we received a Pong, we also Ack it.
		Ack(u8, AccountId),
	}
);


// In this example, we only use the store to keep the list of currently
// authorised keys
decl_storage! {
	trait Store for Module<T: Trait> as OffchainCb {
		/// The current set of keys that may submit pongs
		Authorities get(authorities): Vec<T::AccountId>;
	}
}


// The actual Module definition. This is where we create the callable functions
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		/// Initializing events
		fn deposit_event() = default;

		/// The entry point function: emitting a `Ping` event with the given `nonce`.
		pub fn ping(origin, nonce: u8) -> Result {
			// It first ensures the function was signed, then it emits the `Ping` event
			// with our nonce and author. Finally it results with `Ok`.
			let who = ensure_signed(origin)?;

			Self::deposit_event(RawEvent::Ping(nonce, who));
			Ok(())
		}

		/// Called from the offchain worker to respond to a ping
		pub fn pong(origin, nonce: u8) -> Result {
			// We don't allow anyone to `pong` but only those authorised in the `authorities`
			// set at this point. Therefore after ensuring this is singed, we check whether
			// that given author is allowed to `pong` is. If so, we emit the `Ack` signal,
			// otherwise we've just consumed their fee.
			let author = ensure_signed(origin)?;

			if Self::is_authority(&author) {
				Self::deposit_event(RawEvent::Ack(nonce, author));
			}

			Ok(())
		}

		// Runs after every block within the context and current state of said block.
		fn offchain_worker(_now: T::BlockNumber) {
			// As `pongs` are only accepted by authorities, we only run this code,
			// if a valid local key is found, we could submit them with.
			if let Some(key) = Self::authority_id() {
				Self::offchain(&key);
			}
		}

		// Simple authority management: add a new authority to the set of keys that
		// are allowed to respond with `pong`.
		pub fn add_authority(origin, who: T::AccountId) -> Result {
			// In practice this should be a bit cleverer, but for this example it is enough
			// that this is protected by a root-call (e.g. through governance like `sudo`).
			let _me = ensure_root(origin)?;

			if !Self::is_authority(&who){
				<Authorities<T>>::mutate(|l| l.push(who));
			}

			Ok(())
		}
	}
}


// We've moved the  helper functions outside of the main decleration for briefety.
impl<T: Trait> Module<T> {

	/// The main entry point, called with account we are supposed to sign with
	fn offchain(key: &T::AccountId) {
		// This iterates through all events emitted by the current block and
		// attempts to convert them into a local `event` of this module to find
		// the `Ping`s emitted.
		// Once a ping is found, we inform the user via a command line print
		// and emit the pong and respond by calling `pong` as a transaction
		// signed with the given key.
		// This would be the place, where a regular offchain worker would go off
		// and do its actual thing before reponding async at a later point in time.
		// 
		// Note, that even though this is run directly on the same block, as we are
		// creating a new transaction, this will only react _in the following_ block.
		for e in <system::Module<T>>::events() {
			let evt: <T as Trait>::Event = e.event.into();
			if let Ok(Event::<T>::Ping(nonce, _who)) = evt.try_into() {
				runtime_io::print_utf8(b"Received ping, sending pong");
				let call = Call::pong(nonce);
				let _ = T::SubmitTransaction::sign_and_submit(call, key.clone().into());
			}
		}
	}

	/// Helper that confirms whether the given `AccountId` can sign `pong` transactions
	fn is_authority(who: &T::AccountId) -> bool {
		Self::authorities().into_iter().find(|i| i == who).is_some()
	}

	/// Find a local `AccountId` we can sign with, that is allowed to `pong`
	fn authority_id() -> Option<T::AccountId> {
		// Find all local keys accessible to this app through the localised KeyType.
		// Then go through all keys currently stored on chain and check them against
		// the list of local keys until a match is found, otherwise return `None`.
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
}