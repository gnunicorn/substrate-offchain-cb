//! # Offchain Worker Callback Example
//!
//! This is a minimal example module to show case how the runtime can and should
//! interact with an offchain worker asynchronously.
//!
//! This example plays simple ping-pong with authenticated off-chain workers:
//! Once a signed transaction to `ping` is submitted, the runtime store `Ping` request.
//! After every block the offchain worker is triggered. If it sees a `Ping` request
//! in the current block, it reacts by sending a signed transaction to call
//! `pong`.  When `pong` is called, it emits an `Ack` event so it easy to track
//! with existing UIs whether the Ping-Pong-Ack happened.
//!
//! However, because the `pong` contains trusted information (the `nonce`) the runtime
//! can't verify by itself - the key reason why we have the offchain worker in the
//! first place - we can't allow just anyone to call `pong`. Instead the runtime has a
//! local list of `authorities`-keys that allowed to evoke `pong`. In this simple example
//! this list can only be extended via a root call (e.g. `sudo`). In practice more
//! complex management models and session based key rotations should be considered, but
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
use codec::{Encode, Decode};

/// Our local KeyType.
///
/// For security reasons the offchain worker doesn't have direct access to the keys
/// but only to app-specific subkeys, which are defined and grouped by their `KeyTypeId`.
/// We define it here as `ofcb` (for `offchain callback`). Yours should be specific to
/// the module you are actually building.
pub const KEY_TYPE: app_crypto::KeyTypeId = app_crypto::KeyTypeId(*b"ofcb");

/// The module's main configuration trait.
pub trait Trait: system::Trait  {
	/// The regular events type, we use to emit the `Ack`
	type Event:From<Event<Self>> + Into<<Self as system::Trait>::Event>;

	/// A dispatchable call type. We need to define it for the offchain worker to
	/// reference the `pong` function it wants to call.
	type Call: From<Call<Self>>;

	/// Let's define the helper we use to create signed transactions with
	type SubmitTransaction: SubmitSignedTransaction<Self, <Self as Trait>::Call>;

	/// The local keytype
	type KeyType: RuntimeAppPublic + From<Self::AccountId> + Into<Self::AccountId> + Clone;
}

/// The type of requests we can send to the offchain worker
#[cfg_attr(feature = "std", derive(PartialEq, Eq, Debug))]
#[derive(Encode, Decode)]
pub enum OffchainRequest<T: system::Trait> {
	/// If an authorised offchain worker sees this ping, it shall respond with a `pong` call
	Ping(u8,  <T as system::Trait>::AccountId)
}

// We use the regular Event type to sent the final ack for the nonce
decl_event!(
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		/// When we received a Pong, we also Ack it.
		Ack(u8, AccountId),
	}
);


// We use storage in two important ways here:
// 1. we have a local list of `OcRequests`, which are cleared at the beginning
//    and then collected throughout a block
// 2. we store the list of authorities, from whom we accept `pong` calls.
decl_storage! {
	trait Store for Module<T: Trait> as OffchainCb {
		/// Requests made within this block execution
		OcRequests get(oc_requests): Vec<OffchainRequest<T>>;
		/// The current set of keys that may submit pongs
		Authorities get(authorities) config(): Vec<T::AccountId>;
	}
}


// The actual Module definition. This is where we create the callable functions
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		/// Initializing events
		fn deposit_event() = default;

		/// Clean the state on initialisation of a block
		fn on_initialize(_now: T::BlockNumber) {
			// At the beginning of each block execution, system triggers all
			// `on_initialize` functions, which allows us to set up some temporary state or - like
			// in this case - clean up other states
			<Self as Store>::OcRequests::kill();
		}


		/// The entry point function: storing a `Ping` offchain request with the given `nonce`.
		pub fn ping(origin, nonce: u8) -> Result {
			// It first ensures the function was signed, then it store the `Ping` request
			// with our nonce and author. Finally it results with `Ok`.
			let who = ensure_signed(origin)?;

			<Self as Store>::OcRequests::mutate(|v| v.push(OffchainRequest::Ping(nonce, who)));
			Ok(())
		}

		/// Called from the offchain worker to respond to a ping
		pub fn pong(origin, nonce: u8) -> Result {
			// We don't allow anyone to `pong` but only those authorised in the `authorities`
			// set at this point. Therefore after ensuring this is singed, we check whether
			// that given author is allowed to `pong` is. If so, we emit the `Ack` event,
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


// We've moved the  helper functions outside of the main declaration for brevity.
impl<T: Trait> Module<T> {

	/// The main entry point, called with account we are supposed to sign with
	fn offchain(key: &T::AccountId) {
		// Let's iterate through the locally stored requests and react to them.
		// At the moment, only knows of one request to respond to: `ping`.
		// Once a ping is found, we respond by calling `pong` as a transaction
		// signed with the given key.
		// This would be the place, where a regular offchain worker would go off
		// and do its actual thing before responding async at a later point in time.
		//
		// Note, that even though this is run directly on the same block, as we are
		// creating a new transaction, this will only react _in the following_ block.
		for e in <Self as Store>::OcRequests::get() {
			match e {
				OffchainRequest::Ping(nonce, _who) => {
					Self::respond(key, nonce)
				}
				// there would be potential other calls
			}
		}
	}

	/// Respondong to as the given account to a given nonce by calling `pong` as a
	/// newly signed and submitted trasnaction
	fn respond(key: &T::AccountId, nonce: u8) {
		runtime_io::print_utf8(b"Received ping, sending pong");
		let call = Call::pong(nonce);
		let _ = T::SubmitTransaction::sign_and_submit(call, key.clone().into());
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

/// This module contains all the testing boilerplate, and the unit test functions. We will not go
/// into the details of the setup needed for tests. For more information about test setup, visit the
/// [substrate developer hub](https://substrate.dev). Namely, the substrate collectables workshop
/// has a dedicated
/// [chapter](https://substrate.dev/substrate-collectables-workshop/#/5/introduction) on tests.
#[cfg(test)]
mod tests {
	use codec::Decode;
	use std::sync::Arc;
	use parking_lot::RwLock;
	use sr_primitives::{
		Perbill, generic, RuntimeAppPublic,
		testing::{Header, TestXt, UintAuthorityId},
		traits::{IdentityLookup, BlakeTwo256, Block, Dispatchable},
	};
	use offchain::testing::TestOffchainExt;
	use primitives::{H256, Blake2Hasher};
	use support::{construct_runtime, parameter_types, assert_ok};
	use runtime_io::{with_externalities, TestExternalities};
	use system;
	use crate::offchaincb as offchaincb;

	// Define some type aliases. We use the simplest form of anything which is not relevant for
	// simplicity, e.g. account ids are just numbers and signed extensions are empty (`()`).
	type AccountId = u64;
	type AccountIndex = u64;
	type Extrinsic = TestXt<Call, ()>;
	// Consequently, we use the `UIntAuthorityId` as a mocked identifier for authorities.
	type SubmitTransaction = system::offchain::TransactionSubmitter<UintAuthorityId, Call, Extrinsic>;
	type NodeBlock = generic::Block<Header, Extrinsic>;

	// TODO: implement this for runtime or call?
	impl system::offchain::CreateTransaction<TestRuntime, Extrinsic> for Call {
		type Signature = u64;

		// Pay close attention to how this implementation --drastically-- differs from the real one
		// in the top level runtime aggregator file, and how it creates a mock signature (which is
		// actually the account id itself).
		fn create_transaction<F: system::offchain::Signer<AccountId, Self::Signature>>(
			call: Call,
			account: AccountId,
			_index: AccountIndex,
		) -> Option<(Call, <Extrinsic as sr_primitives::traits::Extrinsic>::SignaturePayload)> {
			let extra = ();
			Some((call, (account, extra)))
		}
	}

	// Define the required constants for system module,
	parameter_types! {
		pub const BlockHashCount: u64 = 250;
		pub const MaximumBlockWeight: u32 = 1024;
		pub const MaximumBlockLength: u32 = 2 * 1024;
		pub const AvailableBlockRatio: Perbill = Perbill::one();
	}

	// and add it to our test runtime.
	impl system::Trait for TestRuntime {
		type Origin = Origin;
		type Index = AccountIndex;
		type BlockNumber = u64;
		type Call = Call;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type AccountId = AccountId;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Header = Header;
		type WeightMultiplierUpdate = ();
		type Event = Event;
		type BlockHashCount = BlockHashCount;
		type MaximumBlockWeight = MaximumBlockWeight;
		type MaximumBlockLength = MaximumBlockLength;
		type AvailableBlockRatio = AvailableBlockRatio;
		type Version = ();
	}

	impl offchaincb::Trait for TestRuntime {
		type Event = Event;
		type Call = Call;
		type SubmitTransaction = SubmitTransaction;
		type KeyType = UintAuthorityId;
	}

	// Create the mock runtime with all the top level structures that we use: `Call`, `Event`, etc.
	construct_runtime!(
		pub enum TestRuntime where
			Block = NodeBlock,
			NodeBlock = NodeBlock,
			UncheckedExtrinsic = Extrinsic
		{
			System: system::{Module, Call, Event},
			OffchainCb: offchaincb::{Module, Call, Event<T> ,Config<T>},
		}
	);

	// Create the externalities (aka. _execution environment_/_storage_) of our test. Just note how
	// this function accepts a parameter and writes that as the _local keys_. These keys are then
	// matched against the `authorities` stored in the runtime storage. For now, we assume that only
	// account 49 is an authority. Hence, in further tests, a `new_test_ext()` called with an
	// parameter that contains `49` is analogous to running the code in a _node who is an
	// authority_.
	pub fn new_test_ext(local_keys: Vec<AccountId>) -> TestExternalities<Blake2Hasher> {
		let mut t = system::GenesisConfig::default().build_storage::<TestRuntime>().unwrap();
		// Any node that has local key `49` can submit a pong.
		offchaincb::GenesisConfig::<TestRuntime> { authorities: vec![49] }
			.assimilate_storage(&mut t).unwrap();
		UintAuthorityId::set_all_keys(local_keys);
		t.into()
	}

	/// A utility function for our tests. It simulates what the system module does for us (almost
	/// analogous to `finalize_block`).
	///
	/// This function increments the block number and simulates what we have written in
	/// `decl_module` as `fn offchain_worker(_now: T::BlockNumber)`: run the offchain logic if the
	/// current node is an authority.
	///
	/// Also, since the offchain code might submit some transactions, it queries the transaction
	/// queue and dispatches any submitted transaction. This is also needed because it is a
	/// non-runtime logic (transaction queue) which needs to mocked inside a runtime test.
	fn seal_block(n: u64, state: Arc<RwLock<offchain::testing::State>>) -> Option<usize> {
		assert_eq!(System::block_number(), n);
		System::set_block_number(n + 1);
		if let Some(key) = OffchainCb::authority_id() {
			// run offchain
			OffchainCb::offchain(&key);

			// if there are any txs submitted to the queue, dispatch them
			let transactions = &mut state.write().transactions;
			let count = transactions.len();
			while let Some(t) = transactions.pop() {
				let e: Extrinsic = Decode::decode(&mut &*t).unwrap();
				let (who, _) = e.0.unwrap();
				let call = e.1;
				// in reality you would do `e.apply`, but this is a test. we assume we don't care
				// about validation etc.
				let _ = call.dispatch(Some(who).into()).unwrap();
			}
			Some(count)
		} else {
			None
		}
	}

	// We just want to test the initial state of the test mockup. No interaction.
	#[test]
	fn test_setup_works() {
		// a normal node.
		with_externalities(&mut new_test_ext(vec![1, 2, 3]), || {
			assert_eq!(OffchainCb::authorities(), vec![49]);
			assert_eq!(
				UintAuthorityId::all(),
				vec![1u64, 2, 3].into_iter().map(Into::into).collect::<Vec<UintAuthorityId>>()
			);

			assert_eq!(OffchainCb::is_authority(&1), false);
			assert_eq!(OffchainCb::is_authority(&2), false);
			assert_eq!(OffchainCb::is_authority(&3), false);
			assert_eq!(OffchainCb::is_authority(&49), true);

			assert!(OffchainCb::authority_id().is_none());
			assert_eq!(OffchainCb::oc_requests().len(), 0);
		});

		// an authority node.
		with_externalities(&mut new_test_ext(vec![2, 49]), || {
			assert_eq!(OffchainCb::authorities(), vec![49]);
			assert_eq!(
				UintAuthorityId::all(),
				vec![2u64, 49].into_iter().map(Into::into).collect::<Vec<UintAuthorityId>>()
			);
			assert!(OffchainCb::authority_id().is_some());
		});
	}

	// Send a ping and verify that the ping struct has been stored in the `OcRequests` storage.
	#[test]
	fn ping_should_work() {
		with_externalities(&mut new_test_ext(vec![1]), || {
			assert_ok!(OffchainCb::ping(Origin::signed(1), 1));
			assert_eq!(OffchainCb::oc_requests().len(), 1);
			assert_eq!(
				OffchainCb::oc_requests()[0],
				offchaincb::OffchainRequest::Ping(1, 1),
			);
		})
	}

	// Verify that any origin can send a ping and the even is triggered regardless.
	#[test]
	fn anyone_can_ping() {
		// Current node is an authority. This does not matter in this test.
		with_externalities(&mut new_test_ext(vec![49, 10]), || {
			// An authority (current node) can submit ping.
			assert_ok!(OffchainCb::ping(Origin::signed(49), 1));
			// normal key can also submit ping.
			assert_ok!(OffchainCb::ping(Origin::signed(10), 4));

			// both should be processed.
			assert_eq!(
				OffchainCb::oc_requests()[0],
				offchaincb::OffchainRequest::Ping(1, 49),
			);

			assert_eq!(
				OffchainCb::oc_requests()[1],
				offchaincb::OffchainRequest::Ping(4, 10),
			);
		})
	}

	// Verify that the offchain is executed if the current node is an authority.
	#[test]
	fn ping_triggers_ack() {
		// Assume current node has key 49, hence is an authority.
		let mut ext = new_test_ext(vec![49]);
		let (offchain, state) = TestOffchainExt::new();
		ext.set_offchain_externalities(offchain);

		with_externalities(&mut ext, || {
			// 2 submits a ping. Assume this is an extrinsic from the outer world.
			assert_ok!(OffchainCb::ping(Origin::signed(2), 1));
			assert_eq!(
				OffchainCb::oc_requests()[0],
				offchaincb::OffchainRequest::Ping(1, 2),
			);

			// 49 is an authority (current externality), should be able to call pong.
			assert!(seal_block(1, state).is_some());

			// which triggers ack
			assert_eq!(
				System::events()[0].event,
				Event::offchaincb(offchaincb::RawEvent::Ack(1, 49)),
			);
		})
	}

	// Verify that a non-authority will not execute the offchain logic.
	#[test]
	fn only_authorities_can_pong() {
		// Current node does not have key 49, hence is not the authority.
		let mut ext = new_test_ext(vec![69]);
		let (offchain, state) = TestOffchainExt::new();
		ext.set_offchain_externalities(offchain);

		with_externalities(&mut ext, || {
			assert_ok!(OffchainCb::ping(Origin::signed(2), 1));
			// 69 is not an authority.
			assert!(seal_block(1, state).is_none());
		})
	}
}

