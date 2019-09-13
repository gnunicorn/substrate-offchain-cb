//! Based off the regular Substrate Node Template runtime.

#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit="256"]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use rstd::prelude::*;
use primitives::{OpaqueMetadata, crypto::key_types};
use sr_primitives::{
	ApplyResult, transaction_validity::TransactionValidity, generic, create_runtime_str,
	impl_opaque_keys, AnySignature
};
use sr_primitives::traits::{NumberFor, BlakeTwo256, Block as BlockT, DigestFor, StaticLookup, Verify, ConvertInto, SaturatedConversion};
use sr_primitives::weights::Weight;
use babe::{AuthorityId as BabeId};
use grandpa::{AuthorityId as GrandpaId, AuthorityWeight as GrandpaWeight};
use grandpa::fg_primitives::{self, ScheduledChange};
use client::{
	block_builder::api::{CheckInherentsResult, InherentData, self as block_builder_api},
	runtime_api as client_api, impl_runtime_apis
};
use version::RuntimeVersion;
#[cfg(feature = "std")]
use version::NativeVersion;

#[cfg(any(feature = "std", test))]
pub use sr_primitives::BuildStorage;
pub use timestamp::Call as TimestampCall;
pub use balances::Call as BalancesCall;
pub use sr_primitives::{Permill, Perbill};
pub use support::{StorageValue, construct_runtime, parameter_types};
/// Additionally, we need `system` here
use system::offchain::TransactionSubmitter;

/// Everything else is as usual
pub type BlockNumber = u32;
pub type Signature = AnySignature;
pub type AccountId = <Signature as Verify>::Signer;
pub type AccountIndex = u32;
pub type Balance = u128;
pub type Index = u32;
pub type Hash = primitives::H256;
pub type DigestItem = generic::DigestItem<Hash>;

/// We import our own module here.`
mod offchaincb;
pub mod opaque {
	use super::*;

	pub use sr_primitives::OpaqueExtrinsic as UncheckedExtrinsic;

	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	pub type BlockId = generic::BlockId<Block>;

	pub type SessionHandlers = (Grandpa, Babe);

	impl_opaque_keys! {
		pub struct SessionKeys {
			#[id(key_types::GRANDPA)]
			pub grandpa: GrandpaId,
			#[id(key_types::BABE)]
			pub babe: BabeId,
		}
	}
}

pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("offchain-cb"),
	impl_name: create_runtime_str!("offchain-cb"),
	authoring_version: 3,
	spec_version: 4,
	impl_version: 4,
	apis: RUNTIME_API_VERSIONS,
};

pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const EPOCH_DURATION_IN_BLOCKS: u32 = 10 * MINUTES;

pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);

#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
	NativeVersion {
		runtime_version: VERSION,
		can_author_with: Default::default(),
	}
}

parameter_types! {
	pub const BlockHashCount: BlockNumber = 250;
	pub const MaximumBlockWeight: Weight = 1_000_000;
	pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
	pub const MaximumBlockLength: u32 = 5 * 1024 * 1024;
	pub const Version: RuntimeVersion = VERSION;
}

impl system::Trait for Runtime {
	type AccountId = AccountId;
	type Call = Call;
	type Lookup = Indices;
	type Index = Index;
	type BlockNumber = BlockNumber;
	type Hash = Hash;
	type Hashing = BlakeTwo256;
	type Header = generic::Header<BlockNumber, BlakeTwo256>;
	type Event = Event;
	type WeightMultiplierUpdate = ();
	type Origin = Origin;
	type BlockHashCount = BlockHashCount;
	type MaximumBlockWeight = MaximumBlockWeight;
	type MaximumBlockLength = MaximumBlockLength;
	type AvailableBlockRatio = AvailableBlockRatio;
	type Version = Version;
}

parameter_types! {
	pub const EpochDuration: u64 = EPOCH_DURATION_IN_BLOCKS as u64;
	pub const ExpectedBlockTime: u64 = MILLISECS_PER_BLOCK;
}

impl babe::Trait for Runtime {
	type EpochDuration = EpochDuration;
	type ExpectedBlockTime = ExpectedBlockTime;
}

impl grandpa::Trait for Runtime {
	type Event = Event;
}

impl indices::Trait for Runtime {
	type AccountIndex = u32;
	type ResolveHint = indices::SimpleResolveHint<Self::AccountId, Self::AccountIndex>;
	type IsDeadAccount = Balances;
	type Event = Event;
}

parameter_types! {
	pub const MinimumPeriod: u64 = 5000;
}

impl timestamp::Trait for Runtime {
	type Moment = u64;
	type OnTimestampSet = Babe;
	type MinimumPeriod = MinimumPeriod;
}

parameter_types! {
	pub const ExistentialDeposit: u128 = 500;
	pub const TransferFee: u128 = 0;
	pub const CreationFee: u128 = 0;
	pub const TransactionBaseFee: u128 = 0;
	pub const TransactionByteFee: u128 = 1;
}

impl balances::Trait for Runtime {
	type Balance = Balance;
	type OnFreeBalanceZero = ();
	type OnNewAccount = Indices;
	type Event = Event;

	type TransactionPayment = ();
	type DustRemoval = ();
	type TransferPayment = ();
	type ExistentialDeposit = ExistentialDeposit;
	type TransferFee = TransferFee;
	type CreationFee = CreationFee;
	type TransactionBaseFee = TransactionBaseFee;
	type TransactionByteFee = TransactionByteFee;
	type WeightToFee = ConvertInto;
}

impl sudo::Trait for Runtime {
	type Event = Event;
	type Proposal = Call;
}


/// We need to define the AppCrypto for the keys that are authorized
/// to `pong`
pub mod offchaincb_crypto {
	pub use crate::offchaincb::KEY_TYPE;
	use primitives::sr25519;
	app_crypto::app_crypto!(sr25519, KEY_TYPE);

	impl From<Signature> for super::Signature {
		fn from(a: Signature) -> Self {
			sr25519::Signature::from(a).into()
		}
	}
}

/// We need to define the Transaction signer for that using the Key definition
type OffchainCbAccount = offchaincb_crypto::Public;
type SubmitTransaction = TransactionSubmitter<OffchainCbAccount, Runtime, UncheckedExtrinsic>;

/// Now we configure our Trait usng the previously defined primitives
impl offchaincb::Trait for Runtime {
	type Call = Call;
	type Event = Event;
	type SubmitTransaction = SubmitTransaction;
	type KeyType = OffchainCbAccount;
}
/// Lastly we also need to implement the CreateTransaction signer for the runtime
impl system::offchain::CreateTransaction<Runtime, UncheckedExtrinsic> for Runtime {
	type Signature = Signature;

	fn create_transaction<F: system::offchain::Signer<AccountId, Self::Signature>>(
		call: Call,
		account: AccountId,
		index: Index,
	) -> Option<(Call, <UncheckedExtrinsic as sr_primitives::traits::Extrinsic>::SignaturePayload)> {
		let period = 1 << 8;
		let current_block = System::block_number().saturated_into::<u64>();
		let tip = 0;
		let extra: SignedExtra = (
			system::CheckVersion::<Runtime>::new(),
			system::CheckGenesis::<Runtime>::new(),
			system::CheckEra::<Runtime>::from(generic::Era::mortal(period, current_block)),
			system::CheckNonce::<Runtime>::from(index),
			system::CheckWeight::<Runtime>::new(),
			balances::TakeFees::<Runtime>::from(tip),
		);
		let raw_payload = SignedPayload::new(call, extra).ok()?;
		let signature = F::sign(account.clone(), &raw_payload)?;
		let address = Indices::unlookup(account);
		let (call, extra, _) = raw_payload.deconstruct();
		Some((call, (address, signature, extra)))
	}
}

/// Then all this can be put together
construct_runtime!(
	pub enum Runtime where
		Block = Block,
		NodeBlock = opaque::Block,
		UncheckedExtrinsic = UncheckedExtrinsic
	{
		System: system::{Module, Call, Storage, Config, Event},
		Timestamp: timestamp::{Module, Call, Storage, Inherent},
		Babe: babe::{Module, Call, Storage, Config, Inherent(Timestamp)},
		Grandpa: grandpa::{Module, Call, Storage, Config, Event},
		Indices: indices::{default, Config<T>},
		Balances: balances,
		Sudo: sudo,
		// Nothing special here.
		OffchainCB: offchaincb::{Module, Call, Event<T>, Storage},
	}
);

pub type Address = <Indices as StaticLookup>::Source;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type SignedBlock = generic::SignedBlock<Block>;
pub type BlockId = generic::BlockId<Block>;
pub type SignedExtra = (
	system::CheckVersion<Runtime>,
	system::CheckGenesis<Runtime>,
	system::CheckEra<Runtime>,
	system::CheckNonce<Runtime>,
	system::CheckWeight<Runtime>,
	balances::TakeFees<Runtime>
);
pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, Call, Signature, SignedExtra>;
/// Just that the Signature Signer needs this aditional definition as well
pub type SignedPayload = generic::SignedPayload<Call, SignedExtra>;
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, Call, SignedExtra>;
pub type Executive = executive::Executive<Runtime, Block, system::ChainContext<Runtime>, Runtime, AllModules>;

impl_runtime_apis! {
	impl client_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block)
		}

		fn initialize_block(header: &<Block as BlockT>::Header) {
			Executive::initialize_block(header)
		}
	}

	impl client_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			Runtime::metadata().into()
		}
	}

	impl block_builder_api::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(block: Block, data: InherentData) -> CheckInherentsResult {
			data.check_extrinsics(&block)
		}

		fn random_seed() -> <Block as BlockT>::Hash {
			System::random_seed()
		}
	}

	impl client_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(tx: <Block as BlockT>::Extrinsic) -> TransactionValidity {
			Executive::validate_transaction(tx)
		}
	}

	/// This comes with new templates now, if you don't have it, you have to implement
	/// this trait in order for the Offchain Worker to be triggerd.
	impl offchain_primitives::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(number: NumberFor<Block>) {
			Executive::offchain_worker(number)
		}
	}

	impl fg_primitives::GrandpaApi<Block> for Runtime {
		fn grandpa_pending_change(digest: &DigestFor<Block>)
			-> Option<ScheduledChange<NumberFor<Block>>>
		{
			Grandpa::pending_change(digest)
		}

		fn grandpa_forced_change(digest: &DigestFor<Block>)
			-> Option<(NumberFor<Block>, ScheduledChange<NumberFor<Block>>)>
		{
			Grandpa::forced_change(digest)
		}

		fn grandpa_authorities() -> Vec<(GrandpaId, GrandpaWeight)> {
			Grandpa::grandpa_authorities()
		}
	}

	impl babe_primitives::BabeApi<Block> for Runtime {
		fn startup_data() -> babe_primitives::BabeConfiguration {
			babe_primitives::BabeConfiguration {
				median_required_blocks: 1000,
				slot_duration: Babe::slot_duration(),
				c: PRIMARY_PROBABILITY,
			}
		}

		fn epoch() -> babe_primitives::Epoch {
			babe_primitives::Epoch {
				start_slot: Babe::epoch_start_slot(),
				authorities: Babe::authorities(),
				epoch_index: Babe::epoch_index(),
				randomness: Babe::randomness(),
				duration: EpochDuration::get(),
				secondary_slots: Babe::secondary_slots().0,
			}
		}
	}

	impl substrate_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			let seed = seed.as_ref().map(|s| rstd::str::from_utf8(&s).expect("Seed is an utf8 string"));
			opaque::SessionKeys::generate(seed)
		}
	}
}
