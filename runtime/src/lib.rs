#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "512"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

pub mod apis;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
pub mod configs;
mod weights;

use smallvec::smallvec;
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiSignature,
};
use frame_support::traits::EitherOfDiverse;
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
use frame_system::EnsureRoot;
use frame_support::PalletId;
use frame_system::EnsureSigned;
use frame_support::parameter_types;
use frame_support::traits::ConstU32;
use frame_support::traits::ConstU128;
use sp_runtime::traits::ConstU64;
use frame_support::traits::VariantCountOf;
use pallet_transaction_payment::Multiplier;
use frame_support::weights::IdentityFee;
use pallet_transaction_payment::ConstFeeMultiplier;
use pallet_transaction_payment::FungibleAdapter;
use sp_runtime::traits::One;

use crate::configs::xcm_config::RelayLocation;
use pallet_xcm::EnsureXcm;
use pallet_xcm::IsVoiceOfBody;
use xcm::latest::prelude::*;


use frame_support::weights::{
    constants::WEIGHT_REF_TIME_PER_SECOND, Weight, WeightToFeeCoefficient, WeightToFeeCoefficients,
    WeightToFeePolynomial,
};
pub use sp_consensus_aura::sr25519::AuthorityId as AuraId;
pub use sp_runtime::{MultiAddress, Perbill, Permill};

#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

use weights::ExtrinsicBaseWeight;

/// Import the template pallet.
pub use pallet_parachain_template;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// An index to a block.
pub type BlockNumber = u32;

/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;

/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// The SignedExtension to the basic transaction logic.
#[docify::export(template_signed_extra)]
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    cumulus_primitives_storage_weight_reclaim::StorageWeightReclaim<Runtime>,
    frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

/// Handles converting a weight scalar to a fee value, based on the scale and granularity of the
/// node's balance type.
///
/// This should typically create a mapping between the following ranges:
///   - `[0, MAXIMUM_BLOCK_WEIGHT]`
///   - `[Balance::min, Balance::max]`
///
/// Yet, it can be used for any other sort of change to weight-fee. Some examples being:
///   - Setting it to `0` will essentially disable the weight fee.
///   - Setting it to `1` will cause the literal `#[weight = x]` values to be charged.
pub struct WeightToFee;
impl WeightToFeePolynomial for WeightToFee {
    type Balance = Balance;
    fn polynomial() -> WeightToFeeCoefficients<Self::Balance> {
        // in Rococo, extrinsic base weight (smallest non-zero weight) is mapped to 1 CENTS:
        // in our template, we map to 1/10 of that, or 1/10 CENTS
        let p = CENTS / 10;
        let q = 100 * Balance::from(ExtrinsicBaseWeight::get().ref_time());
        smallvec![WeightToFeeCoefficient {
            degree: 1,
            negative: false,
            coeff_frac: Perbill::from_rational(p % q, q),
            coeff_integer: p / q,
        }]
    }
}

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;
    use sp_runtime::{
        generic,
        traits::{BlakeTwo256, Hash as HashT},
    };

    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;
    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;
    /// Opaque block hash type.
    pub type Hash = <BlakeTwo256 as HashT>::Output;
}

impl_opaque_keys! {
    pub struct SessionKeys {
        pub aura: Aura,
    }
}
impl pallet_insecure_randomness_collective_flip::Config for Runtime {} 

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("parachain-template-runtime"),
    impl_name: create_runtime_str!("parachain-template-runtime"),
    authoring_version: 1,
    spec_version: 1,
    impl_version: 0,
    apis: apis::RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 1,
};

/// This determines the average expected block time that we are targeting.
/// Blocks will be produced at a minimum duration defined by `SLOT_DURATION`.
/// `SLOT_DURATION` is picked up by `pallet_timestamp` which is in turn picked
/// up by `pallet_aura` to implement `fn slot_duration()`.
///
/// Change this to adjust the block time.
pub const MILLISECS_PER_BLOCK: u64 = 6000;

// NOTE: Currently it is not possible to change the slot duration after the chain has started.
//       Attempting to do so will brick block production.
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

// Time is measured by number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// Unit = the base number of indivisible units for balances
pub const MILLICENTS: Balance = 1_000_000_000;
pub const CENTS: Balance = 1_000 * MILLICENTS; // assume this is worth about a cent.
pub const DOLLARS: Balance = 100 * CENTS;

pub const fn deposit(items: u32, bytes: u32) -> Balance {
    items as Balance * 15 * CENTS + (bytes as Balance) * 6 * CENTS
}
parameter_types! {
pub BlockWeights: frame_system::limits::BlockWeights =
frame_system::limits::BlockWeights::with_sensible_defaults(
	Weight::from_parts(2u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
	NORMAL_DISPATCH_RATIO,
);}



/// We assume that ~5% of the block weight is consumed by `on_initialize` handlers. This is
/// used to limit the maximal weight of a single extrinsic.
const AVERAGE_ON_INITIALIZE_RATIO: Perbill = Perbill::from_percent(5);

/// We allow `Normal` extrinsics to fill up the block up to 75%, the rest can be used by
/// `Operational` extrinsics.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

/// We allow for 2 seconds of compute with a 6 second average block time.
const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::from_parts(
    WEIGHT_REF_TIME_PER_SECOND.saturating_mul(2),
    cumulus_primitives_core::relay_chain::MAX_POV_SIZE as u64,
);

/// Maximum number of blocks simultaneously accepted by the Runtime, not yet included
/// into the relay chain.
const UNINCLUDED_SEGMENT_CAPACITY: u32 = 3;
/// How many parachain blocks are processed by the relay chain per parent. Limits the
/// number of blocks authored per slot.
const BLOCK_PROCESSING_VELOCITY: u32 = 1;
/// Relay chain slot duration, in milliseconds.
const RELAY_CHAIN_SLOT_DURATION_MILLIS: u32 = 6000;

/// Aura consensus hook
type ConsensusHook = cumulus_pallet_aura_ext::FixedVelocityConsensusHook<
    Runtime,
    RELAY_CHAIN_SLOT_DURATION_MILLIS,
    BLOCK_PROCESSING_VELOCITY,
    UNINCLUDED_SEGMENT_CAPACITY,
>;

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}


// Create the runtime by composing the FRAME pallets that were previously configured.
#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask
    )]
    pub struct Runtime;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;
    #[runtime::pallet_index(1)]
    pub type ParachainSystem = cumulus_pallet_parachain_system;
   
    #[runtime::pallet_index(3)]
    pub type ParachainInfo = parachain_info;




   

    #[runtime::pallet_index(24)]
    pub type AuraExt = cumulus_pallet_aura_ext;

    // XCM helpers.
    #[runtime::pallet_index(30)]
    pub type XcmpQueue = cumulus_pallet_xcmp_queue;
    #[runtime::pallet_index(31)]
    pub type PolkadotXcm = pallet_xcm;
    #[runtime::pallet_index(32)]
    pub type CumulusXcm = cumulus_pallet_xcm;
    #[runtime::pallet_index(33)]
    pub type MessageQueue = pallet_message_queue;

    // Template
    #[runtime::pallet_index(50)]
    pub type TemplatePallet = pallet_parachain_template;
    #[runtime::pallet_index(51)]
    pub type RandomnessCollectiveFlip = pallet_insecure_randomness_collective_flip::Pallet<Runtime>;

    
    
	#[runtime::pallet_index(55)]
	pub type Timestamp = pallet_timestamp;    
    
	#[runtime::pallet_index(56)]
	pub type TransactionPayment = pallet_transaction_payment;    
    
	#[runtime::pallet_index(57)]
	pub type CollatorSelection = pallet_collator_selection;    
    
	#[runtime::pallet_index(58)]
	pub type Aura = pallet_aura;    
    
	#[runtime::pallet_index(59)]
	pub type Session = pallet_session;    
    
	#[runtime::pallet_index(60)]
	pub type Authorship = pallet_authorship::Pallet<Runtime>;    
    
	#[runtime::pallet_index(61)]
	pub type Sudo = pallet_sudo;    
    
	#[runtime::pallet_index(62)]
	pub type GeneralCouncil = pallet_collective<Instance1>;    
    
	#[runtime::pallet_index(63)]
	pub type Balances = pallet_balances;
}



impl pallet_timestamp::Config for Runtime {
	type OnTimestampSet = Aura;
	type WeightInfo = ();
	type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
	type Moment = u64;

}

parameter_types! {
    pub FeeMultiplier: Multiplier = Multiplier::one();
}


parameter_types! {
    pub const FTPOperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
	type FeeMultiplierUpdate = ConstFeeMultiplier<FeeMultiplier>;
	type OperationalFeeMultiplier = FTPOperationalFeeMultiplier;
	type OnChargeTransaction = FungibleAdapter<Balances, ()>;
	type WeightToFee = IdentityFee<Balance>;
	type RuntimeEvent = RuntimeEvent;
	type LengthToFee = IdentityFee<Balance>;

}
parameter_types! {
    pub const PotId: PalletId = PalletId(*b"PotStake");
  
    // StakingAdmin pluralistic body.
    pub const StakingAdminBodyId: BodyId = BodyId::Defense;
}

/// We allow root and the StakingAdmin to execute privileged collator selection operations.
pub type CollatorSelectionUpdateOrigin = EitherOfDiverse<
    EnsureRoot<AccountId>,
    EnsureXcm<IsVoiceOfBody<RelayLocation, StakingAdminBodyId>>,
>;


parameter_types! {
    pub const MinEligibleCollators: u32 = 4;
    pub const PCSMaxCandidates: u32 = 100;
    pub const SessionLength: BlockNumber = HOURS * 6;
    pub const MaxInvulnerables: u32 = 20;
}

impl pallet_collator_selection::Config for Runtime {
	type PotId = PotId;
	type Currency = Balances;
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	type ValidatorIdOf = pallet_collator_selection::IdentityCollator;
	type ValidatorRegistration = Session;
	type MaxInvulnerables = MaxInvulnerables;
	type WeightInfo = ();
	type KickThreshold = SessionPeriod;
	type MaxCandidates = PCSMaxCandidates;
	type UpdateOrigin = CollatorSelectionUpdateOrigin;
	type MinEligibleCollators = MinEligibleCollators;

}

parameter_types! {
    pub const MaxAuthoritiesAura: u32 = 32;
    pub const AllowMultipleBlocksPerSlot: bool = false;
}

impl pallet_aura::Config for Runtime {
	type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
	type AuthorityId = AuraId;
	type DisabledValidators = ();
	type AllowMultipleBlocksPerSlot = AllowMultipleBlocksPerSlot;
	type MaxAuthorities = MaxAuthoritiesAura;

}

parameter_types! {
    pub const Offset: u32 = 0;
    pub const SessionPeriod: u32 = HOURS * 6;
}

impl pallet_session::Config for Runtime {
	type NextSessionRotation = pallet_session::PeriodicSessions<SessionPeriod, Offset>;
	type RuntimeEvent = RuntimeEvent;
	type SessionHandler = <SessionKeys as sp_runtime::traits::OpaqueKeys>::KeyTypeIdProviders;
	type Keys = SessionKeys;
	type ValidatorIdOf = pallet_collator_selection::IdentityCollator;
	type WeightInfo = ();
	type ShouldEndSession = pallet_session::PeriodicSessions<SessionPeriod, Offset>;
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	type SessionManager = CollatorSelection;

}


pub struct AuraAccountAdapter;
impl frame_support::traits::FindAuthor<AccountId> for AuraAccountAdapter {
	fn find_author<'a, I>(digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (frame_support::ConsensusEngineId, &'a [u8])>,
	{
		pallet_aura::AuraAuthorId::<Runtime>::find_author(digests)
			.and_then(|k| AccountId::try_from(k.as_ref()).ok())
	}
}




impl pallet_authorship::Config for Runtime {
	type EventHandler = ();
	type FindAuthor = AuraAccountAdapter;

}


impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
	type RuntimeCall = RuntimeCall;

}

parameter_types! {
    pub GeneralMaxCollectivesProposalWeight: Weight = Perbill::from_percent(50) * BlockWeights::get().max_block;
    pub const GeneralCouncilMaxProposals: u32 = 100;
    pub const GeneralCouncilMotionDuration: BlockNumber = MINUTES * 3;
    pub const GeneralCouncilMaxMembers: u32 = 100;
}

type GeneralCouncilCollective = pallet_collective::Instance1;

impl pallet_collective::Config<GeneralCouncilCollective> for Runtime{
	type MaxProposals = GeneralCouncilMaxProposals;
	type SetMembersOrigin = EnsureRoot<Self::AccountId>;
	type MaxProposalWeight = GeneralMaxCollectivesProposalWeight;
	type RuntimeEvent = RuntimeEvent;
	type MotionDuration = GeneralCouncilMotionDuration;
	type WeightInfo = pallet_collective::weights::SubstrateWeight<Runtime>;
	type DefaultVote = pallet_collective::PrimeDefaultVote;
	type Proposal = RuntimeCall;
	type MaxMembers = GeneralCouncilMaxMembers;
	type RuntimeOrigin = RuntimeOrigin;

}


/// Existential deposit.
pub const EXISTENTIAL_DEPOSIT: u128 = 500;


parameter_types! {
    pub const MaxLocks: u32 = 50;
}

impl pallet_balances::Config for Runtime {
	type MaxReserves = ();
	type RuntimeFreezeReason = RuntimeHoldReason;
	type RuntimeHoldReason = RuntimeHoldReason;
	type ReserveIdentifier = [u8; 8];
	type DustRemoval = ();
	type MaxLocks = MaxLocks;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
	type Balance = Balance;
	type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
	type RuntimeEvent = RuntimeEvent;
	type AccountStore = System;
	type FreezeIdentifier = RuntimeFreezeReason;
	type ExistentialDeposit = ConstU128<500>;

}
cumulus_pallet_parachain_system::register_validate_block! {
    Runtime = Runtime,
    BlockExecutor = cumulus_pallet_aura_ext::BlockExecutor::<Runtime, Executive>,
}

