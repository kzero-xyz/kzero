#![cfg_attr(not(feature = "std"), no_std)]

mod jwk;
mod offchain_worker;
#[cfg(test)]
mod tests;

use scale_codec::{Codec, Encode};

use frame_support::{
    dispatch::{
        DispatchClass, DispatchInfo, DispatchResultWithPostInfo, GetDispatchInfo, PostDispatchInfo,
    },
    traits::Time,
};
use sp_runtime::{
    traits::{Applyable, Checkable, Dispatchable, Extrinsic, SignaturePayload, StaticLookup},
    transaction_validity::{
        InvalidTransaction, TransactionValidityError, UnknownTransaction, ValidTransaction,
    },
};
use sp_std::prelude::*;

use primitive_zklogin::{
    traits::{ExtrinsicExt, ReplaceSender, SignaturePayloadExt, TryIntoEphPubKey},
    Jwk, JwkProvider, Kid, ZkMaterial,
};

use crate::offchain_worker::JwksPayload;
// re-export
pub use crate::offchain_worker::crypto;

type AccountIdLookupOf<T> = <<T as frame_system::Config>::Lookup as StaticLookup>::Source;

const TARGET: &str = "runtime::zklogin";

pub use pallet::*;

pub type MomentOf<T> = <<T as Config>::Time as Time>::Moment;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{dispatch::PostDispatchInfo, pallet_prelude::*};
    use frame_system::{
        offchain::{AppCrypto, SignedPayload},
        pallet_prelude::*,
    };
    use sp_core::crypto::AccountId32;

    #[pallet::config]
    pub trait Config:
        frame_system::offchain::SendTransactionTypes<Call<Self>>
        + frame_system::offchain::SigningTypes
        + frame_system::Config
    where
        Self::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
        <<Self as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
        <<<Self as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
    {
        /// The identifier type for an offchain worker.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

        /// The maximum number of keys that can be added.
        type MaxKeys: Get<u32>;

        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>
            + TryInto<Event<Self>>;

        /// Same as `Executive`, required by `Checkable` for `Self::Extrinsic`
        type Context: Default;

        type Extrinsic: ExtrinsicExt<Call = Self::RuntimeCall>
            + Checkable<Self::Context, Checked = Self::CheckedExtrinsic>
            + Codec
            + TypeInfo
            + Member;

        type CheckedExtrinsic: Applyable<Call = Self::RuntimeCall>
            + GetDispatchInfo
            + ReplaceSender<AccountId = Self::AccountId>;

        /// Same as `Executive`
        type UnsignedValidator: ValidateUnsigned<Call = Self::RuntimeCall>;

        type Time: Time;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config>
    where
        T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
        <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
        // <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
    {
        ZkLoginExecuted { result: DispatchResult },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Ephemeral key is is expired.
        EphKeyExpired,
        /// Converted from Error `InvalidTransaction`
        /// No need to get any detailed error here.
        InvalidTransaction,
        /// Converted from Error `UnknownTransaction`
        UnknownTransactionCannotLookup,
        UnknownTransactionNoUnsignedValidator,
        UnknownTransactionCustom,

        /// Parse json to Jwk struct error.
        InvalidJwkJson,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// The current set of keys that may submit a offchain extrinsic.
    #[pallet::storage]
    pub type Keys<T: Config> =
        StorageValue<_, WeakBoundedVec<T::AuthorityId, T::MaxKeys>, ValueQuery>;

    /// TODO
    #[pallet::storage]
    #[pallet::unbounded]
    pub(crate) type Jwks<T> =
        StorageDoubleMap<_, Twox64Concat, JwkProvider, Twox64Concat, Kid, Jwk>;

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
    where
        T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
        <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
        <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
    {
        fn offchain_worker(block_number: BlockNumberFor<T>) {
            offchain_worker::offchain_worker_entrypoint::<T>(block_number);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T>
    where
        T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
        <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
        <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
    {
        // TODO: provide a valid weight
        #[pallet::call_index(0)]
        #[pallet::weight({0})]
        pub fn submit_zklogin_unsigned(
            origin: OriginFor<T>,
            uxt: Box<<T as Config>::Extrinsic>,
            address_seed: AccountIdLookupOf<T>,
            zk_material: ZkMaterial<MomentOf<T>>,
        ) -> DispatchResultWithPostInfo {
            // make sure this call is unsigned signed
            ensure_none(origin)?;

            // check ephemeral key's expiration time
            let now = T::Time::now();
            let expire_at: MomentOf<T> = zk_material.get_ephkey_expire_at();
            ensure!(expire_at >= now, Error::<T>::EphKeyExpired);

            // execute real call
            let r = Executive::<T>::apply_extrinsic(uxt, address_seed);
            let exec_res: DispatchResult = r.map(|_| ()).map_err(|e| e.error);
            Self::deposit_event(Event::ZkLoginExecuted { result: exec_res });
            r
        }

        /// TODO doc
        #[pallet::call_index(1)]
        #[pallet::weight({0})]
        pub fn submit_jwks_unsigned(
            origin: OriginFor<T>,
            payload: JwksPayload<T::Public, BlockNumberFor<T>>,
            _signature: T::Signature,
        ) -> DispatchResultWithPostInfo {
            ensure_none(origin)?;
            for (provider, jwks) in payload.jwks {
                if let Err(_e) = Self::insert_jwks(provider, jwks) {
                    // TODO print event and logs.
                }
            }
            Ok(().into())
        }

        #[pallet::call_index(255)]
        #[pallet::weight(({0}, DispatchClass::Operational))]
        pub fn set_jwk(
            origin: OriginFor<T>,
            provider: JwkProvider,
            json: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;
            let jwk = jwk::parse_jwk::<T>(&json)?;
            Self::insert_jwks(provider, vec![jwk])?;
            Ok(().into())
        }
    }

    // Helper functions
    impl<T: Config> Pallet<T>
    where
        T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
        <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
        <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
    {
        fn insert_jwks(provider: JwkProvider, jwks: Vec<Jwk>) -> Result<(), Error<T>> {
            // TODO delete old jwks first, then insert new
            for jwk in jwks {
                let kid = jwk.common.key_id.as_ref().ok_or(Error::<T>::InvalidJwkJson)?.as_bytes();
                Jwks::<T>::insert(provider, kid, &jwk);
                // TODO print event
            }
            Ok(())
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T>
    where
        T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
        <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
        <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
        T: frame_system::Config<AccountId = AccountId32>,
    {
        type Call = Call<T>;

        fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            // TODO no need? `submit_jwks_unsigned` needs `Local` while `submit_zklogin_unsigned` needs `InBlock` & `External`, while in future `submit_jwks_unsigned` may also need `Local`.
            // validate the transaction that is submitted from external (not local)
            // or included in transaction pool
            // match source {
            //     TransactionSource::InBlock | TransactionSource::External => { /* allowed */ }
            //     _ => return InvalidTransaction::Call.into(),
            // };

            // verify signature
            match call {
                Call::submit_zklogin_unsigned { uxt, address_seed, zk_material } => {
                    let (provider, kid) = zk_material.source();
                    // We require the provider and kid must exist on chain before submit extrinsic.
                    let jwk = Jwks::<T>::get(provider, kid)
                        .ok_or::<TransactionValidityError>(InvalidTransaction::Call.into())?;

                    // Only signed extrinsic is allowed
                    let eph_pubkey = match uxt.signature_payload() {
                        // This extrinsic is not a signed one.
                        None => return InvalidTransaction::Call.into(),
                        Some(payload) => {
                            payload.signature_address().try_into_eph_key().map_err::<TransactionValidityError, _>(|e| {
                                log::warn!(target: TARGET, "The signer can not convert to a valid eph pubkey. err: {:?}", e);
                                InvalidTransaction::BadSigner.into()
                            })?
                        }
                    };

                    // the zkLogin address that will pay for the tx fee and execute the real call
                    let address_seed = T::Lookup::lookup(address_seed.clone())?;

                    let encoded = uxt.encode();
                    let encoded_len = encoded.len();
                    // Check Signature
                    let mut xt = uxt.clone().check(&T::Context::default())?;

                    // IMPORTANT
                    // replace sender in CheckedExtrinsic
                    // This is due to zkLogin's mechanism, it uses `ephemeral key` to sign and submit tx
                    // while the real transaction is executed and transaction fee paid
                    // through the `zklogin_address` that is derived from JWT
                    xt.replace_sender(address_seed.clone());
                    // Decode parameters and dispatch
                    let dispatch_info = xt.get_dispatch_info();
                    // Check dispatch_class: mandatory extrinsic is not allowed to use zklogin
                    if dispatch_info.class == DispatchClass::Mandatory {
                        return InvalidTransaction::BadMandatory.into();
                    }

                    // validate zk proof
                    zk_material
                        .verify_zk_login(eph_pubkey, &address_seed, &jwk)
                        .map_err(|_| InvalidTransaction::BadProof)?;

                    xt.validate::<T::UnsignedValidator>(source, &dispatch_info, encoded_len)
                }
                Call::submit_jwks_unsigned { payload, signature } => {
                    let signature_valid =
                        SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone());
                    if !signature_valid {
                        return InvalidTransaction::BadProof.into();
                    }
                    // TODO validate payload, at least need to verify the public.

                    ValidTransaction::with_tag_prefix("ZkLoginOffchainWorker")
                        // TODO add more parameters to this unsigned extrinsic
                        //.priority()
                        //.and_requires()
                        //.and_provides(next_unsigned_at)
                        .longevity(5)
                        .propagate(true)
                        .build()
                }
                _ => Err(InvalidTransaction::Call.into()),
            }
        }
    }
}

pub type CheckedOf<E, C> = <E as Checkable<C>>::Checked;

struct Executive<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> Executive<T>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
    <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
{
    fn apply_extrinsic(
        uxt: Box<<T as Config>::Extrinsic>,
        address_seed: AccountIdLookupOf<T>,
    ) -> DispatchResultWithPostInfo {
        let encoded = uxt.encode();
        let encoded_len = encoded.len();

        // Verify that the signature is good.
        let mut xt = uxt.check(&T::Context::default()).expect("process ?");
        xt.replace_sender(T::Lookup::lookup(address_seed).expect("lookup should succeed"));

        let dispatch_info = xt.get_dispatch_info();
        let r = Applyable::apply::<T::UnsignedValidator>(xt, &dispatch_info, encoded_len)
            .map_err(Error::<T>::from)?;

        // For we has checked the `dispatch_info.class` in `validate_unsigned`, so the check at here is not
        // necessary. We keep this to be same implementation in `Executive`.
        if r.is_err() && dispatch_info.class == DispatchClass::Mandatory {
            return Err(Error::<T>::InvalidTransaction.into());
        }

        r
    }
}

impl<T: Config> From<TransactionValidityError> for Error<T>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
    <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
{
    fn from(value: TransactionValidityError) -> Self {
        match value {
            TransactionValidityError::Invalid(_) => Error::InvalidTransaction,
            TransactionValidityError::Unknown(u) => match u {
                UnknownTransaction::CannotLookup => Error::UnknownTransactionCannotLookup,
                UnknownTransaction::NoUnsignedValidator => {
                    Error::UnknownTransactionNoUnsignedValidator
                }
                UnknownTransaction::Custom(_) => Error::UnknownTransactionCustom,
            },
        }
    }
}
