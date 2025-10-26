#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(feature = "runtime-benchmarks")]
mod benchmark_data;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

mod jwk;
mod offchain_worker;
#[cfg(test)]
mod tests;

pub mod weights;

use frame_system::RawOrigin;
use scale_codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;

use frame_support::{
    dispatch::{
        DispatchClass, DispatchInfo, DispatchResultWithPostInfo, GetDispatchInfo, PostDispatchInfo,
    },
    traits::{IsSubType, Time},
    BoundedVec, RuntimeDebugNoBound,
};
use sp_runtime::{
    traits::{
        AsSystemOriginSigner, DispatchInfoOf, Dispatchable, PostDispatchInfoOf,
        TransactionExtension,
    },
    transaction_validity::{
        InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError,
        ValidTransaction,
    },
    DispatchResult, Weight,
};
use sp_std::prelude::*;

use primitive_zklogin::{JwkProvider, Kid, ZkMaterial};

use crate::offchain_worker::JwksPayload;
// re-export
pub use crate::offchain_worker::crypto;
pub use weights::WeightInfo;

const TARGET: &str = "runtime::zklogin";

pub use pallet::*;

pub type MomentOf<T> = <<T as Config>::Time as Time>::Moment;
pub type JsonStr<Limit> = BoundedVec<u8, Limit>;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::{
        offchain::{AppCrypto, CreateInherent, CreateSignedTransaction, SignedPayload},
        pallet_prelude::*,
    };
    use sp_core::H256;

    #[pallet::config]
    pub trait Config:
        CreateSignedTransaction<Call<Self>> + CreateInherent<Call<Self>> + frame_system::Config
    {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>
            + TryInto<Event<Self>>;

        /// The overarching call type.
        type RuntimeCall: Parameter
            + Dispatchable<RuntimeOrigin = Self::RuntimeOrigin, PostInfo = PostDispatchInfo>
            + GetDispatchInfo
            + From<frame_system::Call<Self>>
            + IsSubType<Call<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeCall>;

        /// The maximum size of a JWK JSON payload.
        type JwkJsonLimit: Get<u32>;

        /// The identifier type for an offchain worker.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>; // + Parameter + MaxEncodedLen;

        /// The maximum number of keys that can be added.
        type MaxKeys: Get<u32>;

        // type UnsignedValidator: ValidateUnsigned;

        type Time: Time;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ZkLoginExecuted {
            account: T::AccountId,
        },

        /// Update Jwks for the provider.
        JwksUpdated {
            provider: JwkProvider,
            // jwks: Vec<Jwk>,
        },

        /// Current keys that allow to set Jwks.
        Keys {
            keys: Vec<T::Public>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Ephemeral key is is expired.
        EphKeyExpired,
        /// Jwk JSON is too large to fit in BoundedVec.
        JwkJsonTooLarge,
        /// Parse json to Jwk struct error.
        InvalidJwkJson,
        /// Convert Jwk to json to error.
        InvalidJwk,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// The current set of keys that may submit an offchain extrinsic.
    #[pallet::storage]
    // TODO we need more code to bond `T::Public: MaxEncodedLen`, then we can remove `#[pallet::unbounded]`.
    #[pallet::unbounded]
    pub type Keys<T: Config> = StorageValue<_, WeakBoundedVec<T::Public, T::MaxKeys>, ValueQuery>;

    /// The on-chain Jwk JSONs, indexed by (provider, kid).
    #[pallet::storage]
    #[pallet::unbounded]
    pub(crate) type JwkJsons<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        JwkProvider,
        Twox64Concat,
        Kid,
        BoundedVec<u8, T::JwkJsonLimit>,
    >;

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(block_number: BlockNumberFor<T>) {
            offchain_worker::offchain_worker_entrypoint::<T>(block_number);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: provide a valid weight
        #[pallet::call_index(0)]
        #[pallet::weight({
            // uxt.get_dispatch_info().weight
            0
        })]
        pub fn submit_zklogin(
            origin: OriginFor<T>,
            call: Box<<T as Config>::RuntimeCall>,
            _address_seed: H256,
            zk_material: ZkMaterial<MomentOf<T>>,
        ) -> DispatchResultWithPostInfo {
            // make sure this call is unsigned signed
            let zk_account = ensure_signed(origin.clone())?;

            // check ephemeral key's expiration time, TODO move to `validate`?
            let now = T::Time::now();
            let expire_at: MomentOf<T> = zk_material.get_ephkey_expire_at();
            ensure!(expire_at >= now, Error::<T>::EphKeyExpired);

            // execute real call
            let mut filtered_origin = origin.clone();
            // Don't allow users to nest `submit_zklogin` calls.
            filtered_origin.add_filter(move |c: &<T as frame_system::Config>::RuntimeCall| {
                let c = <T as Config>::RuntimeCall::from_ref(c);
                !matches!(c.is_sub_type(), Some(Call::submit_zklogin { .. }))
            });
            // TODO when err return at here? or at final
            let r = call.dispatch(filtered_origin)?;
            Self::deposit_event(Event::ZkLoginExecuted { account: zk_account });
            Ok(r.into())
        }

        /// TODO doc
        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::submit_jwks_unsigned(payload.jwks.len() as u32))]
        pub fn submit_jwks_unsigned(
            origin: OriginFor<T>,
            payload: JwksPayload<T::Public, BlockNumberFor<T>>,
            _signature: T::Signature,
        ) -> DispatchResultWithPostInfo {
            ensure_none(origin)?;
            for (provider, jwks) in payload.jwks {
                Self::insert_jwks(provider, jwks, true).expect(
                    "`insert_jwks` must execute successfully for jwks have checked the validity.",
                )
            }
            Ok(().into())
        }

        #[pallet::call_index(254)]
        #[pallet::weight((<T as Config>::WeightInfo::update_keys(keys.len() as u32), DispatchClass::Operational))]
        pub fn update_keys(
            origin: OriginFor<T>,
            keys: Vec<(T::Public, bool)>,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;

            let mut current_keys = Keys::<T>::get();
            for (key, insert_or_delete) in keys {
                let existed = current_keys.iter().position(|x| x == &key);
                match (existed, insert_or_delete) {
                    (Some(index), false) => {
                        let _k = current_keys.remove(index);
                        // TODO print logs for this removed key
                    }
                    (None, true) => {
                        // It's a new key, append it.
                        if insert_or_delete {
                            if let Err(_) = current_keys.try_push(key) {
                                // TODO print logs
                            }
                        }
                    }
                    _ => { /* ignore */ }
                }
            }
            Keys::<T>::put(&current_keys);

            Self::deposit_event(Event::<T>::Keys { keys: current_keys.into_inner() });
            Ok(().into())
        }

        #[pallet::call_index(255)]
        #[pallet::weight((<T as Config>::WeightInfo::set_jwk(), DispatchClass::Operational))]
        pub fn set_jwk(
            origin: OriginFor<T>,
            provider: JwkProvider,
            json: Vec<u8>,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;
            Self::insert_jwks(provider, vec![json], false)?;
            Ok(().into())
        }
    }

    // Helper functions
    impl<T: Config> Pallet<T> {
        fn insert_jwks(
            provider: JwkProvider,
            jwks: Vec<Vec<u8>>,
            delete_before_insert: bool,
        ) -> Result<(), Error<T>> {
            if delete_before_insert {
                // For normal, Jwks just contains a small group for a provider, so it's safe to set
                // `32` as limit, while ignore the result.
                let _ = JwkJsons::<T>::clear_prefix(provider, 32, None);
            }

            for json in jwks.iter() {
                let jwk = crate::jwk::parse_jwk::<T>(json.as_slice())?; // validate jwk json
                let kid = jwk.prm.kid.as_ref().ok_or(Error::<T>::InvalidJwkJson)?.as_bytes();
                // convert jwk to json again to make sure the stored json is standard
                let jwk_json = crate::jwk::jwk_to_json::<T>(&jwk)?;
                let bounded_json = BoundedVec::<u8, T::JwkJsonLimit>::try_from(jwk_json)
                    .map_err(|_| Error::<T>::JwkJsonTooLarge)?;
                JwkJsons::<T>::insert(provider, kid, bounded_json);
            }
            Self::deposit_event(Event::JwksUpdated { provider });

            Ok(())
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            // TODO no need? `submit_jwks_unsigned` needs `Local` while `submit_zklogin_unsigned` needs `InBlock` & `External`, while in future `submit_jwks_unsigned` may also need `Local`.
            // validate the transaction that is submitted from external (not local)
            // or included in transaction pool
            // match source {
            //     TransactionSource::InBlock | TransactionSource::External => { /* allowed */ }
            //     _ => return InvalidTransaction::Call.into(),
            // };

            // verify signature
            match call {
                // only check `submit_jwks_unsigned` call for we treat it as `inherent` for now.
                Call::submit_jwks_unsigned { payload, signature } => {
                    let signature_valid =
                        SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone());
                    if !signature_valid {
                        return InvalidTransaction::BadProof.into();
                    }
                    let onchain_keys = Keys::<T>::get().into_inner();
                    if !onchain_keys.contains(&payload.public) {
                        return InvalidTransaction::BadSigner.into();
                    }

                    for (provider, jwks) in payload.jwks.iter() {
                        let result = jwks
                            .iter()
                            .map(|json| {
                                let jwk = match jwk::parse_jwk::<T>(json.as_slice()) {
                                    Ok(jwk) => jwk,
                                    Err(e) => {
                                        let json_str = alloc::string::String::from_utf8_lossy(json.as_slice());
                                        log::error!(target: TARGET, "The unsigned contains invalid Jwk. Parse jwk json err, json:{}, err: {:?}", json_str, e);
                                        return None;
                                    }
                                };

                                offchain_worker::check_jwk_not_onchain(
                                    *provider,
                                    &jwk,
                                    |provider, kid| {
                                        JwkJsons::<T>::get(provider, kid)
                                            .and_then(|json| jwk::parse_jwk::<T>(json.as_slice()).ok())
                                    },
                                )
                            })
                            .collect::<Vec<_>>();

                        if result.iter().any(|x| x.is_none()) {
                            // If check return `None`, means this unsigend extrinsic contains
                            // invalid jwk. return error for this check.
                            log::error!(target: TARGET, "The unsigned contains invalid Jwk for provider: {:?}", provider);
                            return Err(InvalidTransaction::Call.into());
                        }

                        if result.iter().map(|x| x.unwrap_or(false)).all(|x| !x) {
                            log::error!(target: TARGET, "All Jwks for provider: {:?} in this unsigned are existed onchain", provider);
                            return Err(InvalidTransaction::Call.into());
                        }
                    }

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

/// Operation to perform from `prepare` to `post_dispatch_details` in [`ZkLoginExtension`] transaction
/// extension.
#[derive(RuntimeDebugNoBound)]
pub enum Val {
    /// The transaction extension weight should not be refunded.
    Checked,
    /// The transaction extension weight should be refunded.
    Refund(Weight),
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo, Debug)]
#[scale_info(skip_type_params(T))]
pub struct ZkLoginExtension<T: Config + Send + Sync> {
    _phantom: core::marker::PhantomData<T>,
}

impl<T: Config + Send + Sync> ZkLoginExtension<T> {
    /// Creates new `TransactionExtension` to check zklogin proof.
    pub fn new() -> Self {
        Self { _phantom: core::marker::PhantomData }
    }
}

impl<T: Config + Send + Sync + core::fmt::Debug> TransactionExtension<<T as Config>::RuntimeCall>
    for ZkLoginExtension<T>
where
    <T as Config>::RuntimeCall: Dispatchable<Info = DispatchInfo> + IsSubType<Call<T>>,
    <<T as Config>::RuntimeCall as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<T::AccountId> + Clone,
    // TODO assume AccountId32 limit can be removed after checking zk logic
    T: frame_system::Config<AccountId = sp_core::crypto::AccountId32>,
{
    const IDENTIFIER: &'static str = "ZkLoginExtension";

    type Implicit = ();

    type Val = Val;

    type Pre = Val;

    fn weight(&self, _call: &<T as Config>::RuntimeCall) -> Weight {
        // TODO change weight value to a proper one, banchmarks for calculate the validation of zk proof
        Weight::from_parts(1_000, 0)
    }

    fn validate(
        &self,
        origin: <<T as Config>::RuntimeCall as Dispatchable>::RuntimeOrigin,
        call: &<T as Config>::RuntimeCall,
        _info: &DispatchInfoOf<<T as Config>::RuntimeCall>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl sp_runtime::traits::Implication,
        _source: frame_support::pallet_prelude::TransactionSource,
    ) -> sp_runtime::traits::ValidateResult<Self::Val, <T as Config>::RuntimeCall> {
        match <<T as Config>::RuntimeCall as IsSubType<Call<T>>>::is_sub_type(call) {
            Some(Call::submit_zklogin { address_seed, zk_material, .. }) => {
                // TODO not decide whether we need to limit call type.
                //     // Check dispatch_class: mandatory extrinsic is not allowed to use zklogin
                //     if dispatch_info.class == DispatchClass::Mandatory {
                //         return InvalidTransaction::BadMandatory.into();
                //     }

                let who: &T::AccountId =
                    origin.as_system_origin_signer().ok_or(InvalidTransaction::BadSigner)?;
                // TODO maybe need a better method to convert to eph_pubkey
                let eph_pubkey = *(who.as_ref());

                // check ephemeral key's expiration time
                let now = T::Time::now();
                let expire_at: MomentOf<T> = zk_material.get_ephkey_expire_at();
                if expire_at < now {
                    return Err(InvalidTransaction::BadProof.into());
                }

                let (provider, kid) = zk_material.source();
                // We require the provider and kid must exist on chain before submit extrinsic.
                let jwk_json = JwkJsons::<T>::get(provider, kid)
                    .ok_or::<TransactionValidityError>(InvalidTransaction::Call.into())?;
                let jwk = jwk::parse_jwk::<T>(jwk_json.as_slice())
                    .map_err(|_| InvalidTransaction::Call)?;

                // validate zk proof
                zk_material
                    .verify_zk_login(eph_pubkey, address_seed, &jwk)
                    .map_err(|_| InvalidTransaction::BadProof)?;

                // TODO only support accountid: accountid32 now.
                let zk_account: T::AccountId = sp_core::crypto::AccountId32::from(address_seed.0);
                Ok((
                    ValidTransaction::default(),
                    Val::Checked,
                    RawOrigin::Signed(zk_account).into(),
                ))
            }
            _ => Ok((ValidTransaction::default(), Val::Refund(self.weight(call)), origin)),
        }
    }

    fn prepare(
        self,
        val: Self::Val,
        _origin: &<<T as Config>::RuntimeCall as Dispatchable>::RuntimeOrigin,
        _call: &<T as Config>::RuntimeCall,
        _info: &DispatchInfoOf<<T as Config>::RuntimeCall>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        Ok(val)
    }

    fn post_dispatch_details(
        pre: Self::Pre,
        _info: &DispatchInfo,
        _post_info: &PostDispatchInfoOf<<T as Config>::RuntimeCall>,
        _len: usize,
        _result: &DispatchResult,
    ) -> Result<Weight, TransactionValidityError> {
        match pre {
            Val::Checked => Ok(Weight::zero()),
            Val::Refund(weight) => Ok(weight),
        }
    }
}
