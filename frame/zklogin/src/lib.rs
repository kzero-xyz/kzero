#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(test)]
mod tests;

use scale_codec::{Codec, Encode};

use frame_support::dispatch::{DispatchClass, DispatchInfo, DispatchResult, GetDispatchInfo};
use sp_runtime::{
    traits::{Applyable, BlockNumberProvider, Checkable, Dispatchable, StaticLookup},
    transaction_validity::InvalidTransaction,
    ApplyExtrinsicResult,
};
use sp_std::prelude::*;
use zklogin_support::ReplaceSender;
use zp_zklogin::{verify_zk_login, ZkLoginInputs};

type AccountIdLookupOf<T> = <<T as frame_system::Config>::Lookup as StaticLookup>::Source;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_core::{crypto::AccountId32, U256};
    use zp_zklogin::{JwkId, ZkLoginEnv, EPH_PUB_KEY_LEN};

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>
            + TryInto<Event<Self>>;

        /// Same as `Executive`, required by `Checkable` for `Self::Extrinsic`
        type Context: Default;

        type Extrinsic: sp_runtime::traits::Extrinsic<Call = Self::RuntimeCall>
            + Checkable<Self::Context, Checked = Self::CheckedExtrinsic>
            + Codec
            + TypeInfo
            + Member;

        type CheckedExtrinsic: Applyable<Call = Self::RuntimeCall>
            + GetDispatchInfo
            + ReplaceSender<AccountId = Self::AccountId>;

        /// Same as `Executive`
        type UnsignedValidator: ValidateUnsigned<Call = Self::RuntimeCall>;

        type BlockNumberProvider: BlockNumberProvider<BlockNumber = BlockNumberFor<Self>>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        No,
    }

    #[pallet::error]
    pub enum Error<T> {
        EphKeyExpired,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T>
    where
        T::RuntimeCall: Dispatchable<Info = DispatchInfo>,
    {
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn submit_zklogin_unsigned(
            origin: OriginFor<T>,
            uxt: Box<T::Extrinsic>,
            address_seed: AccountIdLookupOf<T>,
            _inputs: ZkLoginInputs,
            _jwk_id: JwkId,
            expire_at: u32,
            _eph_pubkey: [u8; EPH_PUB_KEY_LEN],
        ) -> DispatchResultWithPostInfo {
            // make sure this call is unsigned signed
            ensure_none(origin)?;

            // check ehpkey's expiration time
            let now = T::BlockNumberProvider::current_block_number();
            let expire_at: BlockNumberFor<T> = expire_at.into();
            ensure!(expire_at <= now, Error::<T>::EphKeyExpired);

            // execute real call
            let r = Executive::<T>::apply_extrinsic(uxt, address_seed);
            Ok(().into())
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T>
    where
        T::RuntimeCall: Dispatchable<Info = DispatchInfo>,
        T: frame_system::Config<AccountId = AccountId32>,
    {
        type Call = Call<T>;

        fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            // TODO no need?
            match source {
                TransactionSource::InBlock | TransactionSource::External => { /* allowed */ }
                _ => return InvalidTransaction::Call.into(),
            };

            // verify signature
            match call {
                Call::submit_zklogin_unsigned {
                    uxt,
                    address_seed,
                    inputs,
                    jwk_id,
                    expire_at,
                    eph_pubkey,
                    ..
                } => {
                    let _xt = uxt.clone().check(&T::Context::default())?;

                    let address_seed = T::Lookup::lookup(address_seed.clone())?;

                    // TODO remove this!
                    let address_seed = U256::from_big_endian(address_seed.as_ref());

                    // validate zk proof
                    verify_zk_login(
                        address_seed,
                        inputs,
                        jwk_id,
                        *expire_at,
                        eph_pubkey,
                        &ZkLoginEnv::Prod,
                    )
                    .map_err(|_| InvalidTransaction::BadProof)?;
                }
                // TODO use other error type
                _ => return Err(UnknownTransaction::Custom(0).into()),
            }

            // TODO;
            Ok(ValidTransaction::default())
        }
    }
}

pub type CheckedOf<E, C> = <E as Checkable<C>>::Checked;
struct Executive<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> Executive<T>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo>,
{
    fn apply_extrinsic(
        uxt: Box<T::Extrinsic>,
        address_seed: AccountIdLookupOf<T>,
    ) -> ApplyExtrinsicResult {
        use scale_codec::Decode;
        let encoded = uxt.encode();
        let encoded_len = encoded.len();

        // Verify that the signature is good.
        let mut xt = uxt.check(&T::Context::default()).expect("process ?");
        xt.replace_sender(T::Lookup::lookup(address_seed).expect("lookup should succeed"));

        let dispatch_info = xt.get_dispatch_info();
        let r = Applyable::apply::<T::UnsignedValidator>(xt, &dispatch_info, encoded_len)?;

        // Mandatory(inherents) are not allowed to fail.
        //
        // The entire block should be discarded if an inherent fails to apply. Otherwise
        // it may open an attack vector.
        if r.is_err() && dispatch_info.class == DispatchClass::Mandatory {
            return Err(InvalidTransaction::BadMandatory.into())
        }

        Ok(r.map(|_| ()).map_err(|e| e.error))
    }
}
