#![cfg_attr(not(feature = "std"), no_std)]

use scale_codec::{Codec, Encode};

use frame_support::dispatch::{DispatchInfo, GetDispatchInfo};
use sp_runtime::traits::{Applyable, Checkable, Dispatchable};
use sp_std::prelude::*;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

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

        type CheckedExtrinsic: Applyable<Call = Self::RuntimeCall> + GetDispatchInfo;

        /// Same as `Executive`
        type UnsignedValidator: ValidateUnsigned<Call = Self::RuntimeCall>;
    }

    #[pallet::storage]
    pub type Example<T: Config> = StorageValue<_, u32>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        No,
    }

    #[pallet::error]
    pub enum Error<T> {
        NoError,
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
            utx: Box<T::Extrinsic>,
        ) -> DispatchResult {
            // make sure this call is unsigned signed
            ensure_none(origin)?;
            Executive::<T>::apply_extrinsic(utx);
            Ok(())
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T>
    where
        T::RuntimeCall: Dispatchable<Info = DispatchInfo>,
    {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_zklogin_unsigned { .. } => {
                    // TODO add zkp check logic
                }
                // TODO use other error type
                _ => return Err(UnknownTransaction::Custom(0).into()),
            }

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
    fn apply_extrinsic(uxt: Box<T::Extrinsic>) {
        use scale_codec::Decode;
        let encoded = uxt.encode();
        let encoded_len = encoded.len();

        let mut xt = uxt.check(&T::Context::default()).expect("process ?");

        let dispatch_info = xt.get_dispatch_info();
        let r = Applyable::apply::<T::UnsignedValidator>(xt, &dispatch_info, encoded_len)
            .expect("process ?");
    }
}
