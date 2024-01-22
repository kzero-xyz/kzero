#![cfg_attr(not(feature = "std"), no_std)]
use sp_runtime::{generic::UncheckedExtrinsic, MultiSignature};
use sp_std::prelude::*;
use zp_zklogin::Signature as ZkSignature;

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
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn submit_zklogin_unsigned(
            origin: OriginFor<T>,
            // todo: assign type to Extra
            utx: Box<
                UncheckedExtrinsic<T::AccountId, T::RuntimeCall, ZkSignature<MultiSignature>, ()>,
            >,
        ) -> DispatchResult {
            // make sure this call is unsigned signed
            ensure_none(origin)?;

            Ok(())
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            Ok(ValidTransaction::default())
        }
    }
}
