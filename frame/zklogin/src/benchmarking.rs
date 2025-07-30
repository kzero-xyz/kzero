#![cfg(feature = "runtime-benchmarks")]
use super::*;

use frame_benchmarking::benchmarks;
use frame_system::{pallet_prelude::BlockNumberFor, RawOrigin};
use primitive_zklogin::traits::{SignaturePayloadExt, TryIntoEphPubKey};
use sp_core::ed25519;
use sp_io::crypto::ed25519_generate;
use sp_runtime::traits::Dispatchable;
use frame_support::pallet_prelude::ValidateUnsigned;
use frame_support::assert_ok;
use sp_runtime::MultiSignature;
use sp_runtime::generic::UncheckedExtrinsic;
use hex;
use frame_support::traits::Currency;
use pallet_balances::Pallet as BalancesPallet;
use crate::Pallet as ZKLogin;

// Import benchmark data
use crate::benchmark_data::{BenchmarkJwks, BenchmarkKeys};

// Type definitions
type AccountId = <<MultiSignature as sp_runtime::traits::Verify>::Signer as sp_runtime::traits::IdentifyAccount>::AccountId;

type SignedExtraLocal<T> = (
    frame_system::CheckNonZeroSender<T>,
    frame_system::CheckSpecVersion<T>,
    frame_system::CheckTxVersion<T>,
    frame_system::CheckGenesis<T>,
    frame_system::CheckEra<T>,
    frame_system::CheckNonce<T>,
    frame_system::CheckWeight<T>,
    pallet_transaction_payment::ChargeTransactionPayment<T>,
);

benchmarks! {
    where_clause {
        where
        T: Send + Sync + pallet_transaction_payment::Config + pallet_balances::Config<Balance = u128>,
        T::AccountId: From<AccountId>,
        MomentOf<T>: Default + Copy + TryInto<u64> + From<u64>,
        u64: From<MomentOf<T>>,
        sp_runtime::MultiAddress<T::AccountId, ()>: From<sp_runtime::AccountId32>,
        <<T as pallet_transaction_payment::Config>::OnChargeTransaction as pallet_transaction_payment::OnChargeTransaction<T>>::Balance: From<u128> + From<u64>,
        <T as pallet::Config>::Extrinsic: From<UncheckedExtrinsic<sp_runtime::MultiAddress<T::AccountId, ()>, T::RuntimeCall, sp_runtime::MultiSignature, SignedExtraLocal<T>>>,
        T::RuntimeCall: Dispatchable<Info = frame_support::dispatch::DispatchInfo, PostInfo = frame_support::dispatch::PostDispatchInfo>,
        <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
        <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
        T::Public: From<sp_core::ed25519::Public>,
        T::Signature: From<sp_core::ed25519::Signature>,
        BlockNumberFor<T>: From<u32>,
        T: frame_system::Config<AccountId = sp_runtime::AccountId32>,
    }

    submit_jwks_unsigned {
        let c in 0 .. 10;
        use crate::JwksPayload;
        use primitive_zklogin::JwkProvider;

        let public = ed25519_generate(0.into(), None);

        // Generate dynamic JWKs based on count
        let jwks = BenchmarkJwks::generate_test_jwks(c);

        let payload = JwksPayload::<T::Public, BlockNumberFor<T>> {
            public: T::Public::from(public),
            jwks,
            block_number: BlockNumberFor::<T>::from(1u32),
        };

        // Sign the payload using runtime callable signature interface
        let encoded_payload = payload.encode();
        let raw_signature = sp_io::crypto::ed25519_sign(0.into(), &public, &encoded_payload)
            .expect("Signing should succeed in benchmarking environment");
        let signature = T::Signature::from(raw_signature);

    }: _ (RawOrigin::None, payload, signature)
    verify {
    }

    update_keys {
        let c in 0 .. 10;
        let keys = BenchmarkKeys::generate_test_keys::<T>(c);

    }: _ (RawOrigin::Root, keys)
    verify {
    }

    set_jwk {
        // Use benchmark data
        let provider = BenchmarkJwks::default_provider();
        let jwk_json = BenchmarkJwks::set_jwk_json();
        let json = jwk_json.as_bytes().to_vec();

    }: _ (RawOrigin::Root, provider, json)
    verify {
    }

    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}