#![cfg(feature = "runtime-benchmarks")]
use super::*;

use frame_benchmarking::benchmarks;
use frame_system::{pallet_prelude::BlockNumberFor, RawOrigin};
use primitive_zklogin::traits::TryIntoEphPubKey;
use sp_io::crypto::ed25519_generate;
use sp_runtime::{traits::Dispatchable, MultiSignature};

// Import benchmark data
use crate::benchmark_data::{BenchmarkJwks, BenchmarkKeys, BenchmarkZkLogin};

// Type definitions
type AccountId = <<MultiSignature as sp_runtime::traits::Verify>::Signer as sp_runtime::traits::IdentifyAccount>::AccountId;

benchmarks! {
    where_clause {
        where
        T: Send + Sync + pallet_transaction_payment::Config + pallet_balances::Config<Balance = u128>,
        T::AccountId: From<AccountId>,
        MomentOf<T>: Default + Copy + TryInto<u64> + From<u64>,
        u64: From<MomentOf<T>>,
        sp_runtime::MultiAddress<T::AccountId, ()>: From<sp_runtime::AccountId32>,
        <<T as pallet_transaction_payment::Config>::OnChargeTransaction as pallet_transaction_payment::OnChargeTransaction<T>>::Balance: From<u128> + From<u64>,
        <T as pallet::Config>::RuntimeCall: Dispatchable<Info = frame_support::dispatch::DispatchInfo, PostInfo = frame_support::dispatch::PostDispatchInfo>,
        sp_runtime::MultiAddress<T::AccountId, ()>: TryIntoEphPubKey,
        T::Public: From<sp_core::ed25519::Public>,
        T::Signature: From<sp_core::ed25519::Signature>,
        BlockNumberFor<T>: From<u32>,
        T: frame_system::Config<AccountId = sp_runtime::AccountId32>,
    }

    submit_jwks_unsigned {
        let c in 0 .. 10;
        use crate::JwksPayload;

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

    submit_zklogin {
        // Prepare JWK on chain first
        let provider = BenchmarkJwks::default_provider();
        let jwk_json = BenchmarkJwks::set_jwk_json();
        let json = jwk_json.as_bytes().to_vec();
        Pallet::<T>::set_jwk(RawOrigin::Root.into(), provider, json)
            .expect("Setting JWK should succeed");

        // Set block number to ensure key is not expired
        frame_system::Pallet::<T>::set_block_number(BlockNumberFor::<T>::from(10u32));

        // Prepare zk material and address_seed
        let zk_material = BenchmarkZkLogin::prepare_zk_material_with_moment::<MomentOf<T>>();
        let address_seed = BenchmarkZkLogin::get_address_seed();
        
        // Create a simple remark call as the inner call (lightweight operation)
        let system_call = frame_system::Call::<T>::remark_with_event {
            remark: vec![0u8; 32],
        };
        let inner_call: <T as pallet::Config>::RuntimeCall = system_call.into();

        // Get the zk account (derived from address_seed)
        let zk_account: T::AccountId = sp_core::crypto::AccountId32::from(address_seed.0).into();

    }: _(RawOrigin::Signed(zk_account), Box::new(inner_call), address_seed.into(), zk_material)
    verify {
        // Verify that the call was executed successfully
        // The remark call should have been executed
    }

    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
