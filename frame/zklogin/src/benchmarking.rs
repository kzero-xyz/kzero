#![cfg(feature = "runtime-benchmarks")]
use super::*;

use frame_benchmarking::benchmarks;
use frame_system::{pallet_prelude::BlockNumberFor, RawOrigin};
use primitive_zklogin::traits::{SignaturePayloadExt, TryIntoEphPubKey};
use sp_core::ed25519;
use sp_io::crypto::ed25519_generate;
use sp_runtime::traits::Dispatchable;

// Import benchmark data
use crate::benchmark_data::{BenchmarkJwks, BenchmarkKeys};

benchmarks! {
    where_clause {
        where
        T::RuntimeCall: Dispatchable<Info = frame_support::dispatch::DispatchInfo, PostInfo = frame_support::dispatch::PostDispatchInfo>,
        <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
        <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
        T::Public: From<sp_core::ed25519::Public>,
        T::Signature: From<sp_core::ed25519::Signature>,
        BlockNumberFor<T>: From<u32>,
    }
    
    submit_jwks_unsigned {
        use crate::JwksPayload;
        use primitive_zklogin::JwkProvider;

        let public = ed25519_generate(0.into(), None);

        // Use benchmark data
        let jwk1 = BenchmarkJwks::google_jwk();
        let jwk2 = BenchmarkJwks::apple_jwk();

        let payload = JwksPayload::<T::Public, BlockNumberFor<T>> {
            public: T::Public::from(public),
            jwks: vec![
                (JwkProvider::Google, vec![jwk1.clone()]),
                (JwkProvider::Apple, vec![jwk2.clone()]),
            ],
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
        // Use key seeds from benchmark data
        let seeds = BenchmarkKeys::key_seeds();
        let key1 = ed25519_generate(seeds[0].into(), None);
        let key2 = ed25519_generate(seeds[1].into(), None);
        let key3 = ed25519_generate(seeds[2].into(), None);

        let keys = vec![
            (T::Public::from(key1), true),
            (T::Public::from(key2), true),
            (T::Public::from(key3), true),
        ];

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