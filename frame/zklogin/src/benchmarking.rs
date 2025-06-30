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
use crate::benchmark_data::{BenchmarkJwks, BenchmarkKeys, BenchmarkZkMaterial};

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

    submit_zklogin_unsigned {
        let zk_material = BenchmarkZkMaterial::create_test_zk_material::<MomentOf<T>>();
        
        // get the account id from the test seed
        let seed = BenchmarkZkMaterial::seed();
        let account_id = AccountId::new(*seed);
        let address_seed = T::Lookup::unlookup(account_id.clone().into());
        
        // Create a system call for testing
        let call = T::RuntimeCall::from(frame_system::Call::remark {
            remark: vec![0u8; 32],
        });

        let signed_extra = (
            frame_system::CheckNonZeroSender::<T>::new(),
            frame_system::CheckSpecVersion::<T>::new(),
            frame_system::CheckTxVersion::<T>::new(),
            frame_system::CheckGenesis::<T>::new(),
            frame_system::CheckEra::<T>::from(sp_runtime::generic::Era::Immortal),
            frame_system::CheckNonce::<T>::from(0u32.into()),
            frame_system::CheckWeight::<T>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<T>::from(0u128.into()),
        );

        // Use provided signature for benchmark
        let raw_signature = BenchmarkZkMaterial::mock_sign();

        // Use user specified public key for benchmark
        let public_hex = BenchmarkZkMaterial::public_hex();
        let public_bytes: [u8; 32] = hex::decode(public_hex).expect("hex decode failed").try_into().expect("length must be 32");
        let signer_account_id = AccountId::new(public_bytes);

        // Initialize balances using standard Substrate method, otherwise this tx will be failed due to no balance to pay the gas
        type BalancesOf<T> = BalancesPallet<T>;
        let address_seed_account_id_t: T::AccountId = account_id.into();
        
        // Set balances
        let balance_amount = 1_000_000_000u128;
        let _ = <BalancesOf<T> as Currency<_>>::make_free_balance_be(&address_seed_account_id_t, balance_amount);

        let unchecked_extrinsic = UncheckedExtrinsic::<
            sp_runtime::MultiAddress<T::AccountId, ()>,
            T::RuntimeCall,
            sp_runtime::MultiSignature,
            SignedExtraLocal<T>
        >::new_signed(
            call,
            signer_account_id.into(),
            sp_runtime::MultiSignature::Ed25519(raw_signature),
            signed_extra,
        );

        let mock_extrinsic: Box<<T as Config>::Extrinsic> = Box::new(unchecked_extrinsic.into());

        // let source = sp_runtime::transaction_validity::TransactionSource::External;

        // // Insert provider and jwks first to ensure validate_unsigned passes
        // let provider = BenchmarkJwks::default_provider();
        // let jwk_json = BenchmarkJwks::set_jwk_json();
        // let json = jwk_json.as_bytes().to_vec();
        // assert_ok!(ZKLogin::<T>::set_jwk(RawOrigin::Root.into(), provider, json));

        // // Construct Call<T> to pass to validate_unsigned
        // let call_for_validation = Call::<T>::submit_zklogin_unsigned {
        //     uxt: mock_extrinsic.clone(),
        //     address_seed: address_seed.clone(),
        //     zk_material: zk_material.clone(),
        // };
        // assert!(<ZKLogin<T> as ValidateUnsigned>::validate_unsigned(source, &call_for_validation).is_ok());

        frame_system::Pallet::<T>::set_block_number(10u32.into());
    }: _ (RawOrigin::None, mock_extrinsic, address_seed, zk_material)
    verify {}

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