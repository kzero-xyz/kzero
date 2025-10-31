use crate::{Call as ZkLoginCall, Pallet};
use frame_support::{
    assert_ok, derive_impl,
    dispatch::{GetDispatchInfo, RawOrigin},
    parameter_types,
    traits::{Currency, Get, UnfilteredDispatchable},
    weights::{IdentityFee, WeightToFee},
};
use pallet_balances::Call as BalancesCall;
use primitive_zklogin::{
    test_helper::{get_raw_data, get_test_eph_key, get_zklogin_inputs, test_cases::google},
    JwkProvider, Signing, ZkMaterialV1,
};
use scale_codec::Encode;
use sp_core::{ed25519, Pair};
use sp_runtime::{
    generic,
    generic::UncheckedExtrinsic,
    traits::{BlakeTwo256, IdentifyAccount, SaturatedConversion, Verify},
    BuildStorage, MultiAddress, MultiSignature,
};
use sp_runtime::traits::TransactionExtension;

/// An index to a block.
pub type BlockNumber = u32;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Signature = MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Address = MultiAddress<AccountId, ()>;

type TxExtension = (
    super::ZkLoginExtension<Test>,
    frame_system::CheckNonce<Test>,
    frame_system::CheckWeight<Test>,
    pallet_transaction_payment::ChargeTransactionPayment<Test>,
);

type MockUncheckedExtrinsic = UncheckedExtrinsic<Address, RuntimeCall, MultiSignature, TxExtension>;

pub type SignedPayload = generic::SignedPayload<RuntimeCall, TxExtension>;

type Block = generic::Block<Header, MockUncheckedExtrinsic>;

type MockExecutive = frame_executive::Executive<
    Test,
    Block,
    frame_system::ChainContext<Test>,
    Test,
    AllPalletsWithSystem,
>;

frame_support::construct_runtime!(
    pub enum Test
    {
        System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
        Timestamp: pallet_timestamp,
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        ZkLogin: super::{Pallet, Call, Event<T>, ValidateUnsigned},
        TransactionPayment: pallet_transaction_payment::{Pallet, Event<T>},
        Proxy: pallet_proxy::{Pallet, Call, Storage, Event<T>},
        Recovery: pallet_recovery::{Pallet, Call, Storage, Event<T>},
    }
);

parameter_types! {
    pub const MaxProxies: u32 = 8;
    pub const MaxFriends: u16 = 3;
    pub const ConfigDepositBase: u64 = 0;
    pub const FriendDepositFactor: u64 = 0;
    pub const RecoveryDeposit: u64 = 0;
}

impl pallet_proxy::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type ProxyType = ();
    type ProxyDepositBase = (); // For test, use unit type
    type ProxyDepositFactor = ();
    type MaxProxies = MaxProxies;
    type WeightInfo = ();
    type MaxPending = ();
    type CallHasher = sp_runtime::traits::BlakeTwo256;
    type AnnouncementDepositBase = ();
    type AnnouncementDepositFactor = ();
    type BlockNumberProvider = frame_system::Pallet<Test>;
}

impl pallet_recovery::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type ConfigDepositBase = ConfigDepositBase;
    type FriendDepositFactor = FriendDepositFactor;
    type MaxFriends = MaxFriends;
    type RecoveryDeposit = RecoveryDeposit;
    type BlockNumberProvider = frame_system::Pallet<Test>;
}
parameter_types! {
    pub const BlockHashCount: u32 = 250;
    pub const MaxKeys: u32 = 3;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = sp_runtime::traits::AccountIdLookup<Self::AccountId, ()>;
    type AccountData = pallet_balances::AccountData<u64>;
}

impl frame_system::offchain::SigningTypes for Test {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

parameter_types! {
    pub const OperationalFeeMultiplier: u8 = 5;
}

#[derive_impl(pallet_transaction_payment::config_preludes::TestDefaultConfig)]
impl pallet_transaction_payment::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = pallet_transaction_payment::FungibleAdapter<Balances, ()>;
    type OperationalFeeMultiplier = OperationalFeeMultiplier;
    type WeightToFee = IdentityFee<u64>;
    type LengthToFee = IdentityFee<u64>;
    type FeeMultiplierUpdate = ();
}

parameter_types! {
    pub const JwkJsonLimit: u32 = 2048;
}

impl<LocalCall> frame_system::offchain::CreateTransactionBase<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
{
    type Extrinsic = MockUncheckedExtrinsic;
    type RuntimeCall = RuntimeCall;
}

impl frame_system::offchain::CreateInherent<super::Call<Test>> for Test {
    fn create_inherent(call: RuntimeCall) -> Self::Extrinsic {
        MockUncheckedExtrinsic::new_bare(call)
    }
}

impl frame_system::offchain::CreateSignedTransaction<super::Call<Test>> for Test {
    fn create_signed_transaction<
        C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>,
    >(
        call: RuntimeCall,
        public: <Signature as Verify>::Signer,
        account: <Test as frame_system::Config>::AccountId,
        nonce: <Test as frame_system::Config>::Nonce,
    ) -> Option<MockUncheckedExtrinsic> {
        use sp_runtime::traits::StaticLookup;
        let tip = 0;
        let period =
            BlockHashCount::get().checked_next_power_of_two().map(|c| c / 2).unwrap_or(2) as u64;
        let current_block = System::block_number().saturated_into::<u64>().saturating_sub(1);
        let era = sp_runtime::generic::Era::mortal(period, current_block);
        let tx_ext = (
            super::ZkLoginExtension::<Test>::new(),
            frame_system::CheckNonce::<Test>::from(nonce),
            frame_system::CheckWeight::<Test>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<Test>::from(tip),
        );
        let raw_payload = SignedPayload::new(call.clone(), tx_ext.clone()).ok()?;
        let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
        let address = <Test as frame_system::Config>::Lookup::unlookup(account);
        Some(MockUncheckedExtrinsic::new_signed(call, address, signature, tx_ext))
    }
}

impl super::Config for Test {
    type AuthorityId = crate::crypto::ZkLoginAuthId;
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type JwkJsonLimit = JwkJsonLimit;
    type Time = Timestamp;
    type MaxKeys = MaxKeys;
    type WeightInfo = ();
}

// Default WeightInfo implementation for tests
impl crate::weights::WeightInfo for () {
    fn submit_jwks_unsigned(_c: u32) -> frame_support::weights::Weight {
        frame_support::weights::Weight::zero()
    }

    fn update_keys(_c: u32) -> frame_support::weights::Weight {
        frame_support::weights::Weight::zero()
    }

    fn set_jwk() -> frame_support::weights::Weight {
        frame_support::weights::Weight::zero()
    }
}

fn zk_address() -> AccountId {
    let (zklogin_address, ..) = get_raw_data();
    AccountId::from(zklogin_address.0)
}

const INIT_BALANCE: u64 = 1_000_000_000_000_000;

// This function basically just builds a genesis storage key/value store according to
// our desired mockup.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    let addr = zk_address();
    // We use default for brevity, but you can configure as desired if needed.
    pallet_balances::GenesisConfig::<Test> {
        // give `zk_address` an initial value of INIT_BALANCE
        balances: vec![(addr, INIT_BALANCE)],
        ..Default::default()
    }
    .assimilate_storage(&mut t)
    .unwrap();
    t.into()
}

#[test]
fn basic_setup_works() {
    new_test_ext().execute_with(|| {
        assert_eq!(System::account(&zk_address()).data.free, INIT_BALANCE);
    })
}

// ================================ validate_unsigned ================================
/*
#[test]
fn validate_unsigned_should_work() {
    use sp_runtime::traits::ValidateUnsigned;
    let source = sp_runtime::transaction_validity::TransactionSource::External;

    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);

    let signing_key: ed25519::Pair = get_test_eph_key();

    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let kids = google::kids(true);
    let kid = kids[0].clone();

    let zk_material = ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // construct Transfer Call
    let dest = AccountId::from([0u8; 32]);
    let call: RuntimeCall =
        BalancesCall::transfer_keep_alive { dest: MultiAddress::Id(dest.clone()), value: 100 }
            .into();

    // construct submit_zklogin call with inner call
    let final_call = ZkLoginCall::submit_zklogin {
        call: Box::new(call.clone()),
        address_seed: address_seed.into(),
        zk_material,
    };

    // construct outer UncheckedExtrinsic using `TxExtension``
    let outer_uxt = UncheckedExtrinsic::<
        MultiAddress<AccountId, ()>,
        RuntimeCall,
        MultiSignature,
        TxExtension,
    >::new_unsigned(final_call.clone().into());

    // calculate the call_weight & call_weight_to_fee
    let call_weight = call.clone().get_dispatch_info().call_weight;
    let call_weight_to_fee =
        <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&call_weight);

    // calculate the base weight & weight_to_fee
    let block_weights: frame_system::limits::BlockWeights =
        <Test as frame_system::Config>::BlockWeights::get();
    let base_extrinsic =
        block_weights.get(frame_support::dispatch::DispatchClass::Normal).base_extrinsic;
    let base_weight_to_fee =
        <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&base_extrinsic);

    // calculate the proof_size & proof_size_to_fee
    let proof_size = outer_uxt.encode().len() as u64;
    let proof_size_to_fee =
        <Test as pallet_transaction_payment::Config>::LengthToFee::weight_to_fee(
            &frame_support::weights::Weight::from_parts(proof_size, 0),
        );

    // calculate `the total fee` = `call_weight_to_fee` + `base_weight_to_fee` + `proof_size_to_fee`
    let total_fee = call_weight_to_fee + base_weight_to_fee + proof_size_to_fee;

    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        // the eph key's expiration at 834, make sure current number is smaller.
        System::set_block_number(10);

        // check the balance of zk_address before the transfer
        let balance_before = Balances::free_balance(&zk_address());
        assert_eq!(balance_before, INIT_BALANCE);

        // validate the unsigned extrinsic
        assert!(Pallet::<Test>::validate_unsigned(source, &final_call).is_ok());

        // execute through call.dispatch
        assert_ok!(final_call.dispatch_bypass_filter(RawOrigin::None.into()));
        let balance_after = Balances::free_balance(&zk_address());

        // check the balance of zk_address after the transfer (should deduct the `fee` and `the transfer amount``)
        assert_eq!(balance_after, INIT_BALANCE - total_fee - 100);

        // transfer success, check the balance of the destination account should be 100
        assert_eq!(Balances::free_balance(&dest), 100);

        // About to do the second transfer by apply_extrinsic
        // execute through `apply_extrinsic`
        assert_ok!(MockExecutive::apply_extrinsic(outer_uxt));

        let balance_after_apply_extrinsic = Balances::free_balance(&zk_address());

        // check the balance of zk_address after the transfer (should deduct the `fee` and `the transfer amount``)
        assert_eq!(balance_after_apply_extrinsic, balance_after - total_fee - 100);

        // transfer success, check the balance of the destination account should be 200(two times of the transfer)
        assert_eq!(Balances::free_balance(&dest), 200);
    });
}

#[test]
fn validate_unsigned_should_fail_when_jwk_not_match() {
    use sp_runtime::traits::ValidateUnsigned;
    let source = sp_runtime::transaction_validity::TransactionSource::External;

    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);
    let signing_key: ed25519::Pair = get_test_eph_key();
    let provider = JwkProvider::Google;

    // use the second jwk, which is not corresponding to the jwk in the zkMaterial
    let jwks = google::GOOGLE_JWK_JSON_LIST[1];
    let kids = google::kids(true);
    let kid = kids[0].clone();

    let zk_material = ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // construct Transfer Call
    let dest = AccountId::from([0u8; 32]);
    let call: RuntimeCall =
        BalancesCall::transfer_keep_alive { dest: MultiAddress::Id(dest.clone()), value: 100 }
            .into();

    // construct submit_zklogin call with inner call
    let final_call = ZkLoginCall::submit_zklogin {
        call: Box::new(call),
        address_seed: address_seed.into(),
        zk_material,
    };

    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        // the eph key's expiration at 834, make sure current number is smaller.
        System::set_block_number(10);

        // The JWK is not matched, so the validation should fail.
        assert!(Pallet::<Test>::validate_unsigned(source, &final_call).is_err());
    });
}
*/
// ================================ jwk parse tests ================================
#[test]
fn test_parse_jwk_success() {
    use crate::jwk::parse_jwk;
    // Test a valid JWK
    let valid_jwk = google::GOOGLE_JWK_JSON_LIST[1];

    let result = parse_jwk::<Test>(valid_jwk.as_bytes());
    assert!(result.is_ok());

    let jwk = result.unwrap();
    assert_eq!(jwk.prm.kid, Some("48a63bc4767f8550a532dc630cf7eb49ff397e7c".to_string()));
    assert_eq!(jwk.prm.alg, Some(primitive_zklogin::Algorithm::Signing(Signing::Rs256)));
}

#[test]
fn test_parse_jwk_missing_required_fields() {
    use crate::{jwk::parse_jwk, pallet::Error};
    // Set log level to error to suppress error messages
    log::set_max_level(log::LevelFilter::Error);

    // Test JWK missing required fields
    let incomplete_jwk = r#"{
        "kid": "test_key",
        "kty": "RSA"
        // Missing n, e, alg, use fields
    }"#;

    let result = parse_jwk::<Test>(incomplete_jwk.as_bytes());
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::<Test>::InvalidJwkJson));

    // Test invalid JSON format
    let incomplete_jwk_without_kid = r#"{
        "kty": "RSA",
        "n": "test_n",
        "e": "AQAB",
        "alg": "RS256",
        "use": "sig", 
    }"#;

    let result = parse_jwk::<Test>(incomplete_jwk_without_kid.as_bytes());
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::<Test>::InvalidJwkJson));
}

#[test]
fn test_parse_jwk_with_google_format() {
    use crate::jwk::parse_jwk;
    use primitive_zklogin::test_helper::test_cases::google;

    // Test using Google's JWK format
    let google_jwk = google::GOOGLE_JWK_JSON_LIST[0];

    let result = parse_jwk::<Test>(google_jwk.as_bytes());
    assert!(result.is_ok());

    let jwk = result.unwrap();
    assert!(jwk.prm.kid.is_some());
    assert_eq!(jwk.prm.kid.as_ref().unwrap(), "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781");
    assert!(matches!(
        jwk.prm.alg,
        Some(primitive_zklogin::Algorithm::Signing(primitive_zklogin::Signing::Rs256))
    ));
}

// ================================ offchain worker tests ================================
#[test]
fn test_fetch_jwks() {
    use crate::offchain_worker::fetch_jwks;
    use primitive_zklogin::JwkProvider;
    use sp_core::offchain::{
        testing::{PendingRequest, TestOffchainExt},
        OffchainDbExt, OffchainWorkerExt,
    };
    use sp_io::TestExternalities;
    // Create test externalities with offchain worker context
    let (offchain, state) = TestOffchainExt::new();
    let mut t = TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain.clone()));
    t.register_extension(OffchainDbExt::new(offchain));
    // Create a valid JWK response
    let mock_jwks_response = r#"
    {
        "keys": [
            {
            "kid": "884892122e2939fd1f31375b2b363ec815723bbb",
            "e": "AQAB",
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "2ftoBIWdn7XWU1XPPP0B4s-jSKq7nhHZxlT8P52l-OkhpHH8uXUJf8BG6cZFc5lRSx4p0KOjOkfTHUDrbkUOsbL8Q3DCo5z-w35-xvt2iJCe14Em-YrKUbvaRCzBln40c1m6nFf9xJ7y2hTWXFmLYERidFeWEunUbOdF7BzK1r3PJnpCaf9frNZFKh808Q7IR9S--NNIRV8WMJxXhNa0C7ZwvC_Z-arjywdXFhtgiXMQKYhwLWDPtPRQ41CYHTo2wFIh20sBSrzKawHBfloZQSc47CJk85Oz7dA3jsGGj6P00EuvZEoENzk4Czf-bl9wtehJ3xadHDjRkdWDBfhhqQ"
            },
            {
            "e": "AQAB",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "b5e440ae941e9981ee2fa1376d42c46d731dee3f",
            "n": "pZXMN1HbBD2H5iDDuaQM_1gx_B3uIStAT1qAPN6oxKID6Rp8ybt8_SdfuGNonoazOQ4OHiP3Prckr-WuEFISfjzWJkT15lBQ_hc9Wq5-eZBSuTas9yEd3a1AtT-ms_E5Re3CsuFJoO9A5g0UYcZWWbp27f06FUDo3qYvLN2JJcJTIR4Ivi6pWj2Yrm6ShtaW4Jnz5XyIr3lKzJh3uNR79081_9rfvzV5mVdvKY1mPuXJM4Bhev4f1PSAxSyAaP_c3_fUPP7rQHf0re-RT8U4nsDbIRoiGhTE3UeLC2dzMQm8s23ex0Q2EsG-cSKXTXL5Ts9rleqryYqOrEJOTxzCqw"
            }
        ]
    }"#;
    let mock_config_response = r#"{"jwks_uri":"https://example.com/jwks"}"#;

    t.execute_with(|| {
        // Set up two mock responses for each provider
        for provider in JwkProvider::iterator() {
            // First request: get jwks_uri
            state.write().expect_request(PendingRequest {
                method: "GET".into(),
                uri: provider.well_know_link().to_string(),
                response: Some(mock_config_response.as_bytes().to_vec()),
                sent: true,
                ..Default::default()
            });

            // Second request: get JWKs
            state.write().expect_request(PendingRequest {
                method: "GET".into(),
                uri: "https://example.com/jwks".to_string(),
                response: Some(mock_jwks_response.as_bytes().to_vec()),
                sent: true,
                ..Default::default()
            });
        }

        // Test fetch_jwks in offchain worker context
        let jwks = fetch_jwks();
        // Since we provided mock responses, we should get some JWKs
        assert!(!jwks.is_empty());

        // Verify that each provider has at least one JWK
        for (provider, provider_jwks) in jwks {
            assert!(!provider_jwks.is_empty());
            log::info!("Provider {:?} has {} JWKs", provider, provider_jwks.len());
        }
    });
}

#[test]
fn test_check_jwk_not_onchain_when_not_exists() {
    use crate::offchain_worker::check_jwk_not_onchain;
    use primitive_zklogin::{Jwk, JwkProvider};

    // Set up test data
    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let jwk: Jwk = serde_json::from_str(jwks).unwrap();

    // Test case: JWK not on chain
    let result = check_jwk_not_onchain(provider, &jwk, |_, _| None);
    assert_eq!(result, Some(true));
}

#[test]
fn test_check_jwk_not_onchain_when_same_content() {
    use crate::offchain_worker::check_jwk_not_onchain;
    use primitive_zklogin::{Jwk, JwkProvider};

    // Set up test data
    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let jwk: Jwk = serde_json::from_str(jwks).unwrap();

    // Test case: JWK exists on chain with same content
    let result = check_jwk_not_onchain(provider, &jwk, |_, _| Some(jwk.clone()));
    assert_eq!(result, Some(false));
}

#[test]
fn test_check_jwk_not_onchain_when_different_content() {
    use crate::offchain_worker::check_jwk_not_onchain;
    use primitive_zklogin::{Jwk, JwkProvider};

    // Set up test data
    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let jwk: Jwk = serde_json::from_str(jwks).unwrap();

    // Test case: JWK exists on chain with different content
    let mut different_jwk = jwk.clone();
    different_jwk.prm.kid = Some("different".to_string());
    let result = check_jwk_not_onchain(provider, &jwk, |_, _| Some(different_jwk.clone()));
    assert_eq!(result, Some(true));
}

#[test]
fn test_set_jwk() {
    use crate::pallet::Error;
    use frame_support::assert_noop;
    use primitive_zklogin::{test_helper::test_cases::google, Jwk, JwkProvider};
    use sp_runtime::DispatchError;

    let valid_jwk = google::GOOGLE_JWK_JSON_LIST[0];
    let provider = JwkProvider::Google;
    let jwk: Jwk = serde_json::from_str(valid_jwk).unwrap();
    let kid = jwk.prm.kid.as_ref().unwrap().as_bytes();

    let mut ext = new_test_ext();
    ext.execute_with(|| {
        // Set log level to error to suppress error messages
        log::set_max_level(log::LevelFilter::Off);

        // Check that JWK doesn't exist before setting
        assert!(crate::JwkJsons::<Test>::get(provider, kid).is_none());

        // Test valid JWK setting by root
        assert_ok!(ZkLogin::set_jwk(
            RawOrigin::Root.into(),
            provider,
            valid_jwk.as_bytes().to_vec()
        ));

        // Check that JWK exists after setting
        let stored_jwk_json = crate::JwkJsons::<Test>::get(provider, kid).unwrap();
        let stored_jwk = crate::jwk::parse_jwk::<Test>(stored_jwk_json.as_slice()).unwrap();
        assert_eq!(
            stored_jwk.prm.kid.as_ref().unwrap(),
            "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781"
        );

        // Non-root cannot set JWK
        assert_noop!(
            ZkLogin::set_jwk(
                RawOrigin::Signed(AccountId::from([1u8; 32])).into(),
                provider,
                valid_jwk.as_bytes().to_vec()
            ),
            DispatchError::BadOrigin
        );

        // Invalid JWK format should fail
        let invalid_jwk = r#"{
            "kid": "test_key",
            "kty": "RSA"
            // Missing required fields
        }"#;
        assert_noop!(
            ZkLogin::set_jwk(RawOrigin::Root.into(), provider, invalid_jwk.as_bytes().to_vec()),
            Error::<Test>::InvalidJwkJson
        );
    });
}

#[test]
fn test_update_keys() {
    use frame_support::{assert_noop, assert_ok};
    use sp_core::ed25519;
    use sp_runtime::{DispatchError, MultiSigner};

    new_test_ext().execute_with(|| {
        // Generate test keys
        let (key1, _) = ed25519::Pair::generate();
        let (key2, _) = ed25519::Pair::generate();
        let (key3, _) = ed25519::Pair::generate();

        // Test adding new keys
        assert_ok!(ZkLogin::update_keys(
            RawOrigin::Root.into(),
            vec![
                (MultiSigner::Ed25519(key1.public()), true),
                (MultiSigner::Ed25519(key2.public()), true)
            ]
        ));

        // Verify keys were added
        let keys = crate::Keys::<Test>::get();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&MultiSigner::Ed25519(key1.public())));
        assert!(keys.contains(&MultiSigner::Ed25519(key2.public())));

        // Test removing a key and adding another
        assert_ok!(ZkLogin::update_keys(
            RawOrigin::Root.into(),
            vec![
                (MultiSigner::Ed25519(key1.public()), false),
                (MultiSigner::Ed25519(key3.public()), true)
            ]
        ));

        // Verify key1 was removed and key3 was added
        let keys = crate::Keys::<Test>::get();
        assert_eq!(keys.len(), 2);
        assert!(!keys.contains(&MultiSigner::Ed25519(key1.public())));
        assert!(keys.contains(&MultiSigner::Ed25519(key2.public())));
        assert!(keys.contains(&MultiSigner::Ed25519(key3.public())));

        // Test non-root cannot update keys
        assert_noop!(
            ZkLogin::update_keys(
                RawOrigin::Signed(AccountId::from([1u8; 32])).into(),
                vec![(MultiSigner::Ed25519(key1.public()), true)]
            ),
            DispatchError::BadOrigin
        );
    });
}

// ================================ test_submit_jwks_unsigned ================================
#[test]
fn test_submit_jwks_unsigned() {
    use crate::JwksPayload;
    use frame_support::assert_noop;
    use primitive_zklogin::{Jwk, JwkProvider};
    use sp_core::ed25519;
    use sp_runtime::{DispatchError, MultiSigner};

    // Set log level to off to suppress error messages
    log::set_max_level(log::LevelFilter::Off);

    // Generate test keys
    let (key1, _) = ed25519::Pair::generate();

    // Create test JWKs
    let jwk1 = google::GOOGLE_JWK_JSON_LIST[0];
    let jwk2 = google::GOOGLE_JWK_JSON_LIST[1];

    let jwk1: Jwk = serde_json::from_str(jwk1).unwrap();
    let jwk2: Jwk = serde_json::from_str(jwk2).unwrap();

    new_test_ext().execute_with(|| {
        // Create payload with multiple JWKs
        let jwk1_json = serde_json::to_vec(&jwk1).unwrap();
        let jwk2_json = serde_json::to_vec(&jwk2).unwrap();
        let payload = JwksPayload {
            public: MultiSigner::Ed25519(key1.public()),
            jwks: vec![
                (JwkProvider::Google, vec![jwk1_json]),
                (JwkProvider::Apple, vec![jwk2_json]),
            ],
            block_number: 1,
        };

        // Sign the encoded payload
        let signature = MultiSignature::from(key1.sign(&payload.encode()));

        // Test successful submission
        assert_ok!(ZkLogin::submit_jwks_unsigned(
            RawOrigin::None.into(),
            payload.clone(),
            signature.clone()
        ));

        // Verify JWKs were stored
        let kid1 = jwk1.prm.kid.as_ref().unwrap().as_bytes();
        let kid2 = jwk2.prm.kid.as_ref().unwrap().as_bytes();
        assert!(crate::JwkJsons::<Test>::get(JwkProvider::Google, kid1).is_some());
        assert!(crate::JwkJsons::<Test>::get(JwkProvider::Apple, kid2).is_some());

        // Test invalid origin (must be None)
        assert_noop!(
            ZkLogin::submit_jwks_unsigned(RawOrigin::Root.into(), payload.clone(), signature),
            DispatchError::BadOrigin
        );
    });
}

// ================================ submit_zklogin test ================================
#[test]
fn test_submit_zklogin() {
    use frame_support::assert_noop;
    use primitive_zklogin::{JwkProvider, ZkMaterialV1};
    use sp_runtime::DispatchError;
    log::set_max_level(log::LevelFilter::Off);

    // Get test data
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);
    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let kids = google::kids(true);
    let kid = kids[0].clone();
    let zk_material = ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // Create a transfer call
    let dest = AccountId::from([0u8; 32]);
    let call: RuntimeCall =
        BalancesCall::transfer_keep_alive { dest: MultiAddress::Id(dest.clone()), value: 100 }
            .into();
    let final_call: RuntimeCall = ZkLoginCall::submit_zklogin {
        call: Box::new(call.clone()),
        address_seed: address_seed.into(),
        zk_material,
    }.into();
    // Create signed payload
    let signing_key: ed25519::Pair = get_test_eph_key();
    let tx_ext: TxExtension = (
        super::ZkLoginExtension::<Test>::new(),
        frame_system::CheckNonce::<Test>::from(0),
        frame_system::CheckWeight::<Test>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::from(0),
    );
    let sign = SignedPayload::new(final_call.clone(), tx_ext.clone()).expect("payload should succeed").using_encoded(|d| signing_key.sign(d));

    // Create unchecked extrinsic
    let uxt = MockUncheckedExtrinsic::new_signed(
        final_call.clone(),
        AccountId::from(signing_key.public()).into(),
        MultiSignature::from(sign),
        tx_ext.clone(),
    );

    // call_weight & call_weight_to_fee
    let call_weight = call.clone().get_dispatch_info().call_weight;
    let call_weight_to_fee =
        <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&call_weight);

    // base weight & weight_to_fee
    let block_weights: frame_system::limits::BlockWeights =
        <Test as frame_system::Config>::BlockWeights::get();
    let base_extrinsic =
        block_weights.get(frame_support::dispatch::DispatchClass::Normal).base_extrinsic;
    let base_weight_to_fee =
        <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&base_extrinsic);

    // proof_size & proof_size_to_fee
    let proof_size = uxt.clone().encode().len() as u64;
    let proof_size_to_fee =
        <Test as pallet_transaction_payment::Config>::LengthToFee::weight_to_fee(
            &frame_support::weights::Weight::from_parts(proof_size, 0),
        );

    let extension_weight = tx_ext.weight(&final_call);
    let extension_weight_weight_to_fee =
        <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&extension_weight);
    let total_fee = call_weight_to_fee + base_weight_to_fee + proof_size_to_fee + extension_weight_weight_to_fee;

    new_test_ext().execute_with(|| {
        // Set jwk from root
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        // Set block number to ensure key is not expired
        System::set_block_number(10);

        // Test successful execution
        let result = MockExecutive::apply_extrinsic(uxt).unwrap();
        assert_ok!(result);

        // Verify transfer was successful
        assert_eq!(Balances::free_balance(&dest), 100);
        assert_eq!(Balances::free_balance(&zk_address()), INIT_BALANCE - total_fee - 100);
    });
}
// ================================ test proxy should work ================================
#[test]
fn validate_add_proxy_should_work() {
    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);

    let signing_key: ed25519::Pair = get_test_eph_key();

    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let kids = google::kids(true);
    let kid = kids[0].clone();

    let zk_material = ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // construct Proxy Call
    let delegator = AccountId::from(address_seed.0);
    let delegatee = AccountId::from([2u8; 32]);
    // construct Proxy Call(which set the `delegatee` as the proxy)
    let proxy_call: RuntimeCall = pallet_proxy::Call::add_proxy {
        delegate: sp_runtime::MultiAddress::Id(delegatee.clone()),
        proxy_type: (),
        delay: 0u32,
    }
    .into();
    // TODO need to ensure how proxy used at here
    // construct submit_zklogin call with inner proxy_call
    let final_call: RuntimeCall = ZkLoginCall::submit_zklogin {
        call: Box::new(proxy_call),
        address_seed: address_seed.into(),
        zk_material,
    }.into();

    // construct UncheckedExtrinsic using `TxExtension``
    // Create signed payload
    let signing_key: ed25519::Pair = get_test_eph_key();
    let tx_ext: TxExtension = (
        super::ZkLoginExtension::<Test>::new(),
        frame_system::CheckNonce::<Test>::from(0),
        frame_system::CheckWeight::<Test>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::from(0),
    );
    let sign = SignedPayload::new(final_call.clone(), tx_ext.clone()).expect("payload should succeed").using_encoded(|d| signing_key.sign(d));

    let outer_uxt = UncheckedExtrinsic::<
        MultiAddress<AccountId, ()>,
        RuntimeCall,
        MultiSignature,
        TxExtension,
    >::new_signed(final_call.clone(),       AccountId::from(signing_key.public()).into(),
                  MultiSignature::from(sign),
                  tx_ext.clone(),
    );
    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        System::set_block_number(10);

        // check the proxy is not set
        let proxies = pallet_proxy::Proxies::<Test>::get(&delegator);
        assert!(!proxies.0.iter().any(|def| def.delegate == delegatee));

        assert_ok!(MockExecutive::apply_extrinsic(outer_uxt));

        // check the proxy is set successfully
        let proxies = pallet_proxy::Proxies::<Test>::get(&delegator);
        assert!(proxies.0.iter().any(|def| def.delegate == delegatee));
    });
}

#[test]
fn validate_proxy_call_should_work() {
    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);

    let signing_key: ed25519::Pair = get_test_eph_key();

    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let kids = google::kids(true);
    let kid = kids[0].clone();

    let zk_material = ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // construct Proxy Call
    let delegator = AccountId::from(address_seed.0);
    let delegatee_pair: ed25519::Pair = ed25519::Pair::from_seed(&[1u8; 32]);
    let account = delegatee_pair.public();
    let delegatee: AccountId = account.into();

    // construct Proxy Call(which set the `delegatee` as the proxy)
    let proxy_call: RuntimeCall = pallet_proxy::Call::add_proxy {
        delegate: sp_runtime::MultiAddress::Id(delegatee.clone()),
        proxy_type: (),
        delay: 0u32,
    }
    .into();

    // construct submit_zklogin call with inner proxy_call
    let final_call: RuntimeCall = ZkLoginCall::submit_zklogin {
        call: Box::new(proxy_call),
        address_seed: address_seed.into(),
        zk_material,
    }.into();

    // Create signed payload
    let tx_ext: TxExtension = (
        super::ZkLoginExtension::<Test>::new(),
        frame_system::CheckNonce::<Test>::from(0),
        frame_system::CheckWeight::<Test>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::from(0),
    );
    let sign = SignedPayload::new(final_call.clone(), tx_ext.clone()).expect("payload should succeed").using_encoded(|d| signing_key.sign(d));

    // construct outer UncheckedExtrinsic using `TxExtension``
    let outer_uxt = UncheckedExtrinsic::<
        MultiAddress<AccountId, ()>,
        RuntimeCall,
        MultiSignature,
        TxExtension,
    >::new_signed(final_call.clone(), AccountId::from(signing_key.public()).into(), MultiSignature::from(sign), tx_ext.clone());

    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        System::set_block_number(10);

        // check the proxy is not set
        let proxies = pallet_proxy::Proxies::<Test>::get(&delegator);
        assert!(!proxies.0.iter().any(|def| def.delegate == delegatee));

        assert_ok!(MockExecutive::apply_extrinsic(outer_uxt));

        // check the proxy is set successfully
        let proxies = pallet_proxy::Proxies::<Test>::get(&delegator);
        assert!(proxies.0.iter().any(|def| def.delegate == delegatee));

        // Before the proxy execute call, we need to give the `delegatee` some balance to pay the fee
        let _ = Balances::deposit_creating(&delegatee, INIT_BALANCE);

        // transfer 100 from delegator to delegatee through proxy
        let before_delegatee = Balances::free_balance(&delegatee);
        let before_delegator = Balances::free_balance(&delegator);

        // construct the transfer call(which transfer 100 from delegator to delegatee through proxy)
        let transfer_call: RuntimeCall = BalancesCall::transfer_keep_alive {
            dest: MultiAddress::Id(delegatee.clone()),
            value: 100,
        }
        .into();
        let proxy_call = pallet_proxy::Call::<Test>::proxy {
            real: sp_runtime::MultiAddress::Id(delegator.clone()),
            force_proxy_type: None,
            call: Box::new(transfer_call),
        };
        // construct the outer UncheckedExtrinsic using `TxExtension``
        let tx_ext = (
            super::ZkLoginExtension::<Test>::new(),
            frame_system::CheckNonce::<Test>::from(0),
            frame_system::CheckWeight::new(),
            pallet_transaction_payment::ChargeTransactionPayment::from(0),
        );
        let payload = SignedPayload::new(proxy_call.clone().into(), tx_ext.clone())
            .expect("payload should succeed");
        let sign = payload.using_encoded(|d| delegatee_pair.sign(d));

        let proxy_extrinsic = MockUncheckedExtrinsic::new_signed(
            proxy_call.clone().into(),
            delegatee.clone().into(),
            MultiSignature::from(sign),
            tx_ext.clone(),
        );

        // calculate the `call_weight` & `call_weight_to_fee`
        let call_weight = proxy_call.clone().get_dispatch_info().call_weight;
        let call_weight_to_fee =
            <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&call_weight);

        // calculate the `base weight` & `weight_to_fee`
        let block_weights: frame_system::limits::BlockWeights =
            <Test as frame_system::Config>::BlockWeights::get();
        let base_extrinsic =
            block_weights.get(frame_support::dispatch::DispatchClass::Normal).base_extrinsic;
        let base_weight_to_fee =
            <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(
                &base_extrinsic,
            );

        // calculate the `proof_size` & `proof_size_to_fee`
        let proof_size = proxy_extrinsic.encode().len() as u64;
        let proof_size_to_fee =
            <Test as pallet_transaction_payment::Config>::LengthToFee::weight_to_fee(
                &frame_support::weights::Weight::from_parts(proof_size, 0),
            );

        let extension_weight = tx_ext.weight(&proxy_call.clone().into());
        let extension_weight_weight_to_fee =
            <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&extension_weight);
        let total_fee = call_weight_to_fee + base_weight_to_fee + proof_size_to_fee + extension_weight_weight_to_fee;

        // execute the proxy call
        assert_ok!(MockExecutive::apply_extrinsic(proxy_extrinsic));

        // check the balance of the delegatee and delegator after the transfer
        let after_delegatee = Balances::free_balance(&delegatee);
        let after_delegator = Balances::free_balance(&delegator);

        // the balance of the delegatee should be deducted the `total_fee` and the `transfer amount`
        assert_eq!(after_delegatee, before_delegatee - total_fee + 100);
        // the balance of the delegator should be deducted the `transfer amount`
        assert_eq!(after_delegator, before_delegator - 100);
    });
}

#[test]
fn validate_remove_proxy_should_work() {
    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);

    let signing_key: ed25519::Pair = get_test_eph_key();

    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let kids = google::kids(true);
    let kid = kids[0].clone();

    let zk_material: primitive_zklogin::VersionedZkMaterial<u64> =
        ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // construct Proxy Call(which set the `delegatee` as the proxy)
    let delegator = AccountId::from(address_seed.0);
    let delegatee = AccountId::from([2u8; 32]);
    let proxy_call: RuntimeCall = pallet_proxy::Call::add_proxy {
        delegate: sp_runtime::MultiAddress::Id(delegatee.clone()),
        proxy_type: (),
        delay: 0u32,
    }
    .into();

    // construct submit_zklogin call with inner proxy_call
    let final_call: RuntimeCall = ZkLoginCall::submit_zklogin {
        call: Box::new(proxy_call),
        address_seed: address_seed.clone().into(),
        zk_material: zk_material.clone(),
    }.into();

    // Create signed payload
    let tx_ext: TxExtension = (
        super::ZkLoginExtension::<Test>::new(),
        frame_system::CheckNonce::<Test>::from(0),
        frame_system::CheckWeight::<Test>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::from(0),
    );
    let sign = SignedPayload::new(final_call.clone(), tx_ext.clone()).expect("payload should succeed").using_encoded(|d| signing_key.sign(d));

    // construct outer UncheckedExtrinsic using `TxExtension``
    let outer_uxt = UncheckedExtrinsic::<
        MultiAddress<AccountId, ()>,
        RuntimeCall,
        MultiSignature,
        TxExtension,
    >::new_signed(final_call.clone(), AccountId::from(signing_key.public()).into(), MultiSignature::from(sign), tx_ext.clone());

    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        System::set_block_number(10);

        // check the proxy is not set
        let proxies = pallet_proxy::Proxies::<Test>::get(&delegator);
        assert!(!proxies.0.iter().any(|def| def.delegate == delegatee));

        assert_ok!(MockExecutive::apply_extrinsic(outer_uxt));

        // check the proxy is set successfully
        let proxies = pallet_proxy::Proxies::<Test>::get(&delegator);
        assert!(proxies.0.iter().any(|def| def.delegate == delegatee));

        // remove proxy call (which remove the `delegatee` as the proxy)
        let remove_proxy_call: RuntimeCall = pallet_proxy::Call::remove_proxy {
            delegate: sp_runtime::MultiAddress::Id(delegatee.clone()),
            proxy_type: (),
            delay: 0u32,
        }
        .into();

        // construct submit_zklogin call with inner remove_proxy_call
        let final_call: RuntimeCall = ZkLoginCall::submit_zklogin {
            call: Box::new(remove_proxy_call),
            address_seed: address_seed.into(),
            zk_material,
        }.into();

        // Create signed payload
        let signing_key: ed25519::Pair = get_test_eph_key();
        let tx_ext: TxExtension = (
            super::ZkLoginExtension::<Test>::new(),
            frame_system::CheckNonce::<Test>::from(1),
            frame_system::CheckWeight::<Test>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::from(0),
        );
        let sign = SignedPayload::new(final_call.clone(), tx_ext.clone()).expect("payload should succeed").using_encoded(|d| signing_key.sign(d));

        // construct outer UncheckedExtrinsic using `TxExtension``
        let outer_uxt = UncheckedExtrinsic::<
            MultiAddress<AccountId, ()>,
            RuntimeCall,
            MultiSignature,
            TxExtension,
        >::new_signed(final_call.clone(), AccountId::from(signing_key.public()).into(), MultiSignature::from(sign), tx_ext.clone());
        assert_ok!(MockExecutive::apply_extrinsic(outer_uxt));
        let proxies = pallet_proxy::Proxies::<Test>::get(&delegator);
        assert!(!proxies.0.iter().any(|def| def.delegate == delegatee));
    });
}

// ================================ test recovery should work ================================
#[test]
fn validate_create_recovery_should_work() {
    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);

    let signing_key: ed25519::Pair = get_test_eph_key();

    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let kids = google::kids(true);
    let kid = kids[0].clone();

    let zk_material = ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // construct Recovery Call(which create the recovery config) with 3 friends and threshold 1
    let recoverable_account = AccountId::from(address_seed.0);
    let friends =
        vec![AccountId::from([1u8; 32]), AccountId::from([2u8; 32]), AccountId::from([3u8; 32])];
    let threshold = 1u16;
    let delay_period = 0u32;

    let recovery_call: RuntimeCall = pallet_recovery::Call::create_recovery {
        friends: friends.clone(),
        threshold,
        delay_period,
    }
    .into();

    // construct submit_zklogin call with inner recovery_call
    let final_call: RuntimeCall = ZkLoginCall::submit_zklogin {
        call: Box::new(recovery_call),
        address_seed: address_seed.into(),
        zk_material,
    }.into();

    // Create signed payload
    let tx_ext: TxExtension = (
        super::ZkLoginExtension::<Test>::new(),
        frame_system::CheckNonce::<Test>::from(0),
        frame_system::CheckWeight::<Test>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::from(0),
    );
    let sign = SignedPayload::new(final_call.clone(), tx_ext.clone()).expect("payload should succeed").using_encoded(|d| signing_key.sign(d));

    // construct outer UncheckedExtrinsic using `TxExtension``
    let outer_uxt = UncheckedExtrinsic::<
        MultiAddress<AccountId, ()>,
        RuntimeCall,
        MultiSignature,
        TxExtension,
    >::new_signed(final_call.clone(), AccountId::from(signing_key.public()).into(), MultiSignature::from(sign), tx_ext.clone());

    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        System::set_block_number(10);

        // Check that recovery config doesn't exist before
        assert!(pallet_recovery::Recoverable::<Test>::get(&recoverable_account).is_none());

        assert_ok!(MockExecutive::apply_extrinsic(outer_uxt));

        // Check that recovery config is created
        assert!(pallet_recovery::Recoverable::<Test>::get(&recoverable_account).is_some());
    });
}

#[test]
fn validate_complete_recovery_flow_should_work() {
    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);

    let signing_key: ed25519::Pair = get_test_eph_key();

    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let kids = google::kids(true);
    let kid = kids[0].clone();

    let zk_material: primitive_zklogin::VersionedZkMaterial<u64> =
        ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // Setup accounts
    let lost_account = AccountId::from(address_seed.0); // zk account
    let rescuer_account = AccountId::from([5u8; 32]); // rescuer account
    let friend1 = AccountId::from([1u8; 32]); // friend1 account
    let friend2 = AccountId::from([2u8; 32]); // friend2 account
    let friend3 = AccountId::from([3u8; 32]); // friend3 account
    let friends = vec![friend1.clone(), friend2.clone(), friend3.clone()];
    let threshold = 1u16;
    let delay_period = 0u32;

    // Step 1: Lost account creates recovery config using zk account
    let create_recovery_call: RuntimeCall = pallet_recovery::Call::create_recovery {
        friends: friends.clone(),
        threshold,
        delay_period,
    }
    .into();

    // construct submit_zklogin call with inner create_recovery_call
    let create_final_call: RuntimeCall = ZkLoginCall::submit_zklogin {
        call: Box::new(create_recovery_call),
        address_seed: address_seed.clone().into(),
        zk_material: zk_material.clone(),
    }.into();

    // Create signed payload
    let tx_ext: TxExtension = (
        super::ZkLoginExtension::<Test>::new(),
        frame_system::CheckNonce::<Test>::from(0),
        frame_system::CheckWeight::<Test>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::from(0),
    );
    let sign = SignedPayload::new(create_final_call.clone(), tx_ext.clone()).expect("payload should succeed").using_encoded(|d| signing_key.sign(d));

    let create_uxt = UncheckedExtrinsic::<
        MultiAddress<AccountId, ()>,
        RuntimeCall,
        MultiSignature,
        TxExtension,
    >::new_signed(create_final_call.clone(), AccountId::from(signing_key.public()).into(), MultiSignature::from(sign), tx_ext.clone());

    // calculate the `call_weight` & `call_weight_to_fee`
    let call_weight = create_final_call.clone().get_dispatch_info().call_weight;
    let call_weight_to_fee =
        <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&call_weight);

    // calculate the `base weight` & `weight_to_fee`
    let block_weights: frame_system::limits::BlockWeights =
        <Test as frame_system::Config>::BlockWeights::get();
    let base_extrinsic =
        block_weights.get(frame_support::dispatch::DispatchClass::Normal).base_extrinsic;
    let base_weight_to_fee =
        <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&base_extrinsic);

    // calculate the `proof_size` & `proof_size_to_fee`
    let proof_size = create_uxt.clone().encode().len() as u64;
    let proof_size_to_fee =
        <Test as pallet_transaction_payment::Config>::LengthToFee::weight_to_fee(
            &frame_support::weights::Weight::from_parts(proof_size, 0),
        );

    let extension_weight = tx_ext.weight(&create_final_call);
    let extension_weight_weight_to_fee =
        <Test as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&extension_weight);
    let total_fee = call_weight_to_fee + base_weight_to_fee + proof_size_to_fee + extension_weight_weight_to_fee;

    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        System::set_block_number(10);

        // Step 1: Create recovery config using zk account
        assert_ok!(MockExecutive::apply_extrinsic(create_uxt));
        let recoverable = pallet_recovery::Recoverable::<Test>::get(&lost_account);
        assert!(recoverable.is_some());

        // Step 2: Rescuer initiates recovery using regular account
        let initiate_recovery_call: RuntimeCall = pallet_recovery::Call::initiate_recovery {
            account: sp_runtime::MultiAddress::Id(lost_account.clone()),
        }
        .into();

        assert_ok!(initiate_recovery_call
            .dispatch_bypass_filter(RawOrigin::Signed(rescuer_account.clone()).into()));
        let active =
            pallet_recovery::ActiveRecoveries::<Test>::get(&lost_account, &rescuer_account);
        assert!(active.is_some());

        // Step 3: Friend vouches for recovery
        let vouch_recovery_call: RuntimeCall = pallet_recovery::Call::vouch_recovery {
            lost: sp_runtime::MultiAddress::Id(lost_account.clone()),
            rescuer: sp_runtime::MultiAddress::Id(rescuer_account.clone()),
        }
        .into();

        // Before the rescuer initiate recovery, we need to give the `rescuer` and `friend1` some balance to pay the fee
        let _ = Balances::deposit_creating(&rescuer_account, INIT_BALANCE);
        let _ = Balances::deposit_creating(&friend1, INIT_BALANCE);

        assert_ok!(
            vouch_recovery_call.dispatch_bypass_filter(RawOrigin::Signed(friend1.clone()).into())
        );

        // Step 4: Wait for delay period before claiming recovery
        System::set_block_number(10 + delay_period);

        // Step 5: Rescuer claims recovery
        let claim_recovery_call: RuntimeCall = pallet_recovery::Call::claim_recovery {
            account: sp_runtime::MultiAddress::Id(lost_account.clone()),
        }
        .into();
        assert_ok!(claim_recovery_call
            .dispatch_bypass_filter(RawOrigin::Signed(rescuer_account.clone()).into()));
        let proxy = pallet_recovery::Proxy::<Test>::get(&rescuer_account);
        assert!(proxy.is_some());

        // Step 6: Rescuer uses as_recovered to transfer funds from lost account
        let dest_account = AccountId::from([10u8; 32]);
        let transfer_call: RuntimeCall = BalancesCall::transfer_keep_alive {
            dest: MultiAddress::Id(dest_account.clone()),
            value: 100,
        }
        .into();

        let as_recovered_call: RuntimeCall = pallet_recovery::Call::as_recovered {
            account: sp_runtime::MultiAddress::Id(lost_account.clone()),
            call: Box::new(transfer_call),
        }
        .into();

        // check the balance of the destination account before the transfer
        assert_eq!(Balances::free_balance(&dest_account), 0);

        assert_ok!(as_recovered_call
            .dispatch_bypass_filter(RawOrigin::Signed(rescuer_account.clone()).into()));

        // Verify transfer was successful
        assert_eq!(Balances::free_balance(&dest_account), 100);

        // check the balance of the zk_address after the transfer
        // balance should init_balance deducting the `fee` and `the transfer amount` when doing the `create_recovery` call)
        assert_eq!(Balances::free_balance(&zk_address()), INIT_BALANCE - total_fee - 100);
    });
}

fn header_from_number(n: u32) -> sp_runtime::generic::Header<u32, BlakeTwo256> {
    sp_runtime::generic::Header {
        number: n,
        parent_hash: Default::default(),
        extrinsics_root: Default::default(),
        state_root: Default::default(),
        digest: Default::default(),
    }
}
