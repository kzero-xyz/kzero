use crate::{Call as ZkLoginCall, Pallet};
use frame_executive::Executive;
use frame_support::{
    assert_ok, derive_impl, dispatch::RawOrigin, pallet_prelude::TypeInfo, parameter_types,
    traits::UnfilteredDispatchable,
};
use pallet_balances::Call as BalancesCall;
use primitive_zklogin::{
    test_helper::{get_raw_data, get_test_eph_key, get_zklogin_inputs, test_cases::google},
    JwkProvider, ZkMaterialV1,
};
use scale_codec::{Decode, Encode};
use sp_core::{ed25519, Pair};
use sp_runtime::{
    generic,
    generic::{CheckedExtrinsic, UncheckedExtrinsic},
    traits::{BlakeTwo256, DispatchInfoOf, IdentifyAccount, SignedExtension, Verify},
    transaction_validity::TransactionValidityError,
    BuildStorage, MultiAddress, MultiSignature,
};

/// An index to a block.
pub type BlockNumber = u32;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
type Context = frame_system::ChainContext<Test>;
pub type Signature = MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Address = MultiAddress<AccountId, ()>;
type MockUncheckedExtrinsic = UncheckedExtrinsic<Address, RuntimeCall, MultiSignature, MockExtra>;
type MockCheckedExtrinsic = CheckedExtrinsic<AccountId, RuntimeCall, MockExtra>;

pub type SignedPayload = generic::SignedPayload<RuntimeCall, MockExtra>;

type Block = generic::Block<Header, MockUncheckedExtrinsic>;

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, TypeInfo)]
pub struct MockExtra;

impl SignedExtension for MockExtra {
    const IDENTIFIER: &'static str = "MockExtra";
    type AccountId = AccountId;
    type Call = RuntimeCall;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
        Ok(())
    }

    fn pre_dispatch(
        self,
        _who: &Self::AccountId,
        _call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        Ok(())
    }
}

type MockExecutive = Executive<Test, Block, Context, Test, AllPalletsWithSystem, ()>;

frame_support::construct_runtime!(
    pub enum Test
    {
        System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
        Timestamp: pallet_timestamp,
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        ZkLogin: super::{Pallet, Call, Event<T>, ValidateUnsigned},
    }
);

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

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
{
    type OverarchingCall = RuntimeCall;
    type Extrinsic = MockUncheckedExtrinsic;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

impl super::Config for Test {
    type AuthorityId = crate::crypto::ZkLoginAuthId;
    type RuntimeEvent = RuntimeEvent;
    type Context = Context;
    type Extrinsic = MockUncheckedExtrinsic;
    type CheckedExtrinsic = MockCheckedExtrinsic;
    type UnsignedValidator = Test;
    type Time = Timestamp;
    type MaxKeys = MaxKeys;
}

fn zk_address() -> AccountId {
    let (zklogin_address, ..) = get_raw_data();
    zklogin_address
}

// This function basically just builds a genesis storage key/value store according to
// our desired mockup.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    // We use default for brevity, but you can configure as desired if needed.
    pallet_balances::GenesisConfig::<Test> {
        // give `zk_address` an initial value of 1000
        balances: vec![(zk_address(), 1000)],
    }
    .assimilate_storage(&mut t)
    .unwrap();
    t.into()
}

#[test]
fn basic_setup_works() {
    new_test_ext().execute_with(|| {
        assert_eq!(System::account(&zk_address()).data.free, 1000);
    })
}

// ================================ validate_unsigned ================================
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

    let payload = SignedPayload::new(call.clone(), MockExtra).expect("payload should succeed");
    let sign = payload.using_encoded(|d| signing_key.sign(d));

    // construct inner unchecked_extrinsic
    let uxt = MockUncheckedExtrinsic::new_signed(
        call,
        AccountId::from(signing_key.public()).into(),
        MultiSignature::from(sign),
        MockExtra,
    );

    let final_call = ZkLoginCall::submit_zklogin_unsigned {
        uxt: Box::new(uxt),
        address_seed: address_seed.into(),
        zk_material,
    };

    let outer_uxt = UncheckedExtrinsic::<
        MultiAddress<AccountId, ()>,
        RuntimeCall,
        MultiSignature,
        MockExtra,
    >::new_unsigned(final_call.clone().into());

    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        // the eph key's expiration at 834, make sure current number is smaller.
        System::set_block_number(10);
        assert!(Pallet::<Test>::validate_unsigned(source, &final_call).is_ok());

        // execute through call.dispatch
        assert_ok!(final_call.dispatch_bypass_filter(RawOrigin::None.into()));
        // deduct 100 from zk_address
        assert_eq!(Balances::free_balance(&zk_address(),), 900);
        // transfer success
        assert_eq!(Balances::free_balance(&dest), 100);

        // execute through `apply_extrinsic`
        assert_ok!(MockExecutive::apply_extrinsic(outer_uxt));
        // deduct 100 from zk_address
        assert_eq!(Balances::free_balance(&zk_address(),), 800);
        // transfer success
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
    let jwks = google::GOOGLE_JWK_JSON_LIST[1];
    let kids = google::kids(true);
    let kid = kids[0].clone();

    let zk_material = ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // construct Transfer Call
    let dest = AccountId::from([0u8; 32]);
    let call: RuntimeCall =
        BalancesCall::transfer_keep_alive { dest: MultiAddress::Id(dest.clone()), value: 100 }
            .into();

    let payload = SignedPayload::new(call.clone(), MockExtra).expect("payload should succeed");
    let sign = payload.using_encoded(|d| signing_key.sign(d));

    // construct inner unchecked_extrinsic
    let uxt = MockUncheckedExtrinsic::new_signed(
        call,
        AccountId::from(signing_key.public()).into(),
        MultiSignature::from(sign),
        MockExtra,
    );

    let final_call = ZkLoginCall::submit_zklogin_unsigned {
        uxt: Box::new(uxt),
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

// ================================ jwk parse tests ================================
#[test]
fn test_parse_jwk_success() {
    use crate::jwk::parse_jwk;
    // Test a valid JWK
    let valid_jwk = r#"{
        "kid": "test_key",
        "kty": "RSA",
        "n": "test_n",
        "e": "AQAB",
        "alg": "RS256",
        "use": "sig"
    }"#;

    let result = parse_jwk::<Test>(valid_jwk.as_bytes());
    assert!(result.is_ok());

    let jwk = result.unwrap();
    assert_eq!(jwk.common.key_id, Some("test_key".to_string()));
    assert_eq!(jwk.common.key_algorithm, Some(jsonwebtoken::jwk::KeyAlgorithm::RS256));
}

#[test]
fn test_parse_jwk_invalid_json() {
    use crate::jwk::parse_jwk;
    use crate::pallet::Error;
    // Set log level to error to suppress error messages
    log::set_max_level(log::LevelFilter::Error);

    // Test invalid JSON format
    let invalid_json = r#"{
        "kid": "test_key",
        "kty": "RSA",
        "n": "test_n",
        "e": "AQAB",
        "alg": "RS256",
        "use": "sig",
        // Missing closing brace
    "#;

    let result = parse_jwk::<Test>(invalid_json.as_bytes());
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::<Test>::InvalidJwkJson));
}

#[test]
fn test_parse_jwk_missing_required_fields() {
    use crate::jwk::parse_jwk;
    use crate::pallet::Error;
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
    assert!(jwk.common.key_id.is_some());
    assert_eq!(jwk.common.key_id.as_ref().unwrap(), "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781");
    assert_eq!(jwk.common.key_algorithm, Some(jsonwebtoken::jwk::KeyAlgorithm::RS256));
}

// ================================ offchain worker tests ================================
#[test]
fn test_fetch_jwks() {
    use crate::offchain_worker::fetch_jwks;
    use primitive_zklogin::JwkProvider;
    use sp_core::offchain::testing::PendingRequest;
    use sp_core::offchain::{testing::TestOffchainExt, OffchainDbExt, OffchainWorkerExt};
    use sp_io::TestExternalities;

    // Create test externalities with offchain worker context
    let (offchain, state) = TestOffchainExt::new();
    let mut t = TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain.clone()));
    t.register_extension(OffchainDbExt::new(offchain));
    // Create a valid JWK response
    let mock_jwks_response = r#"{"keys":[{"kid":"test_key","kty":"RSA","n":"test_n","e":"AQAB","alg":"RS256","use":"sig"}]}"#;
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
fn test_check_jwk_not_onchain() {
    use crate::offchain_worker::check_jwk_not_onchain;
    use primitive_zklogin::{Jwk, JwkProvider};

    // Set up test data
    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let jwk: Jwk = serde_json::from_str(jwks).unwrap();

    // Test case 1: JWK not on chain
    let result = check_jwk_not_onchain(provider, &jwk, |_, _| None);
    assert_eq!(result, Some(true));

    // Test case 2: JWK exists on chain with same content
    let result = check_jwk_not_onchain(provider, &jwk, |_, _| Some(jwk.clone()));
    assert_eq!(result, Some(false));

    // Test case 3: JWK exists on chain with different content
    let mut different_jwk = jwk.clone();
    different_jwk.common.key_id = Some("different".to_string());
    let result = check_jwk_not_onchain(provider, &jwk, |_, _| Some(different_jwk.clone()));
    assert_eq!(result, Some(true));
}

#[test]
fn test_set_jwk() {
    use crate::pallet::Error;
    use frame_support::assert_noop;
    use primitive_zklogin::Jwk;
    use primitive_zklogin::{test_helper::test_cases::google, JwkProvider};
    use sp_runtime::DispatchError;

    let valid_jwk = google::GOOGLE_JWK_JSON_LIST[0];
    let provider = JwkProvider::Google;
    let jwk: Jwk = serde_json::from_str(valid_jwk).unwrap();
    let kid = jwk.common.key_id.as_ref().unwrap().as_bytes();

    let mut ext = new_test_ext();
    ext.execute_with(|| {
        // Set log level to error to suppress error messages
        log::set_max_level(log::LevelFilter::Off);

        // Check that JWK doesn't exist before setting
        assert!(crate::Jwks::<Test>::get(provider, kid).is_none());

        // Test valid JWK setting by root
        assert_ok!(ZkLogin::set_jwk(
            RawOrigin::Root.into(),
            provider,
            valid_jwk.as_bytes().to_vec()
        ));

        // Check that JWK exists after setting
        let stored_jwk = crate::Jwks::<Test>::get(provider, kid).unwrap();
        assert_eq!(
            stored_jwk.common.key_id.as_ref().unwrap(),
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
    use frame_support::assert_noop;
    use frame_support::assert_ok;
    use sp_core::ed25519;
    use sp_runtime::DispatchError;
    use sp_runtime::MultiSigner;

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

// ================================ testsubmit_jwks_unsigned ================================
#[test]
fn test_submit_jwks_unsigned() {
    use crate::JwksPayload;
    use frame_support::assert_noop;
    use primitive_zklogin::{Jwk, JwkProvider};
    use sp_core::ed25519;
    use sp_runtime::DispatchError;
    use sp_runtime::MultiSigner;

    // Set log level to off to suppress error messages
    log::set_max_level(log::LevelFilter::Off);

    // Generate test keys
    let (key1, _) = ed25519::Pair::generate();

    // Create test JWKs
    let jwk1 = r#"{
        "kid": "test_key1",
        "kty": "RSA",
        "n": "test_n1",
        "e": "AQAB",
        "alg": "RS256",
        "use": "sig"
    }"#;
    let jwk2 = r#"{
        "kid": "test_key2",
        "kty": "RSA",
        "n": "test_n2",
        "e": "AQAB",
        "alg": "RS256",
        "use": "sig"
    }"#;

    let jwk1: Jwk = serde_json::from_str(jwk1).unwrap();
    let jwk2: Jwk = serde_json::from_str(jwk2).unwrap();

    new_test_ext().execute_with(|| {
        // Create payload with multiple JWKs
        let payload = JwksPayload {
            public: MultiSigner::Ed25519(key1.public()),
            jwks: vec![
                (JwkProvider::Google, vec![jwk1.clone()]),
                (JwkProvider::Apple, vec![jwk2.clone()]),
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
        let kid1 = jwk1.common.key_id.as_ref().unwrap().as_bytes();
        let kid2 = jwk2.common.key_id.as_ref().unwrap().as_bytes();
        assert!(crate::Jwks::<Test>::get(JwkProvider::Google, kid1).is_some());
        assert!(crate::Jwks::<Test>::get(JwkProvider::Apple, kid2).is_some());

        // Test invalid origin (must be None)
        assert_noop!(
            ZkLogin::submit_jwks_unsigned(RawOrigin::Root.into(), payload.clone(), signature),
            DispatchError::BadOrigin
        );
    });
}

// ================================ submit_zklogin_unsigned test ================================
#[test]
fn test_submit_zklogin_unsigned() {
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

    // Create signed payload
    let signing_key: ed25519::Pair = get_test_eph_key();
    let payload = SignedPayload::new(call.clone(), MockExtra).expect("payload should succeed");
    let sign = payload.using_encoded(|d| signing_key.sign(d));

    // Create unchecked extrinsic
    let uxt = MockUncheckedExtrinsic::new_signed(
        call,
        AccountId::from(signing_key.public()).into(),
        MultiSignature::from(sign),
        MockExtra,
    );

    let final_call: ZkLoginCall<Test> = ZkLoginCall::submit_zklogin_unsigned {
        uxt: Box::new(uxt),
        address_seed: address_seed.into(),
        zk_material,
    };

    new_test_ext().execute_with(|| {
        // Set jwk from root
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        // Set block number to ensure key is not expired
        System::set_block_number(10);

        // Test successful submission
        assert_ok!(final_call.clone().dispatch_bypass_filter(RawOrigin::None.into()));

        // Verify transfer was successful
        assert_eq!(Balances::free_balance(&dest), 100);
        assert_eq!(Balances::free_balance(&zk_address()), 900);

        // Test invalid origin (must be None)
        assert_noop!(
            final_call.clone().dispatch_bypass_filter(RawOrigin::Root.into()),
            DispatchError::BadOrigin
        );
    });
}
