#![cfg(feature = "runtime-benchmarks")]

use primitive_zklogin::{
    BigNumber, Claim, ZkLoginInputs, ZkLoginProof, JwkProvider, ZkMaterialV1,
};
use num_bigint::BigUint;
use sp_core::{ed25519, H256, U256};
use sp_io::crypto::ed25519_generate;
use sp_runtime::BoundedVec;
use sp_std::{vec, vec::Vec};

/// JWK data for benchmark testing
pub struct BenchmarkJwks;

impl BenchmarkJwks {
    /// Get JWK JSON string for set_jwk test
    pub fn set_jwk_json() -> &'static str {
        r#"{
            "kty": "RSA",
            "e": "AQAB",
            "kid": "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781",
            "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
            "alg": "RS256"
        }"#
    }

    /// Get default JwkProvider
    pub fn default_provider() -> JwkProvider {
        JwkProvider::Google
    }

    /// Generate test JWKs for submit_jwks_unsigned benchmark with specified count
    /// Returns Vec<(JwkProvider, Vec<Vec<u8>>)> as expected by JwksPayload
    pub fn generate_test_jwks(count: u32) -> Vec<(JwkProvider, Vec<Vec<u8>>)> {
        // Use valid JWK JSON from test_helper for Google
        let google_jwk = r#"{
            "kty": "RSA",
            "e": "AQAB",
            "kid": "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781",
            "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
            "alg": "RS256"
        }"#;
        // Use a valid Apple JWK format (similar structure)
        let apple_jwk = r#"{
            "kty": "RSA",
            "e": "AQAB",
            "kid": "test_apple_kid_12345",
            "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
            "alg": "RS256"
        }"#;
        
        let mut jwks = Vec::new();
        for i in 0..count {
            let provider = if i % 2 == 0 { JwkProvider::Google } else { JwkProvider::Apple };
            let jwk_json = if i % 2 == 0 { google_jwk } else { apple_jwk };
            jwks.push((provider, vec![jwk_json.as_bytes().to_vec()]));
        }
        jwks
    }
}

/// Key data for benchmark testing
pub struct BenchmarkKeys;

impl BenchmarkKeys {
    /// Get key seeds index for update_keys test
    pub fn key_seeds() -> [u32; 10] {
        // Generate seeds from 0 to 999
        let mut seeds = [0u32; 10];
        for i in 0..10 {
            seeds[i] = i as u32;
        }
        seeds
    }

    /// Generate test keys for update_keys benchmark with specified count
    pub fn generate_test_keys<T>(count: u32) -> Vec<(T::Public, bool)>
    where
        T: frame_system::offchain::SigningTypes,
        T::Public: From<ed25519::Public>,
    {
        let seeds = Self::key_seeds();
        let mut keys = Vec::new();

        for i in 0..count {
            let seed = seeds[i as usize];
            let key = ed25519_generate(seed.into(), None);
            keys.push((T::Public::from(key), true));
        }

        keys
    }
}

/// ZkLogin data for benchmark testing
pub struct BenchmarkZkLogin;

impl BenchmarkZkLogin {
    /// Get test proof data for submit_zklogin benchmark
    /// This uses the same proof data from test_helper.rs
    pub fn get_proof_data() -> &'static str {
        r#"{
            "proof_points": {
                "a": [
                "9381813773171450462648323179981700992482234003937252912184366692176647122440",
                "17135816274588842394987740577348746744124536487185243735653495512098467176682",
                "1"
                ],
                "b": [
                [
                "12007654400896864202053137919011753862685795325094057089804209969395451364237",
                "9292143971825249679511504837978464260231784546642825774684216241262448276692"
                ],
                [
                "2739509173985286250590833064309803350595900462807230565709419062550672100574",
                "9617502836905847049711738720668642526073457745474007398904997426591688823762"
                ],
                [
                "1",
                "0"
                ]
                ],
                "c": [
                "4236607764644869062435426868625747082828648484430168905284460458292661376562",
                "13765193476064868657640379803797505779241026862161166609423648103540137745710",
                "1"
                ]
            },
            "iss_base64_details": {
                "value" : "17369902616279740791204861702455537230599532803600308871388405295273096679389",
                "index_mod_4": 1
            },
            "header": "913143068733459984664279033783989157259274322902058410967852973431920544493"
        }"#
    }

    /// Get address seed for submit_zklogin benchmark
    /// This uses the same calculation as in test_helper.rs::get_raw_data()
    /// The address_seed is calculated from user_salt, sub, and clientID using gen_address_seed
    pub fn get_address_seed() -> H256 {
        // Use test_helper::get_raw_data() to get the same address_seed as used in tests
        // This ensures consistency between benchmark and test data
        let (address_seed, _, _, _) = primitive_zklogin::test_helper::get_raw_data();
        address_seed
    }

    /// Get expire_at timestamp for submit_zklogin benchmark
    pub fn get_expire_at() -> u64 {
        834u64
    }

    /// Get ephemeral key for submit_zklogin benchmark
    pub fn get_eph_key() -> ed25519::Pair {
        // Use the same key generation logic from test_helper
        let pri_key: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        use sp_core::Pair;
        ed25519::Pair::from_seed(&pri_key)
    }

    /// Helper function to convert decimal string to BigNumber
    fn str_to_bignumber(s: &str) -> BigNumber {
        let uint = BigUint::parse_bytes(s.as_bytes(), 10).expect("Must be a valid dec number.");
        BoundedVec::truncate_from(uint.to_bytes_le())
    }

    /// Manually construct ZkLoginInputs from proof data strings
    fn construct_zklogin_inputs() -> ZkLoginInputs {
        // Construct proof_points
        // CircomG1 = [BigNumber; 3], CircomG2 = [[BigNumber; 2]; 3]
        type CircomG1 = [BigNumber; 3];
        type CircomG2 = [[BigNumber; 2]; 3];
        
        let a: CircomG1 = [
            Self::str_to_bignumber("9381813773171450462648323179981700992482234003937252912184366692176647122440"),
            Self::str_to_bignumber("17135816274588842394987740577348746744124536487185243735653495512098467176682"),
            Self::str_to_bignumber("1"),
        ];
        let b: CircomG2 = [
            [
                Self::str_to_bignumber("12007654400896864202053137919011753862685795325094057089804209969395451364237"),
                Self::str_to_bignumber("9292143971825249679511504837978464260231784546642825774684216241262448276692"),
            ],
            [
                Self::str_to_bignumber("2739509173985286250590833064309803350595900462807230565709419062550672100574"),
                Self::str_to_bignumber("9617502836905847049711738720668642526073457745474007398904997426591688823762"),
            ],
            [
                Self::str_to_bignumber("1"),
                Self::str_to_bignumber("0"),
            ],
        ];
        let c: CircomG1 = [
            Self::str_to_bignumber("4236607764644869062435426868625747082828648484430168905284460458292661376562"),
            Self::str_to_bignumber("13765193476064868657640379803797505779241026862161166609423648103540137745710"),
            Self::str_to_bignumber("1"),
        ];
        let proof_points = ZkLoginProof::new(a, b, c);

        // Construct iss_base64_details
        let iss_value = U256::from_dec_str("17369902616279740791204861702455537230599532803600308871388405295273096679389")
            .expect("Failed to parse iss value");
        let iss_base64_details = Claim::new(iss_value, 1);

        // Construct header
        let header = U256::from_dec_str("913143068733459984664279033783989157259274322902058410967852973431920544493")
            .expect("Failed to parse header");

        ZkLoginInputs::new(proof_points, iss_base64_details, header)
    }

    /// Prepare zk material for submit_zklogin benchmark (returns u64 version)
    pub fn prepare_zk_material() -> primitive_zklogin::VersionedZkMaterial<u64> {
        let inputs = Self::construct_zklogin_inputs();
        let provider = JwkProvider::Google;
        let kid = b"1f40f0a8ef3d880978dc82f25c3ec317c6a5b781".to_vec();
        let expire_at = Self::get_expire_at();
        
        ZkMaterialV1::new(provider, kid, inputs, expire_at).into()
    }

    /// Prepare zk material with generic Moment type for submit_zklogin benchmark
    pub fn prepare_zk_material_with_moment<Moment: From<u64> + Copy + TryInto<u64>>() -> primitive_zklogin::ZkMaterial<Moment> {
        let inputs = Self::construct_zklogin_inputs();
        let provider = JwkProvider::Google;
        let kid = b"1f40f0a8ef3d880978dc82f25c3ec317c6a5b781".to_vec();
        let expire_at = Moment::from(Self::get_expire_at());
        
        primitive_zklogin::ZkMaterial::V1(primitive_zklogin::ZkMaterialV1::new(
            provider,
            kid,
            inputs,
            expire_at,
        ))
    }
}
