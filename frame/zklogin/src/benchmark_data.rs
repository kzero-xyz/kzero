#![cfg(feature = "runtime-benchmarks")]

use primitive_zklogin::{Jwk, JwkProvider, ZkMaterial, ZkMaterialV1, ZkLoginInputs, ZkLoginProof, Claim, BigNumber};
use sp_core::{U256, ed25519};
use sp_std::{vec, vec::Vec};
use sp_io::crypto::ed25519_generate;
use sp_runtime::format;
use hex;

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
    pub fn generate_test_jwks(count: u32) -> Vec<(JwkProvider, Vec<Jwk>)> {
        let mut jwks = Vec::new();
        
        for i in 0..count {
            let provider = if i % 2 == 0 { JwkProvider::Google } else { JwkProvider::Apple };
            
            // Create different JWK content for each iteration
            let jwk_json = if i % 2 == 0 {
                format!(r#"{{
                    "kty": "RSA",
                    "e": "AQAB",
                    "kid": "test_google_kid_{}",
                    "n": "test_google_n_value_{}",
                    "alg": "RS256"
                }}"#, i, i)
            } else {
                format!(r#"{{
                    "kty": "RSA",
                    "n": "test_apple_n_value_{}",
                    "kid": "test_apple_kid_{}",
                    "e": "AQAB",
                    "alg": "RS256"
                }}"#, i, i)
            };
            
            let jwk: Jwk = serde_json::from_str(&jwk_json).expect("Failed to parse test JWK");
            jwks.push((provider, vec![jwk]));
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

/// ZkMaterial data for benchmark testing
pub struct BenchmarkZkMaterial;

impl BenchmarkZkMaterial {
    /// Get the test seed for AccountId
    pub fn seed() -> &'static [u8; 32] {
        &[
            25, 124, 244, 139, 114, 159, 241, 37, 150, 203, 192, 70, 199, 254, 143, 136,
            249, 42, 197, 240, 182, 252, 66, 180, 193, 220, 197, 50, 211, 124, 206, 162
        ]
    }
    /// Get the test signature hex string
    pub fn signature_hex() -> &'static str {
        "b371fdb15bec6bc04f23d82c97bf7d3ced73c4f758b21086d8db47d0c87764be48889c97c9daf6597dcf533203513677416326588762b0ca7f4062c7eb998b09"
    }
    /// Get the test public key hex string
    pub fn public_hex() -> &'static str {
        "fafd1d9e25a87e9652976a7bb06c2e4777c2e539d90f3ee7b6b12b9a45118a88"
    }
    /// Get a mock ed25519 signature for benchmarking
    pub fn mock_sign() -> ed25519::Signature {
        let signature_hex = Self::signature_hex();
        let signature_bytes = hex::decode(signature_hex).expect("Invalid hex signature");
        let signature_array: [u8; 64] = signature_bytes.try_into().expect("Invalid signature length");
        ed25519::Signature::from_raw(signature_array)
    }
    /// Create test ZkMaterial for benchmark
    pub fn create_test_zk_material<Moment: Default + Copy + TryInto<u64> + From<u64>>() -> ZkMaterial<Moment>
    where
        u64: From<Moment>,
    {
        // Test constants
        const TEST_MAX_EPOCH: u64 = 834;
        const TEST_KID: [u8; 40] = [
            49, 102, 52, 48, 102, 48, 97, 56, 101, 102, 51, 100, 56, 56, 48, 57, 
            55, 56, 100, 99, 56, 50, 102, 50, 53, 99, 51, 101, 99, 51, 49, 55, 
            99, 54, 97, 53, 98, 55, 56, 49
        ];

        // Test proof data
        const TEST_PROOF_A: [&[u8]; 3] = [
            &[8, 110, 215, 80, 123, 120, 158, 143, 144, 207, 11, 93, 40, 184, 102, 185, 165, 35, 217, 184, 164, 137, 141, 130, 2, 122, 64, 133, 29, 235, 189, 20],
            &[234, 96, 127, 53, 224, 27, 102, 211, 157, 212, 36, 104, 2, 109, 136, 58, 187, 149, 239, 16, 176, 96, 113, 118, 235, 107, 64, 58, 63, 135, 226, 37],
            &[1]
        ];

        const TEST_PROOF_B: [[&[u8]; 2]; 3] = [
            [
                &[141, 3, 69, 226, 152, 10, 253, 123, 202, 108, 125, 136, 195, 100, 0, 208, 74, 231, 124, 7, 71, 175, 233, 69, 11, 16, 99, 151, 111, 23, 140, 26],
                &[212, 244, 242, 209, 192, 234, 107, 216, 38, 61, 69, 103, 161, 53, 128, 74, 10, 110, 166, 6, 243, 239, 219, 192, 231, 247, 209, 187, 199, 42, 139, 20]
            ],
            [
                &[222, 204, 142, 212, 3, 95, 89, 246, 151, 192, 24, 32, 241, 252, 37, 227, 65, 177, 200, 176, 16, 240, 233, 175, 74, 47, 181, 199, 218, 129, 14, 6],
                &[210, 19, 4, 196, 157, 51, 1, 166, 128, 52, 36, 0, 48, 26, 20, 79, 37, 190, 205, 188, 1, 144, 158, 91, 215, 99, 224, 196, 78, 80, 67, 21]
            ],
            [
                &[1],
                &[0]
            ]
        ];

        const TEST_PROOF_C: [&[u8]; 3] = [
            &[50, 214, 134, 182, 94, 27, 169, 142, 101, 109, 155, 19, 31, 32, 138, 92, 148, 170, 183, 214, 35, 171, 238, 161, 7, 184, 101, 201, 195, 213, 93, 9],
            &[46, 93, 113, 102, 8, 137, 49, 208, 206, 165, 240, 199, 139, 55, 209, 91, 30, 221, 67, 113, 198, 200, 243, 240, 94, 251, 118, 17, 203, 210, 110, 30],
            &[1]
        ];

        const TEST_ISS_VALUE_STR: &str = "17369902616279740791204861702455537230599532803600308871388405295273096679389";
        const TEST_HEADER_STR: &str = "913143068733459984664279033783989157259274322902058410967852973431920544493";
        const TEST_ISS_INDEX_MOD_4: u8 = 1;

        // Helper functions
        fn bytes_to_big_number(bytes: Vec<u8>) -> BigNumber {
            bytes.try_into().unwrap_or_default()
        }

        fn str_to_u256(s: &str) -> U256 {
            let mut result = U256::zero();
            for ch in s.chars() {
                if let Some(digit) = ch.to_digit(10) {
                    result = result * U256::from(10u64) + U256::from(digit as u64);
                }
            }
            result
        }

        // Create test ZkLoginInputs
        let proof_points = ZkLoginProof::new(
            [
                bytes_to_big_number(TEST_PROOF_A[0].to_vec()),
                bytes_to_big_number(TEST_PROOF_A[1].to_vec()),
                bytes_to_big_number(TEST_PROOF_A[2].to_vec()),
            ],
            [
                [bytes_to_big_number(TEST_PROOF_B[0][0].to_vec()), bytes_to_big_number(TEST_PROOF_B[0][1].to_vec())],
                [bytes_to_big_number(TEST_PROOF_B[1][0].to_vec()), bytes_to_big_number(TEST_PROOF_B[1][1].to_vec())],
                [bytes_to_big_number(TEST_PROOF_B[2][0].to_vec()), bytes_to_big_number(TEST_PROOF_B[2][1].to_vec())],
            ],
            [
                bytes_to_big_number(TEST_PROOF_C[0].to_vec()),
                bytes_to_big_number(TEST_PROOF_C[1].to_vec()),
                bytes_to_big_number(TEST_PROOF_C[2].to_vec()),
            ],
        );

        let iss_base64_details = Claim::new(
            str_to_u256(TEST_ISS_VALUE_STR),
            TEST_ISS_INDEX_MOD_4,
        );

        let inputs = ZkLoginInputs::new(
            proof_points,
            iss_base64_details,
            str_to_u256(TEST_HEADER_STR),
        );

        let kid = TEST_KID.to_vec();
        let moment_max_epoch: Moment = TEST_MAX_EPOCH.into();

        ZkMaterial::V1(ZkMaterialV1::new(JwkProvider::Google, kid, inputs, moment_max_epoch))
    }
} 