#![cfg(feature = "runtime-benchmarks")]

use primitive_zklogin::{Jwk, JwkProvider};
use sp_core::ed25519;
use sp_std::{vec, vec::Vec};
use sp_io::crypto::ed25519_generate;
use sp_runtime::format;

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
