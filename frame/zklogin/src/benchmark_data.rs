#![cfg(feature = "runtime-benchmarks")]

use primitive_zklogin::{Jwk, JwkProvider};

/// JWK data for benchmark testing
pub struct BenchmarkJwks;

impl BenchmarkJwks {
    /// Get Google test JWK
    pub fn google_jwk() -> Jwk {
        let jwk_json = r#"{
            "kty": "RSA",
            "e": "AQAB",
            "kid": "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781",
            "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
            "alg": "RS256"
        }"#;
        serde_json::from_str(jwk_json).expect("Failed to parse Google JWK")
    }

    /// Get Apple test JWK
    pub fn apple_jwk() -> Jwk {
        let jwk_json = r#"{
            "kty": "RSA",
            "n": "qwrzl06fwB6OIm62IxNG7NXNIDmgdBrvf09ob2Gsp6ZmAXgU4trHPUYrdBaAlU5aHpchXCf_mVL-U5dzRqeVFQsVqsj4PEIE6E5OPw8EwumP2fzLQSswpkKmJJKFcdncfQ730QBonRUEhKkIbiYdicJl5yTkORd0_BmfdLV98r-sEwEHN4lzTJ15-yw90ob_R6vAH4wPyCSN3Xe5_zV6R4ENL2NlKn2HT9lbV7HhtQongea8wfnthUhdZH38kI4SS5nAaCVNxEAzlvJtUIdCpSgjUgcbah-DwY39l4D800kLxkcF2CGXPSmpF8GPs1aWSsYupY8sTSy9qCFJFPFx8Q",
            "kid": "48a63bc4767f8550a532dc630cf7eb49ff397e7c",
            "e": "AQAB",
            "alg": "RS256"
        }"#;
        serde_json::from_str(jwk_json).expect("Failed to parse Apple JWK")
    }

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
}

/// Key data for benchmark testing
pub struct BenchmarkKeys;

impl BenchmarkKeys {
    /// Get key seeds index for update_keys test
    pub fn key_seeds() -> [u32; 3] {
        [0, 1, 2]
    }
} 