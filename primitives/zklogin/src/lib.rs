//! # Supportive functions of Zklogin
//!
//! Mainly about `zklogin_verify`

#![cfg_attr(not(feature = "std"), no_std)]

use crate::{
    pvk::{prod_pvk, test_pvk},
    zk_input::Bn254Fr,
};
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof};
use base64ct::{Base64UrlUnpadded, Encoding};

use scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::{crypto::AccountId32, U256};
use sp_std::vec::Vec;

pub use error::{ZkAuthError, ZkAuthResult};
pub use zk_input::ZkLoginInputs;

pub use jsonwebtoken::{
    errors::ErrorKind,
    jwk::{AlgorithmParameters, Jwk},
};

mod circom;
mod error;
mod poseidon;
mod pvk;
mod utils;
mod zk_input;
// public mod
#[cfg(feature = "testing")]
pub mod test_helper;
#[cfg(all(feature = "testing", test))]
mod tests;
pub mod traits;

pub const PACK_WIDTH: u8 = 248;
pub const EPH_PUB_KEY_LEN: usize = 32;

/// The Ephemeral Public Key should be [u8; 32]
pub type EphPubKey = [u8; EPH_PUB_KEY_LEN];

/// Parse Jwk from a json bytes.
pub fn jwk_from_slice(json: &[u8]) -> serde_json::Result<Jwk> {
    serde_json::from_slice(json)
}

#[derive(
    Encode,
    Decode,
    Debug,
    MaxEncodedLen,
    TypeInfo,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Ord
)]
pub enum JwkProvider {
    /// See https://accounts.google.com/.well-known/openid-configuration
    Google,
    /// See https://id.twitch.tv/oauth2/.well-known/openid-configuration
    Twitch,
    /// See https://www.facebook.com/.well-known/openid-configuration/
    Facebook,
    /// See https://kauth.kakao.com/.well-known/openid-configuration
    Kakao,
    /// See https://appleid.apple.com/.well-known/openid-configuration
    Apple,
    /// See https://slack.com/.well-known/openid-configuration
    Slack,
    /// See https://token.actions.githubusercontent.com/.well-known/openid-configuration
    Github,
}

impl JwkProvider {
    const COMMON_JWKS_URI_KEY: &'static str = "jwks_uri";
    const COMMON_JWKS_KEY: &'static str = "keys";

    pub fn well_know_link(&self) -> &'static str {
        // TODO choose to query storage first, then use this default.
        match self {
            JwkProvider::Google => "https://accounts.google.com/.well-known/openid-configuration",
            JwkProvider::Twitch => "https://id.twitch.tv/oauth2/.well-known/openid-configuration",
            JwkProvider::Facebook => "https://www.facebook.com/.well-known/openid-configuration/",
            JwkProvider::Kakao => "https://kauth.kakao.com/.well-known/openid-configuration",
            JwkProvider::Apple => "https://appleid.apple.com/.well-known/openid-configuration",
            JwkProvider::Slack => "https://slack.com/.well-known/openid-configuration",
            JwkProvider::Github => {
                "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
            }
        }
    }

    pub fn iterator() -> impl Iterator<Item = Self> {
        use JwkProvider::*;
        [Google, Twitch, Facebook, Kakao, Apple, Slack, Github].iter().copied()
    }

    pub fn fetch_jwks<E>(
        &self,
        fetcher: impl Fn(&str) -> Result<serde_json::Value, E>,
    ) -> Result<Vec<Jwk>, JwkProviderErr<E>> {
        use serde_json::Value;
        let well_know_link = self.well_know_link();
        let obj = fetcher(well_know_link).map_err(JwkProviderErr::Fetch)?;
        let link = match &obj {
            Value::Object(map) => {
                // For now, The structure returned by all current providers meets the following form:
                // ```json
                // {
                //    // other fields
                //    "jwks_uri": "https://...",
                // }
                let value =
                    map.get(Self::COMMON_JWKS_URI_KEY).ok_or(JwkProviderErr::NotFoundJwkUri)?;
                match value {
                    Value::String(link) => link.as_str(),
                    _ => return Err(JwkProviderErr::InvalidJson(obj)),
                }
            }
            _ => return Err(JwkProviderErr::InvalidJson(obj)),
        };

        let obj = fetcher(link).map_err(JwkProviderErr::Fetch)?;
        match obj {
            Value::Object(mut map) => {
                // For now, The structure returned by all current `jwks_uri` meets the following form:
                // ```json
                // {
                //    "keys": [
                //        { // jwks json
                //        },
                //    ],
                // }
                let value =
                    map.get_mut(Self::COMMON_JWKS_KEY).ok_or(JwkProviderErr::NotFoundJwks)?;
                if !value.is_array() {
                    return Err(JwkProviderErr::InvalidJson(value.clone()));
                }

                let jwks = value.take();
                let r = serde_json::from_value::<Vec<Jwk>>(jwks)
                    .map_err(JwkProviderErr::InvalidJwks)?;
                Ok(r)
            }
            _ => Err(JwkProviderErr::InvalidJson(obj)),
        }
    }
}

// TODO add doc and derive for this error.
pub enum JwkProviderErr<Err> {
    Fetch(Err),
    NotFoundJwkUri,
    NotFoundJwks,
    InvalidJson(serde_json::Value),
    InvalidJwks(serde_json::Error),
}

/// Kid is a String in spec, we use `Bytes` to present it.
/// For now, the max length for Kid is 43, which comes from Slack.
pub type Kid = Vec<u8>;

#[derive(Debug, Clone)]
pub enum ZkLoginEnv {
    /// Use the secure global verifying key derived from ceremony.
    Prod,
    /// Use the insecure global verifying key.
    #[allow(unused)]
    Test,
}

impl Default for ZkLoginEnv {
    fn default() -> Self {
        Self::Prod
    }
}

/// Aliasing type for `VersionedZkMaterial`.
pub type ZkMaterial<Moment> = VersionedZkMaterial<Moment>;

/// ZkMaterial with versioned prefix.
#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub enum VersionedZkMaterial<Moment> {
    V1(ZkMaterialV1<Moment>),
}

impl<Moment: Copy + TryInto<u64>> VersionedZkMaterial<Moment> {
    /// Return ephkey expire time.
    pub fn get_ephkey_expire_at(&self) -> Moment {
        match self {
            VersionedZkMaterial::V1(v1) => v1.get_ephkey_expire_at(),
        }
    }

    /// JwkProvider and Key id.
    pub fn source(&self) -> (JwkProvider, &Kid) {
        match self {
            VersionedZkMaterial::V1(v1) => v1.source(),
        }
    }

    /// entry to handle zklogin proof verification
    pub fn verify_zk_login(
        &self,
        eph_pubkey: EphPubKey,
        address_seed: &AccountId32,
        jwk: &Jwk,
    ) -> ZkAuthResult<()> {
        match self {
            VersionedZkMaterial::V1(v1) => v1.verify_zk_login(eph_pubkey, address_seed, jwk),
        }
    }
}

impl<Moment> From<ZkMaterialV1<Moment>> for VersionedZkMaterial<Moment> {
    fn from(value: ZkMaterialV1<Moment>) -> Self {
        VersionedZkMaterial::V1(value)
    }
}

/// The material that is used for zkproof verification (Version 1)
#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub struct ZkMaterialV1<Moment> {
    // source: (JwkProvider, Kid),
    /// (JwkProvider,kid) that is used to get the corresponding `n`, which
    /// will be used in zk proof verification
    provider: JwkProvider,
    /// Kid for this JwkProvider.
    kid: Kid,
    /// ZkProof
    inputs: ZkLoginInputs,
    /// When the ephemeral key is expired
    ephkey_expire_at: Moment,
}

impl<Moment: Copy + TryInto<u64>> ZkMaterialV1<Moment> {
    pub fn new(
        provider: JwkProvider,
        kid: Kid,
        inputs: ZkLoginInputs,
        ephkey_expire_at: Moment,
    ) -> Self {
        Self { provider, kid, inputs, ephkey_expire_at }
    }

    pub fn get_provider(&self) -> JwkProvider {
        self.provider
    }

    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    pub fn source(&self) -> (JwkProvider, &Kid) {
        (self.provider, &self.kid)
    }

    pub fn get_ephkey_expire_at(&self) -> Moment {
        self.ephkey_expire_at
    }
    /// entry to handle zklogin proof verification
    pub fn verify_zk_login(
        &self,
        eph_pubkey: EphPubKey,
        address_seed: &AccountId32,
        jwk: &Jwk,
    ) -> ZkAuthResult<()> {
        let modulus = if let AlgorithmParameters::RSA(ref key_params) = jwk.algorithm {
            // Decode modulus to bytes.
            Base64UrlUnpadded::decode_vec(&key_params.n)
                .map_err(|_| ZkAuthError::ModulusDecodeError)?
        } else {
            return Err(ZkAuthError::UnsupportedAlgorithm);
        };

        let address_seed_u256 = U256::from_big_endian(address_seed.as_ref());

        // Calculate all inputs hash and passed to the verification function.
        match verify_zklogin_proof_in_prod(
            &self.inputs.get_proof().as_arkworks()?,
            &[self.inputs.calculate_all_inputs_hash(
                address_seed_u256,
                &eph_pubkey,
                &modulus,
                self.ephkey_expire_at.try_into().map_err(|_| ZkAuthError::ExpireAtFormatError)?,
            )?],
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(ZkAuthError::ProofVerifyingFailed),
        }
    }
}

/// Verify zklogin proof with pvk in production
fn verify_zklogin_proof_in_prod(
    proof: &Proof<Bn254>,
    public_inputs: &[Bn254Fr],
) -> Result<bool, ZkAuthError> {
    verify_zklogin_proof_with_fixed_vk(&ZkLoginEnv::Prod, proof, public_inputs)
}

/// Verify a proof against its public inputs using the fixed verifying key.
fn verify_zklogin_proof_with_fixed_vk(
    usage: &ZkLoginEnv,
    proof: &Proof<Bn254>,
    public_inputs: &[Bn254Fr],
) -> Result<bool, ZkAuthError> {
    let prod_pvk = prod_pvk();
    let test_pvk = test_pvk();
    let vk = match usage {
        ZkLoginEnv::Prod => &prod_pvk,
        ZkLoginEnv::Test => &test_pvk,
    };
    Groth16::<Bn254>::verify_with_processed_vk(vk, public_inputs, proof)
        .map_err(|e| ZkAuthError::GeneralError(e.into()))
}
