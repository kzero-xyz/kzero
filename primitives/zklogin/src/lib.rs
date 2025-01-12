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
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

pub use error::{ZkAuthError, ZkAuthResult};
pub use zk_input::ZkLoginInputs;

pub use jsonwebtoken::{
    errors::ErrorKind,
    jwk::{AlgorithmParameters, Jwk},
};

mod circom;
mod error;
// mod jwk;
mod poseidon;
mod pvk;
pub mod replace_sender;
#[cfg(feature = "testing")]
pub mod test_helper;
#[cfg(all(test, feature = "testing"))]
mod tests;
mod utils;
mod zk_input;

pub const PACK_WIDTH: u8 = 248;
pub const EPH_PUB_KEY_LEN: usize = 32;

/// The Ephemeral Public Key should be [u8; 32]
pub type PubKey = [u8; EPH_PUB_KEY_LEN];

/// Parse Jwk from a json bytes.
pub fn jwk_from_slice(json: &[u8]) -> serde_json::Result<Jwk> {
    serde_json::from_slice(json)
}

#[derive(
    Encode,
    Decode,
    RuntimeDebug,
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

/// The material that is used for zkproof verification
#[derive(Encode, Decode, TypeInfo, RuntimeDebug, Clone, PartialEq, Eq)]
pub struct ZkMaterial {
    // source: (JwkProvider, Kid),
    /// (JwkProvider,kid) that is used to get the corresponding `n`, which
    /// will be used in zk proof verification
    provider: JwkProvider,
    /// Kid for this JwkProvider.
    kid: Kid,
    /// ZkProof
    inputs: ZkLoginInputs,
    /// When the ephemeral key is expired
    ephkey_expire_at: u32,
    /// The ephemeral public key, for more specific, the ephemeral key
    /// is used to sign the extrinsic
    eph_pubkey: PubKey,
}

impl ZkMaterial {
    pub fn new(
        provider: JwkProvider,
        kid: Kid,
        inputs: ZkLoginInputs,
        ephkey_expire_at: u32,
        eph_pubkey: [u8; 32],
    ) -> Self {
        Self { provider, kid, inputs, ephkey_expire_at, eph_pubkey }
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

    pub fn get_eph_pubkey(&self) -> PubKey {
        return self.eph_pubkey;
    }

    pub fn get_ephkey_expire_at(&self) -> u32 {
        return self.ephkey_expire_at;
    }
    /// entry to handle zklogin proof verification
    pub fn verify_zk_login(&self, address_seed: &AccountId32, jwk: &Jwk) -> ZkAuthResult<()> {
        let modulus = if let AlgorithmParameters::RSA(ref key_params) = jwk.algorithm {
            // Decode modulus to bytes.
            Base64UrlUnpadded::decode_vec(&key_params.n)
                .map_err(|_| ZkAuthError::ModulusDecodeError)?
        } else {
            return Err(ZkAuthError::UnsupportedAlgorithm)
        };

        let address_seed_u256 = U256::from_big_endian(address_seed.as_ref());

        // Calculate all inputs hash and passed to the verification function.
        match verify_zklogin_proof_in_prod(
            &self.inputs.get_proof().as_arkworks()?,
            &[self.inputs.calculate_all_inputs_hash(
                address_seed_u256,
                &self.eph_pubkey,
                &modulus,
                self.ephkey_expire_at,
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
