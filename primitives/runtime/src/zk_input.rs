use super::*;
use crate::{
    circom::{g1_affine_from_str_projective, g2_affine_from_str_projective, CircomG1, CircomG2},
    error::ZkAuthError,
    poseidon::poseidon_zk_login,
    utils::{hash_to_field, split_to_two_frs},
};
use ark_bn254::Fr;
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::{BigInt, PrimeField};
use ark_groth16::Proof;
use num_bigint::BigUint;
use sp_core::U256;
use sp_std::{str::FromStr, vec};

#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, RuntimeDebug, Clone, PartialEq, Eq)]
pub struct ZkLoginInputs {
    pub(crate) proof_points: ZkLoginProof,
    pub(crate) iss_base64_details: Claim,
    pub(crate) header: U256,
    pub(crate) address_seed: U256,
}

impl ZkLoginInputs {
    /// Get the zk login proof.
    pub fn get_proof(&self) -> &ZkLoginProof {
        &self.proof_points
    }

    /// Get the address seed string.
    pub fn get_address_seed(&self) -> U256 {
        self.address_seed
    }

    /// Calculate the poseidon hash from selected fields from inputs, along with the ephemeral pubkey.
    pub fn calculate_all_inputs_hash(
        &self,
        eph_pk_bytes: &[u8],
        modulus: &[u8],
        max_epoch: u64,
    ) -> Result<Bn254Fr, ZkAuthError> {
        let addr_seed = Fr::from_bigint(BigInt(self.address_seed.0)).unwrap();
        let (first, second) = split_to_two_frs(eph_pk_bytes)?;

        let max_epoch_f = BigUint::from(max_epoch).into();
        let index_mod_4_f = BigUint::from(self.iss_base64_details.index_mod_4).into();
        let iss_base64_f = Fr::from_bigint(BigInt(self.iss_base64_details.value.0)).unwrap();
        let header_f: Fr = Fr::from_bigint(BigInt(self.header.0)).unwrap();

        let modulus_f = hash_to_field(&[BigUint::from_bytes_be(modulus)], 2048, PACK_WIDTH)?;
        poseidon_zk_login(vec![
            first,
            second,
            addr_seed,
            max_epoch_f,
            iss_base64_f,
            index_mod_4_f,
            header_f,
            modulus_f,
        ])
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, RuntimeDebug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub(crate) value: U256,
    pub(crate) index_mod_4: u8,
}

/// The struct for zk login proof.
// TODO add construct func
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, RuntimeDebug, Clone, PartialEq, Eq)]
pub struct ZkLoginProof {
    pub(crate) a: CircomG1,
    pub(crate) b: CircomG2,
    pub(crate) c: CircomG1,
}

impl ZkLoginProof {
    /// Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    pub fn as_arkworks(&self) -> Result<Proof<Bn254>, ZkAuthError> {
        Ok(Proof {
            a: g1_affine_from_str_projective(&self.a)?,
            b: g2_affine_from_str_projective(&self.b)?,
            c: g1_affine_from_str_projective(&self.c)?,
        })
    }
}
