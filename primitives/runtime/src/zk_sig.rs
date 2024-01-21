use super::*;
use crate::{
    error::ZkAuthResult,
    jwk::{get_modulo, JwkId},
    pvk::{prod_pvk, test_pvk},
    zk_input::{Bn254Fr, ZkLoginInputs},
};
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof};
pub use base64ct::{Base64UrlUnpadded, Encoding};
use sp_core::U256;

#[derive(Debug, Clone)]
pub enum ZkLoginEnv {
    /// Use the secure global verifying key derived from ceremony.
    Prod,
    /// Use the insecure global verifying key.
    Test,
}

impl Default for ZkLoginEnv {
    fn default() -> Self {
        Self::Prod
    }
}

#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, RuntimeDebug, Clone, PartialEq, Eq)]
pub struct Signature<S> {
    source: JwkId,
    input: ZkLoginInputs,
    max_epoch: u64,
    eph_pubkey: [u8; EPH_PUB_KEY_LEN],
    sig: S,
}

impl<S> Signature<S> {
    pub fn new(
        source: JwkId,
        input: ZkLoginInputs,
        max_epoch: u64,
        eph_pubkey: [u8; 32],
        sig: S,
    ) -> Self {
        Self { source, input, max_epoch, eph_pubkey, sig }
    }
}

impl<S> Verify for Signature<S>
where
    S: Verify,
    S::Signer: IdentifyAccount<AccountId = AccountId32>,
{
    type Signer = S::Signer;

    fn verify<L: Lazy<[u8]>>(
        &self,
        msg: L,
        signer: &<Self::Signer as IdentifyAccount>::AccountId,
    ) -> bool {
        let address_seed = U256::from_big_endian(signer.as_ref());

        if !self.sig.verify(msg, &AccountId32::from(self.eph_pubkey)) {
            return false
        }

        // verify zk proof
        verify_zk_login(
            address_seed,
            &self.input,
            &self.source,
            self.max_epoch,
            &self.eph_pubkey,
            &ZkLoginEnv::Prod,
        )
        .is_ok()
    }
}

pub fn verify_zk_login(
    address_seed: U256,
    input: &ZkLoginInputs,
    jwk_id: &JwkId,
    max_epoch: u64,
    eph_pubkey_bytes: &[u8],
    env: &ZkLoginEnv,
) -> ZkAuthResult<()> {
    // Load the expected JWK based on (iss, kid).
    let jwk = get_modulo(jwk_id)?;

    // Decode modulus to bytes.
    let modulus =
        Base64UrlUnpadded::decode_vec(&jwk.n).map_err(|_| ZkAuthError::ModulusDecodeError)?;

    // Calculate all inputs hash and passed to the verification function.
    match verify_zk_login_proof_with_fixed_vk(
        env,
        &input.get_proof().as_arkworks()?,
        &[input.calculate_all_inputs_hash(address_seed, eph_pubkey_bytes, &modulus, max_epoch)?],
    ) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(ZkAuthError::ProofVerifyingFailed),
    }
}

/// Verify a proof against its public inputs using the fixed verifying key.
fn verify_zk_login_proof_with_fixed_vk(
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
