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
    // todo: remove eph_pubkey
    eph_pubkey_bytes: [u8; EPH_PUB_KEY_LEN],
    sig: S,
}

impl<S> Verify for Signature<S>
where
    S: Verify,
    S::Signer: IdentifyAccount<AccountId = AccountId32>,
{
    type Signer = S::Signer;

    fn verify<L: Lazy<[u8]>>(
        &self,
        mut msg: L,
        signer: &<Self::Signer as IdentifyAccount>::AccountId,
    ) -> bool {
        // check the validity of signer
        let address_seed = self.input.get_address_seed();
        let s: [u8; 32] = address_seed.into();
        let account_id = AccountId32::from(s);

        if &account_id != signer {
            return false;
        }

        // todo: remove
        let pub_key: AccountId32 = if EPH_PUB_KEY_LEN == 33 {
            let mut d = [0_u8; 32];
            d.copy_from_slice(&self.eph_pubkey_bytes[1..]);
            d.into()
        } else {
            todo!("unimpl");
        };

        if !self.sig.verify(msg, &pub_key) {
            return false
        }

        // verify zk proof
        verify_zk_login(
            &self.input,
            &self.source,
            self.max_epoch,
            &self.eph_pubkey_bytes,
            &ZkLoginEnv::Prod,
        )
        .is_ok()
    }
}

pub fn verify_zk_login(
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
        &[input.calculate_all_inputs_hash(eph_pubkey_bytes, &modulus, max_epoch)?],
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
