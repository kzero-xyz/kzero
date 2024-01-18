#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

mod circom;
mod error;
mod jwk;
mod poseidon;
mod pvk;
mod utils;
mod zk_input;
mod zk_sig;

use scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::crypto::AccountId32;
use sp_runtime::{
    traits::{Lazy, Verify},
    MultiSignature, MultiSigner, RuntimeDebug,
};

use error::ZkAuthError;

pub const PACK_WIDTH: u8 = 248;
pub const EPH_PUB_KEY_LEN: usize = 33;

/// Wrapped MultiSignature that is compatible with Substrate
#[derive(Eq, PartialEq, Clone, Encode, Decode, MaxEncodedLen, RuntimeDebug, TypeInfo)]
pub enum ZkMultiSignature {
    /// The MultiSignature that is original in substrate
    Origin(MultiSignature),
    /// The Signature that designed for zkLogin
    Zk(zk_sig::Signature),
}

impl Verify for ZkMultiSignature {
    type Signer = MultiSigner;
    fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId32) -> bool {
        match self {
            ZkMultiSignature::Origin(s) => s.verify(msg, signer),
            ZkMultiSignature::Zk(zk_sig) => zk_sig.verify(msg, signer),
        }
    }
}
