use frame_system::pallet_prelude::*;
use frame_system::{
    self as system,
    offchain::{
        AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
        SignedPayload, Signer, SigningTypes, SubmitTransaction,
    },
    pallet_prelude::BlockNumberFor,
};
use sp_core::bounded::alloc;
use sp_std::vec::Vec;
use sp_runtime::{
    offchain::{
        http,
        storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
        Duration,
    },
    traits::Zero,
    transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
    RuntimeDebug,
};
use primitive_zklogin::{Jwk, JwkProvider, JwkProviderErr};

use crate::Config;


const TARGET: &str = "offchain-worker::zklogin";




/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"zklogin!");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
    use super::KEY_TYPE;
    use sp_core::sr25519::Signature as Sr25519Signature;
    use sp_runtime::{
        app_crypto::{app_crypto, sr25519},
        traits::Verify,
        MultiSignature, MultiSigner,
    };
    app_crypto!(sr25519, KEY_TYPE);

    pub struct ZkLoginAuthId;

    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for ZkLoginAuthId {
        type RuntimeAppPublic = Public;
        type GenericPublic = sp_core::sr25519::Public;
        type GenericSignature = sp_core::sr25519::Signature;
    }

    // implemented for mock runtime in test
    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
    for ZkLoginAuthId
    {
        type RuntimeAppPublic = Public;
        type GenericPublic = sp_core::sr25519::Public;
        type GenericSignature = sp_core::sr25519::Signature;
    }
}

pub fn offchain_worker_entrypoint<T: Config>(block_number: BlockNumberFor<T>) {
    log::debug!(target: TARGET, "Offchain worker for zklogin. number: {}", block_number);

    for (provider, jwks) in fetch_jwks() {
        // TODO compare with the onchain state before
        // TODO check whether the jwk is valid.
    }
}

fn submit_unsiged<T: Config>(data: Vec<(JwkProvider, Vec<Jwk>)>) {
    // -- Sign using any account
    let (_, result) = Signer::<T, T::AuthorityId>::any_account()
        .send_unsigned_transaction(
            |account| PricePayload { price, block_number, public: account.public.clone() },
            |payload, signature| Call::submit_price_unsigned_with_signed_payload {
                price_payload: payload,
                signature,
            },
        )
        .ok_or("No local accounts accounts available.")?;
    result.map_err(|()| "Unable to submit transaction")?;
}

fn fetch_jwks() -> Vec<(JwkProvider, Vec<Jwk>)>{
    let mut result = Vec::new();
    for provider in JwkProvider::iterator() {
        match provider.fetch_jwks(fetch_obj) {
            Ok(jwks) => {
                result.push((provider, jwks));
            },
            Err(_e) => {
                // TODO print error info based on the error type.
                // match e {
                //     JwkProviderErr::NotFoundJwkUri(obj) =>
                // }
                log::error!(target: TARGET, "Failed to fetch Jwks for this provider: {:?}", provider);
                continue
            }

        };
    }
    result
}

fn fetch(url:&str) -> Result<Vec<u8>, http::Error> {
    let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(5_000));
    let request = http::Request::get(url);
    let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;
    let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
    if response.code != 200 {
        log::warn!(target: TARGET, "When try to call {} meet an unexpected status code: {}", url, response.code);
        return Err(http::Error::Unknown)
    }

    Ok(response.body().collect::<Vec<u8>>())
}

fn fetch_obj(url: &str) -> Result<serde_json::Value, Error> {
    let json = fetch(url).map_err(Error::Http)?;
    let obj = serde_json::from_slice(&json).map_err(Error::Serde)?;
    Ok(obj)
}

enum Error {
    Http(http::Error),
    Serde(serde_json::Error),
}

