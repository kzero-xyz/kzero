use scale_codec::{Decode, Encode};
// Substrate
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use frame_system::{
    offchain::{AppCrypto, SendUnsignedTransaction, SignedPayload, Signer, SigningTypes},
    pallet_prelude::BlockNumberFor,
};
use sp_runtime::{
    offchain::{http, Duration},
    traits::{Dispatchable, Extrinsic, SignaturePayload},
    RuntimeAppPublic,
};
use sp_std::vec::Vec;
// zklogin and local
use crate::{Call, Config, Jwks, Keys};
use primitive_zklogin::{
    traits::{SignaturePayloadExt, TryIntoEphPubKey},
    Jwk, JwkProvider, JwkProviderErr,
};

const TARGET: &str = "offchain-worker::zklogin";

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
    use sp_core::{crypto::KeyTypeId, sr25519::Signature as Sr25519Signature};
    use sp_runtime::{
        app_crypto::{app_crypto, sr25519},
        traits::Verify,
        MultiSignature, MultiSigner,
    };

    /// Defines application identifier for crypto keys of this module.
    ///
    /// Every module that deals with signatures needs to declare its unique identifier for
    /// its crypto keys.
    /// When offchain worker is signing transactions it's going to request keys of type
    /// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
    /// The keys can be inserted manually via RPC (see `author_insertKey`).
    pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"zklo");

    app_crypto!(sr25519, KEY_TYPE);

    pub struct ZkLoginAuthId;

    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for ZkLoginAuthId {
        type RuntimeAppPublic = Public;
        type GenericPublic = sr25519::Public;
        type GenericSignature = sr25519::Signature;
    }

    // implemented for mock runtime in test
    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
        for ZkLoginAuthId
    {
        type RuntimeAppPublic = Public;
        type GenericPublic = sr25519::Public;
        type GenericSignature = sr25519::Signature;
    }
}

type RuntimeAppPublicOf<T> = <<T as Config>::AuthorityId as AppCrypto<
    <T as SigningTypes>::Public,
    <T as SigningTypes>::Signature,
>>::RuntimeAppPublic;

fn readable_key_type<T: Config>(id: &sp_core::crypto::KeyTypeId) -> &str
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
    <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
{
    sp_std::str::from_utf8(id.0.as_slice()).unwrap_or("<invalid>")
}

pub(crate) fn check_jwk_not_onchain(
    provider: JwkProvider,
    jwk: &Jwk,
    get_onchain: impl Fn(JwkProvider, &[u8]) -> Option<Jwk>,
) -> Option<bool> {
    jwk.common.key_id.as_ref().map(|key_id| {
        if let Some(onchain_jwk) = get_onchain(provider, key_id.as_bytes()) {
            if &onchain_jwk == jwk {
                log::debug!(target: TARGET, "Jwk[kid:{}] from Provider:{:?} is existed onchain", key_id, provider);
                false
            } else {
                log::warn!(target: TARGET, "Jwk[kid:{}] from Provider:{:?} is existed onchain, but the jwk content is different.", key_id, provider);
                true
            }
        } else {
            log::info!(target: TARGET, "New Jwk[kid:{}] for Provider:{:?}", key_id, provider);
            true
        }
    }).or_else(|| {
        log::warn!(target: TARGET, "This Jwk does not contain `key_id` for Provider: {:?}", provider);
        None
    })
}

pub fn offchain_worker_entrypoint<T: Config>(block_number: BlockNumberFor<T>)
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
    <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
{
    log::debug!(target: TARGET, "ZkLogin offchain worker. number: {:?}", block_number);

    let onchain_keys = Keys::<T>::get().into_inner();
    let signer = Signer::<T, T::AuthorityId>::all_accounts().with_filter(onchain_keys);
    if !signer.can_sign() {
        log::debug!(target: TARGET, "This node does not have the key for KeyType: [{}], exit ZkLogin offchain worker", readable_key_type::<T>(&RuntimeAppPublicOf::<T>::ID));
        return
    }

    let all_jwks = fetch_jwks();
    let prepared_jwks = all_jwks.into_iter().filter_map(|(provider, jwks)| {
        let count = jwks.iter().filter_map(|jwk| {
            check_jwk_not_onchain(provider, jwk, |provider, kid| Jwks::<T>::get(provider, kid))
                .and_then(|upload| upload.then_some(()))
        }).count();
        if count == 0 {
            log::debug!(target: TARGET, "No new Jwk for this provider:{:?}.", provider);
            None
        } else {
            log::info!(target: TARGET, "Provider [{:?}] can update the Jwks, count: [{}]", provider, jwks.len());
            Some((provider, jwks))
        }
    }).collect::<Vec<_>>();

    if prepared_jwks.is_empty() {
        log::info!(target: TARGET, "All Jwks has not updated yet. Ignore to submit extrinsic.");
        return
    }

    match submit_unsigned::<T>(block_number, prepared_jwks) {
        Ok(()) => {
            log::info!(target: TARGET, "ZkLogin Offchain worker submit unsigned extrinsic to update Jwks.");
        }
        Err(err) => {
            log::error!(target:TARGET, "Offchain worker submit unsigned extrinsic err: {:}", err)
        }
    }
}

/// Payload used by this example crate to hold price
/// data required to submit a transaction.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, scale_info::TypeInfo)]
pub struct JwksPayload<Public, BlockNumber> {
    pub jwks: Vec<(JwkProvider, Vec<Jwk>)>,
    pub block_number: BlockNumber,
    pub public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for JwksPayload<T::Public, BlockNumberFor<T>> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

fn submit_unsigned<T: Config>(
    block_number: BlockNumberFor<T>,
    jwks: Vec<(JwkProvider, Vec<Jwk>)>,
) -> Result<(), &'static str>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
    <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
{
    // -- Sign using any account
    let (_, result) = Signer::<T, T::AuthorityId>::any_account()
        .send_unsigned_transaction(
            |account| {
                log::info!(target: TARGET, "Using KeyType: [{}] account: [id: {:?}|public: {:?}|index: {}] to sign payload and submit unsigned.", readable_key_type::<T>(&RuntimeAppPublicOf::<T>::ID), account.id, account.public, account.index);
                JwksPayload {
                    jwks: jwks.clone(),
                    block_number,
                    public: account.public.clone(),
                }
            },
            |payload, signature| Call::submit_jwks_unsigned { payload, signature },
        )
        .ok_or("No local accounts accounts available.")?;
    result.map_err(|()| "Unable to submit transaction")
}

fn fetch_jwks() -> Vec<(JwkProvider, Vec<Jwk>)> {
    let mut result = Vec::new();
    for provider in JwkProvider::iterator() {
        match provider.fetch_jwks(fetch_obj) {
            Ok(jwks) => {
                result.push((provider, jwks));
            }
            Err(e) => {
                // TODO print error info based on the error type.
                match e {
                    JwkProviderErr::Fetch(e) => match e {
                        Error::Http(e) => {
                            log::error!(target: TARGET, "Http error: {:?}", e);
                        }
                        Error::Serde(e) => {
                            log::error!(target: TARGET, "Decode to json error: {:?}", e);
                        }
                    },
                    JwkProviderErr::NotFoundJwkUri => {}
                    JwkProviderErr::NotFoundJwks => {}
                    JwkProviderErr::InvalidJson(_obj) => {}
                    JwkProviderErr::InvalidJwks(_obj) => {}
                }
                log::error!(target: TARGET, "Failed to fetch Jwks for this provider: {:?}", provider);
                continue
            }
        };
    }
    result
}

fn fetch(url: &str) -> Result<Vec<u8>, http::Error> {
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
