use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use sp_runtime::traits::{Dispatchable, Extrinsic, SignaturePayload};

use crate::{Config, Error, TARGET};
use primitive_zklogin::{
    jwk_from_slice,
    traits::{SignaturePayloadExt, TryIntoEphPubKey},
    Jwk,
};

pub fn parse_jwk<T: Config>(json: &[u8]) -> sp_std::result::Result<Jwk, Error<T>>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    <<T as Config>::Extrinsic as Extrinsic>::SignaturePayload: SignaturePayloadExt,
    <<<T as Config>::Extrinsic as Extrinsic>::SignaturePayload as SignaturePayload>::SignatureAddress: TryIntoEphPubKey,
{
    jwk_from_slice(json).map_err(|e| {
        log::error!(target: TARGET, "Parse json to jwk meet error. err: {:?}", e);
        Error::<T>::InvalidJwkJson
    })
}
