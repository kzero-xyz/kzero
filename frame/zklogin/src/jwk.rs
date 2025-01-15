use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use sp_runtime::traits::Dispatchable;

use primitive_zklogin::{jwk_from_slice, Jwk};

use crate::{Config, Error, TARGET};

pub fn parse_jwk<T: Config>(json: &[u8]) -> sp_std::result::Result<Jwk, Error<T>>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
{
    jwk_from_slice(json).map_err(|e| {
        log::error!(target: TARGET, "Parse json to jwk meet error. err: {:?}", e);
        Error::<T>::InvalidJwkJson
    })
}
