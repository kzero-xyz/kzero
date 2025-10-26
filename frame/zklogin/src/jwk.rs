use crate::{Config, Error, TARGET};
use primitive_zklogin::Jwk;

pub fn parse_jwk<T: Config>(json: &[u8]) -> sp_std::result::Result<Jwk, Error<T>> {
    primitive_zklogin::jwk_from_slice(json).map_err(|e| {
        log::error!(target: TARGET, "Parse json to jwk meet error. err: {:?}", e);
        Error::<T>::InvalidJwkJson
    })
}

pub fn jwk_to_json<T: Config>(jwk: &Jwk) -> sp_std::result::Result<sp_std::vec::Vec<u8>, Error<T>> {
    primitive_zklogin::jwk_to_json(jwk).map_err(|e| {
        log::error!(target: TARGET, "Serialize jwk to json meet error. err: {:?}", e);
        Error::<T>::InvalidJwk
    })
}
