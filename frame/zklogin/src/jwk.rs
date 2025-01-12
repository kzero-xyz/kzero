use crate::{Config, Error, TARGET};
use primitive_zklogin::{jwk_from_slice, Jwk};
pub fn parse_jwk<T: Config>(json: &[u8]) -> sp_std::result::Result<Jwk, Error<T>> {
    jwk_from_slice(json).map_err(|e| {
        log::error!(target: TARGET, "Parse json to jwk meet error. err: {:?}", e);
        Error::<T>::InvalidJwkJson
    })
}
