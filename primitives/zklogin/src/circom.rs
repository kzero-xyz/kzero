use crate::error::{ZkAuthError, ZkAuthResult};
use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use num_bigint::BigUint;
use sp_core::bounded::ConstUint;

use sp_runtime::BoundedVec;

pub type BigNumber = BoundedVec<u8, ConstUint<256>>;

pub type GenericGircomG1<T> = [T; 3];
/// A G1 point in BN254 serialized as a vector of three bytes which is the canonical decimal
/// representation of the projective coordinates in Fq.
pub type CircomG1 = GenericGircomG1<BigNumber>;
/// String type for `GenericGircomG1`.
pub(crate) type StrCircomG1 = GenericGircomG1<&'static str>;

pub type GenericCircomG2<T> = [[T; 2]; 3];
/// A G2 point in BN254 serialized as a vector of three vectors each being a vector of two bytes
/// which are the canonical decimal representation of the coefficients of the projective coordinates
/// in Fq2.
pub type CircomG2 = GenericCircomG2<BigNumber>;
/// String type for `GenericGircomG2`.
pub type StrCircomG2 = GenericCircomG2<&'static str>;

fn to_bigint<T: AsRef<[u8]>>(v: &T, le: bool) -> BigUint {
    if le {
        BigUint::from_bytes_le(v.as_ref())
    } else {
        BigUint::from_bytes_be(v.as_ref())
    }
}

/// Deserialize a G1 projective point in BN254 serialized as a vector of three bytes into an affine
/// G1 point in arkworks format. Return an error if the input is not a vector of three bytes or if
/// any of the bytes cannot be parsed as a field element.
pub(crate) fn g1_affine_from_bytes_projective<T: AsRef<[u8]>>(
    s: &GenericGircomG1<T>,
    le: bool,
) -> G1Affine {
    G1Projective::new_unchecked(
        Fq::from(to_bigint(&s[0], le)),
        Fq::from(to_bigint(&s[1], le)),
        Fq::from(to_bigint(&s[2], le)),
    )
    .into()
}

pub(crate) fn g1_affine_from_str_projective<T: AsRef<str>>(
    s: &GenericGircomG1<T>,
) -> ZkAuthResult<G1Affine> {
    let convert = |s: &T| -> ZkAuthResult<BigUint> {
        BigUint::parse_bytes(s.as_ref().as_bytes(), 10).ok_or(ZkAuthError::FqParseError)
    };
    Ok(G1Projective::new_unchecked(
        Fq::from(convert(&s[0])?),
        Fq::from(convert(&s[1])?),
        Fq::from(convert(&s[2])?),
    )
    .into())
}

pub(crate) fn unsafe_g1_affine_from_str_projective<T: AsRef<str>>(
    s: &GenericGircomG1<T>,
) -> G1Affine {
    g1_affine_from_str_projective(s).expect("String must be an valid number.")
}

/// Deserialize a G2 projective point from the BN254 construction serialized as a vector of three
/// vectors each being a vector of two bytes into an affine G2 point in arkworks format. Return an
/// error if the input is not a vector of the right format or if any of the bytes cannot be parsed
/// as a field element.
pub(crate) fn g2_affine_from_bytes_projective<T: AsRef<[u8]>>(
    s: &GenericCircomG2<T>,
    le: bool,
) -> G2Affine {
    G2Projective::new_unchecked(
        Fq2::new(Fq::from(to_bigint(&s[0][0], le)), Fq::from(to_bigint(&s[0][1], le))),
        Fq2::new(Fq::from(to_bigint(&s[1][0], le)), Fq::from(to_bigint(&s[1][1], le))),
        Fq2::new(Fq::from(to_bigint(&s[2][0], le)), Fq::from(to_bigint(&s[2][1], le))),
    )
    .into()
}

pub(crate) fn g2_affine_from_str_projective<T: AsRef<str>>(
    s: &GenericCircomG2<T>,
) -> ZkAuthResult<G2Affine> {
    let convert = |s: &T| -> ZkAuthResult<BigUint> {
        BigUint::parse_bytes(s.as_ref().as_bytes(), 10).ok_or(ZkAuthError::FqParseError)
    };
    Ok(G2Projective::new_unchecked(
        Fq2::new(Fq::from(convert(&s[0][0])?), Fq::from(convert(&s[0][1])?)),
        Fq2::new(Fq::from(convert(&s[1][0])?), Fq::from(convert(&s[1][1])?)),
        Fq2::new(Fq::from(convert(&s[2][0])?), Fq::from(convert(&s[2][1])?)),
    )
    .into())
}

pub(crate) fn unsafe_g2_affine_from_str_projective<T: AsRef<str>>(
    s: &GenericCircomG2<T>,
) -> G2Affine {
    g2_affine_from_str_projective(s).expect("String must be an valid number.")
}
