use crate::{
    error::{ZkAuthError, ZkAuthResult},
    poseidon::poseidon_zk_login,
    zk_input::{Bn254Fr, Claim, ZkLoginInputs, ZkLoginProof},
    PACK_WIDTH,
};
use ark_ff::Zero;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json;
use sp_core::{crypto::AccountId32, ed25519::Pair as Ed25519Pair, Pair, U256};
use std::str::FromStr;
use crate::circom::BigNumber;

const MAX_KEY_CLAIM_NAME_LENGTH: u8 = 32;
const MAX_KEY_CLAIM_VALUE_LENGTH: u8 = 115;
const MAX_AUD_VALUE_LENGTH: u8 = 145;

type CircomG1Json = [String; 3];
type CircomG2Json = [[String; 2]; 3];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkLoginProofJson {
    pub(crate) a: CircomG1Json,
    pub(crate) b: CircomG2Json,
    pub(crate) c: CircomG1Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimJson {
    value: String,
    index_mod_4: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkLoginInputsReaderJson {
    pub(crate) proof_points: ZkLoginProofJson,
    pub(crate) iss_base64_details: ClaimJson,
    pub(crate) header: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkLoginInputsReader {
    pub(crate) proof_points: ZkLoginProof,
    pub(crate) iss_base64_details: Claim,
    pub(crate) header: U256,
}

impl From<ClaimJson> for Claim {
    fn from(value: ClaimJson) -> Self {
        Self { value: U256::from_dec_str(&value.value).expect(""), index_mod_4: value.index_mod_4 }
    }
}

impl From<ZkLoginProofJson> for ZkLoginProof {
    fn from(value: ZkLoginProofJson) -> Self {
        let convert = |s: &str| -> BigNumber {
            let mut buf = s.as_bytes().to_vec();
            buf.reverse();
            BigNumber::truncate_from(buf)
        };

        let a = [convert(&value.a[0]), convert(&value.a[1]), convert(&value.a[2])];
        let b = [
            [convert(&value.b[0][0]), convert(&value.b[0][1])],
            [convert(&value.b[1][0]), convert(&value.b[1][1])],
            [convert(&value.b[2][0]), convert(&value.b[2][1])],
        ];
        let c = [convert(&value.c[0]), convert(&value.c[1]), convert(&value.c[2])];
        Self { a, b, c }
    }
}

impl From<ZkLoginInputsReaderJson> for ZkLoginInputsReader {
    fn from(value: ZkLoginInputsReaderJson) -> Self {
        Self {
            proof_points: value.proof_points.into(),
            iss_base64_details: value.iss_base64_details.into(),
            header: U256::from_dec_str(&value.header).expect(""),
        }
    }
}

impl ZkLoginInputs {
    pub fn from_json(value: &str) -> Result<Self, String> {
        let reader: ZkLoginInputsReaderJson =
            serde_json::from_str(value).map_err(|e| e.to_string())?;
        Self::from_reader(reader.into())
    }

    /// Initialize ZkLoginInputs from the reader
    pub fn from_reader(reader: ZkLoginInputsReader) -> Result<Self, String> {
        Ok(ZkLoginInputs {
            proof_points: reader.proof_points,
            iss_base64_details: reader.iss_base64_details,
            header: reader.header,
        })
    }
}

fn gen_address_seed(
    salt: &str,
    name: &str,  // i.e. "sub"
    value: &str, // i.e. the sub value
    aud: &str,   // i.e. the client ID
) -> ZkAuthResult<String> {
    let salt_hash = poseidon_zk_login(vec![to_field(salt)?])?;
    gen_address_seed_with_salt_hash(&salt_hash.to_string(), name, value, aud)
}

fn to_field(val: &str) -> Result<Bn254Fr, ZkAuthError> {
    Bn254Fr::from_str(val).map_err(|_| ZkAuthError::TestError(()))
}

fn hash_ascii_str_to_field(str: &str, max_size: u8) -> ZkAuthResult<Bn254Fr> {
    let str_padded = str_to_padded_char_codes(str, max_size)?;
    hash_to_field(&str_padded, 8, PACK_WIDTH)
}

fn hash_to_field(input: &[BigUint], in_width: u16, pack_width: u8) -> ZkAuthResult<Bn254Fr> {
    let packed = convert_base(input, in_width, pack_width)?;
    poseidon_zk_login(packed)
}

/// Helper function to pack field elements from big ints.
fn convert_base(in_arr: &[BigUint], in_width: u16, out_width: u8) -> ZkAuthResult<Vec<Bn254Fr>> {
    let bits = big_int_array_to_bits(in_arr, in_width as usize);
    let mut packed: Vec<Bn254Fr> = bits
        .rchunks(out_width as usize)
        .map(|chunk| Bn254Fr::from(BigUint::from_radix_be(chunk, 2).unwrap()))
        .collect();
    packed.reverse();
    match packed.len() != div_ceil(in_arr.len() * in_width as usize, out_width as usize).unwrap() {
        true => Err(ZkAuthError::InvalidInput),
        false => Ok(packed),
    }
}

/// Convert a big int array to a bit array with 0 paddings.
fn big_int_array_to_bits(arr: &[BigUint], int_size: usize) -> Vec<u8> {
    let mut bitarray: Vec<u8> = Vec::new();
    for num in arr {
        let val = num.to_radix_be(2);
        let extra_bits = if val.len() < int_size { int_size - val.len() } else { 0 };

        let mut padded = vec![0; extra_bits];
        padded.extend(val);
        bitarray.extend(padded)
    }
    bitarray
}

fn div_ceil(dividend: usize, divisor: usize) -> ZkAuthResult<usize> {
    if divisor == 0 {
        // Handle division by zero as needed for your application.
        return Err(ZkAuthError::InvalidInput);
    }

    Ok(1 + ((dividend - 1) / divisor))
}

fn str_to_padded_char_codes(str: &str, max_len: u8) -> ZkAuthResult<Vec<BigUint>> {
    let arr: Vec<BigUint> = str.chars().map(|c| BigUint::from_slice(&([c as u32]))).collect();
    pad_with_zeroes(arr, max_len)
}

fn pad_with_zeroes(in_arr: Vec<BigUint>, out_count: u8) -> ZkAuthResult<Vec<BigUint>> {
    if in_arr.len() > out_count as usize {
        return Err(ZkAuthError::TestError(()));
    }
    let mut padded = in_arr;
    padded.resize(out_count as usize, BigUint::zero());
    Ok(padded)
}

/// Same as [`gen_address_seed`] but takes the poseidon hash of the salt as input instead of the salt.
fn gen_address_seed_with_salt_hash(
    salt_hash: &str,
    name: &str,  // i.e. "sub"
    value: &str, // i.e. the sub value
    aud: &str,   // i.e. the client ID
) -> ZkAuthResult<String> {
    Ok(poseidon_zk_login(vec![
        hash_ascii_str_to_field(name, MAX_KEY_CLAIM_NAME_LENGTH)?,
        hash_ascii_str_to_field(value, MAX_KEY_CLAIM_VALUE_LENGTH)?,
        hash_ascii_str_to_field(aud, MAX_AUD_VALUE_LENGTH)?,
        to_field(salt_hash)?,
    ])?
    .to_string())
}

pub fn get_test_eph_key() -> Ed25519Pair {
    let pri_key = [
        251, 112, 167, 63, 195, 4, 26, 202, 18, 45, 182, 138, 84, 202, 34, 15, 209, 217, 76, 114,
        180, 67, 72, 157, 104, 241, 172, 212, 122, 18, 74, 54,
    ];

    Pair::from_seed(&pri_key)
}

pub fn get_raw_data() -> (AccountId32, String, u64, [u8; 32]) {
    let user_salt = "6903439401297002981078976741241818963710729444388942281949823152082404716376301797176193848";

    let address_seed = gen_address_seed(
        user_salt,
        "sub",
        "111140461530246164526", // sub
        "560629365517-mt9j9arflcgi35i8hpoptr66qgo1lmfm.apps.googleusercontent.com", // clientID
    )
    .unwrap();

    let address_u256 = U256::from_dec_str(&address_seed).expect("");
    let s: [u8; 32] = address_u256.into();
    let address_seed = AccountId32::from(s);

    let proof_data = r#"{
        "proof_points": {
            "a": [
            "9381813773171450462648323179981700992482234003937252912184366692176647122440",
            "17135816274588842394987740577348746744124536487185243735653495512098467176682",
            "1"
            ],
            "b": [
            [
            "12007654400896864202053137919011753862685795325094057089804209969395451364237",
            "9292143971825249679511504837978464260231784546642825774684216241262448276692"
            ],
            [
            "2739509173985286250590833064309803350595900462807230565709419062550672100574",
            "9617502836905847049711738720668642526073457745474007398904997426591688823762"
            ],
            [
            "1",
            "0"
            ]
            ],
            "c": [
            "4236607764644869062435426868625747082828648484430168905284460458292661376562",
            "13765193476064868657640379803797505779241026862161166609423648103540137745710",
            "1"
            ]
        },
        "iss_base64_details": {
            "value" : "17369902616279740791204861702455537230599532803600308871388405295273096679389",
            "index_mod_4": 1
        },
        "header": "913143068733459984664279033783989157259274322902058410967852973431920544493"
    }"#;

    let max_epoch: u64 = 834;
    let eph_pubkey_bytes: [u8; 32] = get_test_eph_key().public().0;

    (address_seed, proof_data.to_owned(), max_epoch, eph_pubkey_bytes)
}

pub fn get_zklogin_inputs(proof_data: String) -> ZkLoginInputs {
    let input = ZkLoginInputs::from_json(&proof_data).expect("wrong json parse");
    input
}

pub mod test_cases {
    use crate::{jwk_from_slice, Jwk, Kid};
    pub mod google {
        use super::*;
        pub const GOOGLE_JWK_JSON_LIST: [&str; 2] = [
            r#"{
                "kty": "RSA",
                "e": "AQAB",
                "kid": "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781",
                "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
                "alg": "RS256"
            }"#,
            r#"{
                "kty": "RSA",
                "n": "qwrzl06fwB6OIm62IxNG7NXNIDmgdBrvf09ob2Gsp6ZmAXgU4trHPUYrdBaAlU5aHpchXCf_mVL-U5dzRqeVFQsVqsj4PEIE6E5OPw8EwumP2fzLQSswpkKmJJKFcdncfQ730QBonRUEhKkIbiYdicJl5yTkORd0_BmfdLV98r-sEwEHN4lzTJ15-yw90ob_R6vAH4wPyCSN3Xe5_zV6R4ENL2NlKn2HT9lbV7HhtQongea8wfnthUhdZH38kI4SS5nAaCVNxEAzlvJtUIdCpSgjUgcbah-DwY39l4D800kLxkcF2CGXPSmpF8GPs1aWSsYupY8sTSy9qCFJFPFx8Q",
                "kid": "48a63bc4767f8550a532dc630cf7eb49ff397e7c",
                "e": "AQAB",
                "alg": "RS256"
            }"#,
        ];

        pub fn jwks() -> Vec<Jwk> {
            GOOGLE_JWK_JSON_LIST
                .into_iter()
                .map(|s| jwk_from_slice(s.as_bytes()).expect("Test case muse be a valid jwk"))
                .collect()
        }

        pub fn kids() -> Vec<Kid> {
            jwks()
                .into_iter()
                .map(|jwk| {
                    jwk.common.key_id.expect("Test case JWK must has kid").as_bytes().to_vec()
                })
                .collect()
        }
    }
}
