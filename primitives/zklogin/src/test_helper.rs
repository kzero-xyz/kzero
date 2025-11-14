use crate::{
    circom::BigNumber,
    error::{ZkAuthError, ZkAuthResult},
    poseidon::poseidon_zk_login,
    zk_input::{Bn254Fr, Claim, ZkLoginInputs, ZkLoginProof},
    PACK_WIDTH,
};
use ark_ff::Zero;
use num_bigint::BigUint;
#[cfg(feature = "testing")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "testing")]
use serde_json;
use sp_core::{ed25519::Pair as Ed25519Pair, Pair, H256, U256};
use sp_std::{prelude::*, str::FromStr};

// String and Vec types for no_std environment
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};

const MAX_KEY_CLAIM_NAME_LENGTH: u8 = 32;
const MAX_KEY_CLAIM_VALUE_LENGTH: u8 = 115;
const MAX_AUD_VALUE_LENGTH: u8 = 145;

#[cfg(feature = "testing")]
type CircomG1Json = [String; 3];
#[cfg(feature = "testing")]
type CircomG2Json = [[String; 2]; 3];
#[cfg(feature = "testing")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkLoginProofJson {
    pub(crate) a: CircomG1Json,
    pub(crate) b: CircomG2Json,
    pub(crate) c: CircomG1Json,
}

#[cfg(feature = "testing")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimJson {
    value: String,
    index_mod_4: u8,
}

#[cfg(feature = "testing")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkLoginInputsReaderJson {
    pub(crate) proof_points: ZkLoginProofJson,
    pub(crate) iss_base64_details: ClaimJson,
    pub(crate) header: String,
}

#[cfg(feature = "testing")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkLoginInputsReader {
    pub(crate) proof_points: ZkLoginProof,
    pub(crate) iss_base64_details: Claim,
    pub(crate) header: U256,
}

#[cfg(feature = "testing")]
impl From<ClaimJson> for Claim {
    fn from(value: ClaimJson) -> Self {
        Self { value: U256::from_dec_str(&value.value).expect(""), index_mod_4: value.index_mod_4 }
    }
}

#[cfg(feature = "testing")]
impl From<ZkLoginProofJson> for ZkLoginProof {
    fn from(value: ZkLoginProofJson) -> Self {
        let convert = |s: &str| -> BigNumber {
            let uint = BigUint::parse_bytes(s.as_bytes(), 10).expect("Must be a valid dec number.");
            BigNumber::truncate_from(uint.to_bytes_le())
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

#[cfg(feature = "testing")]
impl From<ZkLoginInputsReaderJson> for ZkLoginInputsReader {
    fn from(value: ZkLoginInputsReaderJson) -> Self {
        Self {
            proof_points: value.proof_points.into(),
            iss_base64_details: value.iss_base64_details.into(),
            header: U256::from_dec_str(&value.header).expect(""),
        }
    }
}

#[cfg(feature = "testing")]
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

pub fn gen_address_seed(
    salt: &str,
    name: &str,  // i.e. "sub"
    value: &str, // i.e. the sub value
    aud: &str,   // i.e. the client ID
) -> ZkAuthResult<String> {
    let salt_hash = poseidon_zk_login(sp_std::vec![to_field(salt)?])?;
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
    Ok(poseidon_zk_login(sp_std::vec![
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

pub fn get_raw_data() -> (H256, String, u64, [u8; 32]) {
    let user_salt = "6903439401297002981078976741241818963710729444388942281949823152082404716376301797176193848";

    let address_seed = gen_address_seed(
        user_salt,
        "sub",
        "111140461530246164526", // sub
        "560629365517-mt9j9arflcgi35i8hpoptr66qgo1lmfm.apps.googleusercontent.com", // clientID
    )
    .unwrap();

    let address_u256 = U256::from_dec_str(&address_seed).expect("");
    let s: [u8; 32] = address_u256.to_big_endian();
    let address_seed = s.into();

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

#[cfg(feature = "testing")]
pub fn get_zklogin_inputs(proof_data: String) -> ZkLoginInputs {
    let input = ZkLoginInputs::from_json(&proof_data).expect("wrong json parse");
    input
}

pub mod test_cases {
    use crate::{jwk_from_slice, Jwk, Kid};
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
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

        pub const WRONG_GOOGLE_JWK_JSON_LIST: [&str; 2] = [
            r#"{
                "kty": "RSA",
                "alg": "RS256",
                "e": "AQAB",
                "n": "jb7Wtq9aDMpiXvHGCB5nrfAS2UutDEkSbK16aDtDhbYJhDWhd7vqWhFbnP0C_XkSxsqWJoku69y49EzgabEiUMf0q3X5N0pNvV64krviH2m9uLnyGP5GMdwZpjTXARK9usGgYZGuWhjfgTTvooKDUdqVQYvbrmXlblkM6xjbA8GnShSaOZ4AtMJCjWnaN_UaMD_vAXvOYj4SaefDMSlSoiI46yipFdggfoIV8RDg1jeffyre_8DwOWsGz7b2yQrL7grhYCvoiPrybKmViXqu-17LTIgBw6TDk8EzKdKzm33_LvxU7AKs3XWW_NvZ4WCPwp4gr7uw6RAkdDX_ZAn0TQ",
                "kid": "23f7a3583796f97129e5418f9b2136fcc0a96462"
            }"#,
            r#"{
                "e": "AQAB",
                "kid": "07b80a365428525f8bf7cd0846d74a8ee4ef3625",
                "kty": "RSA",
                "n": "03Cww27F2O7JxB5Ji9iT9szfKZ4MK-iPzVpQkdLjCuGKfpjaCVAz9zIQ0-7gbZ-8cJRaSLfByWTGMIHRYiX2efdjz1Z9jck0DK9W3mapFrBPvM7AlRni4lPlwUigDd8zxAMDCheqyK3vCOLFW-1xYHt_YGwv8b0dP7rjujarEYlWjeppO_QMNtXdKdT9eZtBEcj_9ms9W0aLdCFNR5AAR3y0kLkKR1H4DW7vncB46rqCJLenhlCbcW0MZ3asqcjqBQ2t9QMRnY83Zf_pNEsCcXlKp4uOQqEvzjAc9ZSr2sOmd_ESZ_3jMlNkCZ4J41TuG-My5illFcW5LajSKvxD3w",
                "alg": "RS256"
            }"#,
        ];
        pub fn jwks(is_valid: bool) -> Vec<Jwk> {
            match is_valid {
                true => GOOGLE_JWK_JSON_LIST
                    .into_iter()
                    .map(|s| jwk_from_slice(s.as_bytes()).expect("Test case muse be a valid jwk"))
                    .collect(),
                false => WRONG_GOOGLE_JWK_JSON_LIST
                    .into_iter()
                    .map(|s| jwk_from_slice(s.as_bytes()).expect("Test case muse be a valid jwk"))
                    .collect(),
            }
        }

        pub fn kids(is_valid: bool) -> Vec<Kid> {
            jwks(is_valid)
                .into_iter()
                .map(|jwk| jwk.prm.kid.expect("Test case JWK must has kid").as_bytes().to_vec())
                .collect()
        }
    }
    pub mod valid_affine {
        use crate::circom::{StrCircomG1, StrCircomG2};
        pub const VK_ALPHA_1: StrCircomG1 = [
            "21529901943976716921335152104180790524318946701278905588288070441048877064089",
            "7775817982019986089115946956794180159548389285968353014325286374017358010641",
            "1",
        ];

        pub const VK_BETA_2: StrCircomG2 = [
            [
                "6600437987682835329040464538375790690815756241121776438004683031791078085074",
                "16207344858883952201936462217289725998755030546200154201671892670464461194903",
            ],
            [
                "17943105074568074607580970189766801116106680981075272363121544016828311544390",
                "18339640667362802607939727433487930605412455701857832124655129852540230493587",
            ],
            ["1", "0"],
        ];

        pub const VK_GAMMA_2: StrCircomG2 = [
            [
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            ],
            [
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            ],
            ["1", "0"],
        ];

        pub const VK_DELTA_2: StrCircomG2 = [
            [
                "19260309516619721648285279557078789954438346514188902804737557357941293711874",
                "2480422554560175324649200374556411861037961022026590718777465211464278308900",
            ],
            [
                "14489104692423540990601374549557603533921811847080812036788172274404299703364",
                "12564378633583954025611992187142343628816140907276948128970903673042690269191",
            ],
            ["1", "0"],
        ];

        pub const E: [StrCircomG1; 2] = [
            [
                "1607694606386445293170795095076356565829000940041894770459712091642365695804",
                "18066827569413962196795937356879694709963206118612267170825707780758040578649",
                "1",
            ],
            [
                "20653794344898475822834426774542692225449366952113790098812854265588083247207",
                "3296759704176575765409730962060698204792513807296274014163938591826372646699",
                "1",
            ],
        ];
        pub const INVALID_VALUES: [&'static str; 3] = ["123456789", "987654321", "1"];
        pub const INVALID_TYPE_VALUES: [&'static str; 3] = ["hello", "world", "kzero"];
    }
    pub mod poseidon_hash {
        // This is calculated by the poseidon hash code, you can check this via `https://www.poseidon-hash.info/``
        pub const POSEIDON_1: &str =
            "18586133768512220936620570745912940619677854269274689475585506675881198879027";
        pub const POSEIDON_1_2: &str =
            "7853200120776062878684798364095072458815029376092732009249414926327459813530";
        pub const POSEIDON_1_TO_15: &str =
            "4203130618016961831408770638653325366880478848856764494148034853759773445968";
        pub const POSEIDON_1_TO_16: &str =
            "9989051620750914585850546081941653841776809718687451684622678807385399211877";
        pub const POSEIDON_0_TO_29: &str =
            "4123755143677678663754455867798672266093104048057302051129414708339780424023";
        pub const POSEIDON_0_TO_32: &str =
            "15368023340287843142129781602124963668572853984788169144128906033251913623349";
    }
}
