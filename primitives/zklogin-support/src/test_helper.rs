use crate::{
    error::{ZkAuthError, ZkAuthResult},
    poseidon::poseidon_zk_login,
    zk_input::{Bn254Fr, Claim, ZkLoginInputs, ZkLoginProof},
    PACK_WIDTH,
};
use ark_bn254::Bn254;
#[cfg(test)]
use ark_circom::circom::{R1CSFile, R1CS};
#[cfg(test)]
use ark_circom::{CircomCircuit, WitnessCalculator};
#[cfg(test)]
use ark_ec::pairing::Pairing;
use ark_ff::{ToConstraintField, Zero};
use ark_groth16::Proof;
#[cfg(test)]
use color_eyre::Result;
use num_bigint::{BigInt, BigUint};
use serde::{de::Error, Deserialize, Serialize};
use serde_json::{self, json};
use sp_core::{crypto::AccountId32, ed25519::Pair as Ed25519Pair, Pair, U256};
use std::{collections::HashMap, str::FromStr};
#[cfg(test)]
use std::{fs::File, path::Path};

const MAX_KEY_CLAIM_NAME_LENGTH: u8 = 32;
const MAX_KEY_CLAIM_VALUE_LENGTH: u8 = 115;
const MAX_AUD_VALUE_LENGTH: u8 = 145;

type CircomG1Json = [String; 2];
type CircomG2Json = [[String; 2]; 2];
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
        let convert = |s: &str| U256::from_dec_str(s).expect("");

        let a = [convert(&value.a[0]), convert(&value.a[1])];
        let b = [
            [convert(&value.b[0][0]), convert(&value.b[0][1])],
            [convert(&value.b[1][0]), convert(&value.b[1][1])],
        ];
        let c = [convert(&value.c[0]), convert(&value.c[1])];
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

const MAX_HEADER_LEN: u8 = 248;
const MAX_EXT_ISS_LEN: u8 = 165;
const MAX_ISS_LEN_B64: u8 = 4 * (1 + MAX_EXT_ISS_LEN / 3);

const ALL_INPUTS_HASH: &str = "all_inputs_hash";
const AUD_COLON_INDEX: &str = "aud_colon_index";
const AUD_INDEX_B64: &str = "aud_index_b64";
const AUD_LENGTH_B64: &str = "aud_length_b64";
const AUD_VALUE_INDEX: &str = "aud_value_index";
const AUD_VALUE_LENGTH: &str = "aud_value_length";
const EPH_PUBLIC_KEY: &str = "eph_public_key";
const EV_COLON_INDEX: &str = "ev_colon_index";
const EV_INDEX_B64: &str = "ev_index_b64";
const EV_LENGTH_B64: &str = "ev_length_b64";
const EV_NAME_LENGTH: &str = "ev_name_length";
const EV_VALUE_INDEX: &str = "ev_value_index";
const EV_VALUE_LENGTH: &str = "ev_value_length";
const EXT_AUD: &str = "ext_aud";
const EXT_AUD_LENGTH: &str = "ext_aud_length";
const EXT_EV: &str = "ext_ev";
const EXT_EV_LENGTH: &str = "ext_ev_length";
const EXT_KC: &str = "ext_kc";
const EXT_KC_LENGTH: &str = "ext_kc_length";
const EXT_NONCE: &str = "ext_nonce";
const EXT_NONCE_LENGTH: &str = "ext_nonce_length";
const ISS_INDEX_B64: &str = "iss_index_b64";
const ISS_LENGTH_B64: &str = "iss_length_b64";
const JWT_RANDOMNESS: &str = "jwt_randomness";
const KC_COLON_INDEX: &str = "kc_colon_index";
const KC_INDEX_B64: &str = "kc_index_b64";
const KC_LENGTH_B64: &str = "kc_length_b64";
const KC_NAME_LENGTH: &str = "kc_name_length";
const KC_VALUE_INDEX: &str = "kc_value_index";
const KC_VALUE_LENGTH: &str = "kc_value_length";
const MAX_EPOCH: &str = "max_epoch";
const MODULUS: &str = "modulus";
const NONCE_COLON_INDEX: &str = "nonce_colon_index";
const NONCE_INDEX_B64: &str = "nonce_index_b64";
const NONCE_LENGTH_B64: &str = "nonce_length_b64";
const NONCE_VALUE_INDEX: &str = "nonce_value_index";
const NUM_SHA2_BLOCKS: &str = "num_sha2_blocks";
const PADDED_UNSIGNED_JWT: &str = "padded_unsigned_jwt";
const PAYLOAD_LEN: &str = "payload_len";
const PAYLOAD_START_INDEX: &str = "payload_start_index";
const SALT: &str = "salt";
const SIGNATURE: &str = "signature";
const INPUTS: &str = "inputs";
const AUTHFIELDS: &str = "authFields";
const HEADER_BASE64: &str = "headerBase64";
const ISS_BASE64_DETAILS: &str = "issBase64Details";
const VALUE: &str = "value";
const INDEX_MOD4: &str = "indexMod4";

pub struct ZkInputResult {
    pub all_inputs_hash: num_bigint::BigInt,
    pub aud_colon_index: num_bigint::BigInt,
    pub aud_index_b64: num_bigint::BigInt,
    pub aud_length_b64: num_bigint::BigInt,
    pub aud_value_index: num_bigint::BigInt,
    pub aud_value_length: num_bigint::BigInt,
    pub eph_public_key: Vec<num_bigint::BigInt>,
    pub ev_colon_index: num_bigint::BigInt,
    pub ev_index_b64: num_bigint::BigInt,
    pub ev_length_b64: num_bigint::BigInt,
    pub ev_name_length: num_bigint::BigInt,
    pub ev_value_index: num_bigint::BigInt,
    pub ev_value_length: num_bigint::BigInt,
    pub ext_aud: Vec<num_bigint::BigInt>,
    pub ext_aud_length: num_bigint::BigInt,
    pub ext_ev: Vec<num_bigint::BigInt>,
    pub ext_ev_length: num_bigint::BigInt,
    pub ext_kc: Vec<num_bigint::BigInt>,
    pub ext_kc_length: num_bigint::BigInt,
    pub ext_nonce: Vec<num_bigint::BigInt>,
    pub ext_nonce_length: num_bigint::BigInt,
    pub iss_index_b64: num_bigint::BigInt,
    pub iss_length_b64: num_bigint::BigInt,
    pub jwt_randomness: num_bigint::BigInt,
    pub kc_colon_index: num_bigint::BigInt,
    pub kc_index_b64: num_bigint::BigInt,
    pub kc_length_b64: num_bigint::BigInt,
    pub kc_name_length: num_bigint::BigInt,
    pub kc_value_index: num_bigint::BigInt,
    pub kc_value_length: num_bigint::BigInt,
    pub max_epoch: num_bigint::BigInt,
    pub modulus: Vec<num_bigint::BigInt>,
    pub nonce_colon_index: num_bigint::BigInt,
    pub nonce_index_b64: num_bigint::BigInt,
    pub nonce_length_b64: num_bigint::BigInt,
    pub nonce_value_index: num_bigint::BigInt,
    pub num_sha2_blocks: num_bigint::BigInt,
    pub padded_unsigned_jwt: Vec<num_bigint::BigInt>,
    pub payload_len: num_bigint::BigInt,
    pub payload_start_index: num_bigint::BigInt,
    pub salt: num_bigint::BigInt,
    pub signature: Vec<num_bigint::BigInt>,
}

fn parse_bigint_from_json(
    inputs: &serde_json::Value,
    field: &str,
) -> Result<num_bigint::BigInt, serde_json::Error> {
    match inputs.get(field).and_then(|v| v.as_str()) {
        Some(value) => num_bigint::BigInt::from_str(value).map_err(|_| {
            serde_json::Error::custom(format!("Failed to parse field {} to BigInt", field))
        }),
        None => Err(serde_json::Error::custom(format!("Fail to parse field {}", field))),
    }
}

fn parse_bigint_vec_from_json(
    inputs: &serde_json::Value,
    field: &str,
) -> Result<Vec<num_bigint::BigInt>, serde_json::Error> {
    let array = inputs
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::custom(format!("Field {} not found or not an array", field)))?;

    let mut vec = Vec::with_capacity(array.len());
    for i in 0..array.len() {
        let value_str = array[i].as_str().ok_or_else(|| {
            Error::custom(format!("Field {} Array element is not a string", field))
        })?;
        let bigint = num_bigint::BigInt::from_str(value_str)
            .map_err(|_| Error::custom(format!("Failed to parse Field {} BigInt", field)))?;
        vec.push(bigint);
    }
    Ok(vec)
}

impl ZkInputResult {
    #[allow(unused)]
    pub fn from_json(inputs: &str) -> Result<Self, serde_json::Error> {
        let whole_inputs_json: &serde_json::Value = &serde_json::from_str(inputs)?;
        let inputs_json: &serde_json::Value = whole_inputs_json.get("inputs").unwrap();
        return Ok(ZkInputResult {
            all_inputs_hash: parse_bigint_from_json(inputs_json, ALL_INPUTS_HASH)?,
            aud_colon_index: parse_bigint_from_json(inputs_json, AUD_COLON_INDEX)?,
            aud_index_b64: parse_bigint_from_json(inputs_json, AUD_INDEX_B64)?,
            aud_length_b64: parse_bigint_from_json(inputs_json, AUD_LENGTH_B64)?,
            aud_value_index: parse_bigint_from_json(inputs_json, AUD_VALUE_INDEX)?,
            aud_value_length: parse_bigint_from_json(inputs_json, AUD_VALUE_LENGTH)?,
            eph_public_key: parse_bigint_vec_from_json(inputs_json, EPH_PUBLIC_KEY)?,
            ev_colon_index: parse_bigint_from_json(inputs_json, EV_COLON_INDEX)?,
            ev_index_b64: parse_bigint_from_json(inputs_json, EV_INDEX_B64)?,
            ev_length_b64: parse_bigint_from_json(inputs_json, EV_LENGTH_B64)?,
            ev_name_length: parse_bigint_from_json(inputs_json, EV_NAME_LENGTH)?,
            ev_value_index: parse_bigint_from_json(inputs_json, EV_VALUE_INDEX)?,
            ev_value_length: parse_bigint_from_json(inputs_json, EV_VALUE_LENGTH)?,
            ext_aud: parse_bigint_vec_from_json(inputs_json, EXT_AUD)?,
            ext_aud_length: parse_bigint_from_json(inputs_json, EXT_AUD_LENGTH)?,
            ext_ev: parse_bigint_vec_from_json(inputs_json, EXT_EV)?,
            ext_ev_length: parse_bigint_from_json(inputs_json, EXT_EV_LENGTH)?,
            ext_kc: parse_bigint_vec_from_json(inputs_json, EXT_KC)?,
            ext_kc_length: parse_bigint_from_json(inputs_json, EXT_KC_LENGTH)?,
            ext_nonce: parse_bigint_vec_from_json(inputs_json, EXT_NONCE)?,
            ext_nonce_length: parse_bigint_from_json(inputs_json, EXT_NONCE_LENGTH)?,
            iss_index_b64: parse_bigint_from_json(inputs_json, ISS_INDEX_B64)?,
            iss_length_b64: parse_bigint_from_json(inputs_json, ISS_LENGTH_B64)?,
            jwt_randomness: parse_bigint_from_json(inputs_json, JWT_RANDOMNESS)?,
            kc_colon_index: parse_bigint_from_json(inputs_json, KC_COLON_INDEX)?,
            kc_index_b64: parse_bigint_from_json(inputs_json, KC_INDEX_B64)?,
            kc_length_b64: parse_bigint_from_json(inputs_json, KC_LENGTH_B64)?,
            kc_name_length: parse_bigint_from_json(inputs_json, KC_NAME_LENGTH)?,
            kc_value_index: parse_bigint_from_json(inputs_json, KC_VALUE_INDEX)?,
            kc_value_length: parse_bigint_from_json(inputs_json, KC_VALUE_LENGTH)?,
            max_epoch: parse_bigint_from_json(inputs_json, MAX_EPOCH)?,
            modulus: parse_bigint_vec_from_json(inputs_json, MODULUS)?,
            nonce_colon_index: parse_bigint_from_json(inputs_json, NONCE_COLON_INDEX)?,
            nonce_index_b64: parse_bigint_from_json(inputs_json, NONCE_INDEX_B64)?,
            nonce_length_b64: parse_bigint_from_json(inputs_json, NONCE_LENGTH_B64)?,
            nonce_value_index: parse_bigint_from_json(inputs_json, NONCE_VALUE_INDEX)?,
            num_sha2_blocks: parse_bigint_from_json(inputs_json, NUM_SHA2_BLOCKS)?,
            padded_unsigned_jwt: parse_bigint_vec_from_json(inputs_json, PADDED_UNSIGNED_JWT)?,
            payload_len: parse_bigint_from_json(inputs_json, PAYLOAD_LEN)?,
            payload_start_index: parse_bigint_from_json(inputs_json, PAYLOAD_START_INDEX)?,
            salt: parse_bigint_from_json(inputs_json, SALT)?,
            signature: parse_bigint_vec_from_json(inputs_json, SIGNATURE)?,
        });
    }
    #[cfg(test)]
    #[allow(unused)]
    pub fn push_circom_input<E: Pairing>(self, builder: &mut CircomBuilder<E>) {
        builder.push_input(ALL_INPUTS_HASH, self.all_inputs_hash);
        builder.push_input(AUD_COLON_INDEX, self.aud_colon_index);
        builder.push_input(AUD_INDEX_B64, self.aud_index_b64);
        builder.push_input(AUD_LENGTH_B64, self.aud_length_b64);
        builder.push_input(AUD_VALUE_INDEX, self.aud_value_index);
        builder.push_input(AUD_VALUE_LENGTH, self.aud_value_length);
        builder.push_input_vec(EPH_PUBLIC_KEY, self.eph_public_key);
        builder.push_input(EV_COLON_INDEX, self.ev_colon_index);
        builder.push_input(EV_INDEX_B64, self.ev_index_b64);
        builder.push_input(EV_LENGTH_B64, self.ev_length_b64);
        builder.push_input(EV_NAME_LENGTH, self.ev_name_length);
        builder.push_input(EV_VALUE_INDEX, self.ev_value_index);
        builder.push_input(EV_VALUE_LENGTH, self.ev_value_length);
        builder.push_input_vec(EXT_AUD, self.ext_aud);
        builder.push_input(EXT_AUD_LENGTH, self.ext_aud_length);
        builder.push_input_vec(EXT_EV, self.ext_ev);
        builder.push_input(EXT_EV_LENGTH, self.ext_ev_length);
        builder.push_input_vec(EXT_KC, self.ext_kc);
        builder.push_input(EXT_KC_LENGTH, self.ext_kc_length);
        builder.push_input_vec(EXT_NONCE, self.ext_nonce);
        builder.push_input(EXT_NONCE_LENGTH, self.ext_nonce_length);
        builder.push_input(ISS_INDEX_B64, self.iss_index_b64);
        builder.push_input(ISS_LENGTH_B64, self.iss_length_b64);
        builder.push_input(JWT_RANDOMNESS, self.jwt_randomness);
        builder.push_input(KC_COLON_INDEX, self.kc_colon_index);
        builder.push_input(KC_INDEX_B64, self.kc_index_b64);
        builder.push_input(KC_LENGTH_B64, self.kc_length_b64);
        builder.push_input(KC_NAME_LENGTH, self.kc_name_length);
        builder.push_input(KC_VALUE_INDEX, self.kc_value_index);
        builder.push_input(KC_VALUE_LENGTH, self.kc_value_length);
        builder.push_input(MAX_EPOCH, self.max_epoch);
        builder.push_input_vec(MODULUS, self.modulus);
        builder.push_input(NONCE_COLON_INDEX, self.nonce_colon_index);
        builder.push_input(NONCE_INDEX_B64, self.nonce_index_b64);
        builder.push_input(NONCE_LENGTH_B64, self.nonce_length_b64);
        builder.push_input(NONCE_VALUE_INDEX, self.nonce_value_index);
        builder.push_input(NUM_SHA2_BLOCKS, self.num_sha2_blocks);
        builder.push_input_vec(PADDED_UNSIGNED_JWT, self.padded_unsigned_jwt);
        builder.push_input(PAYLOAD_LEN, self.payload_len);
        builder.push_input(PAYLOAD_START_INDEX, self.payload_start_index);
        builder.push_input(SALT, self.salt);
        builder.push_input_vec(SIGNATURE, self.signature);
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub struct CircomBuilder<E: Pairing> {
    pub cfg: CircomConfig<E>,
    pub inputs: HashMap<String, Vec<BigInt>>,
}

// Add utils for creating this from files / directly from bytes
#[derive(Clone, Debug)]
#[cfg(test)]
pub struct CircomConfig<E: Pairing> {
    pub r1cs: R1CS<E>,
    pub wtns: WitnessCalculator,
    pub sanity_check: bool,
}

#[cfg(test)]
impl<E: Pairing> CircomConfig<E> {
    pub fn new(wtns: impl AsRef<Path>, r1cs: impl AsRef<Path>) -> Result<Self> {
        let wtns = WitnessCalculator::new(wtns).unwrap();
        let reader = File::open(r1cs)?;
        let r1cs = R1CSFile::new(reader)?.into();
        Ok(Self { wtns, r1cs, sanity_check: false })
    }
}
#[cfg(test)]
impl<E: Pairing> CircomBuilder<E> {
    /// Instantiates a new builder using the provided WitnessGenerator and R1CS files
    /// for your circuit
    pub fn new(cfg: CircomConfig<E>) -> Self {
        Self { cfg, inputs: HashMap::new() }
    }

    /// Pushes a Circom input at the specified name.
    pub fn push_input<T: Into<BigInt>>(&mut self, name: impl ToString, val: T) {
        let values = self.inputs.entry(name.to_string()).or_insert_with(Vec::new);
        values.push(val.into());
    }

    /// Pushes a Circom input with multiple values at the specified name.
    pub fn push_input_vec(&mut self, name: impl ToString, val: Vec<BigInt>) {
        let values = self.inputs.entry(name.to_string()).or_insert_with(Vec::new);
        for v in val {
            values.push(v.into());
        }
    }

    /// Generates an empty circom circuit with no witness set, to be used for
    /// generation of the trusted setup parameters
    pub fn setup(&self) -> CircomCircuit<E> {
        let mut circom = CircomCircuit { r1cs: self.cfg.r1cs.clone(), witness: None };

        // Disable the wire mapping
        circom.r1cs.wire_mapping = None;

        circom
    }

    /// Creates the circuit populated with the witness corresponding to the previously
    /// provided inputs
    pub fn build(mut self) -> Result<CircomCircuit<E>> {
        let mut circom = self.setup();

        // calculate the witness
        let witness = self
            .cfg
            .wtns
            .calculate_witness_element::<E, _>(self.inputs, self.cfg.sanity_check)?;
        circom.witness = Some(witness);

        // sanity check
        debug_assert!({
            use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
            let cs = ConstraintSystem::<E::ScalarField>::new_ref();
            circom.clone().generate_constraints(cs.clone()).unwrap();
            let is_satisfied = cs.is_satisfied().unwrap();
            if !is_satisfied {
                println!("Unsatisfied constraint: {:?}", cs.which_is_unsatisfied().unwrap());
            }

            is_satisfied
        });

        Ok(circom)
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

pub fn get_raw_data_from_json(inputs: &str, user_sub: &str) -> (AccountId32, u32, [u8; 32]) {
    let whole_inputs_json: &serde_json::Value = &serde_json::from_str(inputs).unwrap();
    let input_json: &serde_json::Value = whole_inputs_json.get(INPUTS).unwrap();

    let user_salt = input_json.get(SALT).and_then(|v| v.as_str()).unwrap();
    let max_epoch: u32 = input_json
        .get(MAX_EPOCH)
        .and_then(|v| v.as_str())
        .unwrap()
        .parse()
        .expect("Failed to parse max_epoch as u32");

    let sub_name = "sub";
    let client_id = "560629365517-mt9j9arflcgi35i8hpoptr66qgo1lmfm.apps.googleusercontent.com";

    let address_seed = gen_address_seed(
        user_salt, sub_name, user_sub,  // sub
        client_id, // clientID
    )
    .unwrap();

    let address_u256 = U256::from_dec_str(&address_seed).expect("");
    let s: [u8; 32] = address_u256.into();
    let address_seed = AccountId32::from(s);
    let eph_pubkey_bytes: [u8; 32] = get_test_eph_key().public().0;

    return (address_seed, max_epoch, eph_pubkey_bytes);
}

pub fn build_proof_points(proof: &Proof<Bn254>, inputs: &str) -> String {
    let whole_inputs_json: &serde_json::Value = &serde_json::from_str(inputs).unwrap();
    let input_json: &serde_json::Value = whole_inputs_json.get(AUTHFIELDS).unwrap();

    let proof_json = convert_proof_to_json(&proof);

    let proof_points_json = json!({
        "a": proof_json.a,
        "b": proof_json.b,
        "c": proof_json.c,
    });

    let header = convert_to_u256(
        hash_ascii_str_to_field(
            input_json.get(HEADER_BASE64).and_then(|v| v.as_str()).unwrap_or_default(),
            MAX_HEADER_LEN,
        )
        .unwrap()
        .into(),
    )
    .to_string();

    let iss_base64_details = input_json.get(ISS_BASE64_DETAILS).unwrap();
    let value = convert_to_u256(
        hash_ascii_str_to_field(
            iss_base64_details.get(VALUE).and_then(|v| v.as_str()).unwrap(),
            MAX_ISS_LEN_B64,
        )
        .unwrap()
        .into(),
    )
    .to_string();
    let index_mod_4 =
        iss_base64_details.get(INDEX_MOD4).and_then(|v| v.as_u64()).unwrap_or_default();

    let iss_base64_details = json!({
        "value": value,
        "index_mod_4": index_mod_4,
    });

    let proof_data = json!({
        "proof_points": proof_points_json,
        "iss_base64_details": iss_base64_details,
        "header": header,
    });

    serde_json::to_string(&proof_data).expect("Failed to convert Value to JSON string")
}

pub fn get_raw_data() -> (AccountId32, String, u32, [u8; 32]) {
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
            "17135816274588842394987740577348746744124536487185243735653495512098467176682"
            ],
            "b": [
            [
            "12007654400896864202053137919011753862685795325094057089804209969395451364237",
            "9292143971825249679511504837978464260231784546642825774684216241262448276692"
            ],
            [
            "2739509173985286250590833064309803350595900462807230565709419062550672100574",
            "9617502836905847049711738720668642526073457745474007398904997426591688823762"
            ]
            ],
            "c": [
            "4236607764644869062435426868625747082828648484430168905284460458292661376562",
            "13765193476064868657640379803797505779241026862161166609423648103540137745710"
            ]
        },
        "iss_base64_details": {
            "value" : "17369902616279740791204861702455537230599532803600308871388405295273096679389",
            "index_mod_4": 1
        },
        "header": "913143068733459984664279033783989157259274322902058410967852973431920544493"
    }"#;

    let max_epoch: u32 = 834;
    let eph_pubkey_bytes: [u8; 32] = get_test_eph_key().public().0;

    return (address_seed, proof_data.to_owned(), max_epoch, eph_pubkey_bytes);
}

pub fn get_zklogin_inputs(proof_data: String) -> ZkLoginInputs {
    let input = ZkLoginInputs::from_json(&proof_data).expect("wrong json parse");
    input
}

fn convert_to_u256<const N: usize>(big_int: ark_ff::BigInt<N>) -> U256 {
    let mut u256 = [0u64; 4];
    // Assuming N <= 4, copy elements from BigInt to U256
    for i in 0..N {
        u256[i] = big_int.0[i];
    }
    U256(u256)
}

pub fn convert_proof_to_json(proof: &Proof<Bn254>) -> ZkLoginProofJson {
    let a0 = convert_to_u256(proof.a.to_field_elements().unwrap()[0].into()).to_string();
    let a1 = convert_to_u256(proof.a.to_field_elements().unwrap()[1].into()).to_string();

    let b0 = convert_to_u256(proof.b.to_field_elements().unwrap()[0].into()).to_string();
    let b1 = convert_to_u256(proof.b.to_field_elements().unwrap()[1].into()).to_string();
    let b2 = convert_to_u256(proof.b.to_field_elements().unwrap()[2].into()).to_string();
    let b3 = convert_to_u256(proof.b.to_field_elements().unwrap()[3].into()).to_string();

    let c0 = convert_to_u256(proof.c.to_field_elements().unwrap()[0].into()).to_string();
    let c1 = convert_to_u256(proof.c.to_field_elements().unwrap()[1].into()).to_string();

    let proof_json = ZkLoginProofJson { a: [a0, a1], b: [[b0, b1], [b2, b3]], c: [c0, c1] };
    return proof_json;
}
