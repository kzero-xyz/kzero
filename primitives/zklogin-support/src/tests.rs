use crate::{
    jwk::{JWKProvider, JwkId},
    test_helper::{
        build_auth_data, get_raw_data, get_raw_data_from_json, get_zklogin_inputs,
        get_zklogin_inputs_with_infinity, CircomBuilder, CircomConfig, ZkInputResult,
        ZkMaterialWithInfinity,
    },
    Groth16, ZkMaterial,
};
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sp_core::{bounded::BoundedVec, ConstU32};
type GrothBn = Groth16<Bn254>;

#[test]
fn verify_zklogin() {
    let (address_seed, input_data, max_epoch, eph_pubkey_bytes) = get_raw_data();
    let input = get_zklogin_inputs(input_data);

    let google_kid = "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781";
    let google_jwk_id = JwkId::new(
        JWKProvider::Google,
        BoundedVec::<u8, ConstU32<256>>::truncate_from(google_kid.as_bytes().to_vec()),
    );

    let zk_material = ZkMaterial::new(google_jwk_id, input, max_epoch, eph_pubkey_bytes);
    let zklogin_result = zk_material.verify_zk_login_in_prod(&address_seed);

    assert!(zklogin_result.is_ok());
}

#[test]
fn verify_zklogin_from_prove() {
    // Import inputs.json
    let inputs_json: &str = include_str!("../test-circuits/test_input.json");

    // // Load the WASM and R1CS for witness and proof generation
    let cfg =
        CircomConfig::<Bn254>::new("./test-circuits/zkLogin.wasm", "./test-circuits/zkLogin.r1cs")
            .unwrap();

    // Insert our tes-zkInputResult
    let mut builder = CircomBuilder::new(cfg);
    let zk_input_result = ZkInputResult::from_json(inputs_json).unwrap();
    zk_input_result.push_circom_input(&mut builder);

    // Create an empty instance for setting it up
    let circom = builder.setup();

    // Run a trusted setup via a setted test rng
    let seed: [u8; 32] = [1; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

    // Get the populated instance of the circuit with the witness
    println!("Generating witness and inputs...");
    let start = std::time::Instant::now();
    let circom = builder.build().unwrap();
    let end = std::time::Instant::now();
    println!("Witness generation time: {} ms", (end - start).as_millis());

    // Generate the proof
    println!("Generating proof...");
    let start = std::time::Instant::now();
    let proof = GrothBn::prove(&params, circom, &mut rng).unwrap();
    let end = std::time::Instant::now();
    println!("Proof generation time: {} ms", (end - start).as_millis());

    let user_sub = "111140461530246164526";
    let (address_seed, max_epoch, eph_pubkey_bytes) = get_raw_data_from_json(inputs_json, user_sub);

    let (header, value, index_mod_4) = build_auth_data(inputs_json);

    let input = get_zklogin_inputs_with_infinity(proof, header, value, index_mod_4);

    let google_kid = "85e55107466b7e29836199c58c7581f5b923be44";
    let google_jwk_id = JwkId::new(
        JWKProvider::Google,
        BoundedVec::<u8, ConstU32<256>>::truncate_from(google_kid.as_bytes().to_vec()),
    );

    let zk_material =
        ZkMaterialWithInfinity::new(google_jwk_id, input, max_epoch, eph_pubkey_bytes);

    let zklogin_result = zk_material.verify_zk_login_in_simple_test(&address_seed);

    assert!(zklogin_result.is_ok());
}
