use crate::{
    circom::{
        unsafe_g1_affine_from_str_projective, unsafe_g2_affine_from_str_projective, StrCircomG1,
        StrCircomG2,
    },
    test_helper::{
        get_raw_data, get_zklogin_inputs,
        test_cases::{
            google,
            poseidon_hash::{
                POSEIDON_0_TO_29, POSEIDON_0_TO_32, POSEIDON_1, POSEIDON_1_2, POSEIDON_1_TO_15,
                POSEIDON_1_TO_16,
            },
            valid_affine::{
                E, INVALID_TYPE_VALUES, INVALID_VALUES, VK_ALPHA_1, VK_BETA_2, VK_DELTA_2,
                VK_GAMMA_2,
            },
        },
    },
    traits::TryIntoEphPubKey,
    JwkProvider, ZkMaterial, ZkMaterialV1,
};
use ark_bn254::Bn254;
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};
use num_bigint::BigUint;
use rand;
use sp_core::H256;

// ================================ Test cases for affine points on the curve ================================
#[test]
fn test_valid_affine_should_be_on_curve() {
    let valid_vk_alpha_1 = StrCircomG1::from(VK_ALPHA_1);
    let vk_alpha_1 = unsafe_g1_affine_from_str_projective(&valid_vk_alpha_1);
    assert!(vk_alpha_1.is_on_curve());

    let valid_vk_beta_2 = StrCircomG2::from(VK_BETA_2);
    let vk_beta_2 = unsafe_g2_affine_from_str_projective(&valid_vk_beta_2);
    assert!(vk_beta_2.is_on_curve());

    let valid_vk_gamma_2 = StrCircomG2::from(VK_GAMMA_2);
    let vk_gamma_2 = unsafe_g2_affine_from_str_projective(&valid_vk_gamma_2);
    assert!(vk_gamma_2.is_on_curve());

    let valid_vk_delta_2 = StrCircomG2::from(VK_DELTA_2);
    let vk_delta_2 = unsafe_g2_affine_from_str_projective(&valid_vk_delta_2);
    assert!(vk_delta_2.is_on_curve());

    let vk_gamma_abc_g1 =
        E.iter().map(|e| unsafe_g1_affine_from_str_projective(e)).collect::<Vec<_>>();
    for point in &vk_gamma_abc_g1 {
        assert!(point.is_on_curve());
    }

    let vk = VerifyingKey {
        alpha_g1: vk_alpha_1,
        beta_g2: vk_beta_2,
        gamma_g2: vk_gamma_2,
        delta_g2: vk_delta_2,
        gamma_abc_g1: vk_gamma_abc_g1,
    };

    // Convert the verifying key into the prepared form.
    let pvk = PreparedVerifyingKey::<Bn254>::from(vk);
    assert!(pvk.vk.alpha_g1.is_on_curve());
    assert!(pvk.vk.beta_g2.is_on_curve());
    assert!(pvk.vk.gamma_g2.is_on_curve());
    assert!(pvk.vk.delta_g2.is_on_curve());
    for point in &pvk.vk.gamma_abc_g1 {
        assert!(point.is_on_curve());
    }
}

#[test]
fn test_invalid_affine_should_not_be_on_curve() {
    // Create an invalid point by using values that won't be on the curve
    let invalid_vk_alpha_1 = StrCircomG1::from(INVALID_VALUES);
    let vk_alpha_1 = unsafe_g1_affine_from_str_projective(&invalid_vk_alpha_1);
    assert!(!vk_alpha_1.is_on_curve());

    // Create an invalid point by using values that won't be on the curve
    let invalid_vk_alpha_1 = StrCircomG1::from([VK_ALPHA_1[0], INVALID_VALUES[1], VK_ALPHA_1[2]]);
    let vk_alpha_1 = unsafe_g1_affine_from_str_projective(&invalid_vk_alpha_1);
    assert!(!vk_alpha_1.is_on_curve());
}

#[test]
fn test_invalid_affine_type_should_be_rejected() {
    let invalid_vk_alpha_1 = StrCircomG1::from(INVALID_TYPE_VALUES);
    // This should panic with the message "String must be an valid number."
    let result =
        std::panic::catch_unwind(|| unsafe_g1_affine_from_str_projective(&invalid_vk_alpha_1));
    assert!(result.is_err());

    // Verify that the panic message contains the expected text
    if let Err(e) = result {
        // The panic message can be either a String or a &str, so we need to check both types
        let panic_message = e
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| e.downcast_ref::<&str>().copied());

        match panic_message {
            Some(msg) => assert!(msg.contains("String must be an valid number.")),
            None => panic!("Unexpected panic type"),
        }
    }
}

// ================================ Test cases for poseidon hash ================================
use crate::poseidon::poseidon_merkle_tree;
use ark_bn254::Fr;

fn to_bigint_arr(vals: Vec<u8>) -> Vec<Fr> {
    vals.into_iter().map(Fr::from).collect()
}

#[test]
fn test_to_poseidon_hash() {
    assert!(poseidon_merkle_tree(to_bigint_arr(vec![])).is_err());
    assert_eq!(poseidon_merkle_tree(to_bigint_arr(vec![1])).unwrap().to_string(), POSEIDON_1);
    assert_eq!(poseidon_merkle_tree(to_bigint_arr(vec![1, 2])).unwrap().to_string(), POSEIDON_1_2);
    assert_eq!(
        poseidon_merkle_tree(to_bigint_arr(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
        ]))
        .unwrap()
        .to_string(),
        POSEIDON_1_TO_15
    );
    assert_eq!(
        poseidon_merkle_tree(to_bigint_arr(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        ]))
        .unwrap()
        .to_string(),
        POSEIDON_1_TO_16
    );
    assert_eq!(
        poseidon_merkle_tree(to_bigint_arr(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29
        ]))
        .unwrap()
        .to_string(),
        POSEIDON_0_TO_29
    );
    assert_eq!(
        poseidon_merkle_tree(to_bigint_arr(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32
        ]))
        .unwrap()
        .to_string(),
        POSEIDON_0_TO_32
    );
}

// ================================ Test cases for traits part ================================
use sp_core::crypto::AccountId32;
use sp_runtime::MultiAddress;

#[test]
fn test_try_into_eph_pubkey() {
    // Test AccountId32 (should work)
    let account_id = AccountId32::new([1; 32]);
    let result = account_id.try_into_eph_key();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), [1; 32]);

    // Test MultiAddress::Id (should work)
    let multi_address: MultiAddress<AccountId32, u32> = MultiAddress::Id(account_id);
    let result = multi_address.try_into_eph_key();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), [1; 32]);

    // Test MultiAddress::Index (should fail)
    let multi_address: MultiAddress<AccountId32, u32> = MultiAddress::Index(1);
    let result = multi_address.try_into_eph_key();
    assert!(result.is_err());

    // Test MultiAddress::Raw (should work)
    let raw = [1; 32];
    let multi_address: MultiAddress<AccountId32, u8> = MultiAddress::Raw(raw.to_vec());
    let result = multi_address.try_into_eph_key();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), raw);

    // Test MultiAddress::Raw (should fail)
    let empty: &[u8] = &[];
    let multi_address: MultiAddress<AccountId32, u8> = MultiAddress::Raw(empty.to_vec());
    let result = multi_address.try_into_eph_key();
    assert!(result.is_err());

    // Test input too long
    let too_long = vec![1; 33];
    let multi_address: MultiAddress<AccountId32, u8> = MultiAddress::Raw(too_long);
    let result = multi_address.try_into_eph_key();
    assert!(result.is_err());

    // Test MultiAddress::Address32 (should work)
    let address32 = [1; 32];
    let multi_address: MultiAddress<AccountId32, u8> = MultiAddress::Address32(address32);
    let result = multi_address.try_into_eph_key();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), address32);

    // Test MultiAddress::Address20 (should work)
    let address20 = [1; 20];
    let multi_address: MultiAddress<AccountId32, u8> = MultiAddress::Address20(address20);
    let result = multi_address.try_into_eph_key();
    assert!(result.is_ok());
    let mut expected = [0u8; 32];
    expected[0..20].copy_from_slice(&address20);
    assert_eq!(result.unwrap(), expected);
}

// ================================ Test cases for utils ================================
use crate::utils::hash_to_field;
#[test]
fn test_hash_to_field() {
    let input = vec![BigUint::from(5u32)];
    let result = hash_to_field(&input, 4, 2);
    assert!(result.is_ok());
}

#[test]
#[should_panic(expected = "chunk size must be non-zero")]
fn test_hash_to_field_overflow() {
    let input = vec![BigUint::from(5u32)];
    let _ = hash_to_field(&input, 4, 0); // This should panic with overflow
}

// ================================ Test cases for zklogin ================================
#[test]
fn verify_zklogin() {
    let (address_seed, input_data, max_epoch, eph_pubkey) = get_raw_data();
    let input = get_zklogin_inputs(input_data);

    let kids = google::kids(true);
    let jwks = google::jwks(true);

    let kid = kids[0].clone();
    let jwk = jwks[0].clone();

    let zk_material: ZkMaterial<u64> =
        ZkMaterialV1::new(JwkProvider::Google, kid, input, max_epoch).into();
    let zklogin_result = zk_material.verify_zk_login(eph_pubkey, &address_seed, &jwk);

    assert!(zklogin_result.is_ok())
}

#[test]
fn zk_login_should_fail_when_jwk_not_match() {
    let (address_seed, input_data, max_epoch, eph_pubkey) = get_raw_data();
    let input = get_zklogin_inputs(input_data);

    let kids = google::kids(false);
    let jwks = google::jwks(false);

    let kid = kids[0].clone();
    let jwk = jwks[0].clone();

    let zk_material: ZkMaterial<u64> =
        ZkMaterialV1::new(JwkProvider::Google, kid, input, max_epoch).into();
    let zklogin_result = zk_material.verify_zk_login(eph_pubkey, &address_seed, &jwk);

    assert!(zklogin_result.is_err())
}

#[test]
fn zk_login_should_fail_when_eph_pubkey_not_match() {
    let (address_seed, input_data, max_epoch, _) = get_raw_data();
    let input = get_zklogin_inputs(input_data);

    let kids = google::kids(true);
    let jwks = google::jwks(true);

    let kid = kids[0].clone();
    let jwk = jwks[0].clone();

    let invalid_eph_pubkey = [u8::try_from(rand::random::<u8>()).unwrap_or(0); 32];
    let zk_material: ZkMaterial<u64> =
        ZkMaterialV1::new(JwkProvider::Google, kid, input, max_epoch).into();
    let zklogin_result = zk_material.verify_zk_login(invalid_eph_pubkey, &address_seed, &jwk);

    assert!(zklogin_result.is_err())
}

#[test]
fn zk_login_should_fail_when_max_epoch_not_match() {
    let (address_seed, input_data, _, eph_pubkey) = get_raw_data();
    let input = get_zklogin_inputs(input_data);

    let kids = google::kids(false);
    let jwks = google::jwks(false);

    let kid = kids[0].clone();
    let jwk = jwks[0].clone();

    let invalid_max_epoch = rand::random::<u64>() % 501; // Random number between 0-500
    let zk_material: ZkMaterial<u64> =
        ZkMaterialV1::new(JwkProvider::Google, kid, input, invalid_max_epoch).into();
    let zklogin_result = zk_material.verify_zk_login(eph_pubkey, &address_seed, &jwk);

    assert!(zklogin_result.is_err())
}

#[test]
fn zk_login_should_fail_when_address_seed_not_match() {
    let (_, input_data, max_epoch, eph_pubkey) = get_raw_data();
    let input = get_zklogin_inputs(input_data);

    let kids = google::kids(true);
    let jwks = google::jwks(true);

    let kid = kids[0].clone();
    let jwk = jwks[0].clone();

    let random_seed = [u8::try_from(rand::random::<u8>()).unwrap_or(0); 32];
    let invalid_address_seed = H256::from(random_seed);

    let zk_material: ZkMaterial<u64> =
        ZkMaterialV1::new(JwkProvider::Google, kid, input, max_epoch).into();
    let zklogin_result = zk_material.verify_zk_login(eph_pubkey, &invalid_address_seed, &jwk);

    assert!(zklogin_result.is_err())
}
