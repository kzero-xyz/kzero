use crate::test_helper::test_cases::valid_affine::{
    E, INVALID_TYPE_VALUES, INVALID_VALUES, VK_ALPHA_1, VK_BETA_2, VK_DELTA_2, VK_GAMMA_2,
};
use crate::{
    circom::{
        unsafe_g1_affine_from_str_projective, unsafe_g2_affine_from_str_projective, StrCircomG1,
        StrCircomG2,
    },
    test_helper::{get_raw_data, get_zklogin_inputs, test_cases::google},
    JwkProvider, ZkMaterial, ZkMaterialV1,
};
use ark_bn254::Bn254;
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};
use num_bigint::BigUint;
use sp_runtime::traits::Clear;
use std::str::FromStr;

#[test]
fn valid_affine_should_be_on_curve() {
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
fn invalid_affine_should_not_be_on_curve() {
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
fn invalid_affine_type_should_be_rejected() {
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

#[test]
fn verify_zklogin() {
    let (address_seed, input_data, max_epoch, eph_pubkey) = get_raw_data();
    let input = get_zklogin_inputs(input_data);

    let kids = google::kids();
    let jwks = google::jwks();

    let kid = kids[0].clone();
    let jwk = jwks[0].clone();

    let zk_material: ZkMaterial<u64> =
        ZkMaterialV1::new(JwkProvider::Google, kid, input, max_epoch).into();
    let zklogin_result = zk_material.verify_zk_login(eph_pubkey, &address_seed, &jwk);

    assert!(zklogin_result.is_ok())
}
