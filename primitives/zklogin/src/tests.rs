use crate::{
    test_helper::{get_raw_data, get_zklogin_inputs, test_cases::google},
    JwkProvider, ZkMaterial, ZkMaterialV1
};

#[test]
fn verify_zklogin() {
    let (address_seed, input_data, max_epoch, eph_pubkey) = get_raw_data();
    let input = get_zklogin_inputs(input_data);

    let kids = google::kids();
    let jwks = google::jwks();

    let kid = kids[0].clone();
    let jwk = jwks[0].clone();

    let zk_material: ZkMaterial<u64> = ZkMaterialV1::new(JwkProvider::Google, kid, input, max_epoch).into();
    let zklogin_result = zk_material.verify_zk_login(eph_pubkey, &address_seed, &jwk);

    assert!(zklogin_result.is_ok())
}
