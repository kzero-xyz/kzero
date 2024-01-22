use crate::{
    jwk::{JWKProvider, JwkId},
    test_helper::{get_raw_data, get_zklogin_inputs},
    verify_zk_login,
    zk_sig::{verify_zk_login, ZkLoginEnv},
    ZkLoginEnv,
};
use sp_core::{bounded::BoundedVec, crypto::Pair as TPair, ed25519::Pair, ConstU32, U256};

#[test]
fn verify_zklogin() {
    let (address_seed, input_data, max_epoch, eph_pubkey_bytes) = get_raw_data();

    let address_seed = U256::from_big_endian(address_seed.as_ref());
    let input = get_zklogin_inputs(input_data);

    let google_kid = "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781";
    let google_jwk_id = JwkId::new(
        JWKProvider::Google,
        BoundedVec::<u8, ConstU32<256>>::truncate_from(google_kid.as_bytes().to_vec()),
    );
    let zklogin_result = verify_zk_login(
        address_seed,
        &input,
        &google_jwk_id,
        max_epoch,
        &eph_pubkey_bytes,
        &ZkLoginEnv::Prod,
    );

    assert!(zklogin_result.is_ok());
}

#[test]
fn eph_key_generate_correct() {
    let pri_key = [
        251, 112, 167, 63, 195, 4, 26, 202, 18, 45, 182, 138, 84, 202, 34, 15, 209, 217, 76, 114,
        180, 67, 72, 157, 104, 241, 172, 212, 122, 18, 74, 54,
    ];

    let (_, _, _, eph_pubkey) = get_raw_data();

    let pair = Pair::from_seed(&pri_key);
    let public = pair.public();

    assert_eq!(public.0, eph_pubkey);
}
