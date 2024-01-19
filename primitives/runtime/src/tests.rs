use crate::{
    jwk::{JWKProvider, JwkId},
    test_helper::{
        gen_address_seed, get_raw_data, get_zklogin_inputs, ZkLoginInputsReader,
        ZkLoginInputsReaderJson,
    },
    zk_input::ZkLoginInputs,
    zk_sig::{verify_zk_login, ZkLoginEnv},
};
use sp_core::{
    bounded::BoundedVec,
    crypto::{AccountId32, Pair as TPair},
    ed25519::Pair,
    ConstU32, U256,
};

#[test]
fn verify_zklogin() {
    let (address_seed, input_data, max_epoch, eph_pubkey_bytes) = get_raw_data();
    let input = get_zklogin_inputs(address_seed, input_data);
    let s: [u8; 32] = input.get_address_seed().into();
    let account_id = AccountId32::from(s);
    println!("onchain account_id is {}", &account_id);

    let google_kid = "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781";
    let google_jwk_id = JwkId::new(
        JWKProvider::Google,
        BoundedVec::<u8, ConstU32<256>>::truncate_from(google_kid.as_bytes().to_vec()),
    );
    let zklogin_result =
        verify_zk_login(&input, &google_jwk_id, max_epoch, &eph_pubkey_bytes, &ZkLoginEnv::Prod);

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

    assert_eq!(public.0.as_slice(), &eph_pubkey[1..]);
}
