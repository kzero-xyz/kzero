use scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::generic::Era;
// local
use node_template::node_template_runtime::{
    AccountId, Address, BalancesCall, Runtime, RuntimeCall, Signature, SignedPayload, TxExtension,
    UncheckedExtrinsic, ZkLoginCall,
};
use primitive_zklogin::{
    test_helper::{get_raw_data, get_test_eph_key, get_zklogin_inputs, test_cases::google},
    JwkProvider, ZkMaterialV1,
};

fn main() {
    // transfer to 0x197cf48b729ff12596cbc046c7fe8f88f92ac5f0b6fc42b4c1dcc532d37ccea2 first

    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs: primitive_zklogin::ZkLoginInputs = get_zklogin_inputs(input_data);

    // A test key, may can replace to any one, but must ed25519 key pair.
    let signing_key = get_test_eph_key();
    let signing_pub = signing_key.public();
    println!("{:?}", signing_pub);

    // let jwks = google::jwks();
    let kids = google::kids(true);
    // can be used in test,
    let google_kid = kids[0].clone();
    // let google_jwk = jwks[0].clone();

    // construct zk proof
    let zk_material = ZkMaterialV1::new(JwkProvider::Google, google_kid, inputs, expire_at).into();

    // construct inner example call, using transfer as example
    // construct Transfer Call
    let dest = AccountId::from([0u8; 32]);
    let call: RuntimeCall =
        BalancesCall::transfer_keep_alive { dest: Address::Id(dest.clone()), value: 600 }.into();

    let call: RuntimeCall =
        ZkLoginCall::submit_zklogin { zk_material, address_seed, call: Box::new(call) }.into();

    let tx_ext: TxExtension = (
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckEra::<Runtime>::from(Era::Immortal),
        pallet_zklogin::ZkLoginExtension::<Runtime>::new(),
        frame_system::CheckNonce::<Runtime>::from(0),
        frame_system::CheckWeight::<Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0),
    );
    let raw_payload = SignedPayload::new(call, tx_ext).ok().expect("should build successfully");
    let sign = raw_payload.using_encoded(|d| signing_key.sign(d));
    let (call, tx_ext, _) = raw_payload.deconstruct();
    // construct unchecked_extrinsic
    let uxt = UncheckedExtrinsic::new_signed(
        call,
        AccountId::from(signing_key.public()).into(),
        Signature::from(sign),
        tx_ext,
    );
    println!("outer tx\n0x{}", hex::encode(uxt.encode()))
}
