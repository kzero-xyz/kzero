use scale_codec::Encode;
use sp_core::{Pair, H256};
use sp_runtime::generic::Era;
// local
use node_template::node_template_runtime::{
    self, AccountId, Address, BalancesCall, Runtime, RuntimeCall, Signature, SignedExtra,
    SignedPayload, UncheckedExtrinsic, ZkLoginCall,
};
use primitive_zklogin::{
    test_helper::{get_raw_data, get_test_eph_key, get_zklogin_inputs, test_cases::google},
    JwkProvider, ZkMaterial,
};

// must replace this genesis to your own
const CHAIN_GENESIS: [u8; 32] =
    hex_literal::hex!("ab0330f2324982e2afb7bd23becbd23450262eeb7ac233aca981f281bed056e5");

fn main() {
    // transfer to 0x197cf48b729ff12596cbc046c7fe8f88f92ac5f0b6fc42b4c1dcc532d37ccea2 first

    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);

    // A test key, may can replace to any one, but must ed25519 key pair.
    let signing_key = get_test_eph_key();
    let signing_pub = signing_key.public();
    println!("{:?}", signing_pub);

    // let jwks = google::jwks();
    let kids = google::kids();
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

    let genesis_block: H256 = CHAIN_GENESIS.into();
    let extra: SignedExtra = (
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckEra::<Runtime>::from(Era::Immortal),
        frame_system::CheckNonce::<Runtime>::from(0),
        frame_system::CheckWeight::<Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0),
    );
    let payload = SignedPayload::from_raw(
        call.clone(),
        extra.clone(),
        (
            (),
            node_template_runtime::VERSION.spec_version,
            node_template_runtime::VERSION.transaction_version,
            genesis_block,
            // notice this field should provide for `Era`, but we use genesis to replace it.
            genesis_block,
            (),
            (),
            (),
        ),
    );
    let sign = payload.using_encoded(|d| signing_key.sign(d));
    // construct inner unchecked_extrinsic
    let uxt = UncheckedExtrinsic::new_signed(
        call,
        AccountId::from(signing_key.public()).into(),
        Signature::from(sign),
        extra,
    );

    println!("inner tx\n0x{}", hex::encode(uxt.encode()));

    // construct outer extrinsic
    let final_call: RuntimeCall = ZkLoginCall::submit_zklogin_unsigned {
        uxt: Box::new(uxt),
        address_seed: address_seed.into(),
        zk_material,
    }
    .into();

    let outer_utx = UncheckedExtrinsic::new_unsigned(final_call);

    println!("outer tx\n0x{}", hex::encode(outer_utx.encode()))
}
