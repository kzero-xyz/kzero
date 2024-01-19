use frame_support::BoundedVec;
use frame_system::Call::remark;
use pallet_balances::Call;
use scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::generic::Era;
use sp_runtime::{MultiAddress, MultiSignature};
use zklogin_runtime::{EPH_PUB_KEY_LEN, ZkMultiSignature};
use crate::{AccountId, ConstU32, Nonce, Runtime, RuntimeCall, SignedPayload, UncheckedExtrinsic};
use zklogin_runtime::jwk::{JwkId, JWKProvider};
use zklogin_runtime::zk_sig::Signature as InnerZkSignature;
use zklogin_runtime::zk_input::ZkLoginInputs;
use zklogin_runtime::test_helper::{get_raw_data, get_zklogin_inputs};

fn create_transaction<P: Pair<Signature = sp_core::ed25519::Signature>>(
    call: RuntimeCall,
    nonce: Nonce,
    pair: P,
    source: JwkId,
    input: ZkLoginInputs,
    max_epoch: u64,
    eph_pubkey_bytes: [u8; EPH_PUB_KEY_LEN],
) -> UncheckedExtrinsic {
    let tip: u128 = 0;

    let era = Era::immortal();
    let extra = (
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckEra::<Runtime>::from(era),
        frame_system::CheckNonce::<Runtime>::from(nonce),
        frame_system::CheckWeight::<Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::from(tip.into()),
    );

    let raw_payload = SignedPayload::new(call, extra)
        .map_err(|e| {
            // log::warn!("Unable to create signed payload: {:?}", e);
        })
        .ok().unwrap();
    let signature = raw_payload.using_encoded(|payload| pair.sign(payload));

    // construct inner zk sig
    let inner_zk_sig = InnerZkSignature::new(source, input, max_epoch, eph_pubkey_bytes, signature.into());

    let (call, extra, _) = raw_payload.deconstruct();
    let address = MultiAddress::from(inner_zk_sig.get_onchain_address());

    UncheckedExtrinsic::new_signed(call, address, ZkMultiSignature::Zk(inner_zk_sig), extra)
}

#[test]
fn create_encoded_extrinsic() {
    let (address_seed, input_data, max_epoch, eph_pubkey_bytes) = get_raw_data();
    let input  = get_zklogin_inputs(address_seed, input_data);

    let pri_key = [
        251, 112, 167, 63, 195, 4, 26, 202, 18, 45, 182, 138, 84, 202, 34, 15,
        209, 217, 76, 114, 180, 67, 72, 157, 104, 241, 172, 212, 122, 18, 74, 54
    ];

    let pair = sp_core::ed25519::Pair::from_seed(&pri_key);

    let google_kid = "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781";
    let google_jwk_id = JwkId::new(
        JWKProvider::Google,
        BoundedVec::<u8, ConstU32<256>>::truncate_from(google_kid.as_bytes().to_vec()),
    );

    let zk_transaction = create_transaction(
        RuntimeCall::System(remark { remark: b"hello world".to_vec()}),
        0_u32.into(),
        pair,
        google_jwk_id,
        input,
        max_epoch,
        <[u8; EPH_PUB_KEY_LEN]>::try_from(eph_pubkey_bytes).unwrap()
    );

    let encoded = Encode::encode(&zk_transaction);
    println!("encoded zk transaction is {:?}", &encoded);
}