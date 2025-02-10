use crate::{Call as ZkLoginCall, Pallet};
use frame_executive::Executive;
use frame_support::{
    assert_ok, derive_impl, dispatch::RawOrigin, pallet_prelude::TypeInfo, parameter_types,
    traits::UnfilteredDispatchable,
};
use pallet_balances::Call as BalancesCall;
use primitive_zklogin::{
    test_helper::{get_raw_data, get_test_eph_key, get_zklogin_inputs, test_cases::google},
    JwkProvider, ZkMaterialV1,
};
use scale_codec::{Decode, Encode};
use sp_core::{ed25519, Pair};
use sp_runtime::{
    generic,
    generic::{CheckedExtrinsic, UncheckedExtrinsic},
    traits::{BlakeTwo256, DispatchInfoOf, IdentifyAccount, SignedExtension, Verify},
    transaction_validity::TransactionValidityError,
    BuildStorage, MultiAddress, MultiSignature,
};

/// An index to a block.
pub type BlockNumber = u32;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
type Context = frame_system::ChainContext<Test>;
pub type Signature = MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Address = MultiAddress<AccountId, ()>;
type MockUncheckedExtrinsic = UncheckedExtrinsic<Address, RuntimeCall, MultiSignature, MockExtra>;
type MockCheckedExtrinsic = CheckedExtrinsic<AccountId, RuntimeCall, MockExtra>;

pub type SignedPayload = generic::SignedPayload<RuntimeCall, MockExtra>;

type Block = generic::Block<Header, MockUncheckedExtrinsic>;

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, TypeInfo)]
pub struct MockExtra;

impl SignedExtension for MockExtra {
    const IDENTIFIER: &'static str = "MockExtra";
    type AccountId = AccountId;
    type Call = RuntimeCall;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> Result<Self::AdditionalSigned, TransactionValidityError> {
        Ok(())
    }

    fn pre_dispatch(
        self,
        _who: &Self::AccountId,
        _call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        Ok(())
    }
}

type MockExecutive = Executive<Test, Block, Context, Test, AllPalletsWithSystem, ()>;

frame_support::construct_runtime!(
    pub enum Test
    {
        System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
        Timestamp: pallet_timestamp,
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        ZkLogin: super::{Pallet, Call, Event<T>, ValidateUnsigned},
    }
);

parameter_types! {
    pub const BlockHashCount: u32 = 250;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = sp_runtime::traits::AccountIdLookup<Self::AccountId, ()>;
    type AccountData = pallet_balances::AccountData<u64>;
}

impl frame_system::offchain::SigningTypes for Test {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
{
    type OverarchingCall = RuntimeCall;
    type Extrinsic = MockUncheckedExtrinsic;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

impl super::Config for Test {
    type AuthorityId = crate::crypto::ZkLoginAuthId;
    type RuntimeEvent = RuntimeEvent;
    type Context = Context;
    type Extrinsic = MockUncheckedExtrinsic;
    type CheckedExtrinsic = MockCheckedExtrinsic;
    type UnsignedValidator = Test;
    type Time = Timestamp;
}

fn zk_address() -> AccountId {
    let (zklogin_address, ..) = get_raw_data();
    zklogin_address
}

// This function basically just builds a genesis storage key/value store according to
// our desired mockup.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    // We use default for brevity, but you can configure as desired if needed.
    pallet_balances::GenesisConfig::<Test> {
        // give `zk_address` an initial value of 1000
        balances: vec![(zk_address(), 1000)],
    }
    .assimilate_storage(&mut t)
    .unwrap();
    t.into()
}

#[test]
fn basic_setup_works() {
    new_test_ext().execute_with(|| {
        assert_eq!(System::account(&zk_address()).data.free, 1000);
    })
}

#[test]
fn validate_unsigned_should_work() {
    use sp_runtime::traits::ValidateUnsigned;
    let source = sp_runtime::transaction_validity::TransactionSource::External;

    // get zk-related variables for zk-proof verifying
    let (address_seed, input_data, expire_at, _) = get_raw_data();
    let inputs = get_zklogin_inputs(input_data);

    let signing_key: ed25519::Pair = get_test_eph_key();

    let provider = JwkProvider::Google;
    let jwks = google::GOOGLE_JWK_JSON_LIST[0];
    let kids = google::kids();
    let kid = kids[0].clone();

    let zk_material = ZkMaterialV1::new(provider, kid, inputs, expire_at).into();

    // construct Transfer Call
    let dest = AccountId::from([0u8; 32]);
    let call: RuntimeCall =
        BalancesCall::transfer_keep_alive { dest: MultiAddress::Id(dest.clone()), value: 100 }
            .into();

    let payload = SignedPayload::new(call.clone(), MockExtra).expect("payload should succeed");
    let sign = payload.using_encoded(|d| signing_key.sign(d));

    // construct inner unchecked_extrinsic
    let uxt = MockUncheckedExtrinsic::new_signed(
        call,
        AccountId::from(signing_key.public()).into(),
        MultiSignature::from(sign),
        MockExtra,
    );

    let final_call = ZkLoginCall::submit_zklogin_unsigned {
        uxt: Box::new(uxt),
        address_seed: address_seed.into(),
        zk_material,
    };

    let outer_uxt = UncheckedExtrinsic::<
        MultiAddress<AccountId, ()>,
        RuntimeCall,
        MultiSignature,
        MockExtra,
    >::new_unsigned(final_call.clone().into());

    new_test_ext().execute_with(|| {
        // Set jwk from root.
        assert_ok!(ZkLogin::set_jwk(RawOrigin::Root.into(), provider, jwks.as_bytes().to_vec()));

        // the eph key's expiration at 834, make sure current number is smaller.
        System::set_block_number(10);
        assert!(Pallet::<Test>::validate_unsigned(source, &final_call).is_ok());

        // execute through call.dispatch
        assert_ok!(final_call.dispatch_bypass_filter(RawOrigin::None.into()));
        // deduct 100 from zk_address
        assert_eq!(Balances::free_balance(&zk_address(),), 900);
        // transfer success
        assert_eq!(Balances::free_balance(&dest), 100);

        // execute through `apply_extrinsic`
        assert_ok!(MockExecutive::apply_extrinsic(outer_uxt));
        // deduct 100 from zk_address
        assert_eq!(Balances::free_balance(&zk_address(),), 800);
        // transfer success
        assert_eq!(Balances::free_balance(&dest), 200);
    });
}
