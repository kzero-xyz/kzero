//! Setup code for [`super::command`] which would otherwise bloat that module.
//!
//! Should only be used for benchmarking as it may break in other contexts.

use crate::service::FullClient;

use node_template_runtime as runtime;
use runtime::{AccountId, Balance, BalancesCall, SystemCall};
use sc_cli::Result;
use sc_client_api::BlockBackend;
use sp_core::{Encode, Pair};
use sp_inherents::{InherentData, InherentDataProvider};
use sp_runtime::{traits::SaturatedConversion, OpaqueExtrinsic};

use primitive_zklogin::test_helper::{get_raw_data, get_test_eph_key, get_zklogin_inputs};
use std::{sync::Arc, time::Duration};

/// Generates extrinsics for the `benchmark overhead` command.
///
/// Note: Should only be used for benchmarking.
pub struct ZkLoginRemarkBuilder {
    client: Arc<FullClient>,
}

impl ZkLoginRemarkBuilder {
    /// Creates a new [`Self`] from the given client.
    pub fn new(client: Arc<FullClient>) -> Self {
        Self { client }
    }
}

impl frame_benchmarking_cli::ExtrinsicBuilder for ZkLoginRemarkBuilder {
    fn pallet(&self) -> &str {
        "system"
    }

    fn extrinsic(&self) -> &str {
        "remark"
    }

    fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
        let acc = get_test_eph_key();
        let extrinsic: OpaqueExtrinsic = create_zklogin_benchmark_extrinsic(
            self.client.as_ref(),
            acc,
            SystemCall::remark { remark: vec![] }.into(),
            nonce,
        )
        .into();

        Ok(extrinsic)
    }
}

/// Generates `Balances::TransferKeepAlive` extrinsics for the benchmarks.
///
/// Note: Should only be used for benchmarking.
pub struct ZkTransferKeepAliveBuilder {
    client: Arc<FullClient>,
    dest: AccountId,
    value: Balance,
}

impl ZkTransferKeepAliveBuilder {
    /// Creates a new [`Self`] from the given client.
    pub fn new(client: Arc<FullClient>, dest: AccountId, value: Balance) -> Self {
        Self { client, dest, value }
    }
}

impl frame_benchmarking_cli::ExtrinsicBuilder for ZkTransferKeepAliveBuilder {
    fn pallet(&self) -> &str {
        "balances"
    }

    fn extrinsic(&self) -> &str {
        "transfer_keep_alive"
    }

    fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
        // hardcode eph private key
        let acc = get_test_eph_key();
        let extrinsic: OpaqueExtrinsic = create_zklogin_benchmark_extrinsic(
            self.client.as_ref(),
            acc,
            BalancesCall::transfer_keep_alive { dest: self.dest.clone().into(), value: self.value }
                .into(),
            nonce,
        )
        .into();

        Ok(extrinsic)
    }
}

/// Create a transaction using the given `call`.
///
/// Note: Should only be used for benchmarking.
pub fn create_zklogin_benchmark_extrinsic(
    client: &FullClient,
    eph_signer: sp_core::ed25519::Pair,
    call: runtime::RuntimeCall,
    nonce: u32,
) -> runtime::UncheckedExtrinsic {
    let period =
		runtime::BlockHashCount::get().checked_next_power_of_two().map(|c| c / 2).unwrap_or(2) as u64;
	let best_block = client.chain_info().best_number;
	let era = sp_runtime::generic::Era::mortal(period, best_block.saturated_into());

	let tx_ext: runtime::TxExtension = (
		frame_system::CheckNonZeroSender::<runtime::Runtime>::new(),
		frame_system::CheckSpecVersion::<runtime::Runtime>::new(),
		frame_system::CheckTxVersion::<runtime::Runtime>::new(),
		frame_system::CheckGenesis::<runtime::Runtime>::new(),
		frame_system::CheckEra::<runtime::Runtime>::from(era),
		pallet_zklogin::ZkLoginExtension::<runtime::Runtime>::new(),
		frame_system::CheckNonce::<runtime::Runtime>::from(nonce),
		frame_system::CheckWeight::<runtime::Runtime>::new(),
		pallet_transaction_payment::ChargeTransactionPayment::<runtime::Runtime>::from(0),
	);

	let raw_payload = runtime::SignedPayload::new(call.clone(), tx_ext.clone())
		.expect("Failed to create signed payload");

    let _signature = raw_payload.using_encoded(|e| eph_signer.sign(e));

    let _eph_pubkey = eph_signer.public();
    let (_address_seed, input_data, _max_epoch, _) = get_raw_data();
    let _input = get_zklogin_inputs(input_data);
    unimplemented!("We have not prepared a framework to fetch jwk yet.")
}

/// Generates inherent data for the `benchmark overhead` command.
///
/// Note: Should only be used for benchmarking.
pub fn inherent_benchmark_data() -> Result<InherentData> {
    let mut inherent_data = InherentData::new();
    let d = Duration::from_millis(0);
    let timestamp = sp_timestamp::InherentDataProvider::new(d.into());

    futures::executor::block_on(timestamp.provide_inherent_data(&mut inherent_data))
        .map_err(|e| format!("creating inherent data: {:?}", e))?;
    Ok(inherent_data)
}
