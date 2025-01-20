//! Minimal script to fetch validator set data from a pre-deployed L1 contract using
//! sp1-contract-call library. This helps in simulating calls to L1 independently.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --package operator --bin fetch-valset --release
//! ```
use std::str::FromStr;
use url::Url;

use alloy_primitives::Address;
use alloy_provider::ReqwestProvider;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::SolCall;

use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::HostExecutor;

use common::{ConsensusProofVerifier, CALLER};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();

    // Skip setting the tracer/logger as sp1 already sets it globally
    // tracing_subscriber::fmt()
    //     .with_env_filter(EnvFilter::from_default_env())
    //     .init();

    let _sepolia: u64 = 7433246;
    let mainnet: u64 = 21572281;

    let l1_block_number = BlockNumberOrTag::Number(mainnet);
    let rpc_url =
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| panic!("Missing ETH_RPC_URL in env"));
    let stake_info_address_str = std::env::var("L1_STAKE_INFO").expect("L1_STAKE_INFO not set");

    println!("RPC: {}", rpc_url);
    println!("L1 Stake Info Contract: {}", stake_info_address_str);

    // Prepare the host executor.
    let provider = ReqwestProvider::new_http(Url::parse(&rpc_url)?);
    let mut host_executor = HostExecutor::new(provider.clone(), l1_block_number).await?;
    let stake_info_address: Address =
        Address::from_str(&stake_info_address_str).expect("Invalid L1_STAKE_INFO address");

    // Make the call to the getValidatorInfo function.
    println!(
        "Fetching validator set from L1, block used: {}",
        l1_block_number.as_number().unwrap()
    );
    let call = ConsensusProofVerifier::getValidatorInfoCall {};
    let output = host_executor
        .execute(ContractInput::new_call(
            stake_info_address,
            CALLER,
            call.clone(),
        ))
        .await?;

    println!("Execute call done, output: {:?}", output);

    // Get the `EVMStateSketch` from the host executor.
    let input = host_executor.finalize().await?;
    let _state_sketch_bytes = bincode::serialize(&input)?;

    println!("Finalize done");

    let response =
        ConsensusProofVerifier::getValidatorInfoCall::abi_decode_returns(&output, true).unwrap();
    println!(
        "Decoded response, addresses: {:?}, powers: {:?}, total power: {}",
        response._0, response._1, response._2
    );

    Ok(())
}
