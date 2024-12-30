use std::str::FromStr;
use url::Url;

use alloy_primitives::Address;
use alloy_provider::ReqwestProvider;
use alloy_rpc_types::BlockNumberOrTag;

use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::HostExecutor;

use common::{ConsensusProofVerifier, CALLER};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();

    println!("Start...");

    let l1_block_number = BlockNumberOrTag::Number(21514914);
    let rpc_url =
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| panic!("Missing ETH_RPC_URL in env"));
    let stake_info_address_str = std::env::var("L1_STAKE_INFO").expect("L1_STAKE_INFO not set");

    // Prepare the host executor.
    //
    // Use `ETH_RPC_URL` to get all of the necessary state for the smart contract call.
    let provider = ReqwestProvider::new_http(Url::parse(&rpc_url)?);
    let mut host_executor = HostExecutor::new(provider.clone(), l1_block_number).await?;

    let stake_info_address: Address =
        Address::from_str(&stake_info_address_str).expect("Invalid L1_STAKE_INFO address");

    // Make the call to the getEncodedValidatorInfo function.
    println!(
        "Fetching validator set from L1, block used: {}",
        l1_block_number.as_number().unwrap()
    );
    let call = ConsensusProofVerifier::getEncodedValidatorInfoCall {};
    let _response: ConsensusProofVerifier::getEncodedValidatorInfoReturn = host_executor
        .execute(ContractInput {
            contract_address: stake_info_address,
            caller_address: CALLER,
            calldata: call,
        })
        .await?;

    // Get the `EVMStateSketch` from the host executor.
    let input = host_executor.finalize().await?;
    println!("Done...");

    Ok(())
}
