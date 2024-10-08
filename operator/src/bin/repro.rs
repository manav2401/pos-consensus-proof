use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use prost_types::Timestamp;
use std::str::FromStr;
use url::Url;

use alloy_primitives::FixedBytes;
use alloy_primitives::{address, Address};
use alloy_provider::ReqwestProvider;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::sol;
use reth_primitives::hex;

use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::HostExecutor;

use pos_consensus_proof::{milestone::MilestoneProofInputs, types, types::heimdall_types};
use pos_consensus_proof_operator::{types::Precommit, utils::PosClient, ConsensusProver};

sol! {
    contract ConsensusProofVerifier {
        function verifyConsensusProof(bytes calldata _proofBytes, bytes32 bor_block_hash, bytes32 l1_block_hash) public view;
        function verifyConsensusProof2(bytes calldata _proofBytes, bytes calldata _publicValues) public view;
        function getEncodedValidatorInfo() public view returns(address[] memory, uint256[] memory, uint256);
    }
}

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(long)]
    l1_block_number: u64,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();

    let args = Args::parse();

    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    let prover = ConsensusProver::new();

    println!("Assembling data for generating proof...");
    let inputs: MilestoneProofInputs = generate_inputs(args).await?;

    println!("Starting to generate proof...");
    let proof = prover.generate_consensus_proof(inputs);

    println!("Successfully generated proof: {:?}", proof.bytes());
    println!("Public values: {:?}", proof.public_values.to_vec());

    prover.verify_consensus_proof(&proof);
    println!("Proof verified, sending for on-chain verification!");

    Ok(())
}

pub async fn generate_inputs(args: Args) -> eyre::Result<MilestoneProofInputs> {
    let client = PosClient::default();

    let a: &str = "0x01Eb85F73dA540C66CE1d4262BF7F80d5BA6CF89";
    let verifier_contract: Address = Address::from_str(a).unwrap();
    let caller_address: Address = address!("0000000000000000000000000000000000000000");

    let tx = client
        .fetch_tx_by_hash(
            "0xf921c46e22c2ba2c966b645ca8cb40b9ac2ae76d32a44fd231d7243eef154ebf".to_string(),
        )
        .await
        .expect("unable to fetch milestone tx");

    let number: u64 = tx.result.height.parse().unwrap();
    let block = client
        .fetch_block_by_number(number + 2)
        .await
        .expect("unable to fetch block");

    let block_precommits = block.result.block.last_commit.precommits;
    let mut precommits: Vec<Vec<u8>> = [].to_vec();
    let mut sigs: Vec<String> = [].to_vec();
    let mut signers: Vec<Address> = [].to_vec();

    for precommit in block_precommits.iter() {
        // Only add if the side tx result is non empty
        if precommit.side_tx_results.is_some() {
            let serialized_precommit = serialize_precommit(precommit);
            precommits.push(serialized_precommit);
            sigs.push(precommit.signature.clone());
            signers.push(Address::from_str(&precommit.validator_address).unwrap());
        }
    }

    // Use the host executor to fetch the required bor block
    let bor_block_number = BlockNumberOrTag::Number(12911428);
    let bor_rpc_url =
        std::env::var("BOR_RPC_URL").unwrap_or_else(|_| panic!("Missing BOR_RPC_URL in env"));
    let bor_provider = ReqwestProvider::new_http(Url::parse(&bor_rpc_url)?);
    let bor_host_executor = HostExecutor::new(bor_provider.clone(), bor_block_number).await?;
    let bor_header = bor_host_executor.header;

    // Which block transactions are executed on.
    let block_number = BlockNumberOrTag::Number(args.l1_block_number);

    // Prepare the host executor.
    //
    // Use `ETH_RPC_URL` to get all of the necessary state for the smart contract call.
    let rpc_url =
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| panic!("Missing ETH_RPC_URL in env"));
    let provider = ReqwestProvider::new_http(Url::parse(&rpc_url)?);
    let mut host_executor = HostExecutor::new(provider.clone(), block_number).await?;

    // Keep track of the block hash. Later, validate the client's execution against this.
    let l1_block_hash = host_executor.header.hash_slow();

    // Make the call to the getEncodedValidatorInfo function.
    let call = ConsensusProofVerifier::getEncodedValidatorInfoCall {};
    let _response: ConsensusProofVerifier::getEncodedValidatorInfoReturn = host_executor
        .execute(ContractInput {
            contract_address: verifier_contract,
            caller_address,
            calldata: call,
        })
        .await?;

    // Now that we've executed all of the calls, get the `EVMStateSketch` from the host executor.
    let input = host_executor.finalize().await?;
    let state_sketch_bytes = bincode::serialize(&input)?;

    Ok(MilestoneProofInputs {
        tx_data: tx.result.tx,
        tx_hash: FixedBytes::from_str(&tx.result.hash).unwrap(),
        precommits,
        sigs,
        signers,
        bor_header,
        state_sketch_bytes,
        l1_block_hash,
    })
}

pub fn serialize_precommit(precommit: &Precommit) -> Vec<u8> {
    let timestamp = Timestamp::from_str(&precommit.timestamp).unwrap();
    let parts_header = heimdall_types::CanonicalPartSetHeader {
        total: precommit.block_id.parts.total,
        hash: hex::decode(&precommit.block_id.parts.hash).unwrap(),
    };
    let block_id = Some(heimdall_types::CanonicalBlockId {
        hash: hex::decode(&precommit.block_id.hash).unwrap(),
        parts_header: Some(parts_header),
    });
    let mut sig_bytes: Vec<u8> = [].to_vec();
    let side_tx_result = &precommit.side_tx_results.as_ref().unwrap()[0];
    let sig = side_tx_result.sig.clone().unwrap_or_default();
    if !sig.is_empty() {
        sig_bytes = BASE64_STANDARD.decode(&sig).unwrap();
    }
    let side_tx = heimdall_types::SideTxResult {
        tx_hash: BASE64_STANDARD.decode(&side_tx_result.tx_hash).unwrap(),
        result: side_tx_result.result,
        sig: sig_bytes,
    };
    let vote = heimdall_types::Vote {
        r#type: precommit.type_field,
        height: u64::from_str(&precommit.height).unwrap(),
        round: u64::from_str(&precommit.round).unwrap(),
        block_id,
        timestamp: Some(timestamp),
        chain_id: "heimdall-80002".to_string(),
        data: [].to_vec(),
        side_tx_results: Some(side_tx),
    };
    types::serialize_precommit(&vote)
}
