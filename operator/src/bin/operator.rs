use alloy_primitives::private::alloy_rlp::Decodable;
use alloy_primitives::FixedBytes;
use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use pos_consensus_proof::{milestone::MilestoneProofInputs, types, types::heimdall_types};
use pos_consensus_proof_operator::{contract::ContractClient, types::Precommit, utils::PosClient};
use prost_types::Timestamp;
use reth_primitives::{hex, Header};

use std::str::FromStr;
use url::Url;

use alloy_primitives::{address, Address};
use alloy_provider::ReqwestProvider;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::{sol, SolCall, SolValue};
use serde::{Deserialize, Serialize};
use sp1_cc_client_executor::{ContractInput, ContractPublicValues};
use sp1_cc_host_executor::HostExecutor;
use sp1_sdk::{utils, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

sol! {
    contract ConsensusProofVerifier {
        function verifyConsensusProof(bytes calldata proof) public view;
        function getEncodedValidatorInfo() public view returns(address[] memory, uint256[] memory, uint256);
    }
}

const VERIFIER_CONTRACT: Address = address!("1d42064Fc4Beb5F8aAF85F4617AE8b3b5B8Bd801");
const CALLER: Address = address!("0000000000000000000000000000000000000000");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(long)]
    milestone_id: u64,

    #[clap(long)]
    milestone_hash: String,

    #[clap(long)]
    l1_block_number: u64,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();

    let args = Args::parse();

    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    println!("Assembling data for generating proof...");

    // let prover = ConsensusProver::new();
    let inputs: MilestoneProofInputs = generate_inputs(args).await?;

    // println!("Starting to generate proof...");
    // let proof = prover.generate_consensus_proof(inputs);

    // println!("Successfully generated proof: {:?}", proof.bytes());
    // println!("Public values: {:?}", proof.public_values.to_vec());

    // proof.save("proof.bin").expect("saving proof failed");
    // println!("Proof saved to proof.bin");

    // prover.verify_consensus_proof(&proof);
    // println!("Proof verified, sending for on-chain verification!");

    // send_proof_onchain(proof).await?;
    // println!("Successfully verified proof on-chain!");

    Ok(())
}

pub async fn generate_inputs(args: Args) -> eyre::Result<MilestoneProofInputs> {
    let client = PosClient::default();

    let milestone = client
        .fetch_milestone_by_id(args.milestone_id)
        .await
        .expect("unable to fetch milestone");
    let tx = client
        .fetch_tx_by_hash(args.milestone_hash)
        .await
        .expect("unable to fetch milestone tx");

    let number: u64 = tx.result.height.parse().unwrap();
    let block = client
        .fetch_block_by_number(number + 2)
        .await
        .expect("unable to fetch block");

    let precommits = block.result.block.last_commit.precommits;
    let precommits_input = precommits.iter().map(serialize_precommit).collect();
    let sigs = precommits.iter().map(|p| p.signature.clone()).collect();
    let signers: Vec<Address> = precommits
        .iter()
        .map(|p| Address::from_str(&p.validator_address).unwrap())
        .collect();

    let bor_headed_rlp_encoded = client
        .fetch_bor_header(milestone.result.end_block)
        .await
        .expect("unable to fetch bor header");
    let bor_header_bytes = hex::decode(bor_headed_rlp_encoded).unwrap_or_default();
    let bor_header = Header::decode(&mut bor_header_bytes.as_slice()).unwrap();
    let bor_block_hash = FixedBytes::from_slice(bor_header.hash_slow().as_slice());

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
            contract_address: VERIFIER_CONTRACT,
            caller_address: CALLER,
            calldata: call,
        })
        .await?;

    // Now that we've executed all of the calls, get the `EVMStateSketch` from the host executor.
    let input = host_executor.finalize().await?;
    let state_sketch_bytes = bincode::serialize(&input)?;

    Ok(MilestoneProofInputs {
        tx_data: tx.result.tx,
        tx_hash: FixedBytes::from_str(&tx.result.hash).unwrap(),
        precommits: precommits_input,
        sigs,
        signers,
        bor_header,
        bor_block_hash,
        state_sketch_bytes,
        l1_block_hash,
    })
}

pub async fn send_proof_onchain(proof: SP1ProofWithPublicValues) -> anyhow::Result<()> {
    // Setup the default contract client to interact with on-chain verifier
    let contract_client = ContractClient::default();

    // Construct the on-chain call and relay the proof to the contract.
    let call_data = ConsensusProofVerifier::verifyConsensusProofCall {
        proof: proof.bytes().into(),
    }
    .abi_encode();
    contract_client.send(call_data).await?;

    Ok(())
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
    let side_tx = heimdall_types::SideTxResult {
        tx_hash: BASE64_STANDARD
            .decode(&precommit.side_tx_results[0].tx_hash)
            .unwrap(),
        result: precommit.side_tx_results[0].result,
        sig: [].to_vec(),
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
