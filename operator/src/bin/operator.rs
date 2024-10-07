use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use pos_consensus_proof::milestone::PublicValuesStruct;
use prost_types::Timestamp;
use std::str::FromStr;
use url::Url;

use alloy_primitives::FixedBytes;
use alloy_primitives::{address, Address};
use alloy_provider::ReqwestProvider;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::{sol, SolCall, SolType};
use reth_primitives::hex;

use sp1_cc_client_executor::{io::EVMStateSketch, ClientExecutor, ContractInput};
use sp1_cc_host_executor::HostExecutor;
use sp1_sdk::SP1ProofWithPublicValues;

use pos_consensus_proof::{milestone::MilestoneProofInputs, types, types::heimdall_types};
use pos_consensus_proof_operator::{
    contract::ContractClient, types::Precommit, utils::PosClient, ConsensusProver,
};

sol! {
    contract ConsensusProofVerifier {
        function verifyConsensusProof(bytes calldata _proofBytes, bytes32 bor_block_hash, bytes32 l1_block_hash) public view;
        function getEncodedValidatorInfo() public view returns(address[] memory, uint256[] memory, uint256);
    }
}

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
    let prover = ConsensusProver::new();

    println!("Assembling data for generating proof...");
    let inputs: MilestoneProofInputs = generate_inputs(args).await?;

    // let milestone_prover = MilestoneProver::init(inputs.clone());
    // let outputs = milestone_prover.prove();
    // println!("Public values: {:?}", outputs);

    println!("Starting to generate proof...");
    let proof = prover.generate_consensus_proof(inputs);

    println!("Successfully generated proof: {:?}", proof.bytes());
    println!("Public values: {:?}", proof.public_values.to_vec());

    proof.save("proof.bin").expect("saving proof failed");
    println!("Proof saved to proof.bin");

    prover.verify_consensus_proof(&proof);
    println!("Proof verified, sending for on-chain verification!");

    send_proof_onchain(proof).await?;
    println!("Successfully verified proof on-chain!");

    Ok(())
}

pub async fn generate_inputs(args: Args) -> eyre::Result<MilestoneProofInputs> {
    let client = PosClient::default();

    let a: &str = "0xB07f2FdCBE8b2D9ca815e563B7C0E2F2bD28CbFC";
    let verifier_contract: Address = Address::from_str(a).unwrap();
    let caller_address: Address = address!("0000000000000000000000000000000000000000");

    let milestone = client
        .fetch_milestone_by_id(args.milestone_id)
        .await
        .expect("unable to fetch milestone");
    let tx = client
        .fetch_tx_by_hash(args.milestone_hash)
        .await
        .expect("unable to fetch milestone tx");
    // println!("tx: {:?}", tx.result.tx);

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
    let bor_block_number = BlockNumberOrTag::Number(milestone.result.end_block);
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
    // println!("state_sketch_bytes: {:?}", state_sketch_bytes);

    // Check if we can sketch the state
    // let state_sketch = bincode::deserialize::<EVMStateSketch>(&state_sketch_bytes).unwrap();

    // Initialize the client executor with the state sketch.
    // This step also validates all of the storage against the provided state root.
    // let _executor = ClientExecutor::new(state_sketch).unwrap();

    println!("tx_data: {:?}", tx.result.tx);

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

pub async fn send_proof_onchain(proof: SP1ProofWithPublicValues) -> eyre::Result<()> {
    // Setup the default contract client to interact with on-chain verifier
    let contract_client = ContractClient::default();

    // Decode the public values from the proof
    let vals = PublicValuesStruct::abi_decode(&proof.public_values.to_vec(), true).unwrap();

    // Construct the on-chain call and relay the proof to the contract.
    let call_data = ConsensusProofVerifier::verifyConsensusProofCall {
        _proofBytes: proof.bytes().into(),
        bor_block_hash: vals.bor_block_hash,
        l1_block_hash: vals.l1_block_hash,
    }
    .abi_encode();
    contract_client
        .send(call_data)
        .await
        .expect("failed to send proof on-chain");

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
