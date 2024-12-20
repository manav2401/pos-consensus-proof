use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;

use prost_types::Timestamp;
use sp1_sdk::SP1ProofWithPublicValues;
use std::path::PathBuf;
use std::str::FromStr;
use url::Url;

use alloy_primitives::{Address, FixedBytes};
use alloy_provider::ReqwestProvider;
use alloy_rpc_types::BlockNumberOrTag;
use reth_primitives::{hex, Header};

use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::HostExecutor;

use common::{sha256, ConsensusProofVerifier, PoSConsensusInput};
use common::{CALLER, MAX_HEIMDALL_LOOKUP};
use pos_consensus_proof::{types, types::heimdall_types};
use pos_consensus_proof_operator::{
    types::{Precommit, Validator},
    utils::PosClient,
    ConsensusProver,
};

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(long)]
    milestone_id: u64,

    #[clap(long)]
    milestone_hash: String,

    #[clap(long)]
    prev_l2_block_number: u64,

    #[clap(long)]
    new_l2_block_number: u64,

    #[arg(long, default_value_t = false)]
    prove: bool,

    #[clap(long)]
    proof_type: String,
}

/// Context for storing milestone related values
pub struct Context {
    milestone_end_block: u64,
    milestone_tx_hash: String,
    milestone_tx: String,
    milestone_block_height: u64,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();

    let args = Args::parse();
    let prove = args.prove;
    let prev_l2_block_number = args.prev_l2_block_number;
    let new_l2_block_number = args.new_l2_block_number;
    let mut proof_type = args.proof_type.clone();

    let l2_chain_id = std::env::var("L2_CHAIN_ID").expect("L2_CHAIN_ID not set");

    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    let prover = ConsensusProver::new();

    println!("Assembling data for generating proof...");
    let inputs = generate_inputs(args).await?;

    println!("Executing the program...");
    prover.execute(inputs.clone());

    if prove {
        if proof_type.is_empty() {
            println!("No proof type provided, defaulting to compressed");
            proof_type = "compressed".to_string();
        }
        if proof_type.eq("compressed") {
            let proof = prover.generate_consensus_proof_compressed(inputs);
            prover.verify_consensus_proof(&proof);
            save_proof(
                proof,
                l2_chain_id.as_str(),
                format!(
                    "../../proof/chain{}/consensus_block_{}_to_{}.bin",
                    l2_chain_id.as_str(),
                    prev_l2_block_number,
                    new_l2_block_number
                ),
            );
        } else if proof_type == "plonk" {
            let proof = prover.generate_consensus_proof_plonk(inputs);
            prover.verify_consensus_proof(&proof);
            save_proof(
                proof,
                l2_chain_id.as_str(),
                format!(
                    "../../proof/chain{}/consensus_block_{}_to_{}.bin",
                    l2_chain_id.as_str(),
                    prev_l2_block_number,
                    new_l2_block_number
                ),
            );
        } else {
            println!("Invalid proof type provided")
        }
    } else {
        println!("Proof generation skipped");
    }

    Ok(())
}

pub fn save_proof(proof: SP1ProofWithPublicValues, l2_chain_id: &str, name: String) {
    // Create path to save the proof
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../proof/chain{}", l2_chain_id));
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");

    match proof.save(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name)) {
        Ok(_) => println!("Proof saved successfully."),
        Err(e) => eprintln!("Failed to save proof: {}", e),
    }
}

pub async fn generate_inputs(args: Args) -> eyre::Result<PoSConsensusInput> {
    let client = PosClient::default();

    let context = find_latest_milestone_tx(&client).await?;

    // Fetch the block in which side transaction voting for milestone tx completed (n+2).
    let number: u64 = context.milestone_block_height + 2;
    let block = client
        .fetch_block_by_number(number)
        .await
        .expect("unable to fetch block");

    let block_precommits = block.result.block.last_commit.precommits;
    let mut precommits: Vec<Vec<u8>> = [].to_vec();
    let mut sigs: Vec<String> = [].to_vec();
    let mut signers: Vec<Address> = [].to_vec();

    let heimdall_chain_id = std::env::var("HEIMDALL_CHAIN_ID").expect("HEIMDALL_CHAIN_ID not set");
    for precommit in block_precommits.iter() {
        // Only add if the side tx result is non empty
        if precommit.side_tx_results.is_some() {
            let serialized_precommit = serialize_precommit(precommit, &heimdall_chain_id);
            precommits.push(serialized_precommit);
            sigs.push(precommit.signature.clone());
            signers.push(Address::from_str(&precommit.validator_address).unwrap());
        }
    }

    // Use the host executor to fetch the required bor block
    let bor_block_number = BlockNumberOrTag::Number(context.milestone_end_block);
    let bor_header = client
        .fetch_bor_header_by_number(bor_block_number)
        .await
        .unwrap();

    // Fetch the validator set
    let validator_set = client
        .fetch_validator_set_by_height(number + 2)
        .await
        .expect("unable to fetch validator set");

    let chain_id = std::env::var("L1_CHAIN_ID").expect("L1_CHAIN_ID not set");
    let eth_rpc = format!("RPC_{}", chain_id);
    let rpc_url = std::env::var(eth_rpc).unwrap_or_else(|_| panic!("Missing eth rpc url in env"));

    // Calculate the best l1 block to use
    let l1_block_number_u64 = find_best_l1_block(validator_set.result.validators).await;

    // The L1 block number against which the transaction is executed
    let l1_block_number = BlockNumberOrTag::Number(l1_block_number_u64);

    // Read the stake info contract
    let stake_info_address_str = std::env::var("L1_STAKE_INFO").expect("L1_STAKE_INFO not set");
    let stake_info_address: Address =
        Address::from_str(&stake_info_address_str).expect("Invalid L1_STAKE_INFO address");

    // Prepare the host executor.
    //
    // Use `ETH_RPC_URL` to get all of the necessary state for the smart contract call.
    let provider = ReqwestProvider::new_http(Url::parse(&rpc_url)?);
    let mut host_executor = HostExecutor::new(provider.clone(), l1_block_number).await?;

    // Keep track of the l1 block. Later, validate the client's execution against this.
    let l1_block_header = host_executor.clone().header;
    let l1_block_hash = l1_block_header.hash_slow();

    // Make the call to the getEncodedValidatorInfo function.
    let call = ConsensusProofVerifier::getEncodedValidatorInfoCall {};
    let _response: ConsensusProofVerifier::getEncodedValidatorInfoReturn = host_executor
        .execute(ContractInput {
            contract_address: stake_info_address,
            caller_address: CALLER,
            calldata: call,
        })
        .await?;

    // Make another call to fetch the last verified bor block hash
    let call = ConsensusProofVerifier::lastVerifiedBorBlockHashCall {};
    let response: ConsensusProofVerifier::lastVerifiedBorBlockHashReturn = host_executor
        .execute(ContractInput {
            contract_address: stake_info_address,
            caller_address: CALLER,
            calldata: call,
        })
        .await?;

    // Now that we've executed all of the calls, get the `EVMStateSketch` from the host executor.
    let input = host_executor.finalize().await?;
    let state_sketch_bytes = bincode::serialize(&input)?;

    // Fetch the bor block again the block hash read
    let prev_bor_block_hash = response.lastVerifiedBorBlockHash;

    // If the hash is zero, use a default header
    let mut prev_bor_header = Header::default();

    if !prev_bor_block_hash.is_zero() {
        let prev_bor_block_number = client
            .fetch_bor_number_by_hash(prev_bor_block_hash)
            .await
            .unwrap();
        assert_eq!(
            prev_bor_block_number, args.prev_l2_block_number,
            "prev bor block number mismatch with the one present in contract"
        );

        // Fetch the bor header using the number read
        prev_bor_header = client
            .fetch_bor_header_by_number(BlockNumberOrTag::Number(prev_bor_block_number))
            .await
            .unwrap();

        // Check if the hash matches with the original one because a mismatch can happen if block
        // read is not canonical
        assert_eq!(
            prev_bor_header.hash_slow(),
            prev_bor_block_hash,
            "prev bor block hash mismatch"
        );
    }

    Ok(PoSConsensusInput {
        tx_data: context.milestone_tx,
        tx_hash: FixedBytes::from_str(&context.milestone_tx_hash).unwrap(),
        precommits,
        sigs,
        signers,
        bor_header,
        prev_bor_header,
        state_sketch_bytes,
        l1_block_header,
        l1_block_hash,
        stake_info_address, // verifier interacts with stake manager
    })
}

pub fn serialize_precommit(precommit: &Precommit, heimdall_chain_id: &String) -> Vec<u8> {
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
        chain_id: heimdall_chain_id.to_string(),
        data: [].to_vec(),
        side_tx_results: Some(side_tx),
    };
    types::serialize_precommit(&vote)
}

async fn find_best_l1_block(validator_set: Vec<Validator>) -> u64 {
    let mut latest_l1_block_number = 0;
    for validator in validator_set.iter() {
        // The `last_updated` field in the validator set indicates an L1 block on which the
        // the entry was updated. Because we want the recent most stake details, we'll use
        // the highest block number (i.e. the most recent one) from all entries.
        let last_updated = u64::from_str(&validator.last_updated).unwrap();

        // The block number is multiplied by 100K to get the last updated value in heimdall.
        let block_number = last_updated / 100000;
        if block_number > latest_l1_block_number {
            latest_l1_block_number = block_number;
        }
    }

    latest_l1_block_number
}

async fn find_latest_milestone_tx(client: &PosClient) -> eyre::Result<Context> {
    let block_number = find_latest_milestone_block(client).await?;
    let block = client
        .fetch_block_by_number(block_number)
        .await
        .expect("unable to fetch block by number");
    let txs = block.result.block.data.txs;

    if txs.is_empty() {
        return Err(eyre::eyre!(
            "No transactions found in the selected heimdall block"
        ));
    }

    for tx in txs.iter() {
        // Decode the transaction data and calculate it's hash
        let decoded_tx_data = BASE64_STANDARD.decode(tx).expect("tx data decoding failed");
        let tx_hash = sha256(decoded_tx_data.as_slice());

        // Fetch the tendermint transaction
        let tx_response = client
            .fetch_tx_by_hash(tx_hash.to_string())
            .await
            .expect("unable to fetch tx by hash");

        // Confirm if it's a milestone transaction or not.
        for event in tx_response.result.tx_result.events.iter() {
            if event.type_field == "milestone" {
                for attribute in event.attributes.iter() {
                    // Match with the base64 encoded string of 'end-block'
                    if attribute.key == "ZW5kLWJsb2Nr" {
                        let end_block_vec = BASE64_STANDARD.decode(&attribute.value).unwrap();
                        let end_block = u64::from_le_bytes(end_block_vec.try_into().unwrap());
                        return Ok(Context {
                            milestone_end_block: end_block,
                            milestone_tx_hash: tx_response.result.hash.clone(),
                            milestone_tx: tx_response.result.tx.clone(),
                            milestone_block_height: block_number,
                        });
                    }
                }
            }
        }
    }

    // Ideally we should have found milestone tx and all required data by now. Return error if not.
    Err(eyre::eyre!(
        "Unable to find recentmost milestone transaction"
    ))
}

async fn find_latest_milestone_block(client: &PosClient) -> eyre::Result<u64> {
    // Fetch the status of heimdall node to know if it's in sync and find the latest block
    let status = client
        .fetch_heimdall_status()
        .await
        .expect("unable to fetch heimdall status");

    // Exit if heimdall is out of sync
    if status.result.catching_up {
        // Return an error
        return Err(eyre::eyre!(
            "Heimdall seems to be out of sync, please try with a fully synced node."
        ));
    }

    let mut block_number: u64 = status.result.latest_block_height - 2;
    let mut count: u64 = 0;
    // Iterate from latest block backwards
    loop {
        if count > MAX_HEIMDALL_LOOKUP {
            return Err(eyre::eyre!(
                "Unable to find latest milestone transaction in heimdall"
            ));
        }
        if count % 10 == 0 {
            println!("Looking for milestone tx in block: {}", block_number);
        }

        // Fetch the block result
        let block_result = client
            .fetch_block_results_by_number(block_number)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "unable to fetch heimdall block results for block: {}",
                    block_number
                )
            });

        // Check if the block has any milestone tx or not in the `deliver_tx` field
        let txs = block_result.result.results.deliver_tx;
        if !txs.is_empty() {
            for tx in txs.iter() {
                for event in tx.events.iter() {
                    if event.type_field == "milestone" {
                        println!("Milestone tx found in block: {}", block_number);
                        return Ok(block_number);
                    }
                }
            }
        }

        count += 1;
        block_number -= 1;
    }
}
