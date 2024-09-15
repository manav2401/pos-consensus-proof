use pos_consensus_proof_operator::contract::ContractClient;
use sp1_sdk::SP1ProofWithPublicValues;

use alloy_sol_types::{sol, SolCall};

sol! {
    contract ConsensusProofVerifier {
        function verifyConsensusProof(
            bytes calldata proof,
            bytes calldata publicValues
        ) public;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    println!("Hello, world!");

    let proof = SP1ProofWithPublicValues::load("proof.bin").unwrap();

    // Setup the default contract client to interact with on-chain verifier
    let contract_client = ContractClient::default();

    // Construct the on-chain call and relay the proof to the contract.
    let call_data = ConsensusProofVerifier::verifyConsensusProofCall {
        proof: proof.bytes().into(),
        publicValues: proof.public_values.to_vec().into(),
    }
    .abi_encode();
    contract_client.send(call_data).await?;

    Ok(())
}
