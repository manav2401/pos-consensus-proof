//! This programme generates the consensus proofs for milestone message. It validates the
//! message against header/s and also checks for the signature of majority of validators
//! according to their weight/stake.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{Address, FixedBytes};
use alloy_sol_types::SolType;

use pos_consensus_proof::milestone::{MilestoneProofInputs, MilestoneProver, PublicValuesStruct};
use reth_primitives::{hex::FromHex, Header};

pub fn main() {
    // Read inputs from the zkVM's stdin.
    let tx_data = sp1_zkvm::io::read::<String>();
    let tx_hash = sp1_zkvm::io::read::<FixedBytes<32>>();
    let precommits = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let sigs = sp1_zkvm::io::read::<Vec<String>>();
    let signers = sp1_zkvm::io::read::<Vec<Address>>();
    let bor_header = sp1_zkvm::io::read::<Header>();
    let bor_header_hash = sp1_zkvm::io::read::<FixedBytes<32>>();
    let state_sketch_bytes = sp1_zkvm::io::read::<Vec<u8>>();

    let inputs = MilestoneProofInputs {
        tx_data,
        tx_hash,
        precommits,
        sigs,
        signers,
        bor_header,
        bor_header_hash,
        state_sketch_bytes,
    };
    let prover = MilestoneProver::init(inputs);
    prover.prove();

    // let signer_addresses = signers
    //     .iter()
    //     .map(|s| Address::from_hex(s.as_str()).unwrap_or_default())
    //     .collect();

    // // Encode the public values
    // let bytes = PublicValuesStruct::abi_encode_packed(&PublicValuesStruct {
    //     signers: signer_addresses,
    //     powers,
    //     total_power,
    // });

    // Commit the values as bytes to be exposed to the verifier
    // sp1_zkvm::io::commit_slice(&bytes);
}
