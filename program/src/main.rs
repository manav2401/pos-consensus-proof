//! This programme generates the consensus proofs for milestone message. It validates the
//! message against header/s and also checks for the signature of majority of validators
//! according to their weight/stake.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use pos_consensus_proof::milestone::{MilestoneProofInputs, MilestoneProver};
pub fn main() {
    // Read inputs from the zkVM's stdin.
    let tx_data = sp1_zkvm::io::read::<String>();
    let tx_hash = sp1_zkvm::io::read::<String>();
    let precommits = sp1_zkvm::io::read::<Vec<String>>();
    let precommits_hash = sp1_zkvm::io::read::<String>();
    let sigs = sp1_zkvm::io::read::<Vec<String>>();
    let signers = sp1_zkvm::io::read::<Vec<String>>();
    let headers = sp1_zkvm::io::read::<Vec<String>>();
    let powers = sp1_zkvm::io::read::<Vec<u64>>();
    let total_power = sp1_zkvm::io::read::<u64>();

    let inputs = MilestoneProofInputs {
        tx_data,
        tx_hash: tx_hash.clone(),
        precommits,
        precommits_hash: precommits_hash.clone(),
        sigs,
        signers: signers.clone(),
        headers,
        powers: powers.clone(),
        total_power,
    };

    let prover = MilestoneProver::init(inputs);
    prover.prove();

    // Commit the values to be exposed to verifier
    sp1_zkvm::io::commit::<String>(&tx_hash);
    sp1_zkvm::io::commit::<String>(&precommits_hash);
    sp1_zkvm::io::commit::<Vec<String>>(&signers);
    sp1_zkvm::io::commit::<Vec<u64>>(&powers); // Can be later reduced to a single hash of powers
    sp1_zkvm::io::commit::<u64>(&total_power);
}
