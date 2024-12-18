//! A program which generates consensus proofs for Polygon PoS chain using
//! the milestone message asserting that majority of validators by stake
//! voted on a specific block.

#![no_main]
sp1_zkvm::entrypoint!(main);

use common::PoSConsensusInput;
use pos_consensus_proof::prove;

fn main() {
    // Read inputs from the zkVM's stdin.
    let input = sp1_zkvm::io::read::<PoSConsensusInput>();

    // Verify the inputs and generate a proof
    let commit = prove(input);

    // Commit the values to be exposed to the verifier
    sp1_zkvm::io::commit(&commit);
}
