//! A script to print the program verification key.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --package operator --bin vkey --release
//! ```

use common::CONSENSUS_PROOF_ELF;
use sp1_sdk::{HashableKey, ProverClient};
fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the program.
    let (_, vk) = client.setup(CONSENSUS_PROOF_ELF);

    // Print the verification key.
    println!("Program Verification Key: {}", vk.bytes32());
}
