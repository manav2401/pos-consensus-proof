use pos_consensus_proof::milestone::MilestoneProofInputs;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

pub mod contract;
pub mod types;
pub mod utils;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
///
/// This file is generated by running `cargo prove build` inside the `program` directory.
pub const CONSENSUS_PROOF_ELF: &[u8] =
    include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

pub struct ConsensusProver {
    pub prover_client: ProverClient,
    pub pkey: SP1ProvingKey,
    pub vkey: SP1VerifyingKey,
}

impl Default for ConsensusProver {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusProver {
    pub fn new() -> Self {
        println!("Initializing SP1 ProverClient...");
        sp1_sdk::utils::setup_logger();
        let prover_client = ProverClient::new();
        let (pkey, vkey) = prover_client.setup(CONSENSUS_PROOF_ELF);
        println!("SP1 ProverClient initialized");
        Self {
            prover_client,
            pkey,
            vkey,
        }
    }

    /// Generate a consensus proof suggesting that a state root associated to a bor block has gone
    /// through 2/3+1 consensus in heimdall through the milestone message. Returns an
    /// SP1Groth16Proof.
    pub fn generate_consensus_proof(
        &self,
        inputs: MilestoneProofInputs,
    ) -> SP1ProofWithPublicValues {
        let mut stdin = SP1Stdin::new();

        stdin.write(&inputs.tx_data);
        stdin.write(&inputs.tx_hash);
        stdin.write(&inputs.precommits);
        stdin.write(&inputs.sigs);
        stdin.write(&inputs.signers);
        stdin.write(&inputs.bor_header);
        stdin.write(&inputs.bor_block_hash);
        stdin.write(&inputs.state_sketch_bytes);
        stdin.write(&inputs.l1_block_hash);

        // Generate the proof. Depending on SP1_PROVER env variable, this may be a mock, local or network proof.
        let proof = self
            .prover_client
            .prove(&self.pkey, stdin)
            .plonk()
            .run()
            .expect("Failed to execute.");

        // Return the proof.
        proof
    }

    pub fn verify_consensus_proof(&self, proof: &SP1ProofWithPublicValues) {
        self.prover_client
            .verify(proof, &self.vkey)
            .expect("Failed to verify proof.");
    }
}
