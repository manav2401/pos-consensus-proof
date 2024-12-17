use common::{PoSConsensusInput, CONSENSUS_PROOF_ELF};
use sp1_sdk::{
    HashableKey, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};

pub mod contract;
pub mod types;
pub mod utils;

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
        println!("SP1 ProverClient initialized!");
        println!("VKey: {:?}", vkey.bytes32());
        Self {
            prover_client,
            pkey,
            vkey,
        }
    }

    /// Generate a PLONK proof of consensus which states that a state root associated with a
    /// bor block majority by stake (>2/3 of total stake) votes in heimdall consensus through
    /// the milestone message. It returns the generated PLONK proof.
    pub fn generate_consensus_proof_plonk(
        &self,
        input: PoSConsensusInput,
    ) -> SP1ProofWithPublicValues {
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        println!("Starting to generate PLONK proof...");

        // Generate the proof. Depending on SP1_PROVER env variable, this may be a mock,
        // local or network proof.
        let proof = self
            .prover_client
            .prove(&self.pkey, stdin)
            .plonk()
            .run()
            .expect("Failed to generate PLONK proof.");

        println!("Done generating PLONK proof.");

        // Return the proof.
        proof
    }

    /// Generate a Compressed proof of consensus which states that a state root associated with a
    /// bor block majority by stake (>2/3 of total stake) votes in heimdall consensus through
    /// the milestone message. It returns the generated compressed proof.
    pub fn generate_consensus_proof_compressed(
        &self,
        input: PoSConsensusInput,
    ) -> SP1ProofWithPublicValues {
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        println!("Starting to generate compressed proof...");

        // Generate the proof. Depending on SP1_PROVER env variable, this may be a mock,
        // local or network proof.
        let proof = self
            .prover_client
            .prove(&self.pkey, stdin)
            .compressed()
            .run()
            .expect("Failed to generate compressed proof.");

        println!("Done generating compressed proof.");

        // Return the proof.
        proof
    }

    pub fn verify_consensus_proof(&self, proof: &SP1ProofWithPublicValues) {
        println!("Starting to verify proof...");
        self.prover_client
            .verify(proof, &self.vkey)
            .expect("Failed to verify proof.");
        println!("Done verifying proof.")
    }

    pub fn execute(&self, input: PoSConsensusInput) {
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        let (_, report) = self
            .prover_client
            .execute(&self.pkey.elf, stdin)
            .run()
            .unwrap();

        println!(
            "Finished executing in {} cycles",
            report.total_instruction_count()
        );
    }
}
