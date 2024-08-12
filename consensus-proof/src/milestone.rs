use crate::types::MilestoneMessage;
use crate::*;
use alloy_primitives::Address;
use reth_primitives::{hex, hex::FromHex, keccak256, Header, B256};

pub struct MilestoneProof {
    inputs: MilestoneProofInputs,
}

pub struct MilestoneProofInputs {
    pub tx_data: String,
    pub tx_hash: String,
    pub precommits: Vec<String>,
    pub sigs: Vec<String>,
    pub signers: Vec<String>,
    pub milestone_msg: String,
    pub headers: Vec<String>,
}

impl MilestoneProof {
    pub fn init(inputs: MilestoneProofInputs) -> Self {
        MilestoneProof { inputs }
    }

    pub fn validate(&self) -> bool {
        // Verify if the transaction data provided is actually correct or not
        let mut result = verify_tx_data(&self.inputs.tx_data);
        if !result {
            println!("Transaction data verification failed");
            return false;
        }

        // Verify if the transaction hash provided is actually correct or not
        result = verify_tx_hash(&self.inputs.tx_data, &self.inputs.tx_hash);
        if !result {
            println!("Transaction hash verification failed");
            return false;
        }

        // Make sure that we have equal number of precommits, signatures and signers.
        if self.inputs.precommits.len() != self.inputs.sigs.len()
            || self.inputs.sigs.len() != self.inputs.signers.len()
        {
            println!("Precommits, signatures and signers count mismatch");
            return false;
        }

        // Verify that the signatures generated by signing the precommit message are indeed signed
        // by the given validators.
        for (i, sig) in self.inputs.sigs.iter().enumerate() {
            if !verify_signature(
                sig.as_str(),
                &keccak256(self.inputs.precommits[i].as_bytes()),
                Address::from_hex(self.inputs.signers[i].as_str()).unwrap(),
            ) {
                println!("Signature verification failed for signer: {}", i);
                return false;
            }
        }

        let headers: Vec<Header> = self
            .inputs
            .headers
            .iter()
            .map(|hh| {
                let header_bytes = hex::decode(hh).unwrap_or_default();
                Header::decode(&mut header_bytes.as_slice()).unwrap()
            })
            .collect();

        // In a milestone proof, we assume that we'll only receive 1 element in the headers array
        // and that should be the end block's header present in the milestone message.
        let last_header = headers.last().expect("No headers found");

        // Decode the milestone message. The `milestone_msg` is a hex encoded representation of
        // the milestone. Convert it into appropriate byte array to decode it.
        let mut milestone_msg_bytes = [0u8; 157];
        milestone_msg_bytes.copy_from_slice(
            hex::decode(self.inputs.milestone_msg.clone())
                .unwrap()
                .as_slice(),
        );

        let milestone = MilestoneMessage::decode(milestone_msg_bytes);

        // Check if the header's number matches with milestone message's end block
        let number = last_header.number;
        if milestone.end_block != number {
            println!("Block number mismatch");
            return false;
        }

        // Check if the header's hash matches with the milestone message's hash
        let hash = last_header.hash_slow();
        if milestone.hash != hash {
            println!("Block hash mismatch");
            return false;
        }

        true
    }
}
