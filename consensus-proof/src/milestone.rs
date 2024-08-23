use crate::helper::*;

use alloy_primitives::{private::alloy_rlp::Decodable, Address};
use reth_primitives::{hex, hex::FromHex, keccak256, Header};

pub struct MilestoneProofInputs {
    pub tx_data: String,
    pub tx_hash: String,
    pub precommits: Vec<String>,
    pub sigs: Vec<String>,
    pub signers: Vec<String>,
    pub headers: Vec<String>,
    pub vote: Vec<bool>,
    pub power: Vec<u64>,
}

pub struct MilestoneProver {
    inputs: MilestoneProofInputs,
}

impl MilestoneProver {
    pub fn init(inputs: MilestoneProofInputs) -> Self {
        MilestoneProver { inputs }
    }

    pub fn prove(&self) -> bool {
        // Verify if the transaction data provided is actually correct or not
        // TODO: Handle error
        let milestone = verify_tx_data(&self.inputs.tx_data, &self.inputs.tx_hash).unwrap();

        // Make sure that we have equal number of precommits, signatures and signers.
        if self.inputs.precommits.len() != self.inputs.sigs.len()
            || self.inputs.sigs.len() != self.inputs.signers.len()
            || self.inputs.signers.len() != self.inputs.vote.len()
            || self.inputs.vote.len() != self.inputs.power.len()
        {
            return false;
        }

        let total_power: u64 = self.inputs.power.iter().sum();
        let mut majority_power: u64 = 0;

        // Verify that the signatures generated by signing the precommit message are indeed signed
        // by the given validators.
        for (i, sig) in self.inputs.sigs.iter().enumerate() {
            let decoded_precommit_message =
                hex::decode(self.inputs.precommits[i].as_str()).unwrap();
            let (valid, voted) =
                verify_precommit(decoded_precommit_message.clone(), &self.inputs.tx_hash);
            if !valid {
                println!("Precommit message verification failed for signer: {}", i);
                return false;
            }
            if !voted {
                continue;
            }
            if !verify_signature(
                sig.as_str(),
                &keccak256(decoded_precommit_message),
                Address::from_hex(self.inputs.signers[i].as_str()).unwrap(),
            ) {
                println!("Signature verification failed for signer: {}", i);
                return false;
            } else {
                // Increment majority vote if voted yes
                if self.inputs.vote[i] {
                    majority_power += self.inputs.power[i];
                }
            }
        }

        // Check if the majority power is greater than 2/3rd of the total power
        if majority_power <= total_power / 3 * 2 {
            println!("Majority power is less than 2/3rd of the total power");
            return false;
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

        // Check if the header's number matches with milestone message's end block
        let number = last_header.number;
        if milestone.end_block != number {
            return false;
        }

        // Check if the header's hash matches with the milestone message's hash
        let hash = last_header.hash_slow().to_vec();
        if milestone.hash != hash {
            return false;
        }

        true
    }
}
