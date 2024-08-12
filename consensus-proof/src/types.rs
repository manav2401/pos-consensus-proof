use alloy_primitives::Address;
use reth_primitives::{hex, B256};
use std::fmt::{self, Debug, Formatter};
use std::str::from_utf8;

pub struct MilestoneMessage {
    pub proposer: Address,    // 20 bytes
    pub start_block: u64,     // 8 bytes
    pub end_block: u64,       // 8 bytes
    pub hash: B256,           // 32 bytes
    pub bor_chain_id: u64,    // 8 bytes
    pub milestone_id: String, // 81 bytes (36 + 3 + 42)
}

impl Debug for MilestoneMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Milestone {{ proposer: {}, start_block: {}, end_block: {}, hash: {}, bor_chain_id: {}, milestone_id: {} }}",
            self.proposer,
            self.start_block,
            self.end_block,
            self.hash,
            self.bor_chain_id,
            self.milestone_id,
        )
    }
}

impl MilestoneMessage {
    // encode the milestone message to a byte array
    pub fn encode(self) -> [u8; 157] {
        let mut encoded_milestone: [u8; 157] = [0; 157];
        encoded_milestone[0..20].copy_from_slice(self.proposer.as_slice());
        encoded_milestone[20..28].copy_from_slice(&self.start_block.to_be_bytes());
        encoded_milestone[28..36].copy_from_slice(&self.end_block.to_be_bytes());
        encoded_milestone[36..68].copy_from_slice(self.hash.as_slice());
        encoded_milestone[68..76].copy_from_slice(&self.bor_chain_id.to_be_bytes());
        encoded_milestone[76..157].copy_from_slice(self.milestone_id.as_bytes());
        encoded_milestone
    }

    // decode the byte array into milestone message
    pub fn decode(encoded_milestone: [u8; 157]) -> MilestoneMessage {
        let mut u64_bytes = [0u8; 8];

        u64_bytes.copy_from_slice(&encoded_milestone[20..28]);
        let start_block = u64::from_be_bytes(u64_bytes);

        u64_bytes.copy_from_slice(&encoded_milestone[28..36]);
        let end_block = u64::from_be_bytes(u64_bytes);

        u64_bytes.copy_from_slice(&encoded_milestone[68..76]);
        let bor_chain_id = u64::from_be_bytes(u64_bytes);

        let milestone_id = from_utf8(&encoded_milestone[76..157]).unwrap().to_string();

        MilestoneMessage {
            proposer: Address::from_slice(&encoded_milestone[0..20]),
            start_block,
            end_block,
            hash: B256::from_slice(&encoded_milestone[36..68]),
            bor_chain_id,
            milestone_id,
        }
    }
}
