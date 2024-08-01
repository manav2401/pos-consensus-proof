use reth_primitives::{Address, Header, B256};

pub struct MilestoneProof {
    inputs: MilestoneProofInputs,
}

pub struct MilestoneProofInputs {
    pub milestone: MilestoneMessage,
    pub headers: Vec<Header>,
    pub sigs: Vec<String>,
    pub target_block_hash: B256,
    pub target_state_root: B256,
}

pub struct MilestoneMessage {
    pub proposer: Address,
    pub start_block: u64,
    pub end_block: u64,
    pub hash: B256,
    pub bor_chain_id: u64,
    pub milestone_id: String,
    pub timestamp: u64,
}

impl MilestoneProof {
    pub fn init(inputs: MilestoneProofInputs) -> Self {
        MilestoneProof { inputs }
    }

    pub fn validate(&self) -> bool {
        // In a milestone proof, we assume that we'll only receive 1 element in the headers array
        // and that should be the end block's header present in the milestone message.
        let last_header = self.inputs.headers.last();
        if last_header.is_none() {
            return false;
        }

        // Check if the header's number matches with milestone message's end block
        let number = last_header.unwrap().number;
        if self.inputs.milestone.end_block != number {
            return false;
        }

        // Check if the header's hash matches with the milestone message's hash
        let hash = last_header.unwrap().hash_slow();
        if self.inputs.milestone.hash != hash {
            return false;
        }

        true
    }
}
