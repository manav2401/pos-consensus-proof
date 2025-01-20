use alloy_primitives::{address, Address, FixedBytes, B256};
use alloy_sol_types::sol;
use reth_primitives::Header;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Zero address to be used as caller for eth_call
pub const CALLER: Address = address!("0000000000000000000000000000000000000000");

/// Maximum number of heimdall blocks to search for new milestone from latest block.
pub const MAX_HEIMDALL_LOOKUP: u64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoSConsensusInput {
    // heimdall related data
    pub tx_data: String,
    pub tx_hash: B256,
    pub precommits: Vec<Vec<u8>>,
    pub sigs: Vec<String>,
    pub signers: Vec<Address>,

    // bor related data
    pub bor_header: Header,
    pub prev_bor_header: Header,

    // l1 related data
    pub state_sketch_bytes: Vec<u8>,
    pub l1_block_header: Header,
    pub l1_block_hash: B256,
    pub stake_info_address: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoSConsensusCommit {
    pub prev_bor_hash: B256,
    pub new_bor_hash: B256,
    pub l1_block_hash: B256,
    pub stake_info_address: Address,
}

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes32 prev_bor_block_hash;
        bytes32 new_bor_block_hash;
        bytes32 l1_block_hash;
    }
}

sol! {
    contract ConsensusProofVerifier {
        bytes32 public lastVerifiedBorBlockHash;
        function verifyConsensusProof(bytes calldata _proofBytes, bytes32 new_bor_block_hash, bytes32 l1_block_hash) public view;
        function getEncodedValidatorInfo() public view returns(address[] memory, uint256[] memory, uint256);
        function getValidatorInfo() public view returns(address[] memory, uint256[] memory, uint256);
        function getCappedValidatorInfo() public view returns(address[] memory, uint256[] memory, uint256);
    }
}

pub fn sha256(data: &[u8]) -> FixedBytes<32> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    FixedBytes::from_slice(result.as_slice())
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ChainProofPoSInput {
//     pub prev_l2_block_hash: B256,
//     pub new_l2_block_hash: B256,
//     pub l1_block_hash: B256,
//     pub new_ler: B256,
//     pub l1_ger_addr: Address,
//     pub l2_ger_addr: Address,
//     pub stake_manager_address: Address,
// }
