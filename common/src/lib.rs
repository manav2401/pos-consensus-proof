use alloy_primitives::{address, Address, B256};
use alloy_sol_types::sol;
use reth_primitives::Header;
use serde::{Deserialize, Serialize};

/// Zero address to be used as caller for eth_call
pub const CALLER: Address = address!("0000000000000000000000000000000000000000");

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
///
/// This file is generated by running `cargo prove build` inside the `operator` directory.
pub const CONSENSUS_PROOF_ELF: &[u8] = include_bytes!("../../elf/pos-consensus");

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
    }
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
