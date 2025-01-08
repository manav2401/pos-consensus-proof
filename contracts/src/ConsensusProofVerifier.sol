// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title PoS Consensus Proof Verifier.
/// @author Manav Darji (manav2401)
/// @notice This contract verifies a consensus proof representing that a bor block has been 
///         voted upon by >2/3 of validators.
contract ConsensusProofVerifier {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifier;

    /// @notice The verification key for the consensus proof program.
    bytes32 public consensusProofVKey;

    /// @notice The last verified bor block hash.
    bytes32 public lastVerifiedBorBlockHash;

    constructor(address _verifier, bytes32 _consensusProofVKey) {
        verifier = _verifier;
        consensusProofVKey = _consensusProofVKey;
    }

    /// @notice The entrypoint for the verifier.
    /// @param _proofBytes The encoded proof.
    /// @param new_bor_block_hash The bor block hash to be verified.
    /// @param l1_block_hash The l1 block hash for anchor.
    function verifyConsensusProof(
        bytes calldata _proofBytes, 
        bytes32 new_bor_block_hash,
        bytes32 l1_block_hash
    ) public {
        bytes memory publicValues = abi.encodePacked(lastVerifiedBorBlockHash, new_bor_block_hash, l1_block_hash);
        ISP1Verifier(verifier).verifyProof(consensusProofVKey, publicValues, _proofBytes);
        lastVerifiedBorBlockHash = new_bor_block_hash;
    }
}