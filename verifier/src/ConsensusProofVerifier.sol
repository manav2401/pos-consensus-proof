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

    constructor(address _verifier, bytes32 _consensusProofVKey) {
        verifier = _verifier;
        consensusProofVKey = _consensusProofVKey;
    }

    /// @notice The entrypoint for the verifier.
    /// @param _proofBytes The encoded proof.
    /// @param _publicValues The encoded public values.
    function verifyConsensusProof(bytes calldata _proofBytes, bytes calldata _publicValues)
        public
        view
        returns (bool)
    {
        /// TODO: Fetch data from PoS L1  contracts 
        ISP1Verifier(verifier).verifyProof(consensusProofVKey, _publicValues, _proofBytes);
        return true;
    }
}