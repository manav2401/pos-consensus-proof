// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @dev Interface for the PoS Stake Manager contract with require methods to be used.
interface StakeManager {
    // Borrowed from the StakeManager contracts
    enum Status {Inactive, Active, Locked, Unstaked}
    function signers(uint256) external view returns (address);
    function signerToValidator(address) external view returns (uint256);
    function currentValidatorSetSize() external view returns (uint256);
    function validators(uint256) external view returns (uint256, uint256, uint256, uint256, uint256, address, address, Status, uint256, uint256, uint256, uint256, uint256);
    function validatorState() external view returns (uint256, uint256);
}

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

    /// @notice The address of the PoS Stake Manager contract.
    address public posStakeManager;

    /// @notice The last verified bor block hash.
    bytes32 public lastVerifiedBorBlockHash;

    constructor(address _verifier, bytes32 _consensusProofVKey, address _posStakeManager) {
        verifier = _verifier;
        consensusProofVKey = _consensusProofVKey;
        posStakeManager = _posStakeManager;
    }

    /// @notice Fetches the active validator info like signer address, respective stake, and 
    ///         total stake and returns the encoded data.
    /// @return activeValidators list of active validators in set
    /// @return stakes list of respective stake of active validators in set
    /// @return totalStake total stake of whole validator set
    function getEncodedValidatorInfo() public view returns (address[] memory, uint256[] memory, uint256) {
        uint256 totalValidators = StakeManager(posStakeManager).currentValidatorSetSize();
        address[] memory activeValidators = new address[](totalValidators);
        uint256[] memory stakes = new uint256[](totalValidators);
        for (uint256 i = 0; i < totalValidators; i++) {
            activeValidators[i] = StakeManager(posStakeManager).signers(i);
            (uint256 selfStake, , , , , , , , , , , uint256 delegatedStake, ) = StakeManager(posStakeManager).validators(StakeManager(posStakeManager).signerToValidator(activeValidators[i]));
            stakes[i] = selfStake + delegatedStake;
        }
        uint256 totalStake;
        (totalStake, ) = StakeManager(posStakeManager).validatorState();
        return (activeValidators, stakes, totalStake / 1e18);
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