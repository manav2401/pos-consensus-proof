// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

/// @title PoS Staking Info.
/// @author Manav Darji (manav2401)
/// @notice This is a wrapper contract over PoS staking manager contracts to get validator set info.
contract StakingInfo {
    /// @notice The address of the PoS Stake Manager Proxy Contract.
    address public posStakeManager;

    /// @notice The address of creator.
    address public owner;

    constructor(address _posStakeManager) {
        posStakeManager = _posStakeManager;
        owner = msg.sender;
    }

    // Restrict access so that only 'owner' can execute
    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    /// @notice Sets the stake manager contract address.
    /// @param _posStakeManager The address of the PoS Stake Manager contract.
    function setStakeManager(address _posStakeManager) public onlyOwner {
        posStakeManager = _posStakeManager;
    }

    /// @notice Fetches the active validator info like signer address, respective stake, and 
    ///         total stake and returns the encoded data.
    /// @return activeValidators list of active validators in set
    /// @return stakes list of respective stake of active validators in set
    /// @return totalStake total stake of whole validator set
    function getValidatorInfo() public view returns (address[] memory, uint256[] memory, uint256) {
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

    // getValidatorInfo with result capped to 10
    function getCappedValidatorInfo() public view returns (address[] memory, uint256[] memory, uint256) {
        // uint256 totalValidators = StakeManager(posStakeManager).currentValidatorSetSize();
        uint256 totalValidators = 10;
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
}