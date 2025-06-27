// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./HifadhiGroup.sol";

/**
 * @title HifadhiFactory
 * @dev Factory contract for creating new investment groups using Beefy Finance vaults
 */
contract HifadhiFactory is Ownable {
    using Clones for address;

    // State Variables
    address public immutable implementation;
    uint256 private _groupIds;
    mapping(uint256 => address) public groups;
    mapping(address => uint256[]) public userGroups;
    mapping(address => bool) public verifiedVaults;

    // Events
    event GroupCreated(uint256 indexed groupId, address indexed groupAddress, address indexed creator, string name);

    event VaultVerificationUpdated(address indexed vaultAddress, bool isVerified);

    constructor() Ownable(msg.sender) {
        // Deploy the implementation contract
        implementation = address(new HifadhiGroup());
    }

    /**
     * @dev Add or remove verified Beefy vaults
     * @param vaultAddress Address of the Beefy vault
     * @param isVerified Whether the vault is verified
     */
    function setVaultVerification(address vaultAddress, bool isVerified) external onlyOwner {
        require(vaultAddress != address(0), "Invalid vault address");
        verifiedVaults[vaultAddress] = isVerified;
        emit VaultVerificationUpdated(vaultAddress, isVerified);
    }

    /**
     * @dev Batch add or update verified Beefy vaults
     * @param vaultAddresses Array of vault addresses
     * @param areVerified Array of verification statuses
     */
    function batchSetVaultVerification(address[] calldata vaultAddresses, bool[] calldata areVerified)
        external
        onlyOwner
    {
        require(vaultAddresses.length == areVerified.length, "Array length mismatch");

        for (uint256 i = 0; i < vaultAddresses.length; i++) {
            require(vaultAddresses[i] != address(0), "Invalid vault address");
            verifiedVaults[vaultAddresses[i]] = areVerified[i];
            emit VaultVerificationUpdated(vaultAddresses[i], areVerified[i]);
        }
    }

    /**
     * @dev Create a new investment group
     * @param name Name of the group
     * @param minContribution Minimum contribution amount
     * @param signers Array of multisig signer addresses
     * @param minSignatures Minimum signatures required for approvals
     */
    function createGroup(string memory name, uint256 minContribution, address[] memory signers, uint256 minSignatures)
        external
        returns (address)
    {
        require(bytes(name).length > 0, "Empty name");
        require(minContribution > 0, "Invalid min contribution");
        require(signers.length >= minSignatures, "Invalid signer configuration");

        // Increment group ID
        _groupIds += 1;
        uint256 groupId = _groupIds;

        // Clone the implementation contract
        address groupAddress = implementation.clone();

        // Initialize the cloned contract
        HifadhiGroup(groupAddress).initialize(name, minContribution, signers, minSignatures, msg.sender);

        // Store group information
        groups[groupId] = groupAddress;
        userGroups[msg.sender].push(groupId);

        // Emit creation event
        emit GroupCreated(groupId, groupAddress, msg.sender, name);

        return groupAddress;
    }

    /**
     * @dev Get all groups created by a user
     * @param user Address of the user
     * @return Array of group IDs
     */
    function getUserGroups(address user) external view returns (uint256[] memory) {
        return userGroups[user];
    }

    /**
     * @dev Get a group's address by ID
     * @param groupId ID of the group
     * @return Address of the group contract
     */
    function getGroupAddress(uint256 groupId) external view returns (address) {
        return groups[groupId];
    }

    /**
     * @dev Get the current total number of groups
     * @return Current group ID counter
     */
    function getCurrentGroupId() external view returns (uint256) {
        return _groupIds;
    }

    /**
     * @dev Check if a vault is verified
     * @param vaultAddress Address of the Beefy vault
     * @return Whether the vault is verified
     */
    function isVaultVerified(address vaultAddress) external view returns (bool) {
        return verifiedVaults[vaultAddress];
    }

    /**
     * @dev Batch check if vaults are verified
     * @param vaultAddresses Array of vault addresses to check
     * @return Array of booleans indicating verification status
     */
    function batchIsVaultVerified(address[] calldata vaultAddresses) external view returns (bool[] memory) {
        bool[] memory isVerified = new bool[](vaultAddresses.length); //initialises a new bool array with a size equal to the length of the vaultAddresses array.

        for (uint256 i = 0; i < vaultAddresses.length; i++) {
            isVerified[i] = verifiedVaults[vaultAddresses[i]];
        }

        return isVerified;
    }
}
