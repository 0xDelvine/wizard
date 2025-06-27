// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import "./MockToken.sol";

contract MockBeefyVault is ERC20 {
    address public asset;

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        asset = address(new MockToken("USDC", "USDC", 6));
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        // Mock implementation - returns the same amount as shares
        _mint(receiver, assets);
        return assets;
    }

    function withdraw(
        uint256 assets,
        address receiver,
        address /* owner */ // Parameter commented out to fix warning
    ) external returns (uint256 shares) {
        // Mock implementation
        _burn(msg.sender, assets);
        // Send tokens to receiver
        MockToken(asset).mint(receiver, assets);
        return assets;
    }

    function maxDeposit(address) external pure returns (uint256) {
        return type(uint256).max;
    }

    function maxWithdraw(address) external view returns (uint256) {
        return totalSupply();
    }

    function previewDeposit(uint256 assets) external pure returns (uint256) {
        return assets;
    }

    function previewWithdraw(uint256 assets) external pure returns (uint256) {
        return assets;
    }

    function convertToShares(uint256 assets) external pure returns (uint256) {
        return assets;
    }

    function convertToAssets(uint256 shares) external pure returns (uint256) {
        return shares;
    }
}
