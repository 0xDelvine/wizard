// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

library ShareCalculator {
    function calculateShares(uint256 amount, uint256 totalSupply, uint256 totalAssets)
        internal
        pure
        returns (uint256)
    {
        if (totalSupply == 0 || totalAssets == 0) {
            return amount;
        }
        return (amount * totalSupply) / totalAssets;
    }
}
