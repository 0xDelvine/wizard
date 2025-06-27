// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract MockGroupVault  {
    uint256 private mockBalance;

    function mockVaultBalance(uint256 _balance) external {
        mockBalance = _balance;
    }

    function mockDepositForCycle(uint256 _deposit, address _asset, address _vaultAddress, bytes32 _cycleId) external {
        mockBalance = _deposit;
    }
    function getUserDepositForCycle(address asset, address _vaultAddress, bytes32 _cycleId)
        external
        view
        returns (uint256)
    {
        return mockBalance;
    }

    function getVaultCycleBalance(address asset, address _vaultAddress, bytes32 _cycleId)
        external
     
       view
        returns (uint256)
    {
        return mockBalance;
    }
}
