// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

interface IBeefyVault {
    function deposit(uint256 _amount) external;
    function withdraw(uint256 _shares) external;
    function getPricePerFullShare() external view returns (uint256);
    function balance() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function want() external view returns (address);
}
