// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Benchmark 3: Minimal ERC20 with transfer
contract SimpleERC20 {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(uint256 initialSupply) {
        balanceOf[msg.sender] = initialSupply;
        totalSupply = initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
