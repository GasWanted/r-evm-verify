// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract UncheckedToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        unchecked {
            balanceOf[to] += amount;
        }
    }

    function transfer(address to, uint256 amount) external {
        unchecked {
            balanceOf[msg.sender] -= amount;  // BUG: no balance check
            balanceOf[to] += amount;
        }
    }
}
