// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Safe vault: follows CEI pattern, uses checked arithmetic.
contract SafeVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // CEI: state update BEFORE external call
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
