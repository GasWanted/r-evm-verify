// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/Bench3_ERC20.sol";

contract Bench3Test {
    SimpleERC20 token;

    function setUp() public {
        token = new SimpleERC20(1000);
    }

    /// @notice Transfer should not create tokens
    function check_transfer_conservation(address to, uint256 amount) public {
        uint256 totalBefore = token.totalSupply();
        try token.transfer(to, amount) {} catch {}
        uint256 totalAfter = token.totalSupply();
        assert(totalBefore == totalAfter);
    }
}
