// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/Bench1_SimpleOverflow.sol";

contract Bench1Test {
    SimpleOverflow target;

    function setUp() public {
        target = new SimpleOverflow();
    }

    /// @notice Check that unsafeAdd can overflow
    function check_overflow(uint256 a, uint256 b) public {
        uint256 result = target.unsafeAdd(a, b);
        // This should FAIL — unchecked add can overflow
        assert(result >= a);
    }
}
