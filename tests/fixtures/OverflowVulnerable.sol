// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Uses unchecked arithmetic that can overflow.
contract OverflowVulnerable {
    uint256 public total;

    function unsafeAdd(uint256 a, uint256 b) external returns (uint256) {
        unchecked {
            uint256 result = a + b; // Can overflow!
            total = result;
            return result;
        }
    }

    function unsafeMul(uint256 a, uint256 b) external returns (uint256) {
        unchecked {
            uint256 result = a * b; // Can overflow!
            total = result;
            return result;
        }
    }
}
