// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Benchmark 1: Simple unchecked arithmetic
contract SimpleOverflow {
    uint256 public total;

    function unsafeAdd(uint256 a, uint256 b) external returns (uint256) {
        unchecked {
            uint256 result = a + b;
            total = result;
            return result;
        }
    }
}
