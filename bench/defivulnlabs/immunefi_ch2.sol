// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

/// Immunefi Challenge 2 — Storage collision in proxy
/// Bug: _IMPLEMENTATION_SLOT is a regular storage variable (slot 0),
/// not a constant. It collides with the implementation's storage.
contract BuggyProxy {
    // BUG: should be `constant` — as a variable it occupies slot 0
    bytes32 internal _IMPLEMENTATION_SLOT = keccak256("where.bug.ser");
    address public admin;

    constructor(address impl) {
        admin = msg.sender;
        // This writes to slot from _IMPLEMENTATION_SLOT, but the slot
        // variable itself is at slot 0 — collision!
        assembly {
            sstore(sload(0), impl)
        }
    }

    function upgrade(address newImpl) external {
        require(msg.sender == admin, "Not admin");
        assembly {
            sstore(sload(0), newImpl)
        }
    }

    fallback() external payable {
        address impl;
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
        (bool ok, ) = impl.delegatecall(msg.data);
        require(ok);
    }
}
