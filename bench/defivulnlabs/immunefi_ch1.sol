// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

/// Immunefi Challenge 1 — Incorrect msg.value check in loop
/// Bug: require(msg.value >= PRICE) is inside the loop, so sending
/// 1 ETH lets you mint N items (checked N times against the same msg.value)
contract BuggyMinter {
    uint256 public constant PRICE = 1 ether;
    uint256 public totalMinted;
    mapping(uint256 => address) public owners;

    function mint(uint256 amount) external payable {
        require(amount > 0, "Zero amount");
        for (uint256 i = 0; i < amount; i++) {
            // BUG: should be msg.value >= PRICE * amount BEFORE the loop
            require(msg.value >= PRICE, "Insufficient payment");
            owners[totalMinted] = msg.sender;
            totalMinted++;
        }
    }

    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok);
    }
}
