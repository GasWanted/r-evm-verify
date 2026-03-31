// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// ===== 1. EtherStore — Classic reentrancy =====
// From DeFiVulnLabs/Reentrancy.sol
contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        (bool send, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(send, "send failed");
        balances[msg.sender] -= _weiToWithdraw;
    }
}

// ===== 2. UncheckedOverflow — Integer overflow =====
// From DeFiVulnLabs/Overflow.sol pattern
contract UncheckedOverflow {
    mapping(address => uint256) balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) public {
        unchecked {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
}

// ===== 3. UnprotectedWithdraw — Missing access control =====
// From DeFiVulnLabs/Visibility.sol pattern
contract UnprotectedWithdraw {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // BUG: no access control — anyone can call
    function withdrawAll() public {
        uint256 bal = address(this).balance;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}

// ===== 4. DelegateCallVuln — Delegatecall to untrusted contract =====
// From DeFiVulnLabs/Delegatecall.sol pattern
contract DelegateCallVuln {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    function setValue(address impl, bytes calldata data) public {
        (bool success, ) = impl.delegatecall(data);
        require(success);
    }
}

// ===== 5. TxOriginPhishing — tx.origin misuse =====
// From DeFiVulnLabs/txorigin.sol pattern
contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(address to, uint256 amount) public {
        // BUG: uses tx.origin instead of msg.sender
        require(tx.origin == owner, "Not owner");
        (bool success, ) = to.call{value: amount}("");
        require(success);
    }

    receive() external payable {}
}

// ===== 6. SelfDestructible — Reachable selfdestruct =====
// From DeFiVulnLabs/Selfdestruct.sol pattern
contract SelfDestructible {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BUG: no access control on kill
    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {}
}

// ===== 7. SafeVault — Control (no vulnerabilities) =====
contract SafeVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        balances[msg.sender] = 0; // CEI: state update first
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }

    function adminWithdraw() public {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success);
    }
}
