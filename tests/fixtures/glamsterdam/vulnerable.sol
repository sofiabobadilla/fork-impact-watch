// SPDX-License-Identifier: MIT
// Each contract shows one shape Glamsterdam (EIP-8037/8038) breaks. Expected rule in the comment above it.
pragma solidity ^0.8.28;

interface IHook { function onEvent(uint256 id) external; }
interface IVault { function settle(address who) external; }

// failure-branch-writes-storage (FW-GLAM-1), marker-before-unchecked-call (FW-GLAM-6)
contract Executor {
    mapping(uint256 => bytes) public payloads;
    mapping(uint256 => bool) public done;
    mapping(uint256 => bool) public broken;

    function execute(uint256 id, address target) external {
        require(!done[id], "done");
        done[id] = true;
        (bool success, ) = target.call(payloads[id]);
        if (!success) {
            broken[id] = true;
        }
    }
}

// failure-branch-writes-storage via try/catch (FW-GLAM-1)
contract Settler {
    IVault public vault;
    mapping(address => bool) public skipped;

    function settle(address who) external {
        try vault.settle(who) {
        } catch {
            skipped[who] = true;
        }
    }
}

// set-clear-around-call (FW-GLAM-2), in a function and in a zero-idle lock modifier
contract Messenger {
    address public currentSender;
    uint256 private locked;

    modifier lock() {
        locked = 1;
        _;
        locked = 0;
    }

    function relay(address target, bytes calldata data) external lock {
        currentSender = msg.sender;
        (bool ok, ) = target.call(data);
        require(ok, "relay failed");
        currentSender = address(0);
    }
}

// revert-data-oog-guess, post-call-gas-ratio, unchecked-create (FW-GLAM-3)
contract Router {
    IVault public vault;
    mapping(address => uint256) public refunds;

    function route(address who) external {
        try vault.settle(who) {
        } catch (bytes memory reason) {
            if (reason.length == 0) revert("probably out of gas");
            refunds[who] = 1;
        }
    }

    function forward(address target, bytes calldata data) external {
        uint256 before = gasleft();
        (bool ok, ) = target.call(data);
        if (!ok && gasleft() <= before / 63) revert("out of gas");
    }

    function deploy(bytes memory code, bytes32 salt) external returns (address addr) {
        assembly {
            addr := create2(0, add(code, 0x20), mload(code), salt)
        }
    }

    function deployBlind(bytes memory code) external {
        assembly {
            pop(create(0, add(code, 0x20), mload(code)))
        }
    }
}

// fixed-gas-call (FW-GLAM-4)
contract Oracle {
    uint256 public constant CALLBACK_GAS = 100_000;
    mapping(uint256 => address) public consumer;

    function fulfill(uint256 id) external {
        address c = consumer[id];
        delete consumer[id];
        (bool ok, ) = c.call{gas: CALLBACK_GAS}(abi.encodeCall(IHook.onEvent, (id)));
        ok;
        IHook(c).onEvent{gas: 50000}(id);
    }
}

// gasleft-metering (FW-GLAM-5)
contract Paymaster {
    mapping(address => uint256) public owed;

    function run(address target, bytes calldata data) external {
        uint256 start = gasleft();
        (bool ok, ) = target.call(data);
        require(ok);
        unchecked {
            owed[msg.sender] += (start - gasleft()) * tx.gasprice;
        }
    }
}

// fixed-gas-reserve, min-gas-check, stipend-transfer (FW-GLAM-7)
contract Batcher {
    uint256 constant RESERVE = 40_000;
    mapping(uint256 => bool) public settled;

    function batchCall(uint256 id, address target, uint256 need, bytes calldata data) external {
        require(gasleft() >= need + RESERVE, "gas");
        (bool ok, ) = target.call{gas: gasleft() - RESERVE}(data);
        require(ok);
        settled[id] = true;
    }

    function pay(address payable to, uint256 amount) external {
        to.transfer(amount);
    }
}

// 7702-unprotected-init (FW-GLAM-8). Designed as an EIP-7702 delegate for EOAs.
contract DelegateWallet {
    address public owner;
    bool public initialized;

    function initialize(address newOwner) external {
        require(!initialized, "init");
        initialized = true;
        owner = newOwner;
    }
}
