// SPDX-License-Identifier: MIT
// The same contracts written the way the advisories recommend. The scanner should stay quiet here.
pragma solidity ^0.8.28;

interface IVault { function settle(address who) external; }

contract Executor {
    uint256 public constant POST_CALL_GAS = 60_000;
    mapping(uint256 => bytes) public payloads;
    mapping(uint256 => uint256) public gasFor;
    mapping(uint256 => bool) public done;

    event Failed(uint256 indexed id);

    function execute(uint256 id, address target) external {
        require(!done[id], "done");
        uint256 need = gasFor[id];
        require(gasleft() * 63 / 64 >= need + POST_CALL_GAS, "not enough gas");
        (bool success, ) = target.call{gas: need}(payloads[id]);
        if (success) {
            done[id] = true;
        } else {
            emit Failed(id);
        }
    }
}

contract Messenger {
    address transient currentSender;
    bool transient locked;

    function relay(address target, bytes calldata data) external {
        require(!locked, "reentrant");
        locked = true;
        currentSender = msg.sender;
        (bool ok, ) = target.call(data);
        require(ok, "relay failed");
        currentSender = address(0);
        locked = false;
    }
}

contract Router {
    function deploy(bytes memory code, bytes32 salt) external returns (address addr) {
        assembly {
            addr := create2(0, add(code, 0x20), mload(code), salt)
        }
        require(addr != address(0) && addr.code.length > 0, "deploy failed");
    }
}

contract Oracle {
    uint256 public callbackGas = 500_000; // adjustable by governance
    address public governance;

    function setCallbackGas(uint256 g) external {
        require(msg.sender == governance, "auth");
        callbackGas = g;
    }
}

contract Payer {
    function pay(address payable to, uint256 amount) external {
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "pay failed");
    }
}
