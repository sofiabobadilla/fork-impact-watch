// SPDX-License-Identifier: MIT
// Common, safe shapes that look like red flags to a naive search. The scanner should stay quiet here.
pragma solidity ^0.8.28;

interface IReceiver { function onReceived(address from, uint256 id) external returns (bytes4); }
interface IVault { function settle(address who) external; }

contract ReceiverCheck {
    // Every path reverts, so guessing from empty revert data commits nothing.
    function _check(address to, uint256 id) internal {
        try IReceiver(to).onReceived(msg.sender, id) returns (bytes4 r) {
            require(r == IReceiver.onReceived.selector, "rejected");
        } catch (bytes memory reason) {
            if (reason.length == 0) {
                revert("not a receiver");
            } else {
                assembly { revert(add(32, reason), mload(reason)) }
            }
        }
    }
}

contract TokenTransfer {
    function _safeTransfer(address token, address to, uint256 amount) internal returns (bool success) {
        bytes memory data = abi.encodeWithSelector(0xa9059cbb, to, amount);
        assembly {
            success := call(gas(), token, 0, add(data, 32), mload(data), 0, 32)
            success := and(success, or(iszero(returndatasize()), eq(mload(0), 1)))
        }
    }
}

contract Factory {
    function deploy(bytes memory code, bytes32 salt) external returns (address proxy) {
        assembly { proxy := create2(0, add(code, 0x20), mload(code), salt) }
        require(address(proxy) != address(0), "create2 failed");
    }
}

contract PullPayments {
    mapping(address => uint256) public pending;

    // A failed push becomes a credit the recipient can withdraw later: retryable.
    function _payOrCredit(address to, uint256 amount) internal {
        (bool ok, ) = payable(to).call{value: amount}("");
        if (!ok) pending[to] += amount;
    }
}

contract Batch {
    mapping(bytes32 => bool) public used;
    mapping(address => uint256) public pendingBurn;
    IVault public vault;

    // The failure branch undoes the marker set before the call, so the item can be retried.
    function run(bytes32 h, address target, bytes calldata data) external {
        require(!used[h], "used");
        used[h] = true;
        (bool ok, ) = target.call(data);
        if (!ok) {
            used[h] = false;
        }
    }

    // The failure branch writes and then reverts: nothing is committed.
    function burn(address who, uint256 amount) external {
        pendingBurn[who] = 0;
        try vault.settle(who) {
        } catch {
            pendingBurn[who] = amount;
            revert("burn failed");
        }
    }
}

// EIP-7702 delegate with an empty initializer kept for a proxy interface.
contract DelegateStub {
    function initialize(bytes calldata) external {}
}
