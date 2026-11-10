# pragma version ^0.4.0
# Vyper shapes Glamsterdam breaks.

failed: public(HashMap[address, bool])

@external
def push(target: address, data: Bytes[1024]):
    ok: bool = raw_call(target, data, gas=80000, revert_on_failure=False)
    if not ok:
        self.failed[target] = True

@external
def pay(to: address, amount: uint256):
    send(to, amount)
