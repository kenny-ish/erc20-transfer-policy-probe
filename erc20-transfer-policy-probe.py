#!/usr/bin/env python3
"""Probe ERC-20 transfer calls without sending a transaction."""

import argparse
import json
import re
import sys
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

_MASK64 = (1 << 64) - 1


def _rotation_offsets() -> List[int]:
    offsets = [0] * 25
    x, y = 1, 0
    for t in range(24):
        offsets[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


def _lfsr_bit(t: int) -> int:
    """Return the t-th bit of the Keccak round-constant LFSR."""
    if t % 255 == 0:
        return 1
    register = 0x01
    for _ in range(t % 255):
        if register & 0x80:
            register = ((register << 1) ^ 0x71) & 0xFF
        else:
            register = (register << 1) & 0xFF
    return register & 1


def _round_constants() -> List[int]:
    constants = []
    for round_index in range(24):
        value = 0
        for j in range(7):
            if _lfsr_bit(j + 7 * round_index):
                value ^= 1 << ((1 << j) - 1)
        constants.append(value)
    return constants


_ROTATIONS = _rotation_offsets()
_ROUND_CONSTANTS = _round_constants()


def _rotl(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state: List[int]) -> None:
    for round_constant in _ROUND_CONSTANTS:
        column_parity = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        correction = [
            column_parity[(x - 1) % 5] ^ _rotl(column_parity[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= correction[x]

        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(
                    state[x + 5 * y], _ROTATIONS[x + 5 * y]
                )

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ (
                    (~rotated[(x + 1) % 5 + 5 * y])
                    & rotated[(x + 2) % 5 + 5 * y]
                )
        state[0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Keccak-256, not the standardized SHA3-256 variant."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        _keccak_f(state)

    output = bytearray()
    while len(output) < 32:
        for lane in range(rate // 8):
            output.extend(state[lane].to_bytes(8, "little"))
        if len(output) >= 32:
            break
        _keccak_f(state)
    return bytes(output[:32])


def function_selector(signature: str) -> str:
    return keccak256(signature.encode("ascii"))[:4].hex()


def is_address(value: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value))


def normalize_address(value: str) -> str:
    if not is_address(value):
        raise ValueError(f"invalid address: {value}")
    return value.lower()


def _word(value: int) -> str:
    if value < 0 or value >= 1 << 256:
        raise ValueError("integer does not fit in uint256")
    return f"{value:064x}"


def encode_transfer(recipient: str, amount: int) -> str:
    recipient = normalize_address(recipient)
    if amount < 0:
        raise ValueError("amount must not be negative")
    return "0x" + function_selector("transfer(address,uint256)") + recipient[2:].rjust(64, "0") + _word(amount)


def encode_balance_of(account: str) -> str:
    return "0x" + function_selector("balanceOf(address)") + normalize_address(account)[2:].rjust(64, "0")


def parse_hex_int(value: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"expected a hex quantity, got {value!r}")
    return int(value, 16)


class RpcError(Exception):
    def __init__(self, message: str, data: Any = None):
        super().__init__(message)
        self.message = message
        self.data = data


class JsonRpcClient:
    """Small JSON-RPC client. A transport can be injected by tests."""

    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        transport: Optional[Callable[[str, List[Any]], Dict[str, Any]]] = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.transport = transport
        self._next_id = 1

    def call(self, method: str, params: List[Any]) -> Any:
        if self.transport is not None:
            response = self.transport(method, params)
        else:
            request_body = json.dumps(
                {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
            ).encode("utf-8")
            self._next_id += 1
            request = urllib.request.Request(
                self.url,
                data=request_body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "erc20-transfer-policy-probe/1.0",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    response_body = json.loads(response.read().decode("utf-8"))
            except Exception as exc:
                raise RpcError(f"RPC request failed: {exc}") from exc
            response = response_body

        if "error" in response:
            error = response["error"]
            if isinstance(error, dict):
                raise RpcError(str(error.get("message", "JSON-RPC error")), error.get("data"))
            raise RpcError(str(error))
        if "result" not in response:
            raise RpcError("JSON-RPC response has neither result nor error")
        return response["result"]


def _error_data_hex(data: Any) -> Optional[str]:
    if isinstance(data, str) and data.startswith("0x"):
        return data
    if isinstance(data, dict):
        for key in ("data", "return", "result"):
            found = _error_data_hex(data.get(key))
            if found:
                return found
    return None


def decode_revert(data: Any, fallback: str = "execution reverted") -> str:
    raw = _error_data_hex(data)
    if not raw:
        return fallback
    payload = raw[2:]
    if len(payload) < 8:
        return f"revert data 0x{payload}"
    selector = payload[:8]
    body = payload[8:]
    if selector == "08c379a0" and len(body) >= 128:
        offset = int(body[:64], 16) * 2
        if offset + 64 <= len(body):
            length = int(body[offset : offset + 64], 16)
            start = offset + 64
            encoded = body[start : start + length * 2]
            try:
                return "Error(" + bytes.fromhex(encoded).decode("utf-8", "replace") + ")"
            except ValueError:
                pass
    if selector == "4e487b71" and len(body) >= 64:
        return f"Panic(0x{int(body[:64], 16):x})"
    return f"custom error 0x{selector}"


def decode_transfer_result(result: str) -> Dict[str, Any]:
    if not isinstance(result, str) or not result.startswith("0x"):
        return {"status": "invalid_return", "return_data": result}
    payload = result[2:]
    if payload == "":
        return {
            "status": "accepted",
            "return_value": None,
            "return_data": result,
            "warning": "empty return data; token may use the legacy ERC-20 convention",
        }
    if len(payload) < 64:
        return {"status": "invalid_return", "return_data": result}
    value = int(payload[:64], 16)
    if value == 1:
        return {"status": "accepted", "return_value": True, "return_data": result}
    if value == 0:
        return {"status": "returned_false", "return_value": False, "return_data": result}
    return {"status": "invalid_return", "return_value": value, "return_data": result}


def _call_params(
    token: str,
    sender: str,
    data: str,
    block_tag: str,
    state_override: Optional[Dict[str, Any]],
) -> List[Any]:
    transaction = {"from": sender, "to": token, "data": data}
    params: List[Any] = [transaction, block_tag]
    if state_override is not None:
        params.append(state_override)
    return params


def probe_transfer_policy(
    client: JsonRpcClient,
    token: str,
    sender: str,
    recipient: str,
    amounts: Iterable[int],
    block_tag: str = "latest",
    state_override: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    token = normalize_address(token)
    sender = normalize_address(sender)
    recipient = normalize_address(recipient)
    amount_list = list(amounts)
    if not amount_list:
        raise ValueError("at least one amount is required")

    chain_id = client.call("eth_chainId", [])
    block_number = client.call("eth_blockNumber", [])
    balance_raw: Optional[str]
    balance_error: Optional[str] = None
    try:
        balance_raw = client.call(
            "eth_call",
            _call_params(token, sender, encode_balance_of(sender), block_tag, state_override),
        )
    except RpcError as exc:
        balance_raw = None
        balance_error = str(exc)

    probes: List[Dict[str, Any]] = []
    for amount in amount_list:
        if amount < 0:
            raise ValueError("amount must not be negative")
        try:
            result = client.call(
                "eth_call",
                _call_params(token, sender, encode_transfer(recipient, amount), block_tag, state_override),
            )
            outcome = decode_transfer_result(result)
        except RpcError as exc:
            outcome = {
                "status": "reverted",
                "revert_reason": decode_revert(exc.data, exc.message),
                "rpc_error": exc.message,
            }
        outcome["amount_raw"] = str(amount)
        probes.append(outcome)

    report: Dict[str, Any] = {
        "chain_id": chain_id,
        "block_number": block_number,
        "block_tag": block_tag,
        "token": token,
        "sender": sender,
        "recipient": recipient,
        "sender_balance_raw": balance_raw,
        "probes": probes,
        "state_override_used": state_override is not None,
    }
    if balance_raw is not None:
        try:
            report["sender_balance_int"] = parse_hex_int(balance_raw)
        except ValueError:
            report["sender_balance_error"] = "balanceOf returned a non-quantity"
    if balance_error is not None:
        report["balance_error"] = balance_error
    return report


def _parse_state_override(value: Optional[str]) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid state override JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("state override must be a JSON object")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Probe ERC-20 transfer acceptance with eth_call, without sending a transaction."
    )
    parser.add_argument("--rpc-url", required=True, help="JSON-RPC endpoint")
    parser.add_argument("--token", required=True, help="ERC-20 contract address")
    parser.add_argument("--sender", required=True, help="eth_call from address")
    parser.add_argument("--recipient", required=True, help="transfer recipient")
    parser.add_argument(
        "--amount",
        action="append",
        required=True,
        help="raw token-unit amount; repeat this option for a matrix",
    )
    parser.add_argument("--block", default="latest", dest="block_tag", help="block tag or hex block number")
    parser.add_argument(
        "--state-override-json",
        help="optional Geth-style eth_call state override object, passed unchanged",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        amounts = [int(value, 0) if value.lower().startswith("0x") else int(value) for value in args.amount]
        report = probe_transfer_policy(
            JsonRpcClient(args.rpc_url),
            args.token,
            args.sender,
            args.recipient,
            amounts,
            block_tag=args.block_tag,
            state_override=_parse_state_override(args.state_override_json),
        )
    except (ValueError, RpcError) as exc:
        parser.error(str(exc))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
