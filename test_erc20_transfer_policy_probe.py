import importlib.util
import json
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("erc20-transfer-policy-probe.py")
SPEC = importlib.util.spec_from_file_location("transfer_probe", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
SENDER = "0x000000000000000000000000000000000000dead"
RECIPIENT = "0x0000000000000000000000000000000000000001"
TRANSFER_DATA = (
    "0xa9059cbb"
    "0000000000000000000000000000000000000000000000000000000000000001"
    "00000000000000000000000000000000000000000000000000000000000f4240"
)
BALANCE_DATA = "0x70a08231" + SENDER[2:].rjust(64, "0")


class FakeRpc:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, method, params):
        self.calls.append((method, params))
        key = (method, json.dumps(params, sort_keys=True))
        if key not in self.responses:
            raise AssertionError(f"unexpected RPC request: {method} {params}")
        response = self.responses[key]
        if isinstance(response, Exception):
            return {"error": {"message": response.message, "data": response.data}}
        return {"result": response}


def response_key(method, params):
    return (method, json.dumps(params, sort_keys=True))


class TransferPolicyProbeTests(unittest.TestCase):
    def test_keccak_empty_and_transfer_selector(self):
        self.assertEqual(
            MODULE.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(MODULE.function_selector("transfer(address,uint256)"), "a9059cbb")

    def test_transfer_calldata_is_abi_encoded(self):
        self.assertEqual(MODULE.encode_transfer(RECIPIENT, 1_000_000), TRANSFER_DATA)
        self.assertEqual(MODULE.encode_balance_of(SENDER), BALANCE_DATA)

    def test_fixed_mainnet_usdc_response_is_accepted(self):
        responses = {
            response_key("eth_chainId", []): "0x1",
            response_key("eth_blockNumber", []): "0x18f4300",
            response_key(
                "eth_call",
                [{"from": SENDER, "to": TOKEN, "data": BALANCE_DATA}, "latest"],
            ): "0x0000000000000000000000000000000000000000000000000000000d1ed1d333",
            response_key(
                "eth_call",
                [{"from": SENDER, "to": TOKEN, "data": TRANSFER_DATA}, "latest"],
            ): "0x" + "0" * 63 + "1",
        }
        fake = FakeRpc(responses)
        report = MODULE.probe_transfer_policy(
            MODULE.JsonRpcClient("mock:", transport=fake), TOKEN, SENDER, RECIPIENT, [1_000_000]
        )
        self.assertEqual(report["chain_id"], "0x1")
        self.assertEqual(report["sender_balance_int"], int("0d1ed1d333", 16))
        self.assertEqual(report["probes"][0]["status"], "accepted")
        self.assertTrue(report["probes"][0]["return_value"])

    def test_fixed_optimism_response_is_accepted(self):
        token = "0x0b2c639c533813f4aa9d7837caf62653d097ff85"
        transfer_data = MODULE.encode_transfer(RECIPIENT, 1_000_000)
        balance_data = MODULE.encode_balance_of(SENDER)
        fake = FakeRpc(
            {
                response_key("eth_chainId", []): "0xa",
                response_key("eth_blockNumber", []): "0x96b8884",
                response_key(
                    "eth_call",
                    [{"from": SENDER, "to": token, "data": balance_data}, "latest"],
                ): "0x0000000000000000000000000000000000000000000000000000000000f75e98",
                response_key(
                    "eth_call",
                    [{"from": SENDER, "to": token, "data": transfer_data}, "latest"],
                ): "0x" + "0" * 63 + "1",
            }
        )
        report = MODULE.probe_transfer_policy(
            MODULE.JsonRpcClient("mock:", transport=fake), token, SENDER, RECIPIENT, [1_000_000]
        )
        self.assertEqual(report["chain_id"], "0xa")
        self.assertEqual(report["sender_balance_int"], int("f75e98", 16))
        self.assertEqual(report["probes"][0]["status"], "accepted")

    def test_revert_reason_and_false_return_are_distinguished(self):
        encoded = (
            "0x08c379a0"
            + "0" * 62
            + "20"
            + "0" * 62
            + "25"
            + "45524332303a207472616e736665722066726f6d20746865207a65726f2061646472657373"
            + "0" * 54
        )
        self.assertEqual(MODULE.decode_revert({"data": encoded}), "Error(ERC20: transfer from the zero address)")
        self.assertEqual(MODULE.decode_transfer_result("0x" + "0" * 64)["status"], "returned_false")
        self.assertEqual(MODULE.decode_transfer_result("0x")["status"], "accepted")

    def test_state_override_is_forwarded_as_third_eth_call_parameter(self):
        override = {SENDER: {"balance": "0x0", "stateDiff": {}}}
        responses = {
            response_key("eth_chainId", []): "0x1",
            response_key("eth_blockNumber", []): "0x10",
            response_key(
                "eth_call",
                [
                    {"from": SENDER, "to": TOKEN, "data": BALANCE_DATA},
                    "latest",
                    override,
                ],
            ): "0x" + "0" * 64,
            response_key(
                "eth_call",
                [
                    {"from": SENDER, "to": TOKEN, "data": TRANSFER_DATA},
                    "latest",
                    override,
                ],
            ): "0x" + "0" * 63 + "1",
        }
        fake = FakeRpc(responses)
        report = MODULE.probe_transfer_policy(
            MODULE.JsonRpcClient("mock:", transport=fake),
            TOKEN,
            SENDER,
            RECIPIENT,
            [1_000_000],
            state_override=override,
        )
        self.assertTrue(report["state_override_used"])
        eth_calls = [params for method, params in fake.calls if method == "eth_call"]
        self.assertEqual(len(eth_calls[0]), 3)
        self.assertEqual(eth_calls[0][2], override)

    def test_invalid_address_and_amount_are_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.normalize_address("0x1234")
        with self.assertRaises(ValueError):
            MODULE.encode_transfer(RECIPIENT, -1)


if __name__ == "__main__":
    unittest.main()
