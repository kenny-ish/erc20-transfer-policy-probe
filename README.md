# erc20-transfer-policy-probe

`erc20-transfer-policy-probe` checks whether an ERC-20 transfer call is accepted, returns false, or reverts for chosen raw-unit amounts, without sending a transaction or changing chain state. It is useful for spotting amount limits, sender or recipient restrictions, and custom revert behavior before an integration or test transaction.

## Example

These are real read-only runs made on 2026-10-11 UTC. The first run used an Ethereum mainnet USDC contract and a Geth-style state override for the caller's native balance. The second used the canonical USDC contract on Optimism. The excerpts below show selected fields from the actual output.

```text
$ python erc20-transfer-policy-probe.py --rpc-url https://ethereum-rpc.publicnode.com --token 0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 --sender 0x000000000000000000000000000000000000dEaD --recipient 0x0000000000000000000000000000000000000001 --amount 1000000 --state-override-json '{"0x000000000000000000000000000000000000dEaD":{"balance":"0x0"}}'
{
  "chain_id": "0x1",
  "block_number": "0x18f4345",
  "probes": [
    {
      "amount_raw": "1000000",
      "return_value": true,
      "status": "accepted"
    }
  ],
  "state_override_used": true
}

$ python erc20-transfer-policy-probe.py --rpc-url https://mainnet.optimism.io --token 0x0b2C639c533813f4Aa9D7837CAF62653d097FF85 --sender 0x000000000000000000000000000000000000dEaD --recipient 0x0000000000000000000000000000000000000001 --amount 1000000
{
  "chain_id": "0xa",
  "block_number": "0x96b8a1f",
  "probes": [
    {
      "amount_raw": "1000000",
      "return_value": true,
      "status": "accepted"
    }
  ],
  "state_override_used": false
}
```

## Usage

```text
python erc20-transfer-policy-probe.py --rpc-url RPC_URL --token TOKEN --sender SENDER --recipient RECIPIENT --amount RAW_AMOUNT [--amount RAW_AMOUNT] [--block BLOCK_TAG] [--state-override-json JSON]
```

`--amount` is expressed in the token's smallest units and can be repeated to form a probe matrix. `--state-override-json` is passed as the third `eth_call` parameter, so support depends on the RPC implementation. The tool never calls `eth_sendRawTransaction`.

## How it works

It reads the sender balance and chain snapshot, ABI-encodes `transfer(address,uint256)`, then sends one `eth_call` per amount. It decodes standard ERC-20 boolean returns, empty legacy returns, `Error(string)`, panic data, and generic reverts. The bundled Keccak-256 implementation derives rotation offsets from the specified formula and round constants from the Keccak LFSR.

## Tests

`python -m unittest -v`
