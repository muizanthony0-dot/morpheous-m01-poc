# Morpheus M-01 PoC — Donated yield redirects a period's MOR to the attacker

Foundry test reproducing M-01 against a mainnet fork pinned to Ethereum block 26430535.

## Run

```
forge test
```

That is the only command. It forks Ethereum mainnet at block 26430535 via the
public RPC, runs 2 tests, and asserts the loss: the attacker banks 579.15 MOR
for a ~$260 donation, while the stETH pool is displaced by 912.79 MOR in one
period. No setup beyond an internet connection; no private keys, no
environment variables.

## Note on the price-feed stub

The fork freezes live Chainlink feeds, so after the time warp the deployed
ChainLinkDataConsumer would return 0 and distribution would revert. The test
replaces the CLDC proxy code with a stub returning the exact pinned-block
prices (the same values the Distributor already stores). Only the price source
is stubbed; all accounting under test (Distributor, DepositPool, Aave) is the
deployed bytecode. See the comments in the test file.
