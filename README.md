# Bufi Ingress Hook — audit target

Self-contained Uniswap v4 hook prepared for autonomous audit (Matt's `probably-nothing` grader). Single source file, only upstream dependencies.

## What this hook does

Normalizes inbound stablecoin flow into the Bufi private-inbox corridor. Two pool classes:

1. **Stage 1** — `USDT/USDC` (normalize)
2. **Stage 2** — `USDC/eUSD` (issuance into the protocol stablecoin)

`beforeSwap` validates deposit, alias, direction, and epoch against inlined registries and returns `ZERO_DELTA`. `afterSwap` finalizes settlement and emits a signal.

## Layout

```
src/BufiIngressHook.sol   # audit-ready standalone variant
foundry.toml              # @uniswap/v4-core, v4-periphery, forge-std
```

## Building

```bash
forge install uniswap/v4-core uniswap/v4-periphery foundry-rs/forge-std
forge build
```

## Provenance

Extracted from `protocols/bufi-vortex/evm/src/hooks/BufiIngressHook.sol` in the [secret-secret](https://github.com/tcxcx/secret-secret) repo. Findings here apply to production and must be fixed in both.
