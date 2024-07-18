# pos-consensus-proof
Generate consensus proof for Polygon PoS using SP1

This is an extended version of [polygon-pos-light](https://github.com/paulgoleary/polygon-pos-light) by [Paul](https://github.com/paulgoleary).

> [!WARNING]
> This work is experimental and should not be used in production.

### Background

Polygon PoS contains 2 layers -- heimdall and bor. Bor (a fork of geth) is the block producing layer and heimdall is the consensus layer based on tendermint and maintains governs the validator set and bridging. In order to do settlement on Ethereum and bridging, heimdall submits `Checkpoints` on regular intervals. A checkpoint is nothing but the root hash of a range of bor blocks signed by all validators. With [PIP-11](https://github.com/maticnetwork/Polygon-Improvement-Proposals/blob/main/PIPs/PIP-11.md), a new structure for `Milestones` has been introduced which are meta checkpoints used as a finality gadget for bor. The only difference lies in it's structure and the fact that they're not submitted on Ethereum and are much more frequent.

### Proving consensus

With the PoS chain moving towards being zkPoS and connecting with [AggLayer](https://github.com/agglayer), the first step is attach to AggLayer is to have the ability to generate proof. As generating full execution proofs is very expensive and time consuming as of now, it's not feasible to generate them with a 2s block time. Instead we rely on a consensus proof which is a zk proof which asserts that majority (2/3+1) of the validators signed a particular checkpoint/milestone. This in-directly proves the state of the underlying chain (i.e. bor). While there are multiple ways to achieve this, a generic zk proof seems much simple, efficient and easy to generate with general purpose zkVMs like [SP1](https://github.com/succinctlabs/sp1).

### Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://succinctlabs.github.io/sp1/getting-started/install.html)

### Standard Proof Generation

> [!WARNING]
> You will need at least 16GB RAM to generate the default proof.

Generate the proof for your program using the standard prover.

```sh
cd script
RUST_LOG=info cargo run --bin prove --release
```

### EVM-Compatible Proof Generation & Verification

> [!WARNING]
> You will need at least 128GB RAM to generate the PLONK proof.

Generate the proof that is small enough to be verified on-chain and verifiable by the EVM. This command also generates a fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.

```sh
cd script
RUST_LOG=info cargo run --bin prove --release -- --evm
```

### Using the Prover Network

Make a copy of the example environment file:

```sh
cp .env.example .env
```

Then, set the `SP1_PROVER` environment variable to `network` and set the `SP1_PRIVATE_KEY` environment variable to your whitelisted private key. For more information, see the [setup guide](https://docs.succinct.xyz/prover-network/setup.html).
