# pos-consensus-proof
Generate consensus proof for Polygon PoS chain using SP1.

> [!WARNING]
> This work is not audited. Please use at your own risk.

### Background

Polygon PoS contains 2 layers — bor (execution layer based on geth/erigon) and heimdall (consensus layer based on tendermint). Polygon is also building [AggLayer](https://github.com/agglayer), which expects each chain to generate a ZK proof with different security assumptions. A full execution proof is practically infeasible with a 2s block time for PoS. Hence, as an excercise to plug PoS into AggLayer, we rely on consensus proofs.

### Proving Consensus

Consensus proofs asserts that the majority (>2/3) of PoS validator set agree on a specific state of chain. This allows an external layer (e.g. AggLayer) to verify that the chain is operating honestly assuming the majority validator set is honest. To elaoborate a bit more, the specific state of chain here means a particular state of the execution layer. This is achieved using milestones, which is a also used for finality in PoS. Milestones are messages which are proposed in heimdall representing a range of bor blocks and is being voted upon and persisted. While there is more nuance to it, at a high level consensus proofs basically validates if majority of validators voted upon / signed a milestone message through signature verification.

### Repository Overview

This repositories is organised into the following directories:
- `consensus-proof`: Contains the ZK circuit of verifying a milestone message and respective helper functions.
- `operator`: Implementation of an operator which assembles inputs used to generate the proof.
- `common`: Contains generic global types.
- `contracts`: The solidity contracts for on-chain verification and fetching validator set data.

### Proof Generation

Make sure you've [Rust](https://rustup.rs/) and [SP1](https://docs.succinct.xyz/docs/getting-started/install) installed.

#### Contract Deployments

For proof generation (except the on-chain verification component), the `StakeInfo` contract acts as a proxy to fetch validator set and stake distribution from the respective L1 Stake Manager Contracts (already deployed for PoS mainnet and Amoy). 

Existing deployments for `StakeInfo`:
- Ethereum Mainnet: [0x173ca2f40a37f62527713Bf72b085675A0D5e200](https://etherscan.io/address/0x173ca2f40a37f62527713Bf72b085675A0D5e200)
- Sepolia: [0x978D36Ed8c03EBF2d3b93b492aF8D37aD56ad1B5](https://sepolia.etherscan.io/address/0x978D36Ed8c03EBF2d3b93b492aF8D37aD56ad1B5)

Make a fresh deployment:
1. Make sure you have environment variables set corresponding to the chain you're deploying on.
    ```sh
    RPC=<rpc> # rpc endpoint of chain to be deployed on
    PK=<pk> # private key of account with funds to be used for deployment
    SM=<sm> # stake manager proxy address
    ```
2. Run the forge command to deploy inside the `contracts` directory.
    ```
    forge create --broadcast --rpc-url $RPC --private-key $PK --via-ir src/StakingInfo.sol:StakingInfo --constructor-args $SM
    ```

#### Using operator for proof generation

The `operator` service can be used for generating consensus proofs for any PoS chain given appropriate configurations are provided. Below are the steps to do the same.

1. Create an environment file using the example. Fill in all relevant details which will be used for assembling the inputs. It needs information about L1 (eth mainnet / sepolia), PoS endpoints (mainnet / amoy for heimdall and bor).
    ```sh
    cp .env.example .env
    ```
2. Make sure you're able to build the operator.
    ```sh
    cd operator
    cargo build
    ```
3. Run the operator service
    ```sh
    RUST_LOG=info cargo run --release -- <flags>
    ```
    Following flags are supported:
    - `--prove`: Generates an actual zk proof if set. If not, only executes the code with inputs.
    - `--proof-type`: Type of proof to be generated. Either `compressed` or `plonk`.
    - `--skip-l1-block-validation`: Skip validating the height of L1 block. Useful when testing against a fork.
4. Operator also has some helper commands.
    ```sh
    # To print the vkey
    RUST_LOG=info cargo run --release --bin vkey

    # To verify the proof generated
    RUST_LOG=info cargo run --release --bin verify
    ```

If you want to use the SP1 prover network, set the `SP1_PROVER` env variable to `network` and set the `SP1_PRIVATE_KEY` environment variable to your whitelisted private key. For more information, see the [setup guide](https://docs.succinct.xyz/docs/generating-proofs/prover-network).

### Acknowledgements

- [SP1](https://github.com/succinctlabs/sp1)
- A PoC [polygon-pos-light](https://github.com/paulgoleary/polygon-pos-light) by [Paul](https://github.com/paulgoleary).