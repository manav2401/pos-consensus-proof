use crate::helper::*;
use std::collections::HashMap;

use alloy_primitives::{keccak256, FixedBytes, Uint};
use alloy_sol_types::SolCall;
use sp1_cc_client_executor::{io::EVMStateSketch, ClientExecutor, ContractInput};

use common::{ConsensusProofVerifier, PoSConsensusCommit, PoSConsensusInput, CALLER};

pub mod helper;
pub mod types;

pub fn prove(input: PoSConsensusInput) -> PoSConsensusCommit {
    // Verify if the transaction data provided is actually correct or not
    let milestone = verify_tx_data(&input.tx_data, &input.tx_hash);

    // Calculate the bor block hash from the given header
    let bor_block_hash = input.bor_header.hash_slow();

    // Verify if the bor block header matches with the milestone or not
    assert_eq!(
        milestone.end_block, input.bor_header.number,
        "block number mismatch between milestone and bor block header"
    );
    assert_eq!(
        milestone.hash,
        bor_block_hash.to_vec(),
        "block hash mismatch between milestone and bor block header"
    );

    // Make sure that we have equal number of precommits, signatures and signers.
    assert_eq!(input.precommits.len(), input.sigs.len());
    assert_eq!(input.sigs.len(), input.signers.len());

    // Verify if the hash of l1 header matches with the hash provided in input
    assert_eq!(
        input.l1_block_header.hash_slow(),
        input.l1_block_hash,
        "block hash mismatch between hash derived from header vs hash provided in input",
    );

    // As we verified both l1 and bor block hashes before, we can use their headers to match
    // timestamps. Ensure that the difference between both is not more than 3 hours. This is to
    // make sure that a recent most L1 block hash is used and not any valid block hash.
    let l1_timestamp = i64::try_from(input.l1_block_header.timestamp).unwrap();
    let l2_timestamp = i64::try_from(input.bor_header.timestamp).unwrap();
    if l1_timestamp - l2_timestamp > 10800 || l1_timestamp - l2_timestamp < -10800 {
        panic!("Time difference between L1 and L2 blocks is >3hrs")
    }

    // Deserialize the state sketch from input bytes and initialize the client executor with it.
    // This step also validates all of the storage against the provided state root.
    let state_sketch = bincode::deserialize::<EVMStateSketch>(&input.state_sketch_bytes).unwrap();
    let executor = ClientExecutor::new(state_sketch).unwrap();

    // Execute the `getEncodedValidatorInfo` call using the client executor to fetch the
    // active validator's info from L1.
    let call = ConsensusProofVerifier::getValidatorInfoCall {};
    let output = executor
        .execute(ContractInput::new_call(
            input.stake_info_address,
            CALLER,
            call.clone(),
        ))
        .unwrap();
    let response = ConsensusProofVerifier::getValidatorInfoCall::abi_decode_returns(
        &output.contractOutput,
        true,
    )
    .unwrap();

    // Extract the signers, powers, and total_power from the response.
    let signers = response._0;
    let powers = response._1;
    let total_power = response._2;

    let mut majority_power: Uint<256, 4> = Uint::from(0);
    let mut validator_stakes = HashMap::new();
    for (i, signer) in signers.iter().enumerate() {
        validator_stakes.insert(signer, powers[i]);
    }

    // TODO(manav): Skip fetching the last verified bor block hash for now as it's expected to
    // reside on a different contract than stake info. Once there's some clarity on that, modify
    // the logic accordingly.
    // Execute the `lastVerifiedBorBlockHash` call using the client executor to fetch the
    // last verified bor block hash.
    // let call = ConsensusProofVerifier::lastVerifiedBorBlockHashCall {};
    // let output = executor
    //     .execute(ContractInput::new_call(
    //         input.stake_info_address,
    //         CALLER,
    //         call.clone(),
    //     ))
    //     .unwrap();
    // let last_verified_bor_block_hash_return =
    //     ConsensusProofVerifier::lastVerifiedBorBlockHashCall::abi_decode_returns(
    //         &output.contractOutput,
    //         true,
    //     )
    //     .unwrap();
    // let prev_bor_hash = last_verified_bor_block_hash_return.lastVerifiedBorBlockHash;
    let prev_bor_hash = FixedBytes::default();

    // If we're running prover for the first time, we won't have a previous bor block hash. Skip
    // all validations if that's the case else verify against that.
    if !prev_bor_hash.is_zero() {
        // Verify if the `prev_bor_header`s hash matches with the one we fetched from the contract.
        let prev_derived_bor_hash = input.prev_bor_header.hash_slow();
        assert_eq!(
            prev_derived_bor_hash, prev_bor_hash,
            "prev bor hash mismatch"
        );

        // Ensure that we're maintaining sequence of bor blocks and are not proving anything random
        assert!(
            input.bor_header.number > input.prev_bor_header.number,
            "bor block is not sequential"
        );
    }

    // Verify that the signatures generated by signing the precommit message are indeed signed
    // by the given validators.
    for i in 0..input.precommits.len() {
        // Validate if the signer of this precommit message is a part of the active validator
        // set or not.
        assert!(validator_stakes.contains_key(&input.signers[i]));

        // Verify if the precommit message is for the same milestone transaction or not.
        let precommit = &input.precommits[i];
        verify_precommit(&mut precommit.clone(), &input.tx_hash);

        // Verify if the message is indeed signed by the validator or not.
        verify_signature(
            input.sigs[i].as_str(),
            &keccak256(precommit),
            input.signers[i],
        );

        // Add the power of the validator to the majority power
        majority_power = majority_power.add_mod(validator_stakes[&input.signers[i]], Uint::MAX);
    }

    // Check if the majority power is greater than 2/3rd of the total power
    let expected_majority = total_power
        .mul_mod(Uint::from(2), Uint::MAX)
        .div_ceil(Uint::from(3));
    if majority_power <= expected_majority {
        panic!("Majority voting power is less than 2/3rd of the total power, total_power: {}, majority_power: {}", total_power, majority_power);
    }

    PoSConsensusCommit {
        prev_bor_hash,
        new_bor_hash: bor_block_hash,
        l1_block_hash: input.l1_block_hash,
        stake_info_address: input.stake_info_address,
    }
}
