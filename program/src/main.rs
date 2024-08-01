//! This programme generates the consensus proofs for milestone message. It validates the
//! message against header/s and also checks for the signature of majority of validators
//! according to their weight/stake.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{hex, private::alloy_rlp::Decodable};
use reth_primitives::hex::FromHex;
use reth_primitives::{Address, Header, B256};

use pos_consensus_proof::milestone::{MilestoneMessage, MilestoneProof, MilestoneProofInputs};
pub fn main() {
    let header_hex: String = "f90265a0afe719f6ca102ab7b7b9fd367688e73a777d02d21d6a692a8ff6a6eb3c2f7c27a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0f48ab66c3b39fcf8415ba3f787a529900795b307337fc244949eed20f10de6dca09434da2710a11e1a5c3b61f7feb0dd5a75520befe5a6ccc1be4de14251f00869a0bbdeef8478f908a12f86b906c43a4f0ef2bb62226ccae6af1e34668488ca8323b90100db3a9cb765f57e3ef6b760d1fcaf4eba4bcb5b44c56fb1e838f7f87de18fe9775a2ef30addeb605b5be3e9bfbfd64ccdfab7fdf7ddaee92af58e337f81bee788f869fe176d0bf9db44e9b6dfc86ae9f8962727becd5eb1f2f3078f96dacd3e07eddc79d61bf34e6081a7f9236d997b89fb8901c7c6b1ba75f1b1c7fdf6d9ff3d07776d7e39ec6abd7e2199e265b2e15f79bfadf1afc6a38fafcf1a70f6d55bda6e430b2bf253df0f3874fd44da9090cf4877bf90666bd9a8b42a932fd6808cde5dadbd3311bfecc7ff73025a4e30bca9eb710e22cd6eddc9fd7fe22a3c7bf99e189a8de36bab08ccf50d6efd3e87f935d9ec26776bcf44dfbc3db96d2b9c9b6b158402faf0808401c31a8c84018ec9288465559991b861d78301000683626f7288676f312e32302e38856c696e75780000000000000000b6c6f13270d722c179f577c7669e775841f090e7dc37640e3da15ba28dbaef472f1b963fc7b3ca1b884cc23cb2b302ec1ce6e8bf0a9164d8181407e0d7a2f79801a000000000000000000000000000000000000000000000000000000000000000008800000000000000008518b525e260".to_string();
    let header_bytes = hex::decode(header_hex).unwrap_or_default();
    let header = Header::decode(&mut header_bytes.as_slice()).unwrap();

    let milestone_msg = MilestoneMessage {
        proposer: Address::from_hex("0xeedba2484aaf940f37cd3cd21a5d7c4a7dafbfc0").unwrap(),
        start_block: 59826672,
        end_block: 59826688,
        hash: B256::default(),
        bor_chain_id: 137,
        milestone_id: String::from(
            "1713ea93-6651-4d5f-96b0-c0f29b4d9b9b - 0x93f0bf1af099ca4eb5a0c4ad2522bb05bd1c0377",
        ),
        timestamp: 0,
    };

    let inputs = MilestoneProofInputs {
        milestone: milestone_msg,
        headers: vec![header],
        sigs: vec![],
        target_block_hash: B256::default(),
        target_state_root: B256::default(),
    };

    let proof = MilestoneProof::init(inputs);
    proof.validate();
}
