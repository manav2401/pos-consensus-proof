pub mod checkpoint;
pub mod milestone;
pub mod types;

use std::str::FromStr;

use alloy_primitives::{private::alloy_rlp::Decodable, Address, B256};
use base64::{prelude::BASE64_STANDARD, Engine};
use reth_primitives::{hex, hex::FromHex, keccak256, recover_signer_unchecked, TxHash};
use types::MilestoneMessage;

// Verifies if the signature is indeed signed by the expected signer or not
pub fn verify_signature(
    signature: &str,
    message_hash: &[u8; 32],
    expected_signer: Address,
) -> bool {
    // Decode the tendermint signature using standard base64 decoding
    let decoded_signature = BASE64_STANDARD.decode(signature);
    if decoded_signature.is_err() {
        return false;
    }

    // Construct the byte array from the decoded signature for recovery
    let mut sig = [0u8; 65];
    sig.copy_from_slice(decoded_signature.unwrap().as_slice());

    // Recover the signer address
    let recovered_signer = recover_signer_unchecked(&sig, message_hash).unwrap_or_default();
    if !expected_signer.eq(&recovered_signer) {
        return false;
    }

    true
}

// Verifies if the transaction data actually belongs to the given milestone or not. This method
// requires amino unmarshaling which is not readily available. Hence, we return true until then.
// TODO: Implement the actual verification logic
pub fn verify_tx_data(_: &str) -> bool {
    true
}

// Verifies if the transaction data when hashed results to the given
// transaction hash or not.
pub fn verify_tx_hash(tx_data: &str, tx_hash: &str) -> bool {
    // Decode the transaction data
    let decoded_tx_data = BASE64_STANDARD.decode(tx_data);
    if decoded_tx_data.is_err() {
        return false;
    }

    // Hash the decoded data
    let derived_tx_hash = keccak256(decoded_tx_data.unwrap().as_slice());

    // Unwrap the given transaction hash
    let tx_hash_bytes = TxHash::from_str(tx_hash).unwrap();

    // Encode the hash back to match with given transaction hash
    let encoded_tx_hash = BASE64_STANDARD.encode(derived_tx_hash);

    println!(
        "Required: {:?}, Derived: {:?}",
        tx_hash_bytes, derived_tx_hash
    );

    tx_hash.eq(&encoded_tx_hash)
}

// pub fn signature() {
//     let valid = verify_signature(
//         "c+6/gaYRE2Zi1ld4lgyFP9yvbsqGeT7Zyrww8hlZN694oH5gFifaW0zIDAqzX2iU2hm0oBdZ2QwQHZyd0cZ0XQA=",
//         &keccak256("hello"),
//         Address::from_hex("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap(),
//     );
//     println!("{}", valid);
// }

pub fn byte_testing() {
    let milestone = MilestoneMessage {
        proposer: Address::from_hex("AA6AC02FDDAAF6F120F5BB98CE30809D19CD5D1B").unwrap(),
        start_block: 60486255,
        end_block: 60486267,
        hash: B256::from_hex("0x5510B6CA517CB1C2AA95767E19A2755FB693848A00BEA343D8310A7DC044196D")
            .unwrap(),
        bor_chain_id: 137,
        milestone_id: String::from(
            "373acb8f-78ee-4d37-860e-75fdf42f82a4 - 0x19a2755fb693848a00bea343d8310a7dc044196d",
        ),
    };
    let encoded_milestone = milestone.encode();
    println!("Encoded: {:?}", encoded_milestone);

    let a = hex::encode(encoded_milestone);
    println!("Hex: {:?}", a);

    let mut msg_bytes = [0u8; 157];
    msg_bytes.copy_from_slice(hex::decode(a).unwrap().as_slice());

    let decoded = MilestoneMessage::decode(msg_bytes);
    println!("Decoded: {:?}", decoded);
}

// pub async fn print_block() {
//     let header_hex: String = "f90265a0afe719f6ca102ab7b7b9fd367688e73a777d02d21d6a692a8ff6a6eb3c2f7c27a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0f48ab66c3b39fcf8415ba3f787a529900795b307337fc244949eed20f10de6dca09434da2710a11e1a5c3b61f7feb0dd5a75520befe5a6ccc1be4de14251f00869a0bbdeef8478f908a12f86b906c43a4f0ef2bb62226ccae6af1e34668488ca8323b90100db3a9cb765f57e3ef6b760d1fcaf4eba4bcb5b44c56fb1e838f7f87de18fe9775a2ef30addeb605b5be3e9bfbfd64ccdfab7fdf7ddaee92af58e337f81bee788f869fe176d0bf9db44e9b6dfc86ae9f8962727becd5eb1f2f3078f96dacd3e07eddc79d61bf34e6081a7f9236d997b89fb8901c7c6b1ba75f1b1c7fdf6d9ff3d07776d7e39ec6abd7e2199e265b2e15f79bfadf1afc6a38fafcf1a70f6d55bda6e430b2bf253df0f3874fd44da9090cf4877bf90666bd9a8b42a932fd6808cde5dadbd3311bfecc7ff73025a4e30bca9eb710e22cd6eddc9fd7fe22a3c7bf99e189a8de36bab08ccf50d6efd3e87f935d9ec26776bcf44dfbc3db96d2b9c9b6b158402faf0808401c31a8c84018ec9288465559991b861d78301000683626f7288676f312e32302e38856c696e75780000000000000000b6c6f13270d722c179f577c7669e775841f090e7dc37640e3da15ba28dbaef472f1b963fc7b3ca1b884cc23cb2b302ec1ce6e8bf0a9164d8181407e0d7a2f79801a000000000000000000000000000000000000000000000000000000000000000008800000000000000008518b525e260".to_string();
//     let header_bytes = hex::decode(header_hex).unwrap_or_default();
//     let header = Header::decode(&mut header_bytes.as_slice()).unwrap();
//     println!("{}", header.hash_slow())
// }
