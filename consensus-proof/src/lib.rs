pub mod checkpoint;
pub mod milestone;
pub mod types;

use alloy_primitives::{private::alloy_rlp::Decodable, Address, FixedBytes};
use base64::{prelude::BASE64_STANDARD, Engine};
use core::str;
use reth_primitives::{hex::FromHex, recover_signer_unchecked, TxHash};
use sha2::{Digest, Sha256};

use std::io::Cursor;

use prost::Message;

// Include the `items` module, which is generated from items.proto.
pub mod milestone_message {
    include!(concat!(env!("OUT_DIR"), "/milestone.rs"));
}

pub fn serialize_milestone(m: &milestone_message::Milestone) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(m.encoded_len());
    // Unwrap is safe, since we have reserved sufficient capacity in the vector.
    m.encode_length_delimited(&mut buf).unwrap();
    buf
}

pub fn deserialize_milestone(
    buf: &[u8],
) -> Result<milestone_message::Milestone, prost::DecodeError> {
    milestone_message::Milestone::decode_length_delimited(&mut Cursor::new(buf))
}

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
pub fn verify_tx_hash(tx_data: &str, expected_hash: &str) -> bool {
    // Decode the transaction data
    let decoded_tx_data = BASE64_STANDARD.decode(tx_data);
    if decoded_tx_data.is_err() {
        return false;
    }

    // Calculate the hash of decoded data
    let tx_hash = sha256(decoded_tx_data.unwrap().as_slice());

    // Typecast the expected tx hash
    let expected_hash_bytes = TxHash::from_hex(expected_hash).unwrap();

    expected_hash_bytes.eq(&tx_hash)
}

fn sha256(decoded_tx_data: &[u8]) -> FixedBytes<32> {
    // Create a new Sha256 instance
    let mut hasher = Sha256::new();

    // Write the tx data
    hasher.update(decoded_tx_data);

    // Read hash digest and consume hasher
    let result = hasher.finalize();

    TxHash::from_slice(result.as_slice())
}

// pub fn byte_testing() {
//     let milestone = MilestoneMessage {
//         proposer: Address::from_hex("AA6AC02FDDAAF6F120F5BB98CE30809D19CD5D1B").unwrap(),
//         start_block: 60486255,
//         end_block: 60486267,
//         hash: B256::from_hex("0x5510B6CA517CB1C2AA95767E19A2755FB693848A00BEA343D8310A7DC044196D")
//             .unwrap(),
//         bor_chain_id: 137,
//         milestone_id: String::from(
//             "373acb8f-78ee-4d37-860e-75fdf42f82a4 - 0x19a2755fb693848a00bea343d8310a7dc044196d",
//         ),
//     };
//     let encoded_milestone = milestone.encode();
//     println!("Encoded: {:?}", encoded_milestone);

//     let a = hex::encode(encoded_milestone);
//     println!("Hex: {:?}", a);

//     let mut msg_bytes = [0u8; 157];
//     msg_bytes.copy_from_slice(hex::decode(a).unwrap().as_slice());

//     let decoded = MilestoneMessage::decode(msg_bytes);
//     println!("Decoded: {:?}", decoded);
// }
