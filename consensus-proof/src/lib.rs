pub mod checkpoint;
pub mod milestone;
pub mod types;

use alloy_primitives::{private::alloy_rlp::Decodable, Address, FixedBytes};
use base64::{prelude::BASE64_STANDARD, Engine};
use core::str;
use reth_primitives::{hex, hex::FromHex, recover_signer_unchecked, TxHash};
use sha2::{Digest, Sha256};
use types::MilestoneMessage;

use std::io::{Cursor, Read};

use prost::Message;

// Include the `items` module, which is generated from items.proto.
pub mod milestone_message {
    include!(concat!(env!("OUT_DIR"), "/milestone.rs"));
}

pub fn serialize_msg(m: &milestone_message::StdTx) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(m.encoded_len());
    // Unwrap is safe, since we have reserved sufficient capacity in the vector.
    m.encode_length_delimited(&mut buf).unwrap();
    buf
}

pub fn deserialize_msg(buf: &[u8]) -> Result<milestone_message::StdTx, prost::DecodeError> {
    milestone_message::StdTx::decode_length_delimited(&mut Cursor::new(buf))
}

pub fn temp() {
    println!("Hello world...");
    let m = milestone_message::MilestoneMsg {
        proposer: hex::decode("FCCCD43296D9C1601A904ECA9B339D94A5E5E098")
            .unwrap()
            .to_vec(),
        start_block: 60889208,
        end_block: 60889226,
        hash: hex::decode("7520EE2C289B7ECF623D4F8A44DC6AD772D92EE4375A2014DABEA80E7EF8D552")
            .unwrap()
            .to_vec(),
        bor_chain_id: "137".to_string(),
        milestone_id:
            "d8d09cf4-f75f-48d3-8ee7-f2c210cb7273 - 0x44dc6ad772d92ee4375a2014dabea80e7ef8d552"
                .to_string(),
    };
    let sig = hex::decode("0x7bc767635eb060d2fc42ad3aa67cd0f1991ef1412fc9c28abc1c4eac4700b11d153d6b3258fe29b8e8674a36afdcc5c0203e01987f062fa9fe1ce950265bed2f00").unwrap().to_vec();
    let msg = milestone_message::StdTx {
        msg: Some(m),
        signature: sig,
        memo: "".to_string(),
    };

    let encoded_hex_str = "e801f0625dee0a9e01d2cb3e660a14fcccd43296d9c1601a904eca9b339d94a5e5e09810f8b0841d188ab1841d22207520ee2c289b7ecf623d4f8a44dc6ad772d92ee4375a2014dabea80e7ef8d5522a03313337325164386430396366342d663735662d343864332d386565372d663263323130636237323733202d2030783434646336616437373264393265653433373561323031346461626561383065376566386435353212417bc767635eb060d2fc42ad3aa67cd0f1991ef1412fc9c28abc1c4eac4700b11d153d6b3258fe29b8e8674a36afdcc5c0203e01987f062fa9fe1ce950265bed2f00";
    let encoded = hex::decode(encoded_hex_str).unwrap();

    // let encoded = serialize_msg(&msg);
    println!("{:?}", encoded);

    let mut encoded2 = encoded.clone();
    let old_prefix: Vec<u8> = vec![232, 1, 240, 98, 93, 238, 10, 158, 1, 210, 203, 62, 102];
    let new_prefix: Vec<u8> = vec![224, 1, 10, 154, 1];

    if encoded2.starts_with(&old_prefix) {
        encoded2.splice(..new_prefix.len(), new_prefix);
    }

    println!("{:?}", encoded2);

    let decoded = deserialize_msg(&encoded).unwrap();
    println!("{:?}", decoded);
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
