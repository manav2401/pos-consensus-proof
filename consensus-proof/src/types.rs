use prost::Message;
use std::io::Cursor;

// Include the `types` module, which is generated from types.proto.
pub mod heimdall_types {
    include!(concat!(env!("OUT_DIR"), "/types.rs"));
}

// Serialize the wrapped milestone message into a byte buffer.
pub fn serialize_msg(m: &heimdall_types::StdTx) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(m.encoded_len());
    // Unwrap is safe, since we have reserved sufficient capacity in the vector.
    m.encode_length_delimited(&mut buf).unwrap();
    buf
}

// Deserialize the wrapped milestone message fromt the given buffer. It does byte manipulation
// to handle the decoding of message generated from the go code.
pub fn deserialize_msg(buf: &mut Vec<u8>) -> Result<heimdall_types::StdTx, prost::DecodeError> {
    // This is a hack to handle decoding of message generated from the go code. Old prefix
    // represents the encoded info for the cosmos message interface. Because it's not possible
    // to represent that info in the proto file, we need to replace the prefix with simple bytes
    // which can be decoded into the milestone message generated in rust.
    let old_prefix: Vec<u8> = vec![232, 1, 240, 98, 93, 238, 10, 158, 1, 210, 203, 62, 102];
    let new_prefix: Vec<u8> = vec![224, 1, 10, 154, 1];

    if buf.starts_with(&old_prefix) {
        buf.splice(..old_prefix.len(), new_prefix);
    } else {
        return Err(prost::DecodeError::new("Invalid prefix"));
    }

    heimdall_types::StdTx::decode_length_delimited(&mut Cursor::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_primitives::hex;

    #[test]
    fn test_deserialize_msg() {
        let decoded_str = "e801f0625dee0a9e01d2cb3e660a14fcccd43296d9c1601a904eca9b339d94a5e5e09810f8b0841d188ab1841d22207520ee2c289b7ecf623d4f8a44dc6ad772d92ee4375a2014dabea80e7ef8d5522a03313337325164386430396366342d663735662d343864332d386565372d663263323130636237323733202d2030783434646336616437373264393265653433373561323031346461626561383065376566386435353212417bc767635eb060d2fc42ad3aa67cd0f1991ef1412fc9c28abc1c4eac4700b11d153d6b3258fe29b8e8674a36afdcc5c0203e01987f062fa9fe1ce950265bed2f00";
        let mut decoded_bytes = hex::decode(decoded_str).unwrap();

        let decoded_msg = deserialize_msg(&mut decoded_bytes).unwrap();

        let m = heimdall_types::MilestoneMsg {
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
        let msg = heimdall_types::StdTx {
            msg: Some(m),
            signature: sig,
            memo: "".to_string(),
        };

        assert_eq!(decoded_msg, msg);
    }
}
