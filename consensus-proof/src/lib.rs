pub mod checkpoint;
pub mod milestone;

use alloy_primitives::{hex, private::alloy_rlp::Decodable, Address};
use base64::{prelude::BASE64_STANDARD, Engine};
use reth_primitives::{hex::FromHex, keccak256, recover_signer_unchecked, Header};

pub async fn print_block() {
    let header_hex: String = "f90265a0afe719f6ca102ab7b7b9fd367688e73a777d02d21d6a692a8ff6a6eb3c2f7c27a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0f48ab66c3b39fcf8415ba3f787a529900795b307337fc244949eed20f10de6dca09434da2710a11e1a5c3b61f7feb0dd5a75520befe5a6ccc1be4de14251f00869a0bbdeef8478f908a12f86b906c43a4f0ef2bb62226ccae6af1e34668488ca8323b90100db3a9cb765f57e3ef6b760d1fcaf4eba4bcb5b44c56fb1e838f7f87de18fe9775a2ef30addeb605b5be3e9bfbfd64ccdfab7fdf7ddaee92af58e337f81bee788f869fe176d0bf9db44e9b6dfc86ae9f8962727becd5eb1f2f3078f96dacd3e07eddc79d61bf34e6081a7f9236d997b89fb8901c7c6b1ba75f1b1c7fdf6d9ff3d07776d7e39ec6abd7e2199e265b2e15f79bfadf1afc6a38fafcf1a70f6d55bda6e430b2bf253df0f3874fd44da9090cf4877bf90666bd9a8b42a932fd6808cde5dadbd3311bfecc7ff73025a4e30bca9eb710e22cd6eddc9fd7fe22a3c7bf99e189a8de36bab08ccf50d6efd3e87f935d9ec26776bcf44dfbc3db96d2b9c9b6b158402faf0808401c31a8c84018ec9288465559991b861d78301000683626f7288676f312e32302e38856c696e75780000000000000000b6c6f13270d722c179f577c7669e775841f090e7dc37640e3da15ba28dbaef472f1b963fc7b3ca1b884cc23cb2b302ec1ce6e8bf0a9164d8181407e0d7a2f79801a000000000000000000000000000000000000000000000000000000000000000008800000000000000008518b525e260".to_string();
    let header_bytes = hex::decode(header_hex).unwrap_or_default();
    let header = Header::decode(&mut header_bytes.as_slice()).unwrap();
    println!("{}", header.hash_slow())
}

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

pub fn signature() {
    let valid = verify_signature(
        "c+6/gaYRE2Zi1ld4lgyFP9yvbsqGeT7Zyrww8hlZN694oH5gFifaW0zIDAqzX2iU2hm0oBdZ2QwQHZyd0cZ0XQA=",
        &keccak256("hello"),
        Address::from_hex("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap(),
    );
    println!("{}", valid);
}
