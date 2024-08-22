use base64::{prelude::BASE64_STANDARD, Engine};
use core::str;
use sha2::{Digest, Sha256};

use alloy_primitives::{Address, FixedBytes};
use reth_primitives::{hex::FromHex, recover_signer_unchecked, TxHash};

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