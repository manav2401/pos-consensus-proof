use crate::helper::*;

use alloy_primitives::{private::alloy_rlp::Decodable, Address};
use alloy_sol_types::sol;
use reth_primitives::{hex, hex::FromHex, keccak256, Header};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        // string tx_hash;
        // string precommits_hash;
        address[] signers;
        uint64[] powers;
        uint64 total_power;
    }
}

pub struct MilestoneProofInputs {
    pub tx_data: String,
    pub tx_hash: String,
    pub precommits: Vec<String>,
    pub precommits_hash: String,
    pub sigs: Vec<String>,
    pub signers: Vec<String>,
    pub headers: Vec<String>,
    pub powers: Vec<u64>,
    pub total_power: u64,
}

pub struct MilestoneProver {
    inputs: MilestoneProofInputs,
}

impl MilestoneProver {
    pub fn init(inputs: MilestoneProofInputs) -> Self {
        MilestoneProver { inputs }
    }

    pub fn prove(&self) {
        // Verify if the transaction data provided is actually correct or not
        let milestone = match verify_tx_data(&self.inputs.tx_data, &self.inputs.tx_hash) {
            Ok(m) => m,
            Err(e) => {
                panic!("Error verifying transaction data: {:?}", e);
            }
        };

        // Make sure that we have equal number of precommits, signatures and signers.
        if self.inputs.precommits.len() != self.inputs.sigs.len()
            || self.inputs.sigs.len() != self.inputs.signers.len()
            || self.inputs.signers.len() != self.inputs.powers.len()
        {
            panic!("Invalid number of precommits, signatures or signers");
        }

        // Verify precommit hash by comparing it with the expected hash provided as input
        let message = self.inputs.precommits.join("");
        let hash = keccak256(message);
        if !hash.to_string().eq(&self.inputs.precommits_hash) {
            panic!(
                "Precommit hash mismatch. Expected: {}, Found: {}",
                self.inputs.precommits_hash,
                hash.to_string()
            );
        }

        let mut majority_power: u64 = 0;

        // Verify that the signatures generated by signing the precommit message are indeed signed
        // by the given validators.
        for (i, sig) in self.inputs.sigs.iter().enumerate() {
            let signer = Address::from_hex(self.inputs.signers[i].as_str()).unwrap_or_default();

            let decoded_precommit_message = match hex::decode(self.inputs.precommits[i].as_str()) {
                Ok(v) => v,
                Err(e) => {
                    panic!(
                        "Error decoding precommit message for signer: {:?}, index: {}, error: {:?}",
                        signer, i, e
                    );
                }
            };

            match verify_precommit(decoded_precommit_message.clone(), &self.inputs.tx_hash) {
                Ok(valid) => {
                    if !valid {
                        panic!(
                            "Unable to decode and verify precommit message for signer: {:?}, index: {}",
                            signer, i
                        );
                    }
                }
                Err(e) => {
                    panic!(
                        "Error verrifying precommit message, signer: {:?}, index: {}, error: {:?}",
                        signer, i, e
                    );
                }
            };

            match verify_signature(sig.as_str(), &keccak256(decoded_precommit_message), signer) {
                Ok(_) => (),
                Err(e) => {
                    panic!("Error verifying signature against expected signer: {:?}, index: {}, error: {:?}", signer, i, e);
                }
            }

            majority_power += self.inputs.powers[i];
        }

        // Check if the majority power is greater than 2/3rd of the total power
        if majority_power <= self.inputs.total_power / 3 * 2 {
            panic!("Majority voting power is less than 2/3rd of the total power");
        }

        let headers: Vec<Header> = self
            .inputs
            .headers
            .iter()
            .map(|hh| {
                let header_bytes = hex::decode(hh).unwrap_or_default();
                Header::decode(&mut header_bytes.as_slice()).unwrap()
            })
            .collect();

        // In a milestone proof, we assume that we'll only receive 1 element in the headers array
        // and that should be the end block's header present in the milestone message.
        let last_header = headers.last().expect("No header found");

        // Check if the header's number matches with milestone message's end block
        let number = last_header.number;
        if milestone.end_block != number {
            panic!(
                "block number mismatch between milestone and block header. milestone: {}, header: {}",
                milestone.end_block, number
            );
        }

        // Check if the header's hash matches with the milestone message's hash
        let hash = last_header.hash_slow().to_vec();
        if milestone.hash != hash {
            panic!(
                "block hash mismatch between milestone and block header. milestone: {}, header: {}",
                hex::encode(milestone.hash),
                hex::encode(hash)
            );
        };
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_proof() {
        let inputs = MilestoneProofInputs {
            tx_data: "6AHwYl3uCp4B0ss+ZgoUqmrAL92q9vEg9buYzjCAnRnNXRsQ7+TrHBj75OscIiBVELbKUXyxwqqVdn4ZonVftpOEigC+o0PYMQp9wEQZbSoDMTM3MlEzNzNhY2I4Zi03OGVlLTRkMzctODYwZS03NWZkZjQyZjgyYTQgLSAweDE5YTI3NTVmYjY5Mzg0OGEwMGJlYTM0M2Q4MzEwYTdkYzA0NDE5NmQSQegVvhAXsyj7DXQUYSl+FoNvO/9cvdY2gGKIGtaDOgeSdXZyn5PrNKArkVTgndRHNC+17h4ZO9rF1TF9gEjOwvYB".to_string(),
            tx_hash: "4C6BB9C1426CEF3B0252EFADFBD09B88350F508CC2A4EC0C837612958AD37C85".to_string(),
            precommits: vec!["9701080211327b30010000000022480a20fd648de965c020911f2bcfa3825fe2bd6698aa93009f0e63348ad74506221fae12240a20218d85717b5904942ce7c7b89b201aa1c2711dddb6e380cd0357c4647f35ac9b10012a0c08f29ee6b50610abfdeacc03320c6865696d64616c6c2d31333742240a204c6bb9c1426cef3b0252efadfbd09b88350f508cc2a4ec0c837612958ad37c851001".to_string()],
            precommits_hash: "0x3e72a57a7429daaea878a6c44314432828249a89aa13a44d92409a6dc8ac8a5b".to_string(),
            sigs: vec!["ZnLPE6+g9xfOQdnmugJ94zFRuQO47bH424V62XFgNul/HiiA46RBQYxW0E3+3MpcMLX4Dw5ma1rfFMr4Lr6EDwA=".to_string()],
            signers: vec!["0x00856730088A5C3191BD26EB482E45229555CE57".to_string()],
            headers: vec!["f902d5a095913a64f4f93aeb8fd5ee7c6562bd02e50f4613a5ea230fbbf0aca717996217a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a09eb7f80eafdb4f69520ec7d664402e5b3ce4af3b22cacc5098ebb73342b52301a01fa16db19c3fdc00a6902e29a57a1755dce6be40c4eab66e4b4a16d36a8e9135a00acd40f3f7dc9777f9e39a49654b4e564f18c22ca7ca025e69ea9790b47edd46b90100652a812e80ac124a006b29388ea4d67932562030482081304ea12036c01824200748231b1180241080620011510a9215241492384822a94320320e02aca0301a0608984c0e225aec2200248c103810f8522a2622415f00007843711092b69a0b13a040640b12b2602048e55a011e0d0816e40c505970044ce9a84310020b03f104b31980210f40992051c2c4f484c000180b16b339400b69505982ea42109205ea00238410d8440a906a101074014800f8c42546060068ce1410a600010560e343b1064334100210418b08302a68c003f6050004405aa0560292930b2085aa4534104247000454000c8d0842f520c5d2c01d816010c8094283d82a20231729341784039af27b8401c9c38083821b6d8466b98f45b8d7d78301030683626f7288676f312e32322e35856c696e75780000000000000000f87480f871c0c0c0c101c103c0c104c0c0c108c106c0c0c10ac0c10ec0c110c111c112c113c114c115c116c117c118c119c11ac11bc10fc0c0c10dc0c120c0c122c0c11dc0c124c0c0c20528c12bc0c12cc12ec0c12fc123c0c131c131c0c136c137c138c139c13ac13bc13cc13dc13ec13fc140c141b83e7c0cdd231a11d6cb176bf79f93231670ab808cb1ccd519402acbd7f213032cb3627a00cdf172db0b73d1565c597a8cf2d82c47a022ef0152186e46d05d2901a0000000000000000000000000000000000000000000000000000000000000000088000000000000000028".to_string()],
            powers: vec![100],
            total_power: 100,
        };

        let prover = MilestoneProver::init(inputs);
        prover.prove();
    }
}
