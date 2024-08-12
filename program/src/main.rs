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

use pos_consensus_proof::milestone::{MilestoneProof, MilestoneProofInputs};
pub fn main() {
    // let header_hex: String = "f90265a0afe719f6ca102ab7b7b9fd367688e73a777d02d21d6a692a8ff6a6eb3c2f7c27a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0f48ab66c3b39fcf8415ba3f787a529900795b307337fc244949eed20f10de6dca09434da2710a11e1a5c3b61f7feb0dd5a75520befe5a6ccc1be4de14251f00869a0bbdeef8478f908a12f86b906c43a4f0ef2bb62226ccae6af1e34668488ca8323b90100db3a9cb765f57e3ef6b760d1fcaf4eba4bcb5b44c56fb1e838f7f87de18fe9775a2ef30addeb605b5be3e9bfbfd64ccdfab7fdf7ddaee92af58e337f81bee788f869fe176d0bf9db44e9b6dfc86ae9f8962727becd5eb1f2f3078f96dacd3e07eddc79d61bf34e6081a7f9236d997b89fb8901c7c6b1ba75f1b1c7fdf6d9ff3d07776d7e39ec6abd7e2199e265b2e15f79bfadf1afc6a38fafcf1a70f6d55bda6e430b2bf253df0f3874fd44da9090cf4877bf90666bd9a8b42a932fd6808cde5dadbd3311bfecc7ff73025a4e30bca9eb710e22cd6eddc9fd7fe22a3c7bf99e189a8de36bab08ccf50d6efd3e87f935d9ec26776bcf44dfbc3db96d2b9c9b6b158402faf0808401c31a8c84018ec9288465559991b861d78301000683626f7288676f312e32302e38856c696e75780000000000000000b6c6f13270d722c179f577c7669e775841f090e7dc37640e3da15ba28dbaef472f1b963fc7b3ca1b884cc23cb2b302ec1ce6e8bf0a9164d8181407e0d7a2f79801a000000000000000000000000000000000000000000000000000000000000000008800000000000000008518b525e260".to_string();
    // let header_bytes = hex::decode(header_hex).unwrap_or_default();
    // let header = Header::decode(&mut header_bytes.as_slice()).unwrap();

    // let milestone_msg = MilestoneMessage {
    //     proposer: Address::from_hex("0xeedba2484aaf940f37cd3cd21a5d7c4a7dafbfc0").unwrap(),
    //     start_block: 59826672,
    //     end_block: 59826688,
    //     hash: B256::default(),
    //     bor_chain_id: 137,
    //     milestone_id: String::from(
    //         "1713ea93-6651-4d5f-96b0-c0f29b4d9b9b - 0x93f0bf1af099ca4eb5a0c4ad2522bb05bd1c0377",
    //     ),
    //     timestamp: 0,
    // };

    // let inputs = MilestoneProofInputs {
    //     milestone: milestone_msg,
    //     headers: vec![header],
    //     sigs: vec![],
    //     target_block_hash: B256::default(),
    //     target_state_root: B256::default(),
    // };

    // let proof = MilestoneProof::init(inputs);
    // proof.validate();

    let inputs = MilestoneProofInputs {
        tx_data: "6AHwYl3uCp4B0ss+ZgoUqmrAL92q9vEg9buYzjCAnRnNXRsQ7+TrHBj75OscIiBVELbKUXyxwqqVdn4ZonVftpOEigC+o0PYMQp9wEQZbSoDMTM3MlEzNzNhY2I4Zi03OGVlLTRkMzctODYwZS03NWZkZjQyZjgyYTQgLSAweDE5YTI3NTVmYjY5Mzg0OGEwMGJlYTM0M2Q4MzEwYTdkYzA0NDE5NmQSQegVvhAXsyj7DXQUYSl+FoNvO/9cvdY2gGKIGtaDOgeSdXZyn5PrNKArkVTgndRHNC+17h4ZO9rF1TF9gEjOwvYB".to_string(),
        tx_hash: "4C6BB9C1426CEF3B0252EFADFBD09B88350F508CC2A4EC0C837612958AD37C85".to_string(),
        precommits: vec!["9701080211327b30010000000022480a20fd648de965c020911f2bcfa3825fe2bd6698aa93009f0e63348ad74506221fae12240a20218d85717b5904942ce7c7b89b201aa1c2711dddb6e380cd0357c4647f35ac9b10012a0c08f29ee6b50610abfdeacc03320c6865696d64616c6c2d31333742240a204c6bb9c1426cef3b0252efadfbd09b88350f508cc2a4ec0c837612958ad37c851001".to_string()],
        sigs: vec!["ZnLPE6+g9xfOQdnmugJ94zFRuQO47bH424V62XFgNul/HiiA46RBQYxW0E3+3MpcMLX4Dw5ma1rfFMr4Lr6EDwA=".to_string()],
        signers: vec!["0x00856730088A5C3191BD26EB482E45229555CE57".to_string()],
        milestone_msg: "aa6ac02fddaaf6f120f5bb98ce30809d19cd5d1b00000000039af26f00000000039af27b5510b6ca517cb1c2aa95767e19a2755fb693848a00bea343d8310a7dc044196d000000000000008933373361636238662d373865652d346433372d383630652d373566646634326638326134202d20307831396132373535666236393338343861303062656133343364383331306137646330343431393664".to_string(),
        headers: vec!["f902d5a095913a64f4f93aeb8fd5ee7c6562bd02e50f4613a5ea230fbbf0aca717996217a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a09eb7f80eafdb4f69520ec7d664402e5b3ce4af3b22cacc5098ebb73342b52301a01fa16db19c3fdc00a6902e29a57a1755dce6be40c4eab66e4b4a16d36a8e9135a00acd40f3f7dc9777f9e39a49654b4e564f18c22ca7ca025e69ea9790b47edd46b90100652a812e80ac124a006b29388ea4d67932562030482081304ea12036c01824200748231b1180241080620011510a9215241492384822a94320320e02aca0301a0608984c0e225aec2200248c103810f8522a2622415f00007843711092b69a0b13a040640b12b2602048e55a011e0d0816e40c505970044ce9a84310020b03f104b31980210f40992051c2c4f484c000180b16b339400b69505982ea42109205ea00238410d8440a906a101074014800f8c42546060068ce1410a600010560e343b1064334100210418b08302a68c003f6050004405aa0560292930b2085aa4534104247000454000c8d0842f520c5d2c01d816010c8094283d82a20231729341784039af27b8401c9c38083821b6d8466b98f45b8d7d78301030683626f7288676f312e32322e35856c696e75780000000000000000f87480f871c0c0c0c101c103c0c104c0c0c108c106c0c0c10ac0c10ec0c110c111c112c113c114c115c116c117c118c119c11ac11bc10fc0c0c10dc0c120c0c122c0c11dc0c124c0c0c20528c12bc0c12cc12ec0c12fc123c0c131c131c0c136c137c138c139c13ac13bc13cc13dc13ec13fc140c141b83e7c0cdd231a11d6cb176bf79f93231670ab808cb1ccd519402acbd7f213032cb3627a00cdf172db0b73d1565c597a8cf2d82c47a022ef0152186e46d05d2901a0000000000000000000000000000000000000000000000000000000000000000088000000000000000028".to_string()],
    };

    let proof = MilestoneProof::init(inputs);
    proof.validate();

    // pub struct MilestoneProofInputs {
    //     pub tx_data: String,
    //     pub tx_hash: String,
    //     pub precommits: Vec<String>,
    //     pub sigs: Vec<String>,
    //     pub signers: Vec<String>,
    //     pub milestone_msg: String,
    //     pub headers: Vec<String>,
    // }
}
