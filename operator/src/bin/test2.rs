// // use std::hash::Hash;

// use alloy_primitives::keccak256;
// use alloy_provider::{
//     network::{self, BlockResponse},
//     Provider, ReqwestProvider,
// };
// use reth_primitives::{hex, hex::FromHex, Header};

// use alloy_rlp::{Decodable, Encodable};
// // use alloy_rpc_types::{request, BlockNumberOrTag, Header};
// use alloy_transport_http::Http;
// use bincode;
// use reqwest;
// use reqwest::Url;
// use reth_primitives::{Address, Bloom, Bytes, B256};
// use serde::{Deserialize, Serialize};
// use serde_json::{self, Deserializer};
// use std::{
//     hash::{DefaultHasher, Hash, Hasher},
//     io::Read,
//     os::macos::raw::stat,
// };

// #[tokio::main]
// async fn main() -> anyhow::Result<()> {
//     dotenv::dotenv().ok();

//     println!("Hello, world!");

//     // // Create a simple HTTP client
//     // let client = reqwest::Client::new();
//     // let rpc_url = "https://polygon-rpc.com";

//     // // Fetch the latest block
//     // let response = client
//     //     .post(rpc_url)
//     //     .header("Content-Type", "application/json")
//     //     .json(&serde_json::json!({
//     //         "jsonrpc": "2.0",
//     //         "method": "eth_getBlockByNumber",
//     //         "params": ["latest", false],
//     //         "id": 1
//     //     }))
//     //     .send()
//     //     .await?;

//     // let block_response: serde_json::Value = response.json().await?;
//     // let block = block_response["result"].clone();
//     // println!("Raw response: {}", serde_json::to_string_pretty(&block)?);
//     // let block_str = block.to_string();

//     // // let mut deserializer = Deserializer::from_str(&block_str);
//     // // let header = reth_primitives::Block::deserialize(&mut deserializer).unwrap();

//     // // println!("Header: {:?}", header);

//     // header = reth_primitives::Header {
//     //     parent_hash
//     // }

//     // Parse the JSON block into a reth Block type
//     // let block: Block = serde_json::from_value(block_response["result"].clone())?;

//     // let block_json: serde_json::Value = response.json().await?;
//     // let block = block_json["result"].as_str().unwrap();
//     // println!("Latest block: {}", block);

//     // let rpc_url = "https://polygon-rpc.com".to_string();
//     // let provider: alloy_provider::RootProvider<Http<reqwest::Client>, network::AnyNetwork> =
//     //     ReqwestProvider::new_http(Url::parse(&rpc_url)?);
//     // let number = BlockNumberOrTag::Number(62512110);
//     // let block = provider.get_block_by_number(number, false).await?.unwrap();
//     // let header: Header = block.header.clone();

//     // let parent_hash: [u8; 32] = header.parent_hash.as_slice().try_into()?;
//     // let ommers_hash: [u8; 32] = header.uncles_hash.as_slice().try_into()?;
//     // let beneficiary: [u8; 20] = header.miner.as_slice().try_into()?;
//     // let state_root: [u8; 32] = header.state_root.as_slice().try_into()?;
//     // let transactions_root: [u8; 32] = header.transactions_root.as_slice().try_into()?;
//     // let receipts_root: [u8; 32] = header.receipts_root.as_slice().try_into()?;
//     // let withdrawals_root: [u8; 32] = header
//     //     .withdrawals_root
//     //     .unwrap_or_default()
//     //     .as_slice()
//     //     .try_into()?;
//     // let logs_bloom: [u8; 256] = header.logs_bloom.as_slice().try_into()?;
//     // let mix_hash: [u8; 32] = header.mix_hash.unwrap_or_default().as_slice().try_into()?;
//     // let nonce = u64::from_le_bytes(header.nonce.unwrap_or_default().as_slice().try_into()?);
//     // let parent_beacon_block_root: [u8; 32] = header
//     //     .parent_beacon_block_root
//     //     .unwrap_or_default()
//     //     .as_slice()
//     //     .try_into()?;
//     // let requests_root: [u8; 32] = header
//     //     .requests_root
//     //     .unwrap_or_default()
//     //     .as_slice()
//     //     .try_into()?;
//     // // let extra_data = Bytes(header.extra_data.into()?);
//     // let extra_data = Bytes::copy_from_slice(header.extra_data.to_vec().as_slice());

//     // let reth_header = reth_primitives::Header {
//     //     parent_hash: B256::new(parent_hash),
//     //     ommers_hash: B256::new(ommers_hash),
//     //     beneficiary: Address::new(beneficiary),
//     //     state_root: B256::new(state_root),
//     //     transactions_root: B256::new(transactions_root),
//     //     receipts_root: B256::new(receipts_root),
//     //     withdrawals_root: Some(B256::new(withdrawals_root)),
//     //     logs_bloom: Bloom::new(logs_bloom),
//     //     difficulty: header.difficulty,
//     //     number: header.number,
//     //     gas_limit: header.gas_limit,
//     //     gas_used: header.gas_used,
//     //     timestamp: header.timestamp,
//     //     mix_hash: B256::new(mix_hash),
//     //     nonce,
//     //     base_fee_per_gas: header.base_fee_per_gas,
//     //     blob_gas_used: header.blob_gas_used,
//     //     excess_blob_gas: header.excess_blob_gas,
//     //     parent_beacon_block_root: Some(B256::new(parent_beacon_block_root)),
//     //     requests_root: Some(B256::new(requests_root)),
//     //     extra_data,
//     // };

//     // println!("reth header: {:?}", reth_header);
//     // println!("hash: {:?}", reth_header.hash_slow());

//     // println!("Got block #62512110 - hash: {:?}", header.hash);

//     let header_str = "f902a8a0653daea2d20b0391420e068fb7bad65ba4b4f9dc790ccea70ec457f7bd49dbb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0157ea04b3f5251ab78932ffe4891d8bba9afa093f07f436e9060aaac6aaf8169a093885958bedf7b16050b938420cbe44074e2dfbeccbf5ce442c93f9d2d691279a04adc77d8228da184cca2720e8298a70d5301a2a8607ed2d6469d2fefc1d7f968b90100005d06e25482000884602100151455e4488307ae0044542c548213211362e600248c08c99900c18a714200f1690679419570900c88832614a0000f301425a0351dfa02023222484c02861068f0220ac812e15c254f0480039443030594e206a0721a71eaaa404110182b5c015500f90164310e846fd02457b0835215441c01468041404011982480d028e90021aa850110118ee184ac93044f0014009244b00162d78008ded0020002449b2b08130d02484c400620100387042a0e0b4f011b632e72017b7a90d9634b0140205a5250615d1426e046ee8421607280c4ae40f250265210a27d2baccc0606e150da020520c0c25209143098c041484d8017525809178403b9dbee8401c9c380839f69f38466fc4812b8aad78301040183626f7288676f312e32322e31856c696e75780000000000000000f84780f844c0c0c180c102c0c0c0c106c0c103c105c10ac109c10cc10dc10ec10fc110c107c0c0c0c0c0c0c111c119c0c0c0c11bc0c0c103c11ac21a80c0c11ec123c22226c11cc0c05f26d393b4065cbca0c14182fe98b312f5198005fdbe80054d9540a6f2d248115c63d01cf5641e66cee7ee5ff279081512df2efec1954dba9595686618b8fc0001a0000000000000000000000000000000000000000000000000000000000000000088000000000000000019".to_string();
//     let header_bytes = hex::decode(header_str).unwrap_or_default();
//     let header = Header::decode(&mut header_bytes.as_slice()).unwrap();

//     println!("Header: {:?}", header);
//     println!("Hash: {:?}", header.hash_slow());

//     Ok(())
// }

fn main() {
    println!("hello")
}
