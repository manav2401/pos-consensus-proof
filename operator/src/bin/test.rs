use std::str::FromStr;

use pos_consensus_proof_operator::utils::PosClient;

use alloy_primitives::private::alloy_rlp::Decodable;
use alloy_primitives::FixedBytes;
use alloy_provider::ReqwestProvider;
use alloy_rpc_types::BlockNumberOrTag;
use reth_primitives::{hex, hex::decode, Header};
use sp1_cc_host_executor::HostExecutor;

use url::Url;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();
    println!("hello world");

    let client = PosClient::default();
    let number: u64 = 12899233;
    let bor_headed_rlp_encoded = client
        .fetch_bor_header(number)
        .await
        .expect("unable to fetch bor header");
    let bor_header_bytes = hex::decode(bor_headed_rlp_encoded).unwrap_or_default();
    let bor_header: Header = Header::decode(&mut bor_header_bytes.as_slice()).unwrap();
    let bor_block_hash: FixedBytes<32> = FixedBytes::from_slice(bor_header.hash_slow().as_slice());
    println!("bor_block_hash: {:?}", bor_block_hash);

    let expected = reth_primitives::BlockHash::from_str(
        "0x966359aa1ab8fa76e2fdaa77a92fe3909613f43dc80519a177f5bda03510c9c5",
    )
    .unwrap();

    let rpc_url = "https://rpc-amoy.polygon.technology";
    let provider = ReqwestProvider::new_http(Url::parse(rpc_url)?);
    let mut host_executor =
        HostExecutor::new(provider.clone(), BlockNumberOrTag::Number(number)).await?;
    let block_hash = host_executor.header.hash_slow();

    println!("block_hash: {:?}", block_hash);

    assert_eq!(block_hash, expected);
    Ok(())
}
