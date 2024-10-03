use crate::types::{BlockResponse, MilestoneResponse, TxResponse, ValidatorSetResponse};

use alloy_rpc_types::Block;
use anyhow::Result;
use reqwest::header::{
    self, HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, UPGRADE_INSECURE_REQUESTS, USER_AGENT,
};
use reqwest::Client;
use sp1_sdk::proto::network::twirp::axum::Json;
use std::borrow::Borrow;
use std::env;

// PosClient holds a http client instance along with endpoints for heimdall rest-server,
// tendermint rpc server and bor's rpc server to interact with.
pub struct PosClient {
    heimdall_url: String,
    tendermint_url: String,
    bor_url: String, // For now, pointing to a service which returns the rlp encoded header given a block number
    http_client: Client,
    headers: HeaderMap,
}

impl Default for PosClient {
    fn default() -> Self {
        let heimdall_url =
            env::var("HEIMDALL_REST_ENDPOINT").expect("HEIMDALL_REST_ENDPOINT not set");
        let tendermint_url = env::var("TENDERMINT_ENDPOINT").expect("TENDERMINT_ENDPOINT not set");
        let bor_url = env::var("BOR_RPC").expect("BOR_RPC not set");
        let http_client = Client::new();

        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"),
        );

        Self {
            heimdall_url,
            tendermint_url,
            bor_url,
            http_client,
            headers,
        }
    }
}

impl PosClient {
    pub fn new(heimdall_url: String, tendermint_url: String, bor_url: String) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"),
        );
        Self {
            heimdall_url,
            tendermint_url,
            bor_url,
            http_client: Client::new(),
            headers,
        }
    }

    /// Fetches a heimdall milestone by id
    pub async fn fetch_milestone_by_id(&self, id: u64) -> Result<MilestoneResponse> {
        let url = format!("{}/milestone/{}", self.heimdall_url, id);
        println!("Fetching milestone from: {}", url);
        let response = self
            .http_client
            .get(url)
            .headers(self.headers.clone())
            .send()
            .await?
            .json::<MilestoneResponse>()
            .await?;
        Ok(response)
    }

    /// Fetches a tendermint transaction by hash
    pub async fn fetch_tx_by_hash(&self, hash: String) -> Result<TxResponse> {
        let url = format!("{}/tx?hash={}", self.tendermint_url, hash);
        println!("Fetching milestone tx by hash: {}", url);
        let response: TxResponse = self
            .http_client
            .get(url)
            .headers(self.headers.clone())
            .send()
            .await?
            .json::<TxResponse>()
            .await?;
        Ok(response)
    }

    /// Fetches a tendermint block by number
    pub async fn fetch_block_by_number(&self, number: u64) -> Result<BlockResponse> {
        let url = format!("{}/block?height={}", self.tendermint_url, number);
        println!("Fetching block by number: {}", url);
        let response = self
            .http_client
            .get(url)
            .headers(self.headers.clone())
            .send()
            .await?
            .json::<BlockResponse>()
            .await?;
        Ok(response)
    }

    pub async fn fetch_validator_set(&self) -> Result<ValidatorSetResponse> {
        let url: String = format!("{}/staking/validator-set", self.heimdall_url);
        println!("Fetching validator set from: {}", url);
        let response: ValidatorSetResponse = self
            .http_client
            .get(url)
            .headers(self.headers.clone())
            .send()
            .await?
            .json::<ValidatorSetResponse>()
            .await?;
        Ok(response)
    }

    pub async fn fetch_bor_header(&self, number: u64) -> Result<String> {
        let url = format!("{}/header?number={}", self.bor_url, number);
        let response = self.http_client.get(url).send().await.unwrap();
        let encoded_header = response.text().await.unwrap();
        Ok(encoded_header)
    }
}
