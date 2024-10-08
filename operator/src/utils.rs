use crate::types::{BlockResponse, MilestoneResponse, TxResponse, ValidatorSetResponse};

use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use std::env;

// PosClient holds a http client instance along with endpoints for heimdall rest-server,
// tendermint rpc server and bor's rpc server to interact with.
pub struct PosClient {
    heimdall_url: String,
    tendermint_url: String,
    http_client: Client,
    headers: HeaderMap,
}

impl Default for PosClient {
    fn default() -> Self {
        let heimdall_url =
            env::var("HEIMDALL_REST_ENDPOINT").expect("HEIMDALL_REST_ENDPOINT not set");
        let tendermint_url = env::var("TENDERMINT_ENDPOINT").expect("TENDERMINT_ENDPOINT not set");
        let http_client = Client::new();

        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"),
        );

        Self {
            heimdall_url,
            tendermint_url,
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
}
