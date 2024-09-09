use reqwest::Client;

/// PosClient holds a http client instance along with endpoints for heimdall rest-server,
/// tendermint rpc server and bor's rpc server to interact with.
pub struct PosClient {
    heimdall_url: String,
    tendermint_url: String,
    bor_url: String,
    client: Client,
}

impl PosClient {
    pub fn new(heimdall_url: String, tendermint_url: String, bor_url: String) -> Self {
        Self {
            heimdall_url,
            tendermint_url,
            bor_url,
            client: Client::new(),
        }
    }
}
