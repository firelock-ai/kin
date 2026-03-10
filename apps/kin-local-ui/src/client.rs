use serde::de::DeserializeOwned;

/// HTTP client for the kin-daemon API.
#[derive(Clone)]
pub struct DaemonClient {
    base_url: String,
    client: reqwest::Client,
}

impl DaemonClient {
    pub fn new(base_url: String, client: reqwest::Client) -> Self {
        Self { base_url, client }
    }

    pub async fn health(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/health").await
    }

    pub async fn status(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/status").await
    }

    pub async fn sessions(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/sessions").await
    }

    pub async fn traffic(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/traffic").await
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(ClientError::Request)?;

        if !resp.status().is_success() {
            return Err(ClientError::Status(resp.status().as_u16()));
        }

        resp.json::<T>().await.map_err(ClientError::Request)
    }
}

#[derive(Debug)]
pub enum ClientError {
    Request(reqwest::Error),
    Status(u16),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Request(e) => write!(f, "request error: {}", e),
            ClientError::Status(code) => write!(f, "daemon returned status {}", code),
        }
    }
}

impl std::error::Error for ClientError {}
