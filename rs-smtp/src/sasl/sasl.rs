use anyhow::Result;
use async_trait::async_trait;

pub const ERR_UNEXPECTED_CLIENT_RESPONSE: &str = "sasl: unexpected client response";
pub const ERR_UNEXPECTED_SERVER_CHALLENGE: &str = "sasl: unexpected server challenge";

/// SASL Server interface to perform challenge-response authentication.
#[async_trait]
pub trait Server: Send + Sync {
    fn mechanism(&self) -> &str;

    /// Begins or continues challenge-response authentication. If the client
    /// supplies an initial response, response is non-nil.
    /// 
    /// If the authentication is finished, done is set to true. If the
    /// authentication has failed, an error is returned.
    async fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)>;
}