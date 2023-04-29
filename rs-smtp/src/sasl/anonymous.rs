use crate::sasl;

use anyhow::Result;
use async_trait::async_trait;

/// The ANONYMOUS mechanism name.
pub const ANONYMOUS: &str = "ANONYMOUS";

/// Get trace information from clients logging in anonymously.
#[async_trait]
pub trait AnonymousAuthenticator: Send + Sync {
    async fn authenticate(&mut self, trace: &str) -> Result<()>;
}

pub struct AnonymousServer<AA: AnonymousAuthenticator> {
    authenticator: AA,
}

impl<AA: AnonymousAuthenticator> AnonymousServer<AA> {
    pub fn new(authenticator: AA) -> Self {
        Self { authenticator }
    }
}

#[async_trait]
impl<AA: AnonymousAuthenticator> sasl::Server for AnonymousServer<AA> {
    fn mechanism(&self) -> &str {
        ANONYMOUS
    }

    async fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)> {
        // No initial response, send an empty challenge
        if response.is_none() {
            return Ok((Vec::new(), false));
        }
        let response = response.unwrap();

        self.authenticator.authenticate(std::str::from_utf8(response)?).await?;
        Ok((Vec::new(), true))
    }
}