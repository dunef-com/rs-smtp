use crate::sasl;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

/// The PLAIN mechanism name.
pub const PLAIN: &str = "PLAIN";

/// authenticates users with an identity, a username and a password. If the
/// identity is left blank, it indicates that it is the same as the username.
/// If identity is not empty and the server doesn't support it, an error must be
/// returned.
#[async_trait]
pub trait PlainAuthenticator: Send + Sync {
    async fn authenticate(&mut self, identity: &str, username: &str, password: &str) -> Result<()>;
}

pub struct PlainServer<PA: PlainAuthenticator> {
    authenticator: PA,
}

impl <PA: PlainAuthenticator> PlainServer<PA> {
    pub fn new(authenticator: PA) -> Self {
        Self { authenticator }
    }
}

#[async_trait]
impl<PA: PlainAuthenticator> sasl::Server for PlainServer<PA> {
    fn mechanism(&self) -> &str {
        PLAIN
    }
    
    async fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)> {
        // No initial response, send an empty challenge
        if response.is_none() {
            return Ok((Vec::new(), false));
        }
        let response = response.unwrap();

        let mut parts = response.split(|&b| b == b'\x00');
        let identity = std::str::from_utf8(parts.next().ok_or_else(|| anyhow!("sasl: missing identity"))?)?;
        let username = std::str::from_utf8(parts.next().ok_or_else(|| anyhow!("sasl: missing username"))?)?;
        let password = std::str::from_utf8(parts.next().ok_or_else(|| anyhow!("sasl: missing password"))?)?;

        self.authenticator.authenticate(identity, username, password).await?;

        Ok((Vec::new(), true))
    }
}