use crate::data::SMTPError;

use async_trait::async_trait;

use anyhow::{
    anyhow,
    Result,
};

use tokio::io::AsyncRead;

type BodyType = String;

//const BODY_7BIT: BodyType = "7BIT".to_owned();
//const BODY_8BIT_MIME: BodyType = "8BITMIME".to_string();
//const BODY_BINARY_MIME: BodyType = "BINARYMIME".to_string();

pub trait Backend: Send + Sync + 'static {
    type S: Session + Send;

    fn new_session(&self) -> Result<Self::S>;
}

pub struct MailOptions {
    pub body: BodyType,
    pub size: usize,
    pub require_tls: bool,
    pub utf8: bool,
    pub auth: String,
}

impl MailOptions {
    pub fn new() -> Self {
        MailOptions {
            body: "7BIT".to_string(),
            size: 0,
            require_tls: false,
            utf8: false,
            auth: String::new(),
        }
    }
}

#[async_trait]
pub trait Session {
    fn reset(&mut self);

    fn logout(&mut self) -> Result<()>;

    fn auth_plain(&mut self, username: &str, password: &str) -> Result<()> {
        Err(anyhow!(SMTPError::err_auth_unsupported().error()))
    }

    async fn mail(&mut self, from: &str, opts: &MailOptions) -> Result<()>;

    async fn rcpt(&mut self, to: &str) -> Result<()>;

    async fn data<R: AsyncRead + Send + Unpin>(&mut self, r: R) -> Result<()>;
}