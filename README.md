# rust-smtp-server
A rust smtp server library.
It's mainly a rewrite of the server side parts of the [emersion/go-smtp](https://github.com/emersion/go-smtp) library.

## Features


## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rust-smtp-server = "0.1"
```

## Example

```rust


use anyhow::{
    anyhow,
    Result,
};
use async_trait::async_trait;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite, AsyncBufReadExt};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;
use std::path::{Path, PathBuf};

use rust_smtp_server::backend::{Backend, Session, MailOptions};
use rust_smtp_server::server::Server;

#[derive(Clone)]
struct MyBackend;

struct MySession;

impl Backend for MyBackend {
    type S = MySession;

    fn new_session(&mut self) -> Result<MySession> {
        Ok(MySession)
    }
}

#[async_trait]
impl Session for MySession {
    fn auth_plain(&mut self,username: &str,password: &str) -> Result<()> {
        Ok(())
    }
    
    async fn mail(&mut self, from: &str, opts: &MailOptions) -> Result<()> {
        println!("mail from: {}", from);
        Ok(())
    }

    async fn rcpt(&mut self, to: &str) -> Result<()> {
        println!("rcpt to: {}", to);
        Ok(())
    }
    
    async fn data<R: AsyncRead + Send + Unpin>(&mut self, data_reader: R) -> Result<()> {
        // print whole message
        let mut data = Vec::new();
        let mut reader = io::BufReader::new(data_reader);
        reader.read_to_end(&mut data).await?;
        println!("data: {}", String::from_utf8_lossy(&data));

        Ok(())
    }

    fn reset(&mut self) {}

    fn logout(&mut self) -> Result<()> {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let be = MyBackend;

    let mut s = Server::new(be);

    s.addr = "127.0.0.1:2525".to_string();
    s.domain = "localhost".to_string();
    s.read_timeout = std::time::Duration::from_secs(10);
    s.write_timeout = std::time::Duration::from_secs(10);
    s.max_message_bytes = 10 * 1024 * 1024;
    s.max_recipients = 50;
    s.max_line_length = 1000;
    s.allow_insecure_auth = false;

    let certs = load_certs("server.crt")?;
    let mut keys = load_keys("server.key")?;

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    s.tls_acceptor = Some(acceptor);

    println!("Starting server on {}", s.addr);
    match s.listen_and_serve().await {
        Ok(_) => println!("Server stopped"),
        Err(e) => println!("Server error: {}", e),
    }

    Ok(())
}

fn load_certs(path: &str) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &str) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}
```

You can use the server manually with telnet:
    
```bash
telnet localhost 2525
EHLO localhost
MAIL FROM:<root@nsa.gov>
RCPT TO:<root@gchq.gov.uk>
DATA
Hey <3
.
```

## License

MIT

