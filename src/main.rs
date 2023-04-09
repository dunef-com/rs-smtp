

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

use backend::{Backend, Session, MailOptions};

mod backend;
mod conn;
mod data;
mod lengthlimit_reader;
mod parse;
mod server;
mod stream;
mod textproto;

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
        let mut buf_reader = io::BufReader::new(data_reader);

        println!("data:");

        loop {
            let mut line = String::new();
            match buf_reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => println!("{}", line),
                Err(e) => {
                    println!("error: {}", e);
                    return Err(anyhow!(e));
                }
            }
        }

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

    let mut s = server::Server::new(be);

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