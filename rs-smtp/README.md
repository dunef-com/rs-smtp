# rs-smtp
An ESMTP server library written in Rust.

## Features

- ESMTP client & server implementing RFC 5321
- Support for SMTP AUTH and PIPELINING
- UTF-8 support for subject and message body


## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rs-smtp = "1"

anyhow = "1.0"
tokio = { version = "1.26.0", features = ["full"] }
async-trait = "0.1.67"
```

## Example


### Simple Example
```rust
use anyhow::Result;
use async_trait::async_trait;
use rs_smtp::sasl;
use tokio::io::{AsyncReadExt, AsyncRead};

use rs_smtp::backend::{Backend, Session, MailOptions};
use rs_smtp::conn::Conn;
use rs_smtp::server::Server;

struct MyBackend;

struct MySession;

impl Backend for MyBackend {
    type S = MySession;

    fn new_session(&self, _c: &mut Conn<Self>) -> Result<MySession> {
        Ok(MySession)
    }
}

#[async_trait]
impl Session for MySession {
    fn authenticators(&mut self) -> Vec<Box<dyn sasl::Server>> {
        vec!()
    }
    
    async fn mail(&mut self, from: &str, _: &MailOptions) -> Result<()> {
        println!("mail from: {}", from);
        Ok(())
    }

    async fn rcpt(&mut self, to: &str) -> Result<()> {
        println!("rcpt to: {}", to);
        Ok(())
    }
    
    async fn data<R: AsyncRead + Send + Unpin>(&mut self, mut r: R) -> Result<()> {
        // print whole message
        let mut mail = String::new();
        r.read_to_string(&mut mail).await?;
        println!("data: {}", mail);

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

    println!("Starting server on {}", s.addr);
    match s.listen_and_serve().await {
        Ok(_) => println!("Server stopped"),
        Err(e) => println!("Server error: {}", e),
    }

    Ok(())
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

### Outgoing Mail Server Example With Authentication and STARTTLS

```rust
use anyhow::Result;
use async_trait::async_trait;
use mail_send::SmtpClientBuilder;
use mail_send::mail_auth::common::crypto::{RsaKey, Sha256};
use mail_send::mail_auth::dkim::DkimSigner;
use rs_smtp::sasl;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::io::{self, AsyncReadExt, AsyncRead};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

use std::borrow::Cow;
use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::*;

use mail_send::smtp::message::{
    Address,
    Message
};

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;


use rs_smtp::backend::{Backend, Session, MailOptions};
use rs_smtp::conn::Conn;
use rs_smtp::sasl::plain::{PlainServer, PlainAuthenticator};
use rs_smtp::server::Server;

struct MyBackend;

struct MySession {
    to: Vec<String>,
}

impl Backend for MyBackend {
    type S = MySession;

    fn new_session(&self, _c: &mut Conn<Self>) -> Result<MySession> {
        Ok(MySession {
            to: Vec::new(),
        })
    }
}

struct MyPlainAuthenticator;

#[async_trait]
impl PlainAuthenticator for MyPlainAuthenticator {
    async fn authenticate(&mut self, _identity: &str, username: &str, password: &str) -> Result<()> {
        if username == "nick@dunef.io" && password == "test" {
            Ok(())
        } else {
            Err(anyhow::anyhow!("invalid username or password"))
        }
    }
}

#[async_trait]
impl Session for MySession {
    fn authenticators(&mut self) -> Vec<Box<dyn sasl::Server>> {
        vec!(
            Box::new(PlainServer::new(MyPlainAuthenticator))
        )
    }

    async fn mail(&mut self, from: &str, _: &MailOptions) -> Result<()> {
        println!("mail from: {}", from);
        Ok(())
    }

    async fn rcpt(&mut self, to: &str) -> Result<()> {
        println!("rcpt to: {}", to);
        self.to.push(to.to_string());
        Ok(())
    }
    
    async fn data<R: AsyncRead + Send + Unpin>(&mut self, mut r: R) -> Result<()> {
        // print whole message
        let mut mail = vec![];
        r.read_to_end(&mut mail).await?;

        let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;

        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(DKIM_KEY).unwrap();
        let signer = DkimSigner::from_key(pk_rsa)
            .domain("dunef.io")
            .selector("dkim_selector")
            .headers(["From", "To", "Subject"])
            .expiration(60 * 60 * 7);

        for to in self.to.iter() {

            println!("Sending email to {}", to);

            let mx_response = resolver.mx_lookup(to.split("@").collect::<Vec<&str>>()[1]).await?;

            for mx in mx_response.iter() {

                println!("MX: {}", mx.exchange());

                let builder = SmtpClientBuilder::new(mx.exchange().to_utf8(), 25)
                    .helo_host("dunef.io".to_string())
                    .implicit_tls(false)
                    .connect()
                    .await;

                if builder.is_err() {
                    println!("Failed to connect to {}", mx.exchange());
                    continue;
                }

                match builder.unwrap()
                    .send_signed(
                        Message::new(
                            Address::from("nick@dunef.io"),
                            vec![Address::from(to.clone())],
                            Cow::from(&mail),
                        ),
                        &signer
                    )
                    .await {
                        Ok(_) => {
                            println!("Email sent successfully");
                            break;
                        },
                        Err(e) => {
                            println!("Failed to send email: {}", e);
                            continue;
                        }
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

    let mut s = Server::new(be);

    s.addr = "127.0.0.1:587".to_string();
    s.domain = "dunef.io".to_string();
    s.read_timeout = std::time::Duration::from_secs(10);
    s.write_timeout = std::time::Duration::from_secs(10);
    s.max_message_bytes = 10 * 1024 * 1024;
    s.max_recipients = 50;
    s.max_line_length = 1000;
    s.allow_insecure_auth = false;

    let certs = load_certs("/etc/letsencrypt/live/dunef.io/fullchain.pem")?;
    let mut keys = load_keys("/etc/letsencrypt/live/dunef.io/privkey.pem")?;

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

const DKIM_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwbIlk19eVTa8RayErwcr0PWkH+IDZSddxVw2AKpujKJN642e
PiwMChgj5LRwFdWknT97E9YykVk46vNPdKTjBe1POuUrl2wcm46Hv0easuqiyjRC
WswNIN+avvG2krgMgf3/2T12lyJ2v4wcn34q9vqN+dkLfMz9WWbKEeKHHq80SFyL
PHA6ieTNToXgHgP+Qr5lbL6gh8fjTiUtpIVvHt8N29TIBTpVi3StE+2cu/RCSfcZ
6Wu6tJYzRxlTIKWFxU5Fh+5YL0gue3M7+1e5FyeQHChyRljpDWWywYPGrlN4Thon
KV2nwwV1v3B/1dBEKuXuo3lNPOrkwkc4rgsPvQIDAQABAoIBAQCoIvUdNWbUf5v0
uym+KXJuhByBFJcv4nkyjbXO5CLsbyNGevtHKsMUrBnUOJEnUvn/ChDTilcA9rtC
sAxjy5HKHlJtZGtvmQhIO/Q4JXbzIlxHPA/xczleNNvGLln2iE9LM+o4cHMWBHOi
GITsKgAvvhUqMa8YGXU+esyjs8jo51fyo/XdqUE3iLjm3+d2ZZnC8vjpKdVOIfGd
C/8TLXDFkj1MawRVEBgV06Mqnjxg9pPEwcuxYhTWXxwKXjLCoJ2NmXx4k5+6vsDC
5mqnb0/aOIMX6ZCmkTWS6Sn9HuvVJ3Qvmb3FVh8gk4WY2xS7//emS9hXsrj9qZez
AJxP+Qp9AoGBAO5oK523lRR4yqRqHxEME6aRxKzG74zWVMYKS0SpY8lU7YQDe8AW
xwN4c4FPnxIplm/XNT/EUA8bQ9lZBY8rasTB6nYegujwbITk/QIT7CHdUxmZ4keW
3K18Yn3RZjYJrxAlE5JB756kISsz+rauguYMDi9enLA8hbXd2NBicIbLAoGBAM/9
UxEkgY2+/Eltz0idDSDWpD/DiXgNV8YE7fmZQkE9FZDjnmwGPpfyKjX+gN1dvmk8
qjBsJ6u5DkzyA30IyzUVxaz6Qq0/z1SHzNABoN1leB4ASxruMFSoaeWkb17dKAQ/
KDC/U447VVI5fDatrqsFB1F0CO470KQukTaiouqXAoGBAObKGycD+CqkzS7auJZV
HZTLWhx0PKQXPFu2zWR7omjdeUyp3pt2sVOvwAk3XeNENSixqg+/6EyndUgrwJD3
U9WDb4jHQq1jSXpg/niLdrTVv8Nxz7bD2X9sgSARnSPEvh8f9VFJ2UC23JEpMZS1
XWx70SOUMJT/EeWcDG62TP5/AoGAOsnDnOjQpZwB+09Kc5/QgiOpMUy3onNDB/mE
ujQTghP8gIOV17q8Hn6YZ8KT8f35QA2hnSY04FjiLeWKDuFZbpvEz+u8xPNwSthH
j9OmAG4Z0YELuYTxrDweEoaz5ABmuyyO05iAqYcjyqXs8heNc1FsjB1cGNpXUtDG
wsadfekCgYEAlVvU+StUkNU1bHaKUXc/pa1jCIWkd2a9Hi4/Wibd8YzWF3TZ2hdi
kSWZOLGi8nCYqNDu+oN0t5ItS9bFvuy+cUkuimK0GgMksAwumXSIRx064oguXKGl
FIa62JUQcV2v55xrtLYX+7emRwzq6zUPU9pkn9rqgK44xU8HDvcKgSM=
-----END RSA PRIVATE KEY-----
";
```

## License

MIT

