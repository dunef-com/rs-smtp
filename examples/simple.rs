use anyhow::Result;
use async_trait::async_trait;
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
    async fn auth_plain(&mut self, username: &str, password: &str) -> Result<()> {
        println!("username: {username}");
        println!("password: {password}");

        Ok(())
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