use crate::backend::{
    Backend,
    Session,
};
use crate::conn::Conn;
use crate::parse::parse_cmd;
use std::pin::Pin;
use std::sync::Arc;


use anyhow::Result;
use tokio::sync::Mutex;
use std::time::Duration;

use tokio::io::{self, BufWriter, AsyncBufReadExt, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;


const ERR_TCP_AND_LMTP: &str = "smtp: cannot start LMTP server listening on a TCP socket";

#[derive(Clone)]
pub struct Server<B: Backend> {
    pub addr: String,
    pub tls_acceptor: Option<TlsAcceptor>,

    pub domain: String,
    pub max_recipients: usize,
    pub max_message_bytes: usize,
    pub max_line_length: usize,
    pub allow_insecure_auth: bool,
    pub strict: bool,

    pub read_timeout: Duration,
    pub write_timeout: Duration,

    pub enable_smtputf8: bool,
    pub enable_requiretls: bool,
    pub enable_binarymime: bool,

    pub auth_disabled: bool,

    pub backend: B,

    pub caps: Vec<String>,

    //pub listeners: Mutex<Vec<TcpListener>>,

    //pub conns: HashMap<String, Arc<Mutex<Conn<B, S>>>>,
}

impl<B: Backend> Server<B> {
    pub fn new(be: B) -> Self {
        return Server{
            addr: String::new(),
            tls_acceptor: None,
            domain: String::new(),
            max_recipients: 0,
            max_message_bytes: 0,
            max_line_length: 2000,
            allow_insecure_auth: true,
            strict: false,
            read_timeout: Duration::from_secs(0),
            write_timeout: Duration::from_secs(0),
            enable_smtputf8: false,
            enable_requiretls: false,
            enable_binarymime: false,
            auth_disabled: false,
            backend: be,
            caps: vec!["PIPELINING".to_string(), "8BITMIME".to_string(), "ENHANCEDSTATUSCODES".to_string(), "CHUNKING".to_string()],
            //listeners: Mutex::new(vec![]),
        }
    }

    pub async fn serve(self, l: TcpListener) -> Result<()> {
        loop {
            match l.accept().await {
                Ok((conn, _)) => {
                    let mut server = self.clone();
                    tokio::spawn(async move {
                        if let Err(err) = server.handle_conn(Conn::new(conn, server.max_line_length)).await {
                            println!("Error: {}", err);
                        }
                    });
                }
                Err(e) => {
                    println!("Error: {}", e);
                }
            }
        }
    }

    pub async fn handle_conn(&mut self, mut c: Conn<B>) -> Result<()> {
        c.greet(self.domain.clone()).await;

        let mut buf_reader = io::BufReader::new(c.text.conn.clone());

        loop {
            let mut line = String::new();
            match buf_reader.read_line(&mut line).await {
                Ok(0) => {
                    return Ok(());
                }
                Ok(_) => {
                    match parse_cmd(line) {
                        Ok((cmd, arg)) => {
                            c.handle(cmd, arg, self).await;
                        }
                        Err(err) => {
                            println!("Error: {}", err);
                            c.write_response(501, [5,5,2], &["Bad command"]).await;
                            continue;
                        }
                    }
                }
                Err(err) => {
                    match err.kind() {
                        std::io::ErrorKind::TimedOut => {
                            c.write_response(221, [2,4,2], &["Idle timeout, bye bye"]).await;
                            return Ok(());
                        }
                        _ => {
                            c.write_response(221, [2,4,0], &["Connection error, sorry"]).await;
                            return Err(err.into());
                        }
                    }
                }
            }
        }
    }

    pub async fn listen_and_serve(self) -> Result<()> {
        let l = TcpListener::bind(&self.addr).await?;
        self.serve(l).await
    }

    /*
    pub async fn listen_and_serve_tls(&mut self) -> Result<()> {
        let tls = self.server.tls_acceptor.as_ref().unwrap();
        let l = TcpListener::bind(&self.server.addr).await?;
        let l = tls.accept(l)?;
        self.serve(l).await
    }
    */
}