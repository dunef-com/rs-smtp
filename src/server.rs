use crate::backend::{Backend, Session};
use crate::conn::Conn;
use crate::parse::parse_cmd;

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rs_sasl::sasl;

use anyhow::{bail, Result};

use futures::executor;

use tokio::io::{self, AsyncBufReadExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;


// const ERR_TCP_AND_LMTP: &str = "smtp: cannot start LMTP server listening on a TCP socket";

/// A function that creates SASL servers.
pub type SaslServerFactory<B> = dyn Fn(&Conn<B>) -> Box<dyn sasl::Server> + Send + Sync;

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
    pub auths: HashMap<String, Box<SaslServerFactory<B>>>,

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
            auths: HashMap::from([
                (
                    rs_sasl::plain::PLAIN.to_string(),
                    Box::new(|c: &Conn<B>| {
                        let c_pointer = c as *const Conn<B>;
                        let c = unsafe { // ! USE OF UNSAFE ! Needs to be reviewed or even rewritten with a better solution
                            &*c_pointer
                        };
                        Box::new(rs_sasl::plain::PlainServer::new(Box::new(move |identity, username, password| {
                            // test if identity is empty or equal to username

                            if !identity.is_empty() && identity != username {
                                bail!("Identities not supported");
                            }

                            let mut sess = executor::block_on(async {
                                c.session.lock().await
                            });

                            if sess.is_none() {
                                bail!("No session when AUTH is called");
                            }
                            let sess = sess.as_mut().unwrap();

                            executor::block_on(async {
                                sess.auth_plain(username, password).await
                            })
                        }))) as Box<dyn sasl::Server>
                    }) as Box<SaslServerFactory<B>>
                )
            ]),
            //listeners: Mutex::new(vec![]),
        }
    }

    pub async fn serve(self, l: TcpListener) -> Result<()> {
        let server = Arc::new(self);
        loop {
            match l.accept().await {
                Ok((conn, _)) => {
                    let server = server.clone();
                    tokio::spawn(async move {
                        if let Err(err) = server.clone().handle_conn(Conn::new(conn, server.max_line_length)).await {
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

    pub async fn handle_conn(&self, mut c: Conn<B>) -> Result<()> {
        c.greet(self.domain.clone()).await;

        loop {
            let mut line = String::new();
            let clone = c.stream.clone();
            let mut reader = io::BufReader::new(Pin::new(clone.lock().await));
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    return Ok(());
                }
                Ok(_) => {
                    drop(reader);
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
                    drop(reader);
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