use anyhow::Result;
use thiserror::Error;
use crate::stream::Stream;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::io::{AsyncWrite, AsyncRead, AsyncWriteExt, AsyncBufReadExt, BufReader};

use super::pipeline::Pipeline;
use super::writer::Writer;

#[derive(Error, Debug)]
struct MyError {
    code: u16,
    msg: String,
}

impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code, self.msg)
    }
}

type ProtocolError = String;

pub struct Conn<RW: AsyncRead + AsyncWrite + Clone + Unpin> {
    pub writer: Writer<RW>,
    pub pipeline: Pipeline,
    pub conn: RW,
}

impl<RW: AsyncRead + AsyncWrite + Clone + Unpin> Conn<RW> {
    pub fn new(stream: RW) -> Self {
        Self {
            writer: Writer::new(stream.clone()),
            pipeline: Pipeline::new(),
            conn: stream,
        }
    }

    pub async fn cmd(&mut self, line: &str) -> Result<u64> {
        let id = self.pipeline.next();
        self.pipeline.start_request(id).await;
        let res = self.writer.print_line(line).await;
        self.pipeline.end_request(id);
        res?;
        Ok(id)
    }
}