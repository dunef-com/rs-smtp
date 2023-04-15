use std::sync::Arc;

use anyhow::Result;
use thiserror::Error;
use tokio::io::AsyncWrite;

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

pub struct Conn<W: AsyncWrite + Unpin> {
    pub writer: Writer<W>,
    pub pipeline: Pipeline,
}

impl<W: AsyncWrite + Unpin> Conn<W> {
    pub fn new(stream: Arc<tokio::sync::Mutex<W>>) -> Self {
        Self {
            writer: Writer::new(stream),
            pipeline: Pipeline::new(),
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