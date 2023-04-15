use std::sync::Arc;

use anyhow::{anyhow, Result};
use log::warn;
use tokio::io::{
    AsyncWrite,
    AsyncWriteExt,
};

pub struct Writer<W: AsyncWrite + Unpin> {
    w: Arc<tokio::sync::Mutex<W>>,
    dot: Option<Box<DotWriter<W>>>,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(w: Arc<tokio::sync::Mutex<W>>) -> Self {
        Self {
            w,
            dot: None,
        }
    }

    pub async fn print_line(&mut self, line: &str) -> Result<()> {
        self.close_dot().await;
        let mut w = self.w.lock().await;
        w.write_all(line.as_bytes()).await?;
        w.write_all(&CRNL).await?;
        w.flush().await.map_err(|e| anyhow!(e))
    }

    pub async fn dot_writer(&mut self, dot: DotWriter<W>) {
        self.close_dot().await;
        self.dot = Some(Box::new(dot));
    }

    pub async fn close_dot(&mut self) {
        if let Some(dot) = &mut self.dot {
            let _ = (*dot).close().await;
        }
    }
}

const CRNL: [u8; 2] = [b'\r', b'\n'];
const DOTCRNL: [u8; 3] = [b'.', b'\r', b'\n'];

enum WState {
    Begin,
    BeginLine,
    CR,
    Data,
}

pub struct DotWriter<W: AsyncWrite + Unpin> {
    w: Writer<W>,
    state: WState,
}

impl<W: AsyncWrite + Unpin> DotWriter<W> {
    pub fn new(w: Writer<W>) -> Self {
        Self {
            w,
            state: WState::Begin,
        }
    }

    pub async fn write(&mut self, b: &[u8]) -> Result<usize> {
        let mut n = 0;
        while n < b.len() {
            let c = b[n];

            let mut w = self.w.w.lock().await;

            match self.state {
                WState::Begin | WState::BeginLine => {
                    self.state = WState::Data;
                    match c {
                        b'.' => {
                            w.write_u8(b'.').await?;
                        }
                        b'\r' => {
                            self.state = WState::CR;
                        }
                        b'\n' => {
                            w.write_u8(b'\r').await?;
                            self.state = WState::BeginLine;
                        }
                        _ => {}
                    }
                }
                WState::Data => {
                    match c {
                        b'\r' => {
                            self.state = WState::CR;
                        }
                        b'\n' => {
                            w.write_u8(b'\r').await?;
                            self.state = WState::BeginLine;
                        }
                        _ => {}
                    }
                }
                WState::CR => {
                    self.state = WState::Data;
                    if c == b'\n' {
                        self.state = WState::BeginLine;
                    }
                }
            }
            if let Err(e) = w.write_u8(c).await {
                warn!("{}", e);
                break;
            }
            n += 1;
        }

        Ok(n)
    }

    pub async fn close(&mut self) -> Result<()> {
        if let Some(dot) = &self.w.dot {
            if (dot.as_ref() as *const _) == (self as *const _) {
                self.w.dot = None;
            }
        }

        let mut w = self.w.w.lock().await;

        match self.state {
            WState::CR => {
                w.write_u8(b'\n').await?;
                w.write_all(&DOTCRNL).await?;
                w.write_u8(b'\r').await?;
            }
            WState::BeginLine => {
                w.write_all(&DOTCRNL).await?;
                w.write_u8(b'\r').await?;
            }
            _ => {
                w.write_u8(b'\r').await?;
            }
        }

        w.flush().await?;
        Ok(())
    }
}