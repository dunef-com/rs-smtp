use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::io::{
    AsyncWrite,
    AsyncWriteExt,
};

pub struct Writer<W: AsyncWrite> {
    w: W,
    dot: Option<Box<DotWriter>>,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(w: W) -> Self {
        Self {
            w,
            dot: None,
        }
    }

    pub async fn print_line(&mut self, line: &str) -> Result<()> {
        self.close_dot().await;
        self.w.write_all(line.as_bytes()).await?;
        self.w.write_all(&crnl).await?;
        Ok(())
    }

    pub async fn dot_writer(&mut self, dot: DotWriter) {
        self.close_dot().await;
        self.dot = Some(Box::new(dot));
    }

    pub async fn close_dot(&mut self) {
        if let Some(dot) = &mut self.dot {
            (*dot).close().await;
        }
    }
}

const crnl: [u8; 2] = [b'\r', b'\n'];
const dotcrnl: [u8; 3] = [b'.', b'\r', b'\n'];

enum WState {
    Begin,
    BeginLine,
    CR,
    Data,
}

pub struct DotWriter {
    w: Writer<Box<Self>>,
    state: WState,
}

impl DotWriter {
    pub async fn write(&mut self, b: &[u8]) -> Result<usize> {
        let mut n = 0;
        while n < b.len() {
            let c = b[n];

            match self.state {
                WState::Begin | WState::BeginLine => {
                    self.state = WState::Data;
                    match c {
                        b'.' => {
                            self.w.w.write_u8(b'.').await?;
                        }
                        b'\r' => {
                            self.state = WState::CR;
                        }
                        b'\n' => {
                            self.w.w.write_u8(b'\r').await?;
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
                            self.w.w.write_u8(b'\r').await?;
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
            if let Err(e) = self.w.w.write_u8(c).await {
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

        match self.state {
            WState::CR => {
                self.w.w.write_u8(b'\n').await?;
                self.w.w.write_all(&dotcrnl).await?;
                self.w.w.write_u8(b'\r').await?;
            }
            WState::BeginLine => {
                self.w.w.write_all(&dotcrnl).await?;
                self.w.w.write_u8(b'\r').await?;
            }
            _ => {
                self.w.w.write_u8(b'\r').await?;
            }
        }

        self.w.w.flush().await?;
        Ok(())
    }
}

impl AsyncWrite for DotWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_shutdown(cx)
    }
}