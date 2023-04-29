use std::pin::Pin;

use anyhow::{anyhow, Result};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::data::{ENHANCED_CODE_NOT_SET, NO_ENHANCED_CODE, EnhancedCode};

const CRNL: [u8; 2] = [b'\r', b'\n'];
//const DOTCRNL: [u8; 3] = [b'.', b'\r', b'\n'];

pub struct MyStream {
    pub unsafe_stream: Option<TcpStream>,
    pub safe_stream: Option<TlsStream<TcpStream>>,
    pub limit: usize,
}

impl MyStream {
    pub fn new(unsafe_stream: TcpStream) -> Self {
        Self {
            unsafe_stream: Some(unsafe_stream),
            safe_stream: None,
            limit: 0,
        }
    }

    pub fn is_tls(&self) -> bool {
        self.safe_stream.is_some()
    }

    pub async fn starttls(&mut self, acceptor: TlsAcceptor) -> Result<()> {
        let stream = self.unsafe_stream.take().unwrap();
        let stream = acceptor.accept(stream).await?;
        self.safe_stream = Some(stream);
        Ok(())
    }

    pub async fn print_line(&mut self, line: &str) -> Result<()> {
        self.write_all(line.as_bytes()).await?;
        self.write_all(&CRNL).await?;
        self.flush().await.map_err(|e| anyhow!(e))
    }

    pub async fn write_response(&mut self, code: u16, mut ec: EnhancedCode, texts: &[&str]) {
        if ec == ENHANCED_CODE_NOT_SET {
            let cat = code / 100;
            match cat {
                2 | 4 | 5 => ec = [5, 5, 0],
                _ => ec = NO_ENHANCED_CODE,
            }
        }

        for text in texts {
            let _ = self.print_line(&format!("{}-{}", code, text))
                .await;
        }
        if ec == NO_ENHANCED_CODE {
            let _ = self.print_line(&format!("{} {}", code, texts.last().unwrap()))
                .await;
        } else {
            let _ = self.print_line(&format!(
                    "{} {}.{}.{} {}",
                    code,
                    ec[0],
                    ec[1],
                    ec[2],
                    texts.last().unwrap()
                ))
                .await;
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        if self.unsafe_stream.is_some() {
            self.unsafe_stream.take().unwrap().shutdown().await?;
        }
        if self.safe_stream.is_some() {
            self.safe_stream.take().unwrap().shutdown().await?;
        }
        Ok(())
    }
}

impl AsyncRead for MyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.unsafe_stream.is_some() {
            return AsyncRead::poll_read(Pin::new(self.get_mut().unsafe_stream.as_mut().unwrap()), cx, buf);
        }
        if self.safe_stream.is_some() {
            return AsyncRead::poll_read(Pin::new(self.get_mut().safe_stream.as_mut().unwrap()), cx, buf);
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.unsafe_stream.is_some() {
            return AsyncWrite::poll_write(Pin::new(self.get_mut().unsafe_stream.as_mut().unwrap()), cx, buf);
        }
        if self.safe_stream.is_some() {
            return AsyncWrite::poll_write(Pin::new(self.get_mut().safe_stream.as_mut().unwrap()), cx, buf);
        }
        std::task::Poll::Ready(Ok(0))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.unsafe_stream.is_some() {
            return AsyncWrite::poll_flush(Pin::new(self.get_mut().unsafe_stream.as_mut().unwrap()), cx);
        }
        if self.safe_stream.is_some() {
            return AsyncWrite::poll_flush(Pin::new(self.get_mut().safe_stream.as_mut().unwrap()), cx);
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.unsafe_stream.is_some() {
            return AsyncWrite::poll_shutdown(Pin::new(self.get_mut().unsafe_stream.as_mut().unwrap()), cx);
        }
        if self.safe_stream.is_some() {
            return AsyncWrite::poll_shutdown(Pin::new(self.get_mut().safe_stream.as_mut().unwrap()), cx);
        }
        std::task::Poll::Ready(Ok(()))
    }
}