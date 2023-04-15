use std::pin::Pin;

use anyhow::Result;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

pub struct MyStream {
    pub unsafe_stream: Option<TcpStream>,
    pub safe_stream: Option<TlsStream<TcpStream>>,
}

impl MyStream {
    pub fn new(unsafe_stream: TcpStream) -> Self {
        Self {
            unsafe_stream: Some(unsafe_stream),
            safe_stream: None,
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
        panic!("Stream is not initialized");
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
        panic!("Stream is not initialized");
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
        panic!("Stream is not initialized");
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
        panic!("Stream is not initialized");
    }
}