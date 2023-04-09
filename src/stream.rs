use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct Stream(pub Arc<Mutex<TcpStream>>);

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut stream = self.0.lock().unwrap();
        AsyncRead::poll_read(std::pin::Pin::new(&mut (*stream)), cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut stream = self.0.lock().unwrap();
        AsyncWrite::poll_write(std::pin::Pin::new(&mut (*stream)), cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut stream = self.0.lock().unwrap();
        AsyncWrite::poll_flush(std::pin::Pin::new(&mut (*stream)), cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut stream = self.0.lock().unwrap();
        AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut (*stream)), cx)
    }
}
