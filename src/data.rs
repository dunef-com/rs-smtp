use std::{pin::Pin, future::Future, task::Poll};

use tokio::io::{self, AsyncRead, AsyncReadExt};

use crate::{backend::{Backend}};

pub type EnhancedCode = [i8; 3];

pub struct SMTPError {
    code: u16,
    enhanced_code: EnhancedCode,
    message: String,
}

impl std::fmt::Display for SMTPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code, self.message)
    }
}

pub const NO_ENHANCED_CODE: EnhancedCode = [-1, -1, -1];

pub const ENHANCED_CODE_NOT_SET: EnhancedCode = [0, 0, 0];

#[derive(PartialEq)]
enum State {
    BeginLine,
    Dot,
    DotCR,
    CR,
    Data,
    EOF,
}


impl SMTPError {
    pub fn err_data_too_large() -> Self {
        return SMTPError {
            code: 552,
            enhanced_code: ENHANCED_CODE_NOT_SET,
            message: "Requested mail action aborted: exceeded storage allocation".to_string(),
        };
    }

    pub fn err_auth_required() -> Self {
        return SMTPError {
            code: 502,
            enhanced_code: [5, 7, 0],
            message: "Please authenticate first".to_string(),
        };
    }

    pub fn err_auth_unsupported() -> Self {
        return SMTPError {
            code: 502,
            enhanced_code: [5, 7, 0],
            message: "Authentication not supported".to_string(),
        };
    }

    pub fn error(&self) -> String {
        self.message.clone()
    }

    fn is_temporary(&self) -> bool {
        self.code >= 400 && self.code < 500
    }
}

pub struct DataReader<R: AsyncRead + Unpin> {
    pub r: R,
    state: State,
    pub limited: bool,
    n: usize,
}

impl<R: AsyncRead + Unpin> DataReader<R> {
    pub fn new<B: Backend>(r: R, max_message_bytes: usize) -> Self {
        DataReader {
            r,
            state: State::BeginLine,
            limited: max_message_bytes > 0,
            n: max_message_bytes,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DataReader<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        if this.n == 0 || this.state == State::EOF {
            return Poll::Ready(Ok(()));
        }

        let mut fut = Box::pin(this.r.read_u8());
        match Pin::new(&mut fut).poll(cx) {
            Poll::Ready(Ok(c)) => {
                match this.state {
                    State::BeginLine => {
                        if c == b'.' {
                            this.state = State::Dot;
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        this.state = State::Data;
                    }
                    State::Dot => {
                        if c == b'\r' {
                            this.state = State::DotCR;
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        if c == b'\n' {
                            this.state = State::EOF;
                            return Poll::Ready(Ok(()));
                        }
    
                        this.state = State::Data;
                    }
                    State::DotCR => {
                        if c == b'\n' {
                            this.state = State::EOF;
                            return Poll::Ready(Ok(()));
                        }
                        this.state = State::Data;
                    }
                    State::CR => {
                        if c == b'\n' {
                            this.state = State::BeginLine;
                            return Poll::Ready(Ok(()));
                        }
                        this.state = State::Data;
                    }
                    State::Data => {
                        if c == b'\r' {
                            this.state = State::CR;
                        }
                        if c == b'\n' {
                            this.state = State::BeginLine;
                        }
                    }
                    State::EOF => {
                        return Poll::Ready(Ok(()));
                    }
                }

                this.n -= 1;
                buf.put_slice(&[c]);
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Err(e)) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(e));
            }
            Poll::Pending => {
                return Poll::Pending;
            }
        }

    }
}