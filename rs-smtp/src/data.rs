use std::{pin::Pin, future::Future, task::Poll, io::{ErrorKind, Error}};

use tokio::io::{self, AsyncRead, AsyncBufReadExt, AsyncBufRead, BufReader};

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

const ERR_DATA_TOO_LARGE: &str = "Data too large";

pub struct DataReader<'a, R: AsyncRead + Unpin> {
    pub r: BufReader<&'a mut R>,
    state: State,
    pub limited: bool,
    n: usize,
}

impl<'a, R: AsyncBufRead + Unpin> DataReader<'a, R> {
    pub fn new(r: &'a mut R, max_message_bytes: usize) -> Self {
        DataReader {
            r: BufReader::new(r),
            state: State::BeginLine,
            limited: max_message_bytes > 0,
            n: max_message_bytes,
        }
    }
}

impl<'a, R: AsyncRead + Unpin> AsyncRead for DataReader<'a, R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        if this.state == State::EOF {
            return std::task::Poll::Ready(Ok(()));
        }

        if this.limited && this.n <= 0 {
            return std::task::Poll::Ready(Err(Error::new(
                ErrorKind::Other,
                ERR_DATA_TOO_LARGE,
            )));
        }

        let bytes = match futures::ready!(Pin::new(&mut this.r).poll_fill_buf(cx)) {
            Ok(bytes) => {
                
                if bytes.is_empty() {
                    return std::task::Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "Unexpected EOF",
                    )));
                }

                if bytes.len() > this.n { &bytes[..this.n] } else { bytes }
            }
            Err(e) => return std::task::Poll::Ready(Err(e)),
        };
        

        let mut consumed = 0;
        for c in bytes {
            let c = *c;
            consumed += 1;
            match this.state {
                State::BeginLine => {
                    if c == b'.' {
                        this.state = State::Dot;
                        continue;
                    }
                    this.state = State::Data;
                }
                State::Dot => {
                    if c == b'\r' {
                        this.state = State::DotCR;
                        continue;
                    }
                    if c == b'\n' {
                        this.state = State::EOF;
                        break;
                    }

                    this.state = State::Data;
                }
                State::DotCR => {
                    if c == b'\n' {
                        this.state = State::EOF;
                        break;
                    }
                    this.state = State::Data;
                }
                State::CR => {
                    if c == b'\n' {
                        this.state = State::BeginLine;
                        break;
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
                _ => (),
            }

            buf.put_slice(&[c]);
            this.n -= 1;
        }

        this.r.consume(consumed);

        if this.state != State::EOF {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        
        Poll::Ready(Ok(()))
    }
}