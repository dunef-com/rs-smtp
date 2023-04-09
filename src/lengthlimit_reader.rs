use std::sync::{Arc};



use anyhow::{bail, Result};
use tokio::{io::{ReadHalf, AsyncRead, AsyncReadExt}, net::TcpStream};
use crate::stream::Stream;

use std::sync::Mutex;

const ERR_TOO_LONG_LINE: &str = "smtp: too long a line in input stream";

pub struct LineLimitReader<R: AsyncRead> {
    pub r: R,
    pub line_limit: usize,

    pub cur_line_length: usize,
}

impl<R: AsyncRead + Unpin> LineLimitReader<R> {
    pub fn new(r: R, line_limit: usize) -> Self {
        Self {
            r,
            line_limit,
            cur_line_length: 0,
        }
    }

    async fn read(&mut self, b: &mut [u8]) -> Result<usize> {
        if (self.cur_line_length > self.line_limit) && (self.line_limit > 0) {
            bail!(ERR_TOO_LONG_LINE);
        }

        let n = self.r.read(b).await?;
        if self.line_limit == 0 {
            return Ok(n);
        }

        for chr in b[..n].iter() {
            if *chr == b'\n' {
                self.cur_line_length = 0;
            }

            self.cur_line_length += 1;

            if self.cur_line_length > self.line_limit {
                bail!(ERR_TOO_LONG_LINE);
            }
        }

        return Ok(n);
    }
}