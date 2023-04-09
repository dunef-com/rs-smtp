use anyhow::{
    anyhow,
    Result
};
use tokio::sync::oneshot;
use std::sync::{Arc, Mutex};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::backend::{
    Backend,
    Session, MailOptions,
};
use crate::data::{EnhancedCode, ENHANCED_CODE_NOT_SET, NO_ENHANCED_CODE, DataReader};
use crate::server::Server;
use crate::stream::Stream;
use crate::lengthlimit_reader::LineLimitReader;
use crate::textproto::textproto;
use crate::parse::{parse_args};

use regex::Regex;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite, BufReader};
use tokio::net::{tcp::ReadHalf, tcp::WriteHalf, TcpStream, TcpSocket};
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor, server::TlsStream};

const ERR_THRESHOLD: usize = 3;

#[derive(Clone)]
pub enum StreamState {
    Safe(Arc<Mutex<TlsStream<Stream>>>),
    Unsafe(Stream),
}

impl StreamState {
    pub fn is_tls(&self) -> bool {
        match self {
            StreamState::Safe(_) => true,
            StreamState::Unsafe(_) => false,
        }
    }
}

impl AsyncRead for StreamState {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamState::Safe(stream) => {
                let mut stream = stream.lock().unwrap();
                AsyncRead::poll_read(std::pin::Pin::new(&mut (*stream)) , cx, buf)
            },
            StreamState::Unsafe(stream) => {
                let mut stream = stream.clone();
                AsyncRead::poll_read(std::pin::Pin::new(&mut (stream)), cx, buf)
            }
        }
    }
}

impl AsyncWrite for StreamState {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            StreamState::Safe(stream) => {
                let mut stream = stream.lock().unwrap();
                AsyncWrite::poll_write(std::pin::Pin::new(&mut (*stream)), cx, buf)
            },
            StreamState::Unsafe(stream) => {
                let mut stream = stream.clone();
                AsyncWrite::poll_write(std::pin::Pin::new(&mut (stream)), cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamState::Safe(stream) => {
                let mut stream = stream.lock().unwrap();
                AsyncWrite::poll_flush(std::pin::Pin::new(&mut (*stream)), cx)
            },
            StreamState::Unsafe(stream) => {
                let mut stream = stream.clone();
                AsyncWrite::poll_flush(std::pin::Pin::new(&mut (stream)), cx)
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamState::Safe(stream) => {
                let mut stream = stream.lock().unwrap();
                AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut (*stream)), cx)
            },
            StreamState::Unsafe(stream) => {
                let mut stream = stream.clone();
                AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut (stream)), cx)
            }
        }
    }
}


pub struct Conn<B: Backend> {
    pub stream: StreamState,
    
    pub text: textproto::Conn<StreamState>, // Maybe Arc ?
    pub helo: String,
    pub err_count: usize,

    session: Arc<tokio::sync::Mutex<Option<B::S>>>,
    binarymime: bool,
    line_limit_reader: LineLimitReader<StreamState>,

    bdat_pipe: Option<io::DuplexStream>,
    data_result: Option<oneshot::Receiver<Result<()>>>,
    bytes_received: usize,

    from_received: bool,
    recipients: Vec<String>,
    did_auth: bool,
}

impl<B: Backend> Conn<B> {
    pub fn new(stream: TcpStream, max_line_length: usize) -> Self {
        let stream = StreamState::Unsafe(Stream(Arc::new(Mutex::new(stream))));

        return Conn {
            stream: stream.clone(),
            text: textproto::Conn::new(stream.clone()),
            helo: String::new(),
            err_count: 0,

            session: Arc::new(tokio::sync::Mutex::new(None)),
            binarymime: false,
            line_limit_reader: LineLimitReader::new(stream.clone(), max_line_length),
            
            bdat_pipe: None,
            data_result: None,
            bytes_received: 0,

            from_received: false,
            recipients: Vec::new(),
            did_auth: false,
        };
    }

    pub async fn handle(&mut self, cmd: String, arg: String, server: &mut Server<B>) {
        if cmd.is_empty() {
            self.protocol_error(500, [5,5,2], "Error: bad syntax".to_string()).await;
            return;
        }

        let cmd = cmd.to_uppercase();
        match cmd.as_str() {
            "SEND" | "SOML" | "SAML" | "EXPN" | "HELP" | "TURN" => {
                self.write_response(502, [5,5,1], &[&format!("{} command not implemented", cmd)]).await;
            }
            "HELO" | "EHLO" => {
                let enhanced = cmd == "EHLO";
                self.handle_greet(enhanced, arg, server).await;
            }
            "MAIL" => {
                self.handle_mail(arg, server).await;
            }
            "RCPT" => {
                self.handle_rcpt(arg, server).await;
            }
            "VRFY" => {
                self.write_response(252, [2,5,0], &["Cannot VRFY user, but will accept message"]).await;
            }
            "NOOP" => {
                self.write_response(250, [2,0,0], &["I have sucessfully done nothing"]).await;
            }
            "RSET" => {
                self.reset().await;
                self.write_response(250, [2,0,0], &["Session reset"]).await;
            }
            "BDAT" => {
                self.handle_bdat(arg, server).await;
            }
            "DATA" => {
                self.handle_data(arg, server).await;
            }
            "QUIT" => {
                self.write_response(221, [2,0,0], &["Bye"]).await;
                let _ = self.close().await;
            }
            "AUTH" => {
                self.protocol_error(500, [5,5,2], "Syntax error, AUTH command unrecognized".to_string()).await;
            }
            "STARTTLS" => {
                self.handle_starttls(server).await;
            }
            _ => {
                self.protocol_error(500, [5,5,2], format!("Syntax errors, {} command unrecognized", cmd)).await;
            }
        }
    }

    pub async fn protocol_error(&mut self, code: u16, ec: EnhancedCode, msg: String) {
        self.write_response(code, ec, &[&msg]).await;
        self.err_count += 1;
    }

    pub async fn close(&mut self) -> Result<()> {
        if let Some(pipe) = &mut self.bdat_pipe {
            let _ = pipe.shutdown().await;
            self.bdat_pipe = None;
        }
        self.bytes_received = 0;

        let mut session = self.session.lock().await;
        if session.is_some() {
            let _ = session.as_mut().unwrap().logout();
            drop(session);
            self.session = Arc::new(tokio::sync::Mutex::new(None));
        }

        Ok(())
    }

    pub fn hostname(&self) -> String {
        self.helo.clone()
    }

    pub async fn handle_greet(&mut self, enhanced: bool, arg: String, server: &mut Server<B>) {
        self.helo = arg;

        match server.backend.new_session() {
            Err(err) => {
                self.write_response(451, [4, 0, 0], &[&err.to_string()]).await;
                return;
            }
            Ok(sess) => {
                self.session = Arc::new(tokio::sync::Mutex::new(Some(sess)));
            }
        }

        if !enhanced {
            self.write_response(250, [2, 0, 0], &[&format!("Hello {}", self.helo)]).await;
            return;
        }

        let mut caps = server.caps.clone();

        // TODO auth_allowed

        if server.tls_acceptor.is_some() && !self.stream.is_tls() {
            caps.push("STARTTLS".to_string());
        }
        if server.enable_smtputf8 {
            caps.push("SMTPUTF8".to_string());
        }
        if server.enable_requiretls && self.stream.is_tls() {
            caps.push("REQUIRETLS".to_string());
        }
        if server.enable_binarymime {
            caps.push("BINARYMIME".to_string());
        }

        if server.max_message_bytes > 0 {
            caps.push(format!("SIZE {}", server.max_message_bytes));
        } else {
            caps.push("SIZE".to_string());
        }

        caps.insert(0, format!("Hello {}", self.helo));
        self.write_response(250, NO_ENHANCED_CODE, caps.iter().map(|s| s.as_str()).collect::<Vec<&str>>().as_slice()).await;
    }

    pub async fn handle_mail(&mut self, arg: String, server: &mut Server<B>) {
        if self.helo.len() == 0 {
            self.write_response(502, [2,5,1], &["Please introduce yourself first."]).await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.write_response(502, [5,5,1], &["MAIL not allowed during message transfer"]).await;
            return;
        }

        if arg.len() < 6 || arg[0..5].to_uppercase() != "FROM:" {
            self.write_response(501, [5,5,2], &["Was expecting MAIL arg syntax of FROM:<address>"]).await;
            return;
        }
        let from_args = arg[5..].trim().split(' ').collect::<Vec<&str>>();
        if server.strict {
            if !from_args[0].starts_with('<') || !from_args[0].ends_with('>') {
                self.write_response(501, [5,5,2], &["Was expecting MAIL arg syntax of FROM:<address>"]).await;
                return;
            }
        }
        if from_args.len() == 0 || from_args[0].len() < 3 {
            self.write_response(501, [5,5,2], &["Was expecting MAIL arg syntax of FROM:<address>"]).await;
            return;
        }
        let from = &from_args[0][1..from_args[0].len()-1];

        let mut opts = MailOptions::new();

        self.binarymime = false;

        if from_args.len() > 1 {
            let args = parse_args(&from_args[1..]);
            if args.is_err() {
                self.write_response(501, [5,5,4], &["Unable to parse MAIL ESMTP parameters"]).await;
                return;
            }
            
            for (key, value) in args.unwrap() {
                match key.as_str() {
                    "SIZE" => {
                        let size = value.parse::<usize>();
                        if size.is_err() {
                            self.write_response(501, [5,5,4], &["Unable to parse SIZE as an integer"]).await;
                            return;
                        }
                        let size = size.unwrap();

                        if server.max_message_bytes > 0 && size > server.max_message_bytes {
                            self.write_response(552, [5,3,4], &["Message size exceeds maximum message size"]).await;
                            return;
                        }

                        opts.size = size;
                    }

                    "SMTPUTF8" => {
                        if !server.enable_smtputf8 {
                            self.write_response(504, [5,5,4], &["SMTPUTF8 is not implemented"]).await;
                            return;
                        }
                        opts.utf8 = true;
                    }

                    "REQUIRETLS" => {
                        if !server.enable_requiretls {
                            self.write_response(504, [5,5,4], &["REQUIRETLS is not implemented"]).await;
                            return;
                        }
                        opts.require_tls = true;
                    }

                    "BODY" => {
                        match value.as_str() {
                            "BINARYMIME" => {
                                if !server.enable_binarymime {
                                    self.write_response(501, [5,5,4], &["BINARYMIME is not implemented"]).await;
                                    return;
                                }
                            }
                            "7BIT" | "8BITMIME"  => {}
                            _ => {
                                self.write_response(500, [5,5,4], &["Unknown BODY value"]).await;
                                return;
                            }
                        }
                        opts.body = value;
                    }

                    "AUTH" => {
                        let value = decode_xtext(value);
                        if value.is_err() {
                            self.write_response(500, [5,5,4], &["Malformed AUTH parameter value"]).await;
                            return;
                        }
                        let value = value.unwrap();
                        if !value.starts_with('<') {
                            self.write_response(500, [5,5,4], &["Missing opening angle bracket"]).await;
                            return;
                        }
                        if !value.ends_with('>') {
                            self.write_response(500, [5,5,4], &["Missing closing angle bracket"]).await;
                            return;
                        }
                        let decoded_mbox = value[1..value.len()-1].to_string();
                        opts.auth = decoded_mbox;
                    }

                    _ => {
                        self.write_response(500, [5,5,4], &["Unknown MAIL FROM argument"]).await;
                        return;
                    }
                }
            }
        }

        let mut guard = self.session.lock().await;
        if guard.is_none() {
            drop(guard);
            self.write_response(502, [5,5,1], &["Wrong sequence of commands"]).await;
            return;
        } else {
            if let Err(err) = guard.as_mut().unwrap().mail(from, &opts).await {
                drop(guard);
                self.write_response(451, [4,0,0], &[&err.to_string()]).await;
                return;
            }
        }

        drop(guard);
        self.write_response(250, [2,0,0], &["OK"]).await;
        self.from_received = true;
    }

    pub async fn reject(&mut self) {
        self.write_response(421, [4,4,5], &["Too busy. Try again later."]).await;
        let _ = self.close().await;
    }

    pub async fn greet(&mut self, domain: String) {
        self.write_response(220, NO_ENHANCED_CODE, &[&format!("{} ESMTP Service Ready", domain)]).await;
    }

    pub async fn write_response(&mut self, code: u16, mut ec: EnhancedCode, texts: &[&str]) {
        if ec == ENHANCED_CODE_NOT_SET {
            let cat = code / 100;
            match cat {
                2 | 4  | 5 => ec = [5, 5, 0],
                _ => ec = NO_ENHANCED_CODE,
            }
        }

        for text in texts {
                let _ = self.text.writer.print_line(&format!("{}-{}", code, text)).await;
            }
            if ec == NO_ENHANCED_CODE {
                let _ = self.text.writer.print_line(&format!("{} {}", code, texts.last().unwrap())).await;
            } else {
                let _ = self.text.writer.print_line(&format!("{} {}.{}.{} {}", code, ec[0], ec[1], ec[2], texts.last().unwrap())).await;
            }
    }

    // MAIL state -> waiting for RCPTs followed by DATA
    pub async fn handle_rcpt(&mut self, arg: String, server: &Server<B>) {
        let arg = arg.to_uppercase();
        if !self.from_received {
            self.write_response(502, [5,5,1], &["Missing MAIL FROM command"]).await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.write_response(502, [5,5,1], &["RCPT not allowed during message transfer"]).await;
            return;
        }

        if arg.len() < 4 || !arg.starts_with("TO:") {
            self.write_response(501, [5,5,2], &["Was expecting RCPT arg syntax of TO:<address>"]).await;
            return;
        }

        let recipient = arg[3..].trim_start_matches('<').trim_end_matches('>').trim().to_string();

        if server.max_recipients > 0 && self.recipients.len() >= server.max_recipients {
            self.write_response(552, [5,5,3], &[&format!("Too many recipients. Max is {}", server.max_recipients)]).await;
            return;
        }

        let mut guard = self.session.lock().await;

        if guard.is_none() {
            drop(guard);
            self.write_response(502, [5,5,1], &["Wrong sequence of commands"]).await;
            return;
        } else {
            if let Err(err) = guard.as_mut().unwrap().rcpt(&recipient).await {
                drop(guard);
                self.write_response(451, [4,0,0], &[&err.to_string()]).await;
                return;
            }
        }

        drop(guard);
        self.recipients.push(recipient);
        self.write_response(250, [2,0,0], &["OK"]).await;
    }

    // TODO handle_auth

    pub async fn handle_starttls(&mut self, server: &mut Server<B>) {
        if let StreamState::Unsafe(stream) = self.stream.clone() {
            if server.tls_acceptor.is_none() {
                self.write_response(502, [5,5,1], &["TLS not supported"]).await;
                return;
            }

            self.write_response(220, [2,0,0], &["Ready to start TLS"]).await;

            match server.tls_acceptor.as_ref().unwrap().accept(stream).await {
                Ok(conn) => {
                    self.stream = StreamState::Safe(Arc::new(Mutex::new(conn)));
                    
                    self.line_limit_reader = LineLimitReader::new(self.stream.clone(), server.max_line_length);
                    self.text = textproto::Conn::new(self.stream.clone());

                    if let Some(mut session) = self.session.lock().await.take() {
                        let _ = session.logout();
                    }

                    self.helo = "".to_string();
                    self.did_auth = false;
                    self.reset().await;
                }
                Err(err) => {
                    self.write_response(421, [4,4,5], &[&err.to_string()]).await;
                    let _ = self.close().await;
                    return;
                }
            };
        } else {
            self.write_response(502, [5,5,1], &["Already in TLS mode"]).await;
            return;
        }
    }

    pub async fn handle_data(&mut self, arg: String, server: &mut Server<B>) {
        if arg.len() > 0 {
            self.write_response(501, [5,5,4], &["DATA command should not have any arguments"]).await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.write_response(502, [5,5,1], &["DATA not allowed during message transfer"]).await;
            return;
        }
        if self.binarymime {
            self.write_response(502, [5,5,1], &["DATA not allowed for BINARYMIME messages"]).await;
            return;
        }
        if !self.from_received || self.recipients.is_empty() {
            self.write_response(502, [5,5,1], &["Missing RCPT TO command."]).await;
            return;
        }

        self.write_response(354, [2,0,0] , &["Go ahead. End your data with <CR><LF>.<CR><LF>"]).await;

        let mut r = DataReader::new::<B>(BufReader::new(self.text.conn.clone()), server.max_message_bytes);

        let res = self.session.lock().await.as_mut().unwrap().data(&mut r).await;

        r.limited = false;
        // Make sure all the data has been consumed and discarded
        let _ = r.read_to_end(&mut Vec::new()).await;

        if res.is_ok() {
            self.write_response(250, [2,0,0], &["OK"]).await;
        } else {
            self.write_response(554, [5,0,0], &[&res.err().unwrap().to_string()]).await;
        }

        self.reset().await;
    }

    pub async fn handle_bdat(&mut self, arg: String, server: &mut Server<B>) {
        let args: Vec<&str> = arg.split_whitespace().collect();
        if args.is_empty() {
            self.write_response(501, [5,5,4], &["Missing chunk size argument"]).await;
            return;
        }
        if args.len() > 2 {
            self.write_response(501, [5,5,4], &["Too many arguments"]).await;
            return;
        }

        if !self.from_received || self.recipients.is_empty() {
            self.write_response(502, [5,5,1], &["Missing RCPT TO command."]).await;
            return;
        }

        let mut last = false;
        if args.len() == 2 {
            if args[1].to_lowercase() != "last" {
                self.write_response(501, [5,5,4], &["Unknown BDAT argument"]).await;
                return;
            }
            last = true;
        }

        let size = match args[0].parse::<usize>() {
            Ok(size) => size,
            Err(_) => {
                self.write_response(501, [5,5,4], &["Malformed size argument"]).await;
                return;
            }
        };

        if server.max_message_bytes != 0 && self.bytes_received+size > server.max_message_bytes {
            self.write_response(552, [5,3,4], &["Max message size exceeded"]).await;

            let mut limit_reader = self.text.conn.clone().take(size as u64);
            let _ = io::copy(&mut limit_reader, &mut io::sink()).await;

            self.reset().await;
            return;
        }

        if self.bdat_pipe.is_none() {
            // create duplexstream pipe
            let (tx, rx) = io::duplex(1024);
            self.bdat_pipe = Some(tx);
            let session_clone = self.session.clone();

            let (one_tx, one_rx) = oneshot::channel();
            self.data_result = Some(one_rx);


            tokio::spawn(async move {
                let _ = one_tx.send(session_clone.lock().await.as_mut().unwrap().data(rx).await);
            });
        }

        self.line_limit_reader.line_limit = 0;

        let mut limit_reader = self.text.conn.clone().take(size as u64);
        let mut pipe = self.bdat_pipe.as_mut().unwrap();

        let res = io::copy(&mut limit_reader, &mut pipe).await;
        if let Err(err) = res {
            // discard the rest of the message
            let _ = io::copy(&mut self.text.conn.clone().take(u64::MAX), &mut io::sink()).await;

            self.write_response(554, [5,0,0], &[&err.to_string()]).await;

            self.reset().await;
            self.line_limit_reader.line_limit = server.max_line_length;
            return;
        }

        self.bytes_received += size;

        if last {
            self.line_limit_reader.line_limit = server.max_line_length;

            let _ = self.bdat_pipe.as_mut().unwrap().shutdown().await;

            if let Some(one_rx) = self.data_result.take() {
                let res = one_rx.await;
                if res.is_ok() {
                    self.write_response(250, [2,0,0], &["OK"]).await;
                } else {
                    self.write_response(554, [5,0,0], &[&res.err().unwrap().to_string()]).await;
                }
            }

            self.reset().await;
        } else {
            self.write_response(250, [2,0,0], &["Continue"]).await;
        }
    }

    pub async fn reset(&mut self) {
        if let Some(pipe) = self.bdat_pipe.as_mut() {
            let _ = pipe.shutdown().await;
            self.bdat_pipe = None;
        }
        self.bytes_received = 0;

        if let Some(session) = self.session.lock().await.as_mut() {
            session.reset();
        }

        self.from_received = false;
        self.recipients = Vec::new();
    }

}

fn decode_xtext(val: String) -> Result<String> {
    if !val.contains('+') {
        return Ok(val);
    }

    let hex_char_re = Regex::new(r"\+[0-9A-F]?[0-9A-F]?").unwrap();

    let mut replace_err = None;

    let mut decoded = val.clone();

    for re_match in hex_char_re.find_iter(&val) {
        let str_re_match = re_match.as_str();
        if str_re_match.len() != 3 {
            replace_err = Some(anyhow!("incomplete hexchar"));
            decoded.replace_range(re_match.range(), "");
        }
        let char = u8::from_str_radix(str_re_match, 16);
        if char.is_err() {
            replace_err = Some(anyhow!("invalid hexchar"));
            decoded.replace_range(re_match.range(), "");
        }
        decoded.replace_range(re_match.range(), &String::from_utf8(vec![char.unwrap()]).unwrap());
    }

    if replace_err.is_some() {
        return Err(replace_err.unwrap());
    }

    Ok(decoded)
}

fn encode_xtext(raw: String) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch == '+' || ch == '=' {
            out.push('+');
            out.push_str(&format!("{:02X}", ch as u8));
        }
        if ch > '!' && ch < '~' {
            out.push(ch);
        }
        // Non-ASCII
        out.push('+');
        out.push_str(&format!("{:02X}", ch as u8));
    }
    out
}

/*
func toSMTPStatus(err error) (code int, enchCode EnhancedCode, msg string) {
	if err != nil {
		if smtperr, ok := err.(*SMTPError); ok {
			return smtperr.Code, smtperr.EnhancedCode, smtperr.Message
		} else {
			return 554, EnhancedCode{5, 0, 0}, "Error: transaction failed, blame it on the weather: " + err.Error()
		}
	}

	return 250, EnhancedCode{2, 0, 0}, "OK: queued"
}
 */