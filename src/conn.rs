use anyhow::{anyhow, Result};
use base64::{
    engine::general_purpose,
    Engine as _,
};
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::backend::{Backend, MailOptions, Session};
use crate::data::{DataReader, EnhancedCode, ENHANCED_CODE_NOT_SET, NO_ENHANCED_CODE};
//use crate::lengthlimit_reader::LineLimitReader;
use crate::parse::parse_args;
use crate::server::Server;
use crate::stream::MyStream;
use crate::textproto::textproto;

use regex::Regex;

use tokio::io::{self, AsyncReadExt, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

//const ERR_THRESHOLD: usize = 3;

pub struct Conn<B: Backend> {
    pub stream: Arc<tokio::sync::Mutex<MyStream>>,

    pub text: textproto::Conn<MyStream>,
    pub helo: String,
    pub err_count: usize,

    pub session: Arc<tokio::sync::Mutex<Option<B::S>>>,
    binarymime: bool,
    //line_limit_reader: LineLimitReader<StreamState>,

    bdat_pipe: Option<io::DuplexStream>,
    data_result: Option<oneshot::Receiver<Result<()>>>,
    bytes_received: usize,

    from_received: bool,
    recipients: Vec<String>,
    did_auth: bool,
}

impl<B: Backend> Conn<B> {
    pub fn new(stream: TcpStream, max_line_length: usize) -> Self {
        let stream = Arc::new(tokio::sync::Mutex::new(MyStream::new(stream)));

        return Conn {
            stream: stream.clone(),
            text: textproto::Conn::new(stream.clone()),
            helo: String::new(),
            err_count: 0,

            session: Arc::new(tokio::sync::Mutex::new(None)),
            binarymime: false,
            //line_limit_reader: LineLimitReader::new(stream.clone(), max_line_length),

            bdat_pipe: None,
            data_result: None,
            bytes_received: 0,

            from_received: false,
            recipients: Vec::new(),
            did_auth: false,
        };
    }

    pub async fn handle(&mut self, cmd: String, arg: String, server: &Server<B>) {
        if cmd.is_empty() {
            self.protocol_error(500, [5, 5, 2], "Error: bad syntax".to_string())
                .await;
            return;
        }

        let cmd = cmd.to_uppercase();
        match cmd.as_str() {
            "SEND" | "SOML" | "SAML" | "EXPN" | "HELP" | "TURN" => {
                self.write_response(
                    502,
                    [5, 5, 1],
                    &[&format!("{} command not implemented", cmd)],
                )
                .await;
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
                self.write_response(
                    252,
                    [2, 5, 0],
                    &["Cannot VRFY user, but will accept message"],
                )
                .await;
            }
            "NOOP" => {
                self.write_response(250, [2, 0, 0], &["I have sucessfully done nothing"])
                    .await;
            }
            "RSET" => {
                self.reset().await;
                self.write_response(250, [2, 0, 0], &["Session reset"])
                    .await;
            }
            "BDAT" => {
                self.handle_bdat(arg, server).await;
            }
            "DATA" => {
                self.handle_data(arg, server).await;
            }
            "QUIT" => {
                self.write_response(221, [2, 0, 0], &["Bye"]).await;
                let _ = self.close().await;
            }
            "AUTH" => {
                if server.auth_disabled {
                    self.protocol_error(
                        500,
                        [5, 5, 2],
                        "Syntax error, AUTH command unrecognized".to_string(),
                    )
                    .await;
                } else {
                    println!("AUTH: {:?}", arg);
                    self.handle_auth(arg, server).await;
                }
            }
            "STARTTLS" => {
                self.handle_starttls(server).await;
            }
            _ => {
                self.protocol_error(
                    500,
                    [5, 5, 2],
                    format!("Syntax errors, {} command unrecognized", cmd),
                )
                .await;
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

        self.stream.lock().await.close().await
    }

    pub fn hostname(&self) -> String {
        self.helo.clone()
    }

    pub async fn auth_allowed(&self, server: &Server<B>) -> bool {
        !server.auth_disabled && (self.stream.lock().await.is_tls() || server.allow_insecure_auth)
    }

    pub async fn handle_greet(&mut self, enhanced: bool, arg: String, server: &Server<B>) {
        self.helo = arg;

        match server.backend.new_session(self) {
            Err(err) => {
                self.write_response(451, [4, 0, 0], &[&err.to_string()])
                    .await;
                return;
            }
            Ok(sess) => {
                self.session = Arc::new(tokio::sync::Mutex::new(Some(sess)));
            }
        }

        if !enhanced {
            self.write_response(250, [2, 0, 0], &[&format!("Hello {}", self.helo)])
                .await;
            return;
        }

        let mut caps = server.caps.clone();

        if server.tls_acceptor.is_some() && !self.stream.lock().await.is_tls() {
            caps.push("STARTTLS".to_string());
        }

        if self.auth_allowed(server).await {
            let mut auth_cap = "AUTH".to_string();
            for name in server.auths.keys() {
                auth_cap.push_str(" ");
                auth_cap.push_str(name);
            }

            caps.push(auth_cap);
        }
        if server.enable_smtputf8 {
            caps.push("SMTPUTF8".to_string());
        }
        if server.enable_requiretls && self.stream.lock().await.is_tls() {
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
        self.write_response(
            250,
            NO_ENHANCED_CODE,
            caps.iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
                .as_slice(),
        )
        .await;
    }

    pub async fn handle_mail(&mut self, arg: String, server: &Server<B>) {
        if self.helo.len() == 0 {
            self.write_response(502, [2, 5, 1], &["Please introduce yourself first."])
                .await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.write_response(
                502,
                [5, 5, 1],
                &["MAIL not allowed during message transfer"],
            )
            .await;
            return;
        }

        if arg.len() < 6 || arg[0..5].to_uppercase() != "FROM:" {
            self.write_response(
                501,
                [5, 5, 2],
                &["Was expecting MAIL arg syntax of FROM:<address>"],
            )
            .await;
            return;
        }
        let from_args = arg[5..].trim().split(' ').collect::<Vec<&str>>();
        if server.strict {
            if !from_args[0].starts_with('<') || !from_args[0].ends_with('>') {
                self.write_response(
                    501,
                    [5, 5, 2],
                    &["Was expecting MAIL arg syntax of FROM:<address>"],
                )
                .await;
                return;
            }
        }
        if from_args.len() == 0 || from_args[0].len() < 3 {
            self.write_response(
                501,
                [5, 5, 2],
                &["Was expecting MAIL arg syntax of FROM:<address>"],
            )
            .await;
            return;
        }
        let from = &from_args[0][1..from_args[0].len() - 1];

        let mut opts = MailOptions::new();

        self.binarymime = false;

        if from_args.len() > 1 {
            let args = parse_args(&from_args[1..]);
            if args.is_err() {
                self.write_response(501, [5, 5, 4], &["Unable to parse MAIL ESMTP parameters"])
                    .await;
                return;
            }

            for (key, value) in args.unwrap() {
                match key.as_str() {
                    "SIZE" => {
                        let size = value.parse::<usize>();
                        if size.is_err() {
                            self.write_response(
                                501,
                                [5, 5, 4],
                                &["Unable to parse SIZE as an integer"],
                            )
                            .await;
                            return;
                        }
                        let size = size.unwrap();

                        if server.max_message_bytes > 0 && size > server.max_message_bytes {
                            self.write_response(
                                552,
                                [5, 3, 4],
                                &["Message size exceeds maximum message size"],
                            )
                            .await;
                            return;
                        }

                        opts.size = size;
                    }

                    "SMTPUTF8" => {
                        if !server.enable_smtputf8 {
                            self.write_response(504, [5, 5, 4], &["SMTPUTF8 is not implemented"])
                                .await;
                            return;
                        }
                        opts.utf8 = true;
                    }

                    "REQUIRETLS" => {
                        if !server.enable_requiretls {
                            self.write_response(504, [5, 5, 4], &["REQUIRETLS is not implemented"])
                                .await;
                            return;
                        }
                        opts.require_tls = true;
                    }

                    "BODY" => {
                        match value.as_str() {
                            "BINARYMIME" => {
                                if !server.enable_binarymime {
                                    self.write_response(
                                        501,
                                        [5, 5, 4],
                                        &["BINARYMIME is not implemented"],
                                    )
                                    .await;
                                    return;
                                }
                            }
                            "7BIT" | "8BITMIME" => {}
                            _ => {
                                self.write_response(500, [5, 5, 4], &["Unknown BODY value"])
                                    .await;
                                return;
                            }
                        }
                        opts.body = value;
                    }

                    "AUTH" => {
                        let value = decode_xtext(value);
                        if value.is_err() {
                            self.write_response(
                                500,
                                [5, 5, 4],
                                &["Malformed AUTH parameter value"],
                            )
                            .await;
                            return;
                        }
                        let value = value.unwrap();
                        if !value.starts_with('<') {
                            self.write_response(500, [5, 5, 4], &["Missing opening angle bracket"])
                                .await;
                            return;
                        }
                        if !value.ends_with('>') {
                            self.write_response(500, [5, 5, 4], &["Missing closing angle bracket"])
                                .await;
                            return;
                        }
                        let decoded_mbox = value[1..value.len() - 1].to_string();
                        opts.auth = decoded_mbox;
                    }

                    _ => {
                        self.write_response(500, [5, 5, 4], &["Unknown MAIL FROM argument"])
                            .await;
                        return;
                    }
                }
            }
        }

        let mut guard = self.session.lock().await;
        if guard.is_none() {
            drop(guard);
            self.write_response(502, [5, 5, 1], &["Wrong sequence of commands"])
                .await;
            return;
        } else {
            if let Err(err) = guard.as_mut().unwrap().mail(from, &opts).await {
                drop(guard);
                self.write_response(451, [4, 0, 0], &[&err.to_string()])
                    .await;
                return;
            }
        }

        drop(guard);
        self.write_response(250, [2, 0, 0], &["OK"]).await;
        self.from_received = true;
    }

    pub async fn reject(&mut self) {
        self.write_response(421, [4, 4, 5], &["Too busy. Try again later."])
            .await;
        let _ = self.close().await;
    }

    pub async fn greet(&mut self, domain: String) {
        self.write_response(
            220,
            NO_ENHANCED_CODE,
            &[&format!("{} ESMTP Service Ready", domain)],
        )
        .await;
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
            let _ = self
                .text
                .writer
                .print_line(&format!("{}-{}", code, text))
                .await;
        }
        if ec == NO_ENHANCED_CODE {
            let _ = self
                .text
                .writer
                .print_line(&format!("{} {}", code, texts.last().unwrap()))
                .await;
        } else {
            let _ = self
                .text
                .writer
                .print_line(&format!(
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

    pub async fn read_line(&mut self, server: &Server<B>) -> Result<String> {
        let mut line = String::new();
        timeout(server.read_timeout, BufReader::new(Pin::new(self.stream.lock().await)).read_line(&mut line)).await?;
        Ok(line)
    }

    // MAIL state -> waiting for RCPTs followed by DATA
    pub async fn handle_rcpt(&mut self, arg: String, server: &Server<B>) {
        let arg = arg.to_uppercase();
        if !self.from_received {
            self.write_response(502, [5, 5, 1], &["Missing MAIL FROM command"])
                .await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.write_response(
                502,
                [5, 5, 1],
                &["RCPT not allowed during message transfer"],
            )
            .await;
            return;
        }

        if arg.len() < 4 || !arg.starts_with("TO:") {
            self.write_response(
                501,
                [5, 5, 2],
                &["Was expecting RCPT arg syntax of TO:<address>"],
            )
            .await;
            return;
        }

        let recipient = arg[3..]
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim()
            .to_string();

        if server.max_recipients > 0 && self.recipients.len() >= server.max_recipients {
            self.write_response(
                552,
                [5, 5, 3],
                &[&format!(
                    "Too many recipients. Max is {}",
                    server.max_recipients
                )],
            )
            .await;
            return;
        }

        let mut guard = self.session.lock().await;
        if guard.is_none() {
            drop(guard);
            self.write_response(502, [5, 5, 1], &["Wrong sequence of commands"])
                .await;
            return;
        } else {
            if let Err(err) = guard.as_mut().unwrap().rcpt(&recipient).await {
                drop(guard);
                self.write_response(451, [4, 0, 0], &[&err.to_string()])
                    .await;
                return;
            }
        }
        drop(guard);

        self.recipients.push(recipient);
        self.write_response(250, [2, 0, 0], &["OK"]).await;
    }

    pub async fn handle_auth(&mut self, arg: String, server: &Server<B>) {
        if self.helo.is_empty() {
            self.write_response(502, [5, 5, 1], &["Please introduce yourself first."])
                .await;
            return;
        }
        if self.did_auth {
            self.write_response(503, [5, 5, 1], &["Already authenticated."])
                .await;
            return;
        }

        let parts: Vec<&str> = arg.split_whitespace().collect();
        if parts.is_empty() {
            self.write_response(502, [5, 5, 4], &["Missing parameter"])
                .await;
            return;
        }

        if !self.stream.lock().await.is_tls() && !server.allow_insecure_auth {
            self.write_response(502, [5, 5, 1], &["TLS is required"])
                .await;
            return;
        }

        let mechanism = parts[0].to_uppercase();

        // Parse client initial response if there is one
        let mut ir = Vec::new();
        if parts.len() > 1 {
            let res = general_purpose::STANDARD.decode(parts[1]);
            if res.is_err() {
                return;
            } else {
                ir = res.unwrap();
            }
        }

        let new_sasl = server.auths.get(&mechanism);
        if new_sasl.is_none() {
            self.write_response(504, [5, 7, 4], &["Unsupported authentication mechanism"])
                .await;
            return;
        }

        let mut sasl = (new_sasl.unwrap())(self);

        let mut response = ir;
        loop {
            let res = sasl.next(Some(&response));
            if let Err(err) = res {
                self.write_response(454, [4, 7, 0], &[&err.to_string()])
                    .await;
                return;
            }
            let (challenge, done) = res.unwrap();

            if done {
                break;
            }

            let mut encoded = "".to_string();
            if !challenge.is_empty() {
                encoded = general_purpose::STANDARD.encode(&challenge);
            }

            self.write_response(334, NO_ENHANCED_CODE, &[&encoded]).await;

            let res = self.read_line(server).await;
            if res.is_err() {
                return; // TODO: error handling
            }
            let encoded = res.unwrap();

            if encoded == "*" {
                // https://tools.ietf.org/html/rfc4954#page-4
                self.write_response(501, [5, 0, 0], &["Negotiation cancelled"]).await;
                return;
            }

            let res = general_purpose::STANDARD.decode(&encoded);
            if res.is_err() {
                self.write_response(454, [4, 7, 0], &["Invalid base64 data"]).await;
                return;
            }
            response = res.unwrap();
        }

        self.write_response(235, [2,0,0], &["Authentication succeeded"]).await;
        self.did_auth = true;
    }

    pub async fn handle_starttls(&mut self, server: &Server<B>) {
        if self.stream.lock().await.is_tls() {
            self.write_response(502, [5, 5, 1], &["Already in TLS mode"]).await;
            return;
        }

        if server.tls_acceptor.is_none() {
            self.write_response(502, [5, 5, 1], &["TLS not supported"]).await;
            return;
        }
        let tls_acceptor = server.tls_acceptor.as_ref().unwrap();

        self.write_response(220, [2, 0, 0], &["Ready to start TLS"]).await;

        if self.stream.lock().await.unsafe_stream.is_none() {
            self.write_response(550, [5, 0, 0], &["Handshake error"]).await;
            return;
        }

        let mut guard = self.stream.lock().await;
        if let Err(_) = guard.starttls(server.tls_acceptor.clone().unwrap()).await {
            drop(guard);
            self.write_response(550, [5, 0, 0], &["Handshake error"]).await;
            return;
        }
        drop(guard);

        if let Some(mut session) = self.session.lock().await.take() {
            let _ = session.logout();
        }

        self.helo = "".to_string();
        self.did_auth = false;
        self.reset().await;
    }

    pub async fn handle_data(&mut self, arg: String, server: &Server<B>) {
        if arg.len() > 0 {
            self.write_response(
                501,
                [5, 5, 4],
                &["DATA command should not have any arguments"],
            )
            .await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.write_response(
                502,
                [5, 5, 1],
                &["DATA not allowed during message transfer"],
            )
            .await;
            return;
        }
        if self.binarymime {
            self.write_response(
                502,
                [5, 5, 1],
                &["DATA not allowed for BINARYMIME messages"],
            )
            .await;
            return;
        }
        if !self.from_received || self.recipients.is_empty() {
            self.write_response(502, [5, 5, 1], &["Missing RCPT TO command."])
                .await;
            return;
        }

        self.write_response(
            354,
            [2, 0, 0],
            &["Go ahead. End your data with <CR><LF>.<CR><LF>"],
        )
        .await;

        let mut r = DataReader::new::<B>(
            Pin::new(self.stream.lock().await),
            server.max_message_bytes,
        );

        let res = self
            .session
            .lock()
            .await
            .as_mut()
            .unwrap()
            .data(&mut r)
            .await;

        r.limited = false;
        // Make sure all the data has been consumed and discarded
        let _ = r.read_to_end(&mut Vec::new()).await;

        drop(r);

        if res.is_ok() {
            self.write_response(250, [2, 0, 0], &["OK"]).await;
        } else {
            self.write_response(554, [5, 0, 0], &[&res.err().unwrap().to_string()])
                .await;
        }

        self.reset().await;
    }

    pub async fn handle_bdat(&mut self, arg: String, server: &Server<B>) {
        let args: Vec<&str> = arg.split_whitespace().collect();
        if args.is_empty() {
            self.write_response(501, [5, 5, 4], &["Missing chunk size argument"])
                .await;
            return;
        }
        if args.len() > 2 {
            self.write_response(501, [5, 5, 4], &["Too many arguments"])
                .await;
            return;
        }

        if !self.from_received || self.recipients.is_empty() {
            self.write_response(502, [5, 5, 1], &["Missing RCPT TO command."])
                .await;
            return;
        }

        let mut last = false;
        if args.len() == 2 {
            if args[1].to_lowercase() != "last" {
                self.write_response(501, [5, 5, 4], &["Unknown BDAT argument"])
                    .await;
                return;
            }
            last = true;
        }

        let size = match args[0].parse::<usize>() {
            Ok(size) => size,
            Err(_) => {
                self.write_response(501, [5, 5, 4], &["Malformed size argument"])
                    .await;
                return;
            }
        };

        if server.max_message_bytes != 0 && self.bytes_received + size > server.max_message_bytes {
            self.write_response(552, [5, 3, 4], &["Max message size exceeded"])
                .await;

            let _ = self.stream.lock().await.read_to_end(&mut Vec::new()).await;

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

            let session_clone = self.session.clone();

            tokio::spawn(async move {
                let _ = one_tx.send(session_clone.lock().await.as_mut().unwrap().data(rx).await);
            });
        }

        //self.line_limit_reader.line_limit = 0;

        //let mut limit_reader = self.text.conn.clone().take(size as u64);
        let mut pipe = self.bdat_pipe.as_mut().unwrap();

        let res = io::copy(&mut Pin::new(self.stream.lock().await), &mut pipe).await;
        if let Err(err) = res {
            // discard the rest of the message
            let _ = io::copy(&mut Pin::new(self.stream.lock().await), &mut io::sink()).await;

            self.write_response(554, [5, 0, 0], &[&err.to_string()])
                .await;

            self.reset().await;
            //self.line_limit_reader.line_limit = server.max_line_length;
            return;
        }

        self.bytes_received += size;

        if last {
            //self.line_limit_reader.line_limit = server.max_line_length;

            let _ = self.bdat_pipe.as_mut().unwrap().shutdown().await;

            if let Some(one_rx) = self.data_result.take() {
                let res = one_rx.await;
                if res.is_ok() {
                    self.write_response(250, [2, 0, 0], &["OK"]).await;
                } else {
                    self.write_response(554, [5, 0, 0], &[&res.err().unwrap().to_string()])
                        .await;
                }
            }

            self.reset().await;
        } else {
            self.write_response(250, [2, 0, 0], &["Continue"]).await;
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
        decoded.replace_range(
            re_match.range(),
            &String::from_utf8(vec![char.unwrap()]).unwrap(),
        );
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
