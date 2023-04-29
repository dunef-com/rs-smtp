use std::collections::HashMap;

use anyhow::{anyhow, Result};
use base64::{
    engine::general_purpose,
    Engine as _,
};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::backend::{Backend, MailOptions, Session};
use crate::data::{DataReader, EnhancedCode, NO_ENHANCED_CODE};
//use crate::lengthlimit_reader::LineLimitReader;
use crate::parse::parse_args;
use crate::sasl;
use crate::server::Server;
use crate::stream::MyStream;

use regex::Regex;

use tokio::io::{self, BufReader, AsyncWriteExt, AsyncReadExt, AsyncBufReadExt};
use tokio::net::TcpStream;

//const ERR_THRESHOLD: usize = 3;

pub struct Conn<B: Backend> {
    pub stream: BufReader<MyStream>,

    //pub text: textproto::Conn<MyStream>,
    pub helo: String,
    pub err_count: usize,

    pub session: Option<B::S>,
    binarymime: bool,
    //line_limit_reader: LineLimitReader<StreamState>,

    bdat_pipe: Option<io::DuplexStream>,
    data_result: Option<JoinHandle<(Result<()>, B::S)>>,
    bytes_received: usize,

    from_received: bool,
    recipients: Vec<String>,
    did_auth: bool,

    auths: HashMap<String, Box<dyn sasl::Server>>,
}

impl<B: Backend> Conn<B> {
    pub fn new(stream: TcpStream, _max_line_length: usize) -> Self {
        return Conn {
            stream: BufReader::new(MyStream::new(stream)),
            //text: textproto::Conn::new(stream.clone()),
            helo: String::new(),
            err_count: 0,

            session: None,
            binarymime: false,
            //line_limit_reader: LineLimitReader::new(stream.clone(), max_line_length),

            bdat_pipe: None,
            data_result: None,
            bytes_received: 0,

            from_received: false,
            recipients: Vec::new(),
            did_auth: false,

            auths: HashMap::new(),
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
                self.stream.get_mut().write_response(
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
                self.stream.get_mut().write_response(
                    252,
                    [2, 5, 0],
                    &["Cannot VRFY user, but will accept message"],
                )
                .await;
            }
            "NOOP" => {
                self.stream.get_mut().write_response(250, [2, 0, 0], &["I have sucessfully done nothing"])
                    .await;
            }
            "RSET" => {
                self.reset().await;
                self.stream.get_mut().write_response(250, [2, 0, 0], &["Session reset"])
                    .await;
            }
            "BDAT" => {
                self.handle_bdat(arg, server).await;
            }
            "DATA" => {
                self.handle_data(arg, server).await;
            }
            "QUIT" => {
                self.stream.get_mut().write_response(221, [2, 0, 0], &["Bye"]).await;
                match self.close().await {
                    Ok(_) => {
                        println!("Connection successfully closed");
                    }
                    Err(e) => {
                        println!("Error closing connection: {}", e);
                    }
                }
            }
            "AUTH" => {
                if self.auths.is_empty() {
                    self.protocol_error(
                        500,
                        [5, 5, 2],
                        "Syntax error, AUTH command unrecognized".to_string(),
                    )
                    .await;
                } else {
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
        self.stream.get_mut().write_response(code, ec, &[&msg]).await;
        self.err_count += 1;
    }

    pub async fn close(&mut self) -> Result<()> {

        if let Some(mut session) = self.session.take() {
            let _ = session.logout();
        }

        let _ = self.stream.get_mut().close().await;

        if let Some(pipe) = &mut self.bdat_pipe.take() {
            let _ = pipe.shutdown().await;
        }
        self.bytes_received = 0;

        Ok(())
    }

    pub fn hostname(&self) -> String {
        self.helo.clone()
    }

    pub fn auth_allowed(&self, server: &Server<B>) -> bool {
        !self.auths.is_empty() && (self.stream.get_ref().is_tls() || server.allow_insecure_auth)
    }

    pub async fn handle_greet(&mut self, enhanced: bool, arg: String, server: &Server<B>) {
        self.helo = arg;

        match server.backend.new_session(self) {
            Err(err) => {
                self.stream.get_mut().write_response(451, [4, 0, 0], &[&err.to_string()])
                    .await;
                return;
            }
            Ok(mut sess) => {
                self.auths = sess.authenticators()
                    .into_iter()
                    .map(|a| (a.mechanism().to_string(), a))
                    .collect();

                self.session = Some(sess);
            }
        }

        if !enhanced {
            self.stream.get_mut().write_response(250, [2, 0, 0], &[&format!("Hello {}", self.helo)])
                .await;
            return;
        }

        let mut caps = server.caps.clone();

        if server.tls_acceptor.is_some() && !self.stream.get_ref().is_tls() {
            caps.push("STARTTLS".to_string());
        }

        if self.auth_allowed(server) {
            let mut auth_cap = "AUTH".to_string();
            for name in self.auths.keys() {
                auth_cap.push_str(" ");
                auth_cap.push_str(name);
            }

            caps.push(auth_cap);
        }
        if server.enable_smtputf8 {
            caps.push("SMTPUTF8".to_string());
        }
        if server.enable_requiretls && self.stream.get_ref().is_tls() {
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
        self.stream.get_mut().write_response(
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
            self.stream.get_mut().write_response(502, [2, 5, 1], &["Please introduce yourself first."])
                .await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.stream.get_mut().write_response(
                502,
                [5, 5, 1],
                &["MAIL not allowed during message transfer"],
            )
            .await;
            return;
        }

        if arg.len() < 6 || arg[0..5].to_uppercase() != "FROM:" {
            self.stream.get_mut().write_response(
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
                self.stream.get_mut().write_response(
                    501,
                    [5, 5, 2],
                    &["Was expecting MAIL arg syntax of FROM:<address>"],
                )
                .await;
                return;
            }
        }
        if from_args.len() == 0 || from_args[0].len() < 3 {
            self.stream.get_mut().write_response(
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
                self.stream.get_mut().write_response(501, [5, 5, 4], &["Unable to parse MAIL ESMTP parameters"])
                    .await;
                return;
            }

            for (key, value) in args.unwrap() {
                match key.as_str() {
                    "SIZE" => {
                        let size = value.parse::<usize>();
                        if size.is_err() {
                            self.stream.get_mut().write_response(
                                501,
                                [5, 5, 4],
                                &["Unable to parse SIZE as an integer"],
                            )
                            .await;
                            return;
                        }
                        let size = size.unwrap();

                        if server.max_message_bytes > 0 && size > server.max_message_bytes {
                            self.stream.get_mut().write_response(
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
                            self.stream.get_mut().write_response(504, [5, 5, 4], &["SMTPUTF8 is not implemented"])
                                .await;
                            return;
                        }
                        opts.utf8 = true;
                    }

                    "REQUIRETLS" => {
                        if !server.enable_requiretls {
                            self.stream.get_mut().write_response(504, [5, 5, 4], &["REQUIRETLS is not implemented"])
                                .await;
                            return;
                        }
                        opts.require_tls = true;
                    }

                    "BODY" => {
                        match value.as_str() {
                            "BINARYMIME" => {
                                if !server.enable_binarymime {
                                    self.stream.get_mut().write_response(
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
                                self.stream.get_mut().write_response(500, [5, 5, 4], &["Unknown BODY value"])
                                    .await;
                                return;
                            }
                        }
                        opts.body = value;
                    }

                    "AUTH" => {
                        let value = decode_xtext(value);
                        if value.is_err() {
                            self.stream.get_mut().write_response(
                                500,
                                [5, 5, 4],
                                &["Malformed AUTH parameter value"],
                            )
                            .await;
                            return;
                        }
                        let value = value.unwrap();
                        if !value.starts_with('<') {
                            self.stream.get_mut().write_response(500, [5, 5, 4], &["Missing opening angle bracket"])
                                .await;
                            return;
                        }
                        if !value.ends_with('>') {
                            self.stream.get_mut().write_response(500, [5, 5, 4], &["Missing closing angle bracket"])
                                .await;
                            return;
                        }
                        let decoded_mbox = value[1..value.len() - 1].to_string();
                        opts.auth = decoded_mbox;
                    }

                    _ => {
                        self.stream.get_mut().write_response(500, [5, 5, 4], &["Unknown MAIL FROM argument"])
                            .await;
                        return;
                    }
                }
            }
        }

        if self.session.is_none() {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["Wrong sequence of commands"])
                .await;
            return;
        } else {
            if let Err(err) = self.session.as_mut().unwrap().mail(from, &opts).await {
                self.stream.get_mut().write_response(451, [4, 0, 0], &[&err.to_string()])
                    .await;
                return;
            }
        }
        self.stream.get_mut().write_response(250, [2, 0, 0], &["OK"]).await;
        self.from_received = true;
    }

    pub async fn reject(&mut self) {
        self.stream.get_mut().write_response(421, [4, 4, 5], &["Too busy. Try again later."])
            .await;
        let _ = self.close().await;
    }

    pub async fn greet(&mut self, domain: String) {
        self.stream.get_mut().write_response(
            220,
            NO_ENHANCED_CODE,
            &[&format!("{} ESMTP Service Ready", domain)],
        )
        .await;
    }

    pub async fn read_line(&mut self, mut line: &mut String, server: &Server<B>) -> Result<usize> {
        let res = timeout(server.read_timeout, self.stream.read_line(&mut line)).await?;
        res.map_err(|e| anyhow!(e))
    }

    // MAIL state -> waiting for RCPTs followed by DATA
    pub async fn handle_rcpt(&mut self, arg: String, server: &Server<B>) {
        let arg = arg.to_uppercase();
        if !self.from_received {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["Missing MAIL FROM command"])
                .await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.stream.get_mut().write_response(
                502,
                [5, 5, 1],
                &["RCPT not allowed during message transfer"],
            )
            .await;
            return;
        }

        if arg.len() < 4 || !arg.starts_with("TO:") {
            self.stream.get_mut().write_response(
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
            .to_lowercase();

        if server.max_recipients > 0 && self.recipients.len() >= server.max_recipients {
            self.stream.get_mut().write_response(
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

        if self.session.is_none() {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["Wrong sequence of commands"])
                .await;
            return;
        } else {
            if let Err(err) = self.session.as_mut().unwrap().rcpt(&recipient).await {
                self.stream.get_mut().write_response(451, [4, 0, 0], &[&err.to_string()])
                    .await;
                return;
            }
        }

        self.recipients.push(recipient);
        self.stream.get_mut().write_response(250, [2, 0, 0], &["OK"]).await;
    }

    pub async fn handle_auth(&mut self, arg: String, server: &Server<B>) {
        if self.auths.is_empty() {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["Authentication disabled"])
                .await;
            return;
        }

        if self.helo.is_empty() {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["Please introduce yourself first."])
                .await;
            return;
        }
        if self.did_auth {
            self.stream.get_mut().write_response(503, [5, 5, 1], &["Already authenticated."])
                .await;
            return;
        }

        let parts: Vec<&str> = arg.split_whitespace().collect();
        if parts.is_empty() {
            self.stream.get_mut().write_response(502, [5, 5, 4], &["Missing parameter"])
                .await;
            return;
        }

        if !self.stream.get_ref().is_tls() && !server.allow_insecure_auth {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["TLS is required"])
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

        if !self.auths.contains_key(&mechanism) {
            self.stream.get_mut().write_response(504, [5, 7, 4], &["Unsupported authentication mechanism"])
                .await;
            return;
        }
        let sasl = self.auths.get_mut(&mechanism).unwrap();

        let mut response = ir;
        loop {
            let res = sasl.next(Some(&response)).await;
            if let Err(err) = res {
                self.stream.get_mut().write_response(454, [4, 7, 0], &[&err.to_string()])
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

            self.stream.get_mut().write_response(334, NO_ENHANCED_CODE, &[&encoded]).await;

            let encoded = &mut String::new();
            let res = timeout(server.read_timeout, self.stream.read_line(encoded)).await;
            if res.is_err() {
                self.stream.get_mut().write_response(454, [4, 7, 0], &["Read timeout"]).await;
                return;
            }
            let res = res.unwrap();
            if res.is_err() {
                self.stream.get_mut().write_response(454, [4, 7, 0], &["Read error"]).await;
                return;
            }
            let encoded = encoded.trim_end();

            if encoded == "*" {
                // https://tools.ietf.org/html/rfc4954#page-4
                self.stream.get_mut().write_response(501, [5, 0, 0], &["Negotiation cancelled"]).await;
                return;
            }

            let res = general_purpose::STANDARD.decode(&encoded);
            if res.is_err() {
                self.stream.get_mut().write_response(454, [4, 7, 0], &["Invalid base64 data"]).await;
                return;
            }
            response = res.unwrap();
        }

        self.stream.get_mut().write_response(235, [2,0,0], &["Authentication succeeded"]).await;
        self.did_auth = true;
    }

    pub async fn handle_starttls(&mut self, server: &Server<B>) {
        if self.stream.get_ref().is_tls() {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["Already in TLS mode"]).await;
            return;
        }

        if server.tls_acceptor.is_none() {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["TLS not supported"]).await;
            return;
        }

        self.stream.get_mut().write_response(220, [2, 0, 0], &["Ready to start TLS"]).await;

        if self.stream.get_ref().unsafe_stream.is_none() {
            self.stream.get_mut().write_response(550, [5, 0, 0], &["Handshake error"]).await;
            return;
        }

        if let Err(_) = self.stream.get_mut().starttls(server.tls_acceptor.clone().unwrap()).await {
            self.stream.get_mut().write_response(550, [5, 0, 0], &["Handshake error"]).await;
            return;
        }

        if let Some(mut session) = self.session.take() {
            let _ = session.logout();
        }

        self.helo = "".to_string();
        self.did_auth = false;
        self.reset().await;
    }

    pub async fn handle_data(&mut self, arg: String, server: &Server<B>) {
        if arg.len() > 0 {
            self.stream.get_mut().write_response(
                501,
                [5, 5, 4],
                &["DATA command should not have any arguments"],
            )
            .await;
            return;
        }
        if self.bdat_pipe.is_some() {
            self.stream.get_mut().write_response(
                502,
                [5, 5, 1],
                &["DATA not allowed during message transfer"],
            )
            .await;
            return;
        }
        if self.binarymime {
            self.stream.get_mut().write_response(
                502,
                [5, 5, 1],
                &["DATA not allowed for BINARYMIME messages"],
            )
            .await;
            return;
        }
        if !self.from_received || self.recipients.is_empty() {
            self.stream.get_mut().write_response(502, [5, 5, 1], &["Missing RCPT TO command."])
                .await;
            return;
        }

        self.stream.get_mut().write_response(
            354,
            [2, 0, 0],
            &["Go ahead. End your data with <CR><LF>.<CR><LF>"],
        )
        .await;

        let mut r = DataReader::new(
            &mut self.stream,
            server.max_message_bytes,
        );

        let res = self
            .session
            .as_mut()
            .unwrap()
            .data(&mut r)
            .await;

        r.limited = false;
        // Make sure all the data has been consumed and discarded
        //let _ = r.read_to_end(&mut Vec::new()).await;

        drop(r);

        if res.is_ok() {
            self.stream.get_mut().write_response(250, [2, 0, 0], &["OK"]).await;
        } else {
            self.stream.get_mut().write_response(554, [5, 0, 0], &[&res.err().unwrap().to_string()])
                .await;
        }

        self.reset().await;
    }

    pub async fn handle_bdat(&mut self, arg: String, server: &Server<B>) {
        let args: Vec<&str> = arg.split_whitespace().collect();
        if args.is_empty() {
            println!("Missing chunk size argument");
            self.stream.get_mut().write_response(501, [5, 5, 4], &["Missing chunk size argument"])
                .await;
            return;
        }
        if args.len() > 2 {
            println!("Too many arguments");
            self.stream.get_mut().write_response(501, [5, 5, 4], &["Too many arguments"])
                .await;
            return;
        }

        if !self.from_received || self.recipients.is_empty() {
            println!("Missing RCPT TO command");
            self.stream.get_mut().write_response(502, [5, 5, 1], &["Missing RCPT TO command."])
                .await;
            return;
        }

        let mut last = false;
        if args.len() == 2 {
            if args[1].to_lowercase() != "last" {
                println!("Unknown BDAT argument");
                self.stream.get_mut().write_response(501, [5, 5, 4], &["Unknown BDAT argument"])
                    .await;
                return;
            }
            last = true;
        }

        let size = match args[0].parse::<usize>() {
            Ok(size) => size,
            Err(_) => {
                println!("Malformed size argument");
                self.stream.get_mut().write_response(501, [5, 5, 4], &["Malformed size argument"])
                    .await;
                return;
            }
        };

        if server.max_message_bytes != 0 && self.bytes_received + size > server.max_message_bytes {
            println!("Max message size exceeded");
            self.stream.get_mut().write_response(552, [5, 3, 4], &["Max message size exceeded"])
                .await;

            let _ = self.stream.get_mut().read_to_end(&mut Vec::new()).await;

            self.reset().await;
            return;
        }

        if self.bdat_pipe.is_none() {
            // create duplexstream pipe
            let (tx, rx) = io::duplex(size);
            self.bdat_pipe = Some(tx);

            //let fut = self.session.as_mut().unwrap().data(rx);

            let mut session = self.session.take().unwrap();

            self.data_result = Some(tokio::spawn(async move {
                let res = session.data(rx).await;

                return (res, session);
            }));
        }

        //self.line_limit_reader.line_limit = 0;

        //let mut limit_reader = self.text.conn.clone().take(size as u64);
        let mut pipe = self.bdat_pipe.as_mut().unwrap();

        let mut buf = vec![0; size];

        println!("I'm about to read {} bytes", size);

        self.stream.read_exact(&mut buf).await.unwrap();

        let res = io::copy(&mut (&buf[..]), &mut pipe).await;
        if let Err(err) = res {
            // discard the rest of the message
            let _ = io::copy(&mut self.stream, &mut io::sink()).await;

            self.stream.get_mut().write_response(554, [5, 0, 0], &[&err.to_string()])
                .await;

            self.reset().await;
            //self.line_limit_reader.line_limit = server.max_line_length;
            return;
        }

        self.bytes_received += size;

        if last {
            //self.line_limit_reader.line_limit = server.max_line_length;

            let _ = self.bdat_pipe.as_mut().unwrap().shutdown().await;

            if let Some(join_handle) = self.data_result.take() {
                let (res, session) = join_handle.await.unwrap();
                if res.is_ok() {
                    self.stream.get_mut().write_response(250, [2, 0, 0], &["OK"]).await;
                } else {
                    self.stream.get_mut().write_response(554, [5, 0, 0], &[&res.err().unwrap().to_string()])
                        .await;
                }
                self.session = Some(session);
            }

            self.reset().await;
        } else {
            self.stream.get_mut().write_response(250, [2, 0, 0], &["Continue"]).await;
        }
    }

    pub async fn reset(&mut self) {
        if let Some(pipe) = self.bdat_pipe.as_mut() {
            let _ = pipe.shutdown().await;
            self.bdat_pipe = None;
        }
        self.bytes_received = 0;

        if let Some(session) = self.session.as_mut() {
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

fn _encode_xtext(raw: String) -> String {
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
