use std::{fmt::Display, net::IpAddr, time::Duration};

use futures_util::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[cfg(feature = "tokio1")]
use super::async_net::AsyncTokioStream;
#[cfg(feature = "tracing")]
use super::escape_crlf;
use super::{AsyncNetworkStream, ClientCodec, TlsParameters};
use crate::{
    transport::smtp::{
        authentication::{Credentials, Mechanism},
        client::{ConnectionState, ConnectionWrapper},
        commands::{Auth, Data, Ehlo, Mail, Noop, Quit, Rcpt, Starttls},
        error::{self, Error},
        extension::{ClientId, Extension, MailBodyParameter, MailParameter, ServerInfo},
        response::{parse_response, Response},
    },
    Envelope,
};

/// Structure that implements the SMTP client
pub struct AsyncSmtpConnection {
    /// TCP stream between client and server
    stream: ConnectionWrapper<BufReader<AsyncNetworkStream>>,
    /// Whether QUIT has been sent
    sent_quit: bool,
    /// Information about the server
    server_info: ServerInfo,
}

impl AsyncSmtpConnection {
    /// Get information about the server
    pub fn server_info(&self) -> &ServerInfo {
        &self.server_info
    }

    /// Connects with existing async stream
    ///
    /// Sends EHLO and parses server information
    #[cfg(feature = "tokio1")]
    pub async fn connect_with_transport(
        stream: Box<dyn AsyncTokioStream>,
        hello_name: &ClientId,
    ) -> Result<AsyncSmtpConnection, Error> {
        let stream = AsyncNetworkStream::use_existing_tokio1(stream);
        Self::connect_impl(stream, hello_name).await
    }

    /// Connects to the configured server
    ///
    /// If `tls_parameters` is `Some`, then the connection will use Implicit TLS (sometimes
    /// referred to as `SMTPS`). See also [`AsyncSmtpConnection::starttls`].
    ///
    /// If `local_address` is `Some`, then the address provided shall be used to bind the
    /// connection to a specific local address using [`tokio1_crate::net::TcpSocket::bind`].
    ///
    /// Sends EHLO and parses server information
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use lettre::transport::smtp::{client::{AsyncSmtpConnection, TlsParameters}, extension::ClientId};
    /// # use tokio1_crate::{self as tokio, net::ToSocketAddrs as _};
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let connection = AsyncSmtpConnection::connect_tokio1(
    ///     ("example.com", 465),
    ///     Some(Duration::from_secs(60)),
    ///     &ClientId::default(),
    ///     Some(TlsParameters::new("example.com".to_owned())?),
    ///     None,
    /// )
    /// .await
    /// .unwrap();
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "tokio1")]
    pub async fn connect_tokio1<T: tokio1_crate::net::ToSocketAddrs>(
        server: T,
        timeout: Option<Duration>,
        hello_name: &ClientId,
        tls_parameters: Option<TlsParameters>,
        local_address: Option<IpAddr>,
    ) -> Result<AsyncSmtpConnection, Error> {
        let stream =
            AsyncNetworkStream::connect_tokio1(server, timeout, tls_parameters, local_address)
                .await?;
        Self::connect_impl(stream, hello_name).await
    }

    /// Connects to the configured server
    ///
    /// Sends EHLO and parses server information
    #[cfg(feature = "async-std1")]
    pub async fn connect_asyncstd1<T: async_std::net::ToSocketAddrs>(
        server: T,
        timeout: Option<Duration>,
        hello_name: &ClientId,
        tls_parameters: Option<TlsParameters>,
    ) -> Result<AsyncSmtpConnection, Error> {
        let stream = AsyncNetworkStream::connect_asyncstd1(server, timeout, tls_parameters).await?;
        Self::connect_impl(stream, hello_name).await
    }

    async fn connect_impl(
        stream: AsyncNetworkStream,
        hello_name: &ClientId,
    ) -> Result<AsyncSmtpConnection, Error> {
        let stream = BufReader::new(stream);
        let mut conn = AsyncSmtpConnection {
            stream: ConnectionWrapper::new(stream),
            sent_quit: false,
            server_info: ServerInfo::default(),
        };
        // TODO log
        let _response = conn.read_response().await?;

        conn.ehlo(hello_name).await?;

        // Print server information
        #[cfg(feature = "tracing")]
        tracing::debug!("server {}", conn.server_info);
        Ok(conn)
    }

    pub async fn send(&mut self, envelope: &Envelope, email: &[u8]) -> Result<Response, Error> {
        // Mail
        let mut mail_options = vec![];

        // Internationalization handling
        //
        // * 8BITMIME: https://tools.ietf.org/html/rfc6152
        // * SMTPUTF8: https://tools.ietf.org/html/rfc653

        // Check for non-ascii addresses and use the SMTPUTF8 option if any.
        if envelope.has_non_ascii_addresses() {
            if !self.server_info().supports_feature(Extension::SmtpUtfEight) {
                // don't try to send non-ascii addresses (per RFC)
                return Err(error::client(
                    "Envelope contains non-ascii chars but server does not support SMTPUTF8",
                ));
            }
            mail_options.push(MailParameter::SmtpUtfEight);
        }

        // Check for non-ascii content in the message
        if !email.is_ascii() {
            if !self.server_info().supports_feature(Extension::EightBitMime) {
                return Err(error::client(
                    "Message contains non-ascii chars but server does not support 8BITMIME",
                ));
            }
            mail_options.push(MailParameter::Body(MailBodyParameter::EightBitMime));
        }

        self.command(Mail::new(envelope.from().cloned(), mail_options))
            .await?;

        // Recipient
        for to_address in envelope.to() {
            self.command(Rcpt::new(to_address.clone(), vec![])).await?;
        }

        // Data
        self.command(Data).await?;

        // Message content
        let result = self.message(email).await?;
        Ok(result)
    }

    pub fn has_broken(&self) -> bool {
        self.sent_quit
            || matches!(
                self.stream.state(),
                ConnectionState::BrokenConnection | ConnectionState::BrokenResponse
            )
    }

    pub fn can_starttls(&self) -> bool {
        !self.is_encrypted() && self.server_info.supports_feature(Extension::StartTls)
    }

    /// Upgrade the connection using `STARTTLS`.
    ///
    /// As described in [rfc3207]. Note that this mechanism has been deprecated in [rfc8314].
    ///
    /// [rfc3207]: https://www.rfc-editor.org/rfc/rfc3207
    /// [rfc8314]: https://www.rfc-editor.org/rfc/rfc8314
    #[allow(unused_variables)]
    pub async fn starttls(
        &mut self,
        tls_parameters: TlsParameters,
        hello_name: &ClientId,
    ) -> Result<(), Error> {
        if self.server_info.supports_feature(Extension::StartTls) {
            self.command(Starttls).await?;
            self.stream
                .async_op(|stream| stream.get_mut().upgrade_tls(tls_parameters))
                .await?;
            #[cfg(feature = "tracing")]
            tracing::debug!("connection encrypted");
            // Send EHLO again
            self.ehlo(hello_name).await?;
            Ok(())
        } else {
            Err(error::client("STARTTLS is not supported on this server"))
        }
    }

    /// Send EHLO and update server info
    async fn ehlo(&mut self, hello_name: &ClientId) -> Result<(), Error> {
        let ehlo_response = self.command(Ehlo::new(hello_name.clone())).await?;
        self.server_info = ServerInfo::from_response(&ehlo_response)?;
        Ok(())
    }

    pub async fn quit(&mut self) -> Result<Response, Error> {
        self.sent_quit = true;
        self.command(Quit).await
    }

    pub async fn abort(&mut self) {
        // Only try to quit if we are not already broken
        // `write` already rejects writes if the connection state if bad
        if !self.sent_quit {
            let _ = self.quit().await;
        }

        if !matches!(self.stream.state(), ConnectionState::BrokenConnection) {
            let _ = self
                .stream
                .async_op(|stream| async { stream.close().await.map_err(error::network) })
                .await;
        }
    }

    /// Sets the underlying stream
    pub fn set_stream(&mut self, stream: AsyncNetworkStream) {
        self.stream = ConnectionWrapper::new(BufReader::new(stream));
    }

    /// Tells if the underlying stream is currently encrypted
    pub fn is_encrypted(&self) -> bool {
        self.stream.get_ref().get_ref().is_encrypted()
    }

    /// Checks if the server is connected using the NOOP SMTP command
    pub async fn test_connected(&mut self) -> bool {
        self.command(Noop).await.is_ok()
    }

    /// Sends an AUTH command with the given mechanism, and handles the challenge if needed
    pub async fn auth(
        &mut self,
        mechanisms: &[Mechanism],
        credentials: &Credentials,
    ) -> Result<Response, Error> {
        let mechanism = self
            .server_info
            .get_auth_mechanism(mechanisms)
            .ok_or_else(|| error::client("No compatible authentication mechanism was found"))?;

        // Limit challenges to avoid blocking
        let mut challenges: u8 = 10;
        let mut response = self
            .command(Auth::new(mechanism, credentials.clone(), None)?)
            .await?;

        while challenges > 0 && response.has_code(334) {
            challenges -= 1;
            response = self
                .command(Auth::new_from_response(
                    mechanism,
                    credentials.clone(),
                    &response,
                )?)
                .await?;
        }

        if challenges == 0 {
            Err(error::response("Unexpected number of challenges"))
        } else {
            Ok(response)
        }
    }

    /// Sends the message content
    pub async fn message(&mut self, message: &[u8]) -> Result<Response, Error> {
        let mut out_buf: Vec<u8> = vec![];
        let mut codec = ClientCodec::new();
        codec.encode(message, &mut out_buf);
        self.write(out_buf.as_slice()).await?;
        self.write(b"\r\n.\r\n").await?;
        self.read_response().await
    }

    /// Sends an SMTP command
    pub async fn command<C: Display>(&mut self, command: C) -> Result<Response, Error> {
        self.write(command.to_string().as_bytes()).await?;
        self.read_response().await
    }

    /// Writes a string to the server
    async fn write(&mut self, string: &[u8]) -> Result<(), Error> {
        self.stream
            .async_op(|stream| async {
                stream
                    .get_mut()
                    .write_all(string)
                    .await
                    .map_err(error::network)
            })
            .await?;
        self.stream
            .async_op(|stream| async { stream.get_mut().flush().await.map_err(error::network) })
            .await?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Wrote: {}", escape_crlf(&String::from_utf8_lossy(string)));
        Ok(())
    }

    /// Gets the SMTP response
    pub async fn read_response(&mut self) -> Result<Response, Error> {
        let mut buffer = String::with_capacity(100);

        while self
            .stream
            .async_op(|stream| async {
                stream.read_line(&mut buffer).await.map_err(error::network)
            })
            .await?
            > 0
        {
            #[cfg(feature = "tracing")]
            tracing::debug!("<< {}", escape_crlf(&buffer));
            match parse_response(&buffer) {
                Ok((_remaining, response)) => {
                    return if response.is_positive() {
                        Ok(response)
                    } else {
                        Err(error::code(
                            response.code(),
                            Some(response.message().collect()),
                        ))
                    }
                }
                Err(nom::Err::Failure(e)) => {
                    self.stream.set_state(ConnectionState::BrokenResponse);
                    return Err(error::response(e.to_string()));
                }
                Err(nom::Err::Incomplete(_)) => { /* read more */ }
                Err(nom::Err::Error(e)) => {
                    self.stream.set_state(ConnectionState::BrokenResponse);
                    return Err(error::response(e.to_string()));
                }
            }
        }

        Err(error::response("incomplete response"))
    }

    /// The X509 certificate of the server (DER encoded)
    #[cfg(any(feature = "native-tls", feature = "rustls-tls", feature = "boring-tls"))]
    pub fn peer_certificate(&self) -> Result<Vec<u8>, Error> {
        self.stream.get_ref().get_ref().peer_certificate()
    }

    /// All the X509 certificates of the chain (DER encoded)
    #[cfg(any(feature = "rustls-tls", feature = "boring-tls"))]
    pub fn certificate_chain(&self) -> Result<Vec<Vec<u8>>, Error> {
        self.stream.get_ref().get_ref().certificate_chain()
    }
}
