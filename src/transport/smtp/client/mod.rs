//! SMTP client
//!
//! `SmtpConnection` allows manually sending SMTP commands.
//!
//! ```rust,no_run
//! # use std::error::Error;
//!
//! # #[cfg(feature = "smtp-transport")]
//! # fn main() -> Result<(), Box<dyn Error>> {
//! use lettre::transport::smtp::{
//!     client::SmtpConnection, commands::*, extension::ClientId, SMTP_PORT,
//! };
//!
//! let hello = ClientId::Domain("my_hostname".to_owned());
//! let mut client = SmtpConnection::connect(&("localhost", SMTP_PORT), None, &hello, None, None)?;
//! client.command(Mail::new(Some("user@example.com".parse()?), vec![]))?;
//! client.command(Rcpt::new("user@example.org".parse()?, vec![]))?;
//! client.command(Data)?;
//! client.message("Test email".as_bytes())?;
//! client.command(Quit)?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "serde")]
use std::fmt::Debug;
#[cfg(any(feature = "tokio1", feature = "async-std1"))]
use std::future::Future;

#[cfg(any(feature = "tokio1", feature = "async-std1"))]
pub use self::async_connection::AsyncSmtpConnection;
#[cfg(any(feature = "tokio1", feature = "async-std1"))]
pub use self::async_net::AsyncNetworkStream;
#[cfg(feature = "tokio1")]
pub use self::async_net::AsyncTokioStream;
use self::net::NetworkStream;
#[cfg(any(feature = "native-tls", feature = "rustls-tls", feature = "boring-tls"))]
pub(super) use self::tls::InnerTlsParameters;
#[cfg(any(feature = "native-tls", feature = "rustls-tls", feature = "boring-tls"))]
pub use self::tls::TlsVersion;
pub use self::{
    connection::SmtpConnection,
    tls::{Certificate, CertificateStore, Identity, Tls, TlsParameters, TlsParametersBuilder},
};
use super::{error, Error};

#[cfg(any(feature = "tokio1", feature = "async-std1"))]
mod async_connection;
#[cfg(any(feature = "tokio1", feature = "async-std1"))]
mod async_net;
mod connection;
mod net;
mod tls;

#[derive(Debug)]
pub(super) struct ConnectionWrapper<C> {
    conn: C,
    state: ConnectionState,
}

impl<C> ConnectionWrapper<C> {
    pub(super) fn new(conn: C) -> Self {
        Self {
            conn,
            state: ConnectionState::ProbablyConnected,
        }
    }

    pub(super) fn get_ref(&self) -> &C {
        &self.conn
    }

    pub(super) fn get_mut(&mut self) -> &mut C {
        &mut self.conn
    }

    pub(super) fn state(&self) -> ConnectionState {
        self.state
    }

    pub(super) fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    pub(super) fn sync_op<F, T>(&mut self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut C) -> Result<T, Error>,
    {
        if !matches!(
            self.state,
            ConnectionState::ProbablyConnected | ConnectionState::BrokenResponse
        ) {
            return Err(error::client(
                "attempted to send operation to broken connection",
            ));
        }

        self.state = ConnectionState::Writing;
        match f(&mut self.conn) {
            Ok(t) => {
                self.state = ConnectionState::ProbablyConnected;
                Ok(t)
            }
            Err(err) => {
                self.state = ConnectionState::BrokenConnection;
                Err(err)
            }
        }
    }

    #[cfg(any(feature = "tokio1", feature = "async-std1"))]
    pub(super) async fn async_op<'a, F, Fut, T>(&'a mut self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&'a mut C) -> Fut,
        Fut: Future<Output = Result<T, Error>>,
    {
        if !matches!(
            self.state,
            ConnectionState::ProbablyConnected | ConnectionState::BrokenResponse
        ) {
            return Err(error::client(
                "attempted to send operation to broken connection",
            ));
        }

        self.state = ConnectionState::Writing;
        match f(&mut self.conn).await {
            Ok(t) => {
                self.state = ConnectionState::ProbablyConnected;
                Ok(t)
            }
            Err(err) => {
                self.state = ConnectionState::BrokenConnection;
                Err(err)
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(super) enum ConnectionState {
    ProbablyConnected,
    Writing,
    BrokenResponse,
    BrokenConnection,
}

/// The codec used for transparency
#[derive(Debug)]
struct ClientCodec {
    status: CodecStatus,
}

impl ClientCodec {
    /// Creates a new client codec
    pub fn new() -> Self {
        Self {
            status: CodecStatus::StartOfNewLine,
        }
    }

    /// Adds transparency
    fn encode(&mut self, frame: &[u8], buf: &mut Vec<u8>) {
        for &b in frame {
            buf.push(b);
            match (b, self.status) {
                (b'\r', _) => {
                    self.status = CodecStatus::StartingNewLine;
                }
                (b'\n', CodecStatus::StartingNewLine) => {
                    self.status = CodecStatus::StartOfNewLine;
                }
                (_, CodecStatus::StartingNewLine) => {
                    self.status = CodecStatus::MiddleOfLine;
                }
                (b'.', CodecStatus::StartOfNewLine) => {
                    self.status = CodecStatus::MiddleOfLine;
                    buf.push(b'.');
                }
                (_, CodecStatus::StartOfNewLine) => {
                    self.status = CodecStatus::MiddleOfLine;
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(clippy::enum_variant_names)]
enum CodecStatus {
    /// We are past the first character of the current line
    MiddleOfLine,
    /// We just read a `\r` character
    StartingNewLine,
    /// We are at the start of a new line
    StartOfNewLine,
}

/// Returns the string replacing all the CRLF with "\<CRLF\>"
/// Used for debug displays
#[cfg(feature = "tracing")]
pub(super) fn escape_crlf(string: &str) -> String {
    string.replace("\r\n", "<CRLF>")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_codec() {
        let mut buf = Vec::new();
        let mut codec = ClientCodec::new();

        codec.encode(b".\r\n", &mut buf);
        codec.encode(b"test\r\n", &mut buf);
        codec.encode(b"test\r\n\r\n", &mut buf);
        codec.encode(b".\r\n", &mut buf);
        codec.encode(b"\r\ntest", &mut buf);
        codec.encode(b"te\r\n.\r\nst", &mut buf);
        codec.encode(b"test", &mut buf);
        codec.encode(b"test.", &mut buf);
        codec.encode(b"test\n", &mut buf);
        codec.encode(b".test\n", &mut buf);
        codec.encode(b"test", &mut buf);
        codec.encode(b"test", &mut buf);
        codec.encode(b"test\r\n", &mut buf);
        codec.encode(b".test\r\n", &mut buf);
        codec.encode(b"test.\r\n", &mut buf);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "..\r\ntest\r\ntest\r\n\r\n..\r\n\r\ntestte\r\n..\r\nsttesttest.test\n.test\ntesttesttest\r\n..test\r\ntest.\r\n"
        );
    }

    #[test]
    #[cfg(feature = "tracing")]
    fn test_escape_crlf() {
        assert_eq!(escape_crlf("\r\n"), "<CRLF>");
        assert_eq!(escape_crlf("EHLO my_name\r\n"), "EHLO my_name<CRLF>");
        assert_eq!(
            escape_crlf("EHLO my_name\r\nSIZE 42\r\n"),
            "EHLO my_name<CRLF>SIZE 42<CRLF>"
        );
    }
}
