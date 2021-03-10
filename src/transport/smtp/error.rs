//! Error and result type for SMTP clients

use crate::transport::smtp::response::{Code, Severity};
use std::{error::Error as StdError, fmt, io};

// Inspired by https://github.com/seanmonstar/reqwest/blob/a8566383168c0ef06c21f38cbc9213af6ff6db31/src/error.rs

/// The Errors that may occur when sending an email over SMTP
pub struct Error {
    inner: Box<Inner>,
}

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

struct Inner {
    kind: Kind,
    source: Option<BoxError>,
}

impl Error {
    pub(crate) fn new<E>(kind: Kind, source: Option<E>) -> Error
    where
        E: Into<BoxError>,
    {
        Error {
            inner: Box::new(Inner {
                kind,
                source: source.map(Into::into),
            }),
        }
    }

    /// Returns true if the error is from response
    pub fn is_response(&self) -> bool {
        matches!(self.inner.kind, Kind::Response)
    }

    /// Returns true if the error is from client
    pub fn is_client(&self) -> bool {
        matches!(self.inner.kind, Kind::Client)
    }

    /// Returns true if the error is transient SMTP error
    pub fn is_transient(&self) -> bool {
        matches!(self.inner.kind, Kind::Transient(_))
    }

    /// Returns true if the error is a permanent SMTP error
    pub fn is_permanent(&self) -> bool {
        matches!(self.inner.kind, Kind::Permanent(_))
    }

    /// Returns true if the error is from TLS
    #[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "native-tls", feature = "rustls-tls"))))]
    pub fn is_tls(&self) -> bool {
        matches!(self.inner.kind, Kind::Tls)
    }

    /// Returns the status code, if the error was generated from a response.
    pub fn status(&self) -> Option<Code> {
        match self.inner.kind {
            Kind::Transient(code) => Some(code),
            Kind::Permanent(code) => Some(code),
            _ => None,
        }
    }

    #[allow(unused)]
    pub(crate) fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::Other, self)
    }
}

#[derive(Debug)]
pub(crate) enum Kind {
    /// Transient SMTP error, 4xx reply code
    ///
    /// [RFC 5321, section 4.2.1](https://tools.ietf.org/html/rfc5321#section-4.2.1)
    Transient(Code),
    /// Permanent SMTP error, 5xx reply code
    ///
    /// [RFC 5321, section 4.2.1](https://tools.ietf.org/html/rfc5321#section-4.2.1)
    Permanent(Code),
    /// Error parsing a response
    Response,
    /// Internal client error
    Client,
    /// TLS error
    #[cfg_attr(docsrs, doc(cfg(any(feature = "native-tls", feature = "rustls-tls"))))]
    #[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
    Tls,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("lettre::Error");

        builder.field("kind", &self.inner.kind);

        if let Some(ref source) = self.inner.source {
            builder.field("source", source);
        }

        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.kind {
            Kind::Response => f.write_str("response error")?,
            Kind::Client => f.write_str("internal client error")?,
            #[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
            Kind::Tls => f.write_str("tls error")?,
            Kind::Transient(ref code) => {
                write!(f, "transient error ({})", code)?;
            }
            Kind::Permanent(ref code) => {
                write!(f, "transient error ({})", code)?;
            }
        };

        if let Some(ref e) = self.inner.source {
            write!(f, ": {}", e)?;
        }

        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner.source.as_ref().map(|e| {
            let r: &(dyn std::error::Error + 'static) = &**e;
            r
        })
    }
}

pub(crate) fn code(c: Code) -> Error {
    match c.severity {
        Severity::TransientNegativeCompletion => Error::new::<Error>(Kind::Transient(c), None),
        Severity::PermanentNegativeCompletion => Error::new::<Error>(Kind::Permanent(c), None),
        _ => client("Unknown error code"),
    }
}

pub(crate) fn response<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Response, Some(e))
}

pub(crate) fn client<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Client, Some(e))
}

#[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
pub(crate) fn tls<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Tls, Some(e))
}
