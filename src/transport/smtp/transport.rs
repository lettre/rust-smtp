use std::time::Duration;

#[cfg(feature = "r2d2")]
use r2d2::Pool;

#[cfg(feature = "r2d2")]
use super::PoolConfig;
#[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
use super::{error, Tls, TlsParameters, SUBMISSIONS_PORT, SUBMISSION_PORT};
use super::{ClientId, Credentials, Error, Mechanism, Response, SmtpConnection, SmtpInfo};
use crate::{address::Envelope, Transport};

/// Sends emails using the SMTP protocol
#[cfg_attr(docsrs, doc(cfg(feature = "smtp-transport")))]
#[derive(Clone)]
pub struct SmtpTransport {
    #[cfg(feature = "r2d2")]
    inner: Pool<SmtpClient>,
    get_timeout: Option<Duration>,
    #[cfg(not(feature = "r2d2"))]
    inner: SmtpClient,
}

impl Transport for SmtpTransport {
    type Ok = Response;
    type Error = Error;

    /// Sends an email
    fn send_raw(&self, envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        #[cfg(feature = "r2d2")]
        let mut conn = match self.get_timeout {
            None => self.inner.get().map_err(error::client)?,
            Some(tmo) => self.inner.get_timeout(tmo).map_err(error::client)?,
        };
        #[cfg(not(feature = "r2d2"))]
        let mut conn = self.inner.connection()?;

        let result = conn.send(envelope, email)?;

        #[cfg(not(feature = "r2d2"))]
        conn.quit()?;

        Ok(result)
    }
}

impl SmtpTransport {
    /// Simple and secure transport, using TLS connections to communicate with the SMTP server
    ///
    /// The right option for most SMTP servers.
    ///
    /// Creates an encrypted transport over submissions port, using the provided domain
    /// to validate TLS certificates.
    #[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "native-tls", feature = "rustls-tls"))))]
    pub fn relay(relay: &str) -> Result<SmtpTransportBuilder, Error> {
        let tls_parameters = TlsParameters::new(relay.into())?;

        Ok(Self::builder_dangerous(relay)
            .port(SUBMISSIONS_PORT)
            .tls(Tls::Wrapper(tls_parameters)))
    }

    /// Simple an secure transport, using STARTTLS to obtain encrypted connections
    ///
    /// Alternative to [`SmtpTransport::relay`](#method.relay), for SMTP servers
    /// that don't take SMTPS connections.
    ///
    /// Creates an encrypted transport over submissions port, by first connecting using
    /// an unencrypted connection and then upgrading it with STARTTLS. The provided
    /// domain is used to validate TLS certificates.
    ///
    /// An error is returned if the connection can't be upgraded. No credentials
    /// or emails will be sent to the server, protecting from downgrade attacks.
    #[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "native-tls", feature = "rustls-tls"))))]
    pub fn starttls_relay(relay: &str) -> Result<SmtpTransportBuilder, Error> {
        let tls_parameters = TlsParameters::new(relay.into())?;

        Ok(Self::builder_dangerous(relay)
            .port(SUBMISSION_PORT)
            .tls(Tls::Required(tls_parameters)))
    }

    /// Creates a new local SMTP client to port 25
    ///
    /// Shortcut for local unencrypted relay (typical local email daemon that will handle relaying)
    pub fn unencrypted_localhost() -> SmtpTransport {
        Self::builder_dangerous("localhost").build()
    }

    /// Creates a new SMTP client
    ///
    /// Defaults are:
    ///
    /// * No authentication
    /// * No TLS
    /// * A 60 seconds timeout for smtp commands
    /// * Port 25
    ///
    /// Consider using [`SmtpTransport::relay`](#method.relay) or
    /// [`SmtpTransport::starttls_relay`](#method.starttls_relay) instead,
    /// if possible.
    pub fn builder_dangerous<T: Into<String>>(server: T) -> SmtpTransportBuilder {
        let new = SmtpInfo {
            server: server.into(),
            ..Default::default()
        };

        SmtpTransportBuilder {
            info: new,
            #[cfg(feature = "r2d2")]
            pool_config: PoolConfig::default(),
        }
    }
}

/// Contains client configuration.
/// Instances of this struct can be created using functions of [`SmtpTransport`].
#[derive(Debug, Clone)]
pub struct SmtpTransportBuilder {
    info: SmtpInfo,
    #[cfg(feature = "r2d2")]
    pool_config: PoolConfig,
}

/// Builder for the SMTP `SmtpTransport`
impl SmtpTransportBuilder {
    /// Set the name used during EHLO
    pub fn hello_name(mut self, name: ClientId) -> Self {
        self.info.hello_name = name;
        self
    }

    /// Set the authentication mechanism to use
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.info.credentials = Some(credentials);
        self
    }

    /// Set the authentication mechanism to use
    pub fn authentication(mut self, mechanisms: Vec<Mechanism>) -> Self {
        self.info.authentication = mechanisms;
        self
    }

    /// Set the timeout duration
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.info.timeout = timeout;
        self
    }

    /// Set the port to use
    pub fn port(mut self, port: u16) -> Self {
        self.info.port = port;
        self
    }

    /// Set the TLS settings to use
    #[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "native-tls", feature = "rustls-tls"))))]
    pub fn tls(mut self, tls: Tls) -> Self {
        self.info.tls = tls;
        self
    }

    /// Use a custom configuration for the connection pool
    ///
    /// Defaults can be found at [`PoolConfig`]
    #[cfg(feature = "r2d2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "r2d2")))]
    pub fn pool_config(mut self, pool_config: PoolConfig) -> Self {
        self.pool_config = pool_config;
        self
    }

    /// Build the transport
    ///
    /// If the `r2d2` feature is enabled an `Arc` wrapped pool is be created.
    /// Defaults can be found at [`PoolConfig`]
    pub fn build(self) -> SmtpTransport {
        let client = SmtpClient { info: self.info };
        SmtpTransport {
            #[cfg(feature = "r2d2")]
            inner: self.pool_config.build(client),
            get_timeout: self.pool_config.get_timeout,
            #[cfg(not(feature = "r2d2"))]
            inner: client,
        }
    }
}

/// Build client
#[derive(Debug, Clone)]
pub struct SmtpClient {
    info: SmtpInfo,
}

impl SmtpClient {
    /// Creates a new connection directly usable to send emails
    ///
    /// Handles encryption and authentication
    pub fn connection(&self) -> Result<SmtpConnection, Error> {
        #[allow(clippy::match_single_binding)]
        let tls_parameters = match self.info.tls {
            #[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
            Tls::Wrapper(ref tls_parameters) => Some(tls_parameters),
            _ => None,
        };

        #[allow(unused_mut)]
        let mut conn = SmtpConnection::connect::<(&str, u16)>(
            (self.info.server.as_ref(), self.info.port),
            self.info.timeout,
            &self.info.hello_name,
            tls_parameters,
        )?;

        #[cfg(any(feature = "native-tls", feature = "rustls-tls"))]
        match self.info.tls {
            Tls::Opportunistic(ref tls_parameters) => {
                if conn.can_starttls() {
                    conn.starttls(tls_parameters, &self.info.hello_name)?;
                }
            }
            Tls::Required(ref tls_parameters) => {
                conn.starttls(tls_parameters, &self.info.hello_name)?;
            }
            _ => (),
        }

        if let Some(credentials) = &self.info.credentials {
            conn.auth(&self.info.authentication, credentials)?;
        }
        Ok(conn)
    }
}
