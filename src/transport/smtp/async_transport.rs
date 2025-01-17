#[cfg(feature = "pool")]
use std::sync::Arc;
use std::{
    fmt::{self, Debug},
    marker::PhantomData,
    time::Duration,
};

use async_trait::async_trait;

#[cfg(feature = "pool")]
use super::pool::async_impl::Pool;
#[cfg(feature = "pool")]
use super::PoolConfig;
#[cfg(any(
    feature = "tokio1-native-tls",
    feature = "tokio1-rustls-tls",
    feature = "async-std1-rustls-tls"
))]
use super::Tls;
use super::{
    client::AsyncSmtpConnection, ClientId, Credentials, Error, Mechanism, Response, SmtpInfo,
};
#[cfg(feature = "async-std1")]
use crate::AsyncStd1Executor;
#[cfg(any(feature = "tokio1", feature = "async-std1"))]
use crate::AsyncTransport;
#[cfg(feature = "tokio1")]
use crate::Tokio1Executor;
use crate::{Envelope, Executor};

/// Asynchronously sends emails using the SMTP protocol
///
/// `AsyncSmtpTransport` is the primary way for communicating
/// with SMTP relay servers to send email messages. It holds the
/// client connect configuration and creates new connections
/// as necessary.
///
/// # Connection pool
///
/// When the `pool` feature is enabled (default), `AsyncSmtpTransport` maintains a
/// connection pool to manage SMTP connections. The pool:
///
/// - Establishes a new connection when sending a message.
/// - Recycles connections internally after a message is sent.
/// - Reuses connections for subsequent messages, reducing connection setup overhead.
///
/// The connection pool can grow to hold multiple SMTP connections if multiple
/// emails are sent concurrently, as SMTP does not support multiplexing within a
/// single connection.
///
/// However, **connection reuse is not possible** if the `SyncSmtpTransport` instance
/// is dropped after every email send operation. You must reuse the instance
/// of this struct for the connection pool to be of any use.
///
/// To customize connection pool settings, use [`AsyncSmtpTransportBuilder::pool_config`].
#[cfg_attr(docsrs, doc(cfg(any(feature = "tokio1", feature = "async-std1"))))]
pub struct AsyncSmtpTransport<E: Executor> {
    #[cfg(feature = "pool")]
    inner: Arc<Pool<E>>,
    #[cfg(not(feature = "pool"))]
    inner: AsyncSmtpClient<E>,
}

#[cfg(feature = "tokio1")]
#[async_trait]
impl AsyncTransport for AsyncSmtpTransport<Tokio1Executor> {
    type Ok = Response;
    type Error = Error;

    /// Sends an email
    async fn send_raw(&self, envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        let mut conn = self.inner.connection().await?;

        let result = conn.send(envelope, email).await?;

        #[cfg(not(feature = "pool"))]
        conn.abort().await;

        Ok(result)
    }
}

#[cfg(feature = "async-std1")]
#[async_trait]
impl AsyncTransport for AsyncSmtpTransport<AsyncStd1Executor> {
    type Ok = Response;
    type Error = Error;

    /// Sends an email
    async fn send_raw(&self, envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        let mut conn = self.inner.connection().await?;

        let result = conn.send(envelope, email).await?;

        conn.quit().await?;

        Ok(result)
    }
}

impl<E> AsyncSmtpTransport<E>
where
    E: Executor,
{
    /// Simple and secure transport, using TLS connections to communicate with the SMTP server
    ///
    /// The right option for most SMTP servers.
    ///
    /// Creates an encrypted transport over submissions port, using the provided domain
    /// to validate TLS certificates.
    #[cfg(any(
        feature = "tokio1-native-tls",
        feature = "tokio1-rustls-tls",
        feature = "async-std1-rustls-tls"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "tokio1-native-tls",
            feature = "tokio1-rustls-tls",
            feature = "async-std1-rustls-tls"
        )))
    )]
    pub fn relay(relay: &str) -> Result<AsyncSmtpTransportBuilder, Error> {
        use super::{Tls, TlsParameters, SUBMISSIONS_PORT};

        let tls_parameters = TlsParameters::new(relay.into())?;

        Ok(Self::builder_dangerous(relay)
            .port(SUBMISSIONS_PORT)
            .tls(Tls::Wrapper(tls_parameters)))
    }

    /// Simple and secure transport, using STARTTLS to obtain encrypted connections
    ///
    /// Alternative to [`AsyncSmtpTransport::relay`](#method.relay), for SMTP servers
    /// that don't take SMTPS connections.
    ///
    /// Creates an encrypted transport over submissions port, by first connecting using
    /// an unencrypted connection and then upgrading it with STARTTLS. The provided
    /// domain is used to validate TLS certificates.
    ///
    /// An error is returned if the connection can't be upgraded. No credentials
    /// or emails will be sent to the server, protecting from downgrade attacks.
    #[cfg(any(
        feature = "tokio1-native-tls",
        feature = "tokio1-rustls-tls",
        feature = "async-std1-rustls-tls"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "tokio1-native-tls",
            feature = "tokio1-rustls-tls",
            feature = "async-std1-rustls-tls"
        )))
    )]
    pub fn starttls_relay(relay: &str) -> Result<AsyncSmtpTransportBuilder, Error> {
        use super::{Tls, TlsParameters, SUBMISSION_PORT};

        let tls_parameters = TlsParameters::new(relay.into())?;

        Ok(Self::builder_dangerous(relay)
            .port(SUBMISSION_PORT)
            .tls(Tls::Required(tls_parameters)))
    }

    /// Creates a new local SMTP client to port 25
    ///
    /// Shortcut for local unencrypted relay (typical local email daemon that will handle relaying)
    pub fn unencrypted_localhost() -> AsyncSmtpTransport<E> {
        Self::builder_dangerous("localhost").build()
    }

    /// Creates a new SMTP client
    ///
    /// Defaults are:
    ///
    /// * No authentication
    /// * No TLS
    /// * A 60-seconds timeout for smtp commands
    /// * Port 25
    ///
    /// Consider using [`AsyncSmtpTransport::relay`](#method.relay) or
    /// [`AsyncSmtpTransport::starttls_relay`](#method.starttls_relay) instead,
    /// if possible.
    pub fn builder_dangerous<T: Into<String>>(server: T) -> AsyncSmtpTransportBuilder {
        AsyncSmtpTransportBuilder::new(server)
    }

    /// Creates a `AsyncSmtpTransportBuilder` from a connection URL
    ///
    /// The protocol, credentials, host and port can be provided in a single URL.
    /// Use the scheme `smtp` for an unencrypted relay (optionally in combination with the
    /// `tls` parameter to allow/require STARTTLS) or `smtps` for SMTP over TLS.
    /// The path section of the url can be used to set an alternative name for
    /// the HELO / EHLO command.
    /// For example `smtps://username:password@smtp.example.com/client.example.com:465`
    /// will set the HELO / EHLO name `client.example.com`.
    ///
    /// <table>
    ///   <thead>
    ///     <tr>
    ///       <th>scheme</th>
    ///       <th>tls parameter</th>
    ///       <th>example</th>
    ///       <th>remarks</th>
    ///     </tr>
    ///   </thead>
    ///   <tbody>
    ///     <tr>
    ///      <td>smtps</td>
    ///      <td>-</td>
    ///      <td>smtps://smtp.example.com</td>
    ///      <td>SMTP over TLS, recommended method</td>
    ///     </tr>
    ///     <tr>
    ///      <td>smtp</td>
    ///      <td>required</td>
    ///      <td>smtp://smtp.example.com?tls=required</td>
    ///      <td>SMTP with STARTTLS required, when SMTP over TLS is not available</td>
    ///     </tr>
    ///     <tr>
    ///      <td>smtp</td>
    ///      <td>opportunistic</td>
    ///      <td>smtp://smtp.example.com?tls=opportunistic</td>
    ///      <td>
    ///         SMTP with optionally STARTTLS when supported by the server.
    ///         Caution: this method is vulnerable to a man-in-the-middle attack.
    ///         Not recommended for production use.
    ///       </td>
    ///     </tr>
    ///     <tr>
    ///      <td>smtp</td>
    ///      <td>-</td>
    ///      <td>smtp://smtp.example.com</td>
    ///      <td>Unencrypted SMTP, not recommended for production use.</td>
    ///     </tr>
    ///   </tbody>
    /// </table>
    ///
    /// ```rust,no_run
    /// use lettre::{
    ///     message::header::ContentType, transport::smtp::authentication::Credentials,
    ///     AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    /// };
    /// # use tokio1_crate as tokio;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let email = Message::builder()
    ///     .from("NoBody <nobody@domain.tld>".parse().unwrap())
    ///     .reply_to("Yuin <yuin@domain.tld>".parse().unwrap())
    ///     .to("Hei <hei@domain.tld>".parse().unwrap())
    ///     .subject("Happy new year")
    ///     .header(ContentType::TEXT_PLAIN)
    ///     .body(String::from("Be happy!"))
    ///     .unwrap();
    ///
    /// // Open a remote connection to gmail
    /// let mailer: AsyncSmtpTransport<Tokio1Executor> =
    ///     AsyncSmtpTransport::<Tokio1Executor>::from_url(
    ///         "smtps://username:password@smtp.example.com:465",
    ///     )
    ///     .unwrap()
    ///     .build();
    ///
    /// // Send the email
    /// match mailer.send(email).await {
    ///     Ok(_) => println!("Email sent successfully!"),
    ///     Err(e) => panic!("Could not send email: {e:?}"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(any(feature = "native-tls", feature = "rustls-tls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls-tls", feature = "boring-tls")))
    )]
    pub fn from_url(connection_url: &str) -> Result<AsyncSmtpTransportBuilder, Error> {
        super::connection_url::from_connection_url(connection_url)
    }

    /// Tests the SMTP connection
    ///
    /// `test_connection()` tests the connection by using the SMTP NOOP command.
    /// The connection is closed afterward if a connection pool is not used.
    pub async fn test_connection(&self) -> Result<bool, Error> {
        let mut conn = self.inner.connection().await?;

        let is_connected = conn.test_connected().await;

        #[cfg(not(feature = "pool"))]
        conn.quit().await?;

        Ok(is_connected)
    }
}

impl<E: Executor> Debug for AsyncSmtpTransport<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("AsyncSmtpTransport");
        builder.field("inner", &self.inner);
        builder.finish()
    }
}

impl<E> Clone for AsyncSmtpTransport<E>
where
    E: Executor,
{
    fn clone(&self) -> Self {
        Self {
            #[cfg(feature = "pool")]
            inner: Arc::clone(&self.inner),
            #[cfg(not(feature = "pool"))]
            inner: self.inner.clone(),
        }
    }
}

/// Contains client configuration.
/// Instances of this struct can be created using functions of [`AsyncSmtpTransport`].
#[derive(Debug, Clone)]
#[cfg_attr(docsrs, doc(cfg(any(feature = "tokio1", feature = "async-std1"))))]
pub struct AsyncSmtpTransportBuilder {
    info: SmtpInfo,
    #[cfg(feature = "pool")]
    pool_config: PoolConfig,
}

/// Builder for the SMTP `AsyncSmtpTransport`
impl AsyncSmtpTransportBuilder {
    // Create new builder with default parameters
    pub(crate) fn new<T: Into<String>>(server: T) -> Self {
        let info = SmtpInfo {
            server: server.into(),
            ..Default::default()
        };

        AsyncSmtpTransportBuilder {
            info,
            #[cfg(feature = "pool")]
            pool_config: PoolConfig::default(),
        }
    }

    /// Set the name used during EHLO
    pub fn hello_name(mut self, name: ClientId) -> Self {
        self.info.hello_name = name;
        self
    }

    /// Set the authentication credentials to use
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.info.credentials = Some(credentials);
        self
    }

    /// Set the authentication mechanism to use
    pub fn authentication(mut self, mechanisms: Vec<Mechanism>) -> Self {
        self.info.authentication = mechanisms;
        self
    }

    /// Set the port to use
    ///
    /// # ⚠️⚠️⚠️ You probably don't need to call this method ⚠️⚠️⚠️
    ///
    /// lettre usually picks the correct `port` when building
    /// [`AsyncSmtpTransport`] using [`AsyncSmtpTransport::relay`] or
    /// [`AsyncSmtpTransport::starttls_relay`].
    ///
    /// # Errors
    ///
    /// Using the incorrect `port` and [`Self::tls`] combination may
    /// lead to hard to debug IO errors coming from the TLS library.
    pub fn port(mut self, port: u16) -> Self {
        self.info.port = port;
        self
    }

    /// Set the timeout duration
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.info.timeout = timeout;
        self
    }

    /// Set the TLS settings to use
    ///
    /// # ⚠️⚠️⚠️ You probably don't need to call this method ⚠️⚠️⚠️
    ///
    /// By default lettre chooses the correct `tls` configuration when
    /// building [`AsyncSmtpTransport`] using [`AsyncSmtpTransport::relay`] or
    /// [`AsyncSmtpTransport::starttls_relay`].
    ///
    /// # Errors
    ///
    /// Using the incorrect [`Tls`] and [`Self::port`] combination may
    /// lead to hard to debug IO errors coming from the TLS library.
    #[cfg(any(
        feature = "tokio1-native-tls",
        feature = "tokio1-rustls-tls",
        feature = "async-std1-rustls-tls"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "tokio1-native-tls",
            feature = "tokio1-rustls-tls",
            feature = "async-std1-rustls-tls"
        )))
    )]
    pub fn tls(mut self, tls: Tls) -> Self {
        self.info.tls = tls;
        self
    }

    /// Use a custom configuration for the connection pool
    ///
    /// Defaults can be found at [`PoolConfig`]
    #[cfg(feature = "pool")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pool")))]
    pub fn pool_config(mut self, pool_config: PoolConfig) -> Self {
        self.pool_config = pool_config;
        self
    }

    /// Build the transport
    pub fn build<E>(self) -> AsyncSmtpTransport<E>
    where
        E: Executor,
    {
        let client = AsyncSmtpClient {
            info: self.info,
            marker_: PhantomData,
        };

        #[cfg(feature = "pool")]
        let client = Pool::new(self.pool_config, client);

        AsyncSmtpTransport { inner: client }
    }
}

/// Build client
pub struct AsyncSmtpClient<E> {
    info: SmtpInfo,
    marker_: PhantomData<E>,
}

impl<E> AsyncSmtpClient<E>
where
    E: Executor,
{
    /// Creates a new connection directly usable to send emails
    ///
    /// Handles encryption and authentication
    pub async fn connection(&self) -> Result<AsyncSmtpConnection, Error> {
        let mut conn = E::connect(
            &self.info.server,
            self.info.port,
            self.info.timeout,
            &self.info.hello_name,
            &self.info.tls,
        )
        .await?;

        if let Some(credentials) = &self.info.credentials {
            conn.auth(&self.info.authentication, credentials).await?;
        }
        Ok(conn)
    }
}

impl<E> Debug for AsyncSmtpClient<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("AsyncSmtpClient");
        builder.field("info", &self.info);
        builder.finish()
    }
}

// `clone` is unused when the `pool` feature is on
#[allow(dead_code)]
impl<E> AsyncSmtpClient<E>
where
    E: Executor,
{
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            marker_: PhantomData,
        }
    }
}
