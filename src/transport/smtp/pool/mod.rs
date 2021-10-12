use std::time::Duration;

#[cfg(all(feature = "pool", any(feature = "tokio1", feature = "async-std1")))]
pub mod async_impl;
#[cfg(feature = "r2d2")]
pub mod sync_impl;

/// Configuration for a connection pool
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
#[cfg_attr(docsrs, doc(cfg(any(feature = "r2d2", feature = "pool"))))]
pub struct PoolConfig {
    min_idle: u32,
    max_size: u32,
    connection_timeout: Duration,
    idle_timeout: Duration,
    pub(crate) get_timeout: Option<Duration>,
}

impl PoolConfig {
    /// Create a new pool configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Minimum number of idle connections
    ///
    /// Defaults to `0`
    pub fn min_idle(mut self, min_idle: u32) -> Self {
        self.min_idle = min_idle;
        self
    }

    /// Maximum number of pooled connections
    ///
    /// Defaults to `10`
    pub fn max_size(mut self, max_size: u32) -> Self {
        self.max_size = max_size;
        self
    }

    /// Connection timeout
    ///
    /// Defaults to `30 seconds`
    #[doc(hidden)]
    #[deprecated(note = "The Connection timeout is already configured on the SMTP transport")]
    pub fn connection_timeout(mut self, connection_timeout: Duration) -> Self {
        self.connection_timeout = connection_timeout;
        self
    }

    /// Connection idle timeout
    ///
    /// Defaults to `60 seconds`
    pub fn idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Connection get timeout
    ///
    /// Defaults to `None`, meaning no timeout.
    pub fn get_timeout(mut self, get_timeout: Option<Duration>) -> Self {
        self.get_timeout = get_timeout;
        self
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_idle: 0,
            max_size: 10,
            connection_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            get_timeout: None,
        }
    }
}
