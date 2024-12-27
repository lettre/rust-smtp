//! Provides a strongly typed way to build emails
//!
//! ## Usage
//!
//! This section demonstrates how to build messages.
//!
//! <style>
//! summary, details:not([open]) { cursor: pointer; }
//! </style>
//!
//!
//! ### Plain body
//!
//! The easiest way of creating a message, which uses a plain text body.
//!
//! ```rust
//! use lettre::message::{header::ContentType, Message};
//!
//! # use std::error::Error;
//! # fn main() -> Result<(), Box<dyn Error>> {
//! let m = Message::builder()
//!     .from("NoBody <nobody@domain.tld>".parse()?)
//!     .reply_to("Yuin <yuin@domain.tld>".parse()?)
//!     .to("Hei <hei@domain.tld>".parse()?)
//!     .subject("Happy new year")
//!     .header(ContentType::TEXT_PLAIN)
//!     .body(String::from("Be happy!"))?;
//! # Ok(())
//! # }
//! ```
//!
//! Which produces:
//! <details>
//! <summary>Click to expand</summary>
//!
//! ```sh
//! From: NoBody <nobody@domain.tld>
//! Reply-To: Yuin <yuin@domain.tld>
//! To: Hei <hei@domain.tld>
//! Subject: Happy new year
//! Date: Sat, 12 Dec 2020 16:33:19 GMT
//! Content-Type: text/plain; charset=utf-8
//! Content-Transfer-Encoding: 7bit
//!
//! Be happy!
//! ```
//! </details>
//! <br />
//!
//! The unicode header data is encoded using _UTF8-Base64_ encoding, when necessary.
//!
//! The `Content-Transfer-Encoding` is chosen based on the best encoding
//! available for the given body, between `7bit`, `quoted-printable` and `base64`.
//!
//! ### Plain and HTML body
//!
//! Uses a MIME body to include both plain text and HTML versions of the body.
//!
//! ```rust
//! # use std::error::Error;
//! use lettre::message::{header, Message, MultiPart, SinglePart};
//!
//! # fn main() -> Result<(), Box<dyn Error>> {
//! let m = Message::builder()
//!     .from("NoBody <nobody@domain.tld>".parse()?)
//!     .reply_to("Yuin <yuin@domain.tld>".parse()?)
//!     .to("Hei <hei@domain.tld>".parse()?)
//!     .subject("Happy new year")
//!     .multipart(MultiPart::alternative_plain_html(
//!         String::from("Hello, world! :)"),
//!         String::from("<p><b>Hello</b>, <i>world</i>! <img src=\"cid:123\"></p>"),
//!     ))?;
//! # Ok(())
//! # }
//! ```
//!
//! Which produces:
//! <details>
//! <summary>Click to expand</summary>
//!
//! ```sh
//! From: NoBody <nobody@domain.tld>
//! Reply-To: Yuin <yuin@domain.tld>
//! To: Hei <hei@domain.tld>
//! Subject: Happy new year
//! MIME-Version: 1.0
//! Date: Sat, 12 Dec 2020 16:33:19 GMT
//! Content-Type: multipart/alternative; boundary="0oVZ2r6AoLAhLlb0gPNSKy6BEqdS2IfwxrcbUuo1"
//!
//! --0oVZ2r6AoLAhLlb0gPNSKy6BEqdS2IfwxrcbUuo1
//! Content-Type: text/plain; charset=utf8
//! Content-Transfer-Encoding: 7bit
//!
//! Hello, world! :)
//! --0oVZ2r6AoLAhLlb0gPNSKy6BEqdS2IfwxrcbUuo1
//! Content-Type: text/html; charset=utf8
//! Content-Transfer-Encoding: 7bit
//!
//! <p><b>Hello</b>, <i>world</i>! <img src="cid:123"></p>
//! --0oVZ2r6AoLAhLlb0gPNSKy6BEqdS2IfwxrcbUuo1--
//! ```
//! </details>
//!
//! ### Complex MIME body
//!
//! This example shows how to include both plain and HTML versions of the body,
//! attachments and inlined images.
//!
//! ```rust
//! # use std::error::Error;
//! use std::fs;
//!
//! use lettre::message::{header, Attachment, Body, Message, MultiPart, SinglePart};
//!
//! # fn main() -> Result<(), Box<dyn Error>> {
//! let image = fs::read("docs/lettre.png")?;
//! // this image_body can be cloned and reused between emails.
//! // since `Body` holds a pre-encoded body, reusing it means avoiding having
//! // to re-encode the same body for every email (this clearly only applies
//! // when sending multiple emails with the same attachment).
//! let image_body = Body::new(image);
//!
//! let m = Message::builder()
//!     .from("NoBody <nobody@domain.tld>".parse()?)
//!     .reply_to("Yuin <yuin@domain.tld>".parse()?)
//!     .to("Hei <hei@domain.tld>".parse()?)
//!     .subject("Happy new year")
//!     .multipart(
//!         MultiPart::mixed()
//!             .multipart(
//!                 MultiPart::alternative()
//!                     .singlepart(SinglePart::plain(String::from("Hello, world! :)")))
//!                     .multipart(
//!                         MultiPart::related()
//!                             .singlepart(SinglePart::html(String::from(
//!                                 "<p><b>Hello</b>, <i>world</i>! <img src=cid:123></p>",
//!                             )))
//!                             .singlepart(
//!                                 Attachment::new_inline(String::from("123"))
//!                                     .body(image_body, "image/png".parse().unwrap()),
//!                             ),
//!                     ),
//!             )
//!             .singlepart(Attachment::new(String::from("example.rs")).body(
//!                 String::from("fn main() { println!(\"Hello, World!\") }"),
//!                 "text/plain".parse().unwrap(),
//!             )),
//!     )?;
//! # Ok(())
//! # }
//! ```
//!
//! Which produces:
//! <details>
//! <summary>Click to expand</summary>
//!
//! ```sh
//! From: NoBody <nobody@domain.tld>
//! Reply-To: Yuin <yuin@domain.tld>
//! To: Hei <hei@domain.tld>
//! Subject: Happy new year
//! MIME-Version: 1.0
//! Date: Sat, 12 Dec 2020 16:30:45 GMT
//! Content-Type: multipart/mixed; boundary="0oVZ2r6AoLAhLlb0gPNSKy6BEqdS2IfwxrcbUuo1"
//!
//! --0oVZ2r6AoLAhLlb0gPNSKy6BEqdS2IfwxrcbUuo1
//! Content-Type: multipart/alternative; boundary="EyXdAZIgZuyUjAounq4Aj44a6MpJfqCKhm6pE1zk"
//!
//! --EyXdAZIgZuyUjAounq4Aj44a6MpJfqCKhm6pE1zk
//! Content-Type: text/plain; charset=utf8
//! Content-Transfer-Encoding: 7bit
//!
//! Hello, world! :)
//! --EyXdAZIgZuyUjAounq4Aj44a6MpJfqCKhm6pE1zk
//! Content-Type: multipart/related; boundary="eM5Z18WZVOQsqi5GQ71XGAXk6NNvHUA1Xv1FWrXr"
//!
//! --eM5Z18WZVOQsqi5GQ71XGAXk6NNvHUA1Xv1FWrXr
//! Content-Type: text/html; charset=utf8
//! Content-Transfer-Encoding: 7bit
//!
//! <p><b>Hello</b>, <i>world</i>! <img src=cid:123></p>
//! --eM5Z18WZVOQsqi5GQ71XGAXk6NNvHUA1Xv1FWrXr
//! Content-Type: image/png
//! Content-Disposition: inline
//! Content-ID: <123>
//! Content-Transfer-Encoding: base64
//!
//! PHNtaWxlLXJhdy1pbWFnZS1kYXRhPg==
//! --eM5Z18WZVOQsqi5GQ71XGAXk6NNvHUA1Xv1FWrXr--
//! --EyXdAZIgZuyUjAounq4Aj44a6MpJfqCKhm6pE1zk--
//! --0oVZ2r6AoLAhLlb0gPNSKy6BEqdS2IfwxrcbUuo1
//! Content-Type: text/plain; charset=utf8
//! Content-Disposition: attachment; filename="example.rs"
//! Content-Transfer-Encoding: 7bit
//!
//! fn main() { println!("Hello, World!") }
//! --0oVZ2r6AoLAhLlb0gPNSKy6BEqdS2IfwxrcbUuo1--
//! ```
//! </details>

use std::{io::Write, iter, time::SystemTime};

pub use attachment::Attachment;
pub use body::{Body, IntoBody, MaybeString};
#[cfg(feature = "dkim")]
pub use dkim::*;
pub use mailbox::*;
pub use mimebody::*;

mod attachment;
mod body;
#[cfg(feature = "dkim")]
pub mod dkim;
#[cfg(all(feature = "dkim", feature = "gpgme"))]
pub mod gnupg;
pub mod header;
mod mailbox;
mod mimebody;

use crate::{
    address::Envelope,
    message::header::{ContentTransferEncoding, Header, Headers, MailboxesHeader},
    Error as EmailError,
};

const DEFAULT_MESSAGE_ID_DOMAIN: &str = "localhost";

/// Something that can be formatted as an email message
trait EmailFormat {
    // Use a writer?
    fn format(&self, out: &mut Vec<u8>);
}

/// A builder for messages
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    headers: Headers,
    envelope: Option<Envelope>,
    drop_bcc: bool,
}

impl MessageBuilder {
    /// Creates a new default message builder
    pub fn new() -> Self {
        Self {
            headers: Headers::new(),
            envelope: None,
            drop_bcc: true,
        }
    }

    /// Set or add mailbox to `From` header
    ///
    /// Defined in [RFC5322](https://tools.ietf.org/html/rfc5322#section-3.6.2).
    ///
    /// Shortcut for `self.mailbox(header::From(mbox))`.
    pub fn from(self, mbox: Mailbox) -> Self {
        self.mailbox(header::From::from(Mailboxes::from(mbox)))
    }

    /// Set `Sender` header. Should be used when providing several `From` mailboxes.
    ///
    /// Defined in [RFC5322](https://tools.ietf.org/html/rfc5322#section-3.6.2).
    ///
    /// Shortcut for `self.header(header::Sender(mbox))`.
    pub fn sender(self, mbox: Mailbox) -> Self {
        self.header(header::Sender::from(mbox))
    }

    /// Add `Date` header to message
    ///
    /// Shortcut for `self.header(header::Date::new(st))`.
    pub fn date(self, st: SystemTime) -> Self {
        self.header(header::Date::new(st))
    }

    /// Set `Date` header using current date/time
    ///
    /// Shortcut for `self.date(SystemTime::now())`, it is automatically inserted
    /// if no date has been provided.
    pub fn date_now(self) -> Self {
        self.date(SystemTime::now())
    }

    /// Set or add mailbox to `ReplyTo` header
    ///
    /// Defined in [RFC5322](https://tools.ietf.org/html/rfc5322#section-3.6.2).
    ///
    /// Shortcut for `self.mailbox(header::ReplyTo(mbox))`.
    pub fn reply_to(self, mbox: Mailbox) -> Self {
        self.mailbox(header::ReplyTo(mbox.into()))
    }

    /// Set or add mailbox to `To` header
    ///
    /// Shortcut for `self.mailbox(header::To(mbox))`.
    pub fn to(self, mbox: Mailbox) -> Self {
        self.mailbox(header::To(mbox.into()))
    }

    /// Set or add mailbox to `Cc` header
    ///
    /// Shortcut for `self.mailbox(header::Cc(mbox))`.
    pub fn cc(self, mbox: Mailbox) -> Self {
        self.mailbox(header::Cc(mbox.into()))
    }

    /// Set or add mailbox to `Bcc` header
    ///
    /// Shortcut for `self.mailbox(header::Bcc(mbox))`.
    pub fn bcc(self, mbox: Mailbox) -> Self {
        self.mailbox(header::Bcc(mbox.into()))
    }

    /// Set or add message id to [`In-Reply-To`
    /// header](https://tools.ietf.org/html/rfc5322#section-3.6.4)
    pub fn in_reply_to(self, id: String) -> Self {
        self.header(header::InReplyTo::from(id))
    }

    /// Set or add message id to [`References`
    /// header](https://tools.ietf.org/html/rfc5322#section-3.6.4)
    pub fn references(self, id: String) -> Self {
        self.header(header::References::from(id))
    }

    /// Set `Subject` header to message
    ///
    /// Shortcut for `self.header(header::Subject(subject.into()))`.
    pub fn subject<S: Into<String>>(self, subject: S) -> Self {
        let s: String = subject.into();
        self.header(header::Subject::from(s))
    }

    /// Set [Message-ID
    /// header](https://tools.ietf.org/html/rfc5322#section-3.6.4)
    ///
    /// Should generally be inserted by the mail relay.
    ///
    /// If `None` is provided, an id will be generated in the
    /// `<UUID@HOSTNAME>`.
    pub fn message_id(self, id: Option<String>) -> Self {
        match id {
            Some(i) => self.header(header::MessageId::from(i)),
            None => {
                #[cfg(feature = "hostname")]
                let hostname = hostname::get()
                    .map_err(|_| ())
                    .and_then(|s| s.into_string().map_err(|_| ()))
                    .unwrap_or_else(|()| DEFAULT_MESSAGE_ID_DOMAIN.to_owned());
                #[cfg(not(feature = "hostname"))]
                let hostname = DEFAULT_MESSAGE_ID_DOMAIN.to_owned();

                self.header(header::MessageId::from(
                    // https://tools.ietf.org/html/rfc5322#section-3.6.4
                    format!("<{}@{}>", make_message_id(), hostname),
                ))
            }
        }
    }

    /// Set [User-Agent
    /// header](https://tools.ietf.org/html/draft-melnikov-email-user-agent-00)
    pub fn user_agent(self, id: String) -> Self {
        self.header(header::UserAgent::from(id))
    }

    /// Set custom header to message
    pub fn header<H: Header>(mut self, header: H) -> Self {
        self.headers.set(header);
        self
    }

    /// Add mailbox to header
    pub fn mailbox<H: Header + MailboxesHeader>(self, header: H) -> Self {
        match self.headers.get::<H>() {
            Some(mut header_) => {
                header_.join_mailboxes(header);
                self.header(header_)
            }
            None => self.header(header),
        }
    }

    /// Force specific envelope (by default it is derived from headers)
    pub fn envelope(mut self, envelope: Envelope) -> Self {
        self.envelope = Some(envelope);
        self
    }

    /// Keep the `Bcc` header
    ///
    /// By default, the `Bcc` header is removed from the email after
    /// using it to generate the message envelope. In some cases though,
    /// like when saving the email as an `.eml`, or sending through
    /// some transports (like the Gmail API) that don't take a separate
    /// envelope value, it becomes necessary to keep the `Bcc` header.
    ///
    /// Calling this method overrides the default behavior.
    pub fn keep_bcc(mut self) -> Self {
        self.drop_bcc = false;
        self
    }

    // TODO: High-level methods for attachments and embedded files

    /// Create message from body
    fn build(self, body: MessageBody) -> Result<Message, EmailError> {
        // Check for missing required headers
        // https://tools.ietf.org/html/rfc5322#section-3.6

        // Insert Date if missing
        let mut res = if self.headers.get::<header::Date>().is_none() {
            self.date_now()
        } else {
            self
        };

        // Fail is missing correct originator (Sender or From)
        match res.headers.get::<header::From>() {
            Some(header::From(f)) => {
                let from: Vec<Mailbox> = f.into();
                if from.len() > 1 && res.headers.get::<header::Sender>().is_none() {
                    return Err(EmailError::TooManyFrom);
                }
            }
            None => {
                return Err(EmailError::MissingFrom);
            }
        }

        let envelope = match res.envelope {
            Some(e) => e,
            None => Envelope::try_from(&res.headers)?,
        };

        if res.drop_bcc {
            // Remove `Bcc` headers now the envelope is set
            res.headers.remove::<header::Bcc>();
        }

        Ok(Message {
            headers: res.headers,
            body,
            envelope,
        })
    }

    /// Create [`Message`] using a [`Vec<u8>`], [`String`], or [`Body`] body
    ///
    /// Automatically gets encoded with `7bit`, `quoted-printable` or `base64`
    /// `Content-Transfer-Encoding`, based on the most efficient and valid encoding
    /// for `body`.
    pub fn body<T: IntoBody>(mut self, body: T) -> Result<Message, EmailError> {
        let maybe_encoding = self.headers.get::<ContentTransferEncoding>();
        let body = body.into_body(maybe_encoding);

        self.headers.set(body.encoding());
        self.build(MessageBody::Raw(body.into_vec()))
    }

    /// Create message using mime body ([`MultiPart`])
    pub fn multipart(self, part: MultiPart) -> Result<Message, EmailError> {
        self.mime_1_0().build(MessageBody::Mime(Part::Multi(part)))
    }

    /// Create message using mime body ([`SinglePart`])
    pub fn singlepart(self, part: SinglePart) -> Result<Message, EmailError> {
        self.mime_1_0().build(MessageBody::Mime(Part::Single(part)))
    }

    /// Set `MIME-Version` header to 1.0
    ///
    /// Shortcut for `self.header(header::MIME_VERSION_1_0)`.
    ///
    /// Not exposed as it is set by body methods
    fn mime_1_0(self) -> Self {
        self.header(header::MIME_VERSION_1_0)
    }
}

/// Email message which can be formatted
#[cfg_attr(docsrs, doc(cfg(feature = "builder")))]
#[derive(Clone, Debug)]
pub struct Message {
    headers: Headers,
    body: MessageBody,
    envelope: Envelope,
}

#[derive(Clone, Debug)]
enum MessageBody {
    Mime(Part),
    Raw(Vec<u8>),
}

impl Message {
    /// Create a new message builder without headers
    pub fn builder() -> MessageBuilder {
        MessageBuilder::new()
    }

    /// Get the headers from the Message
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Get a mutable reference to the headers
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Get `Message` envelope
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// Get message content formatted for SMTP
    pub fn formatted(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.format(&mut out);
        out
    }

    #[cfg(feature = "dkim")]
    /// Format body for signing
    pub(crate) fn body_raw(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.body {
            MessageBody::Mime(p) => p.format_body(&mut out),
            MessageBody::Raw(r) => out.extend_from_slice(r),
        };
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Sign the message using Dkim
    ///
    /// Example:
    /// ```rust
    /// use lettre::{
    ///     message::{
    ///         dkim::{DkimConfig, DkimSigningAlgorithm, DkimSigningKey},
    ///         header::ContentType,
    ///     },
    ///     Message,
    /// };
    ///
    /// let mut message = Message::builder()
    ///     .from("Alice <alice@example.org>".parse().unwrap())
    ///     .reply_to("Bob <bob@example.org>".parse().unwrap())
    ///     .to("Carla <carla@example.net>".parse().unwrap())
    ///     .subject("Hello")
    ///     .header(ContentType::TEXT_PLAIN)
    ///     .body("Hi there, it's a test email, with utf-8 chars ë!\n\n\n".to_owned())
    ///     .unwrap();
    /// let key = "-----BEGIN RSA PRIVATE KEY-----
    /// MIIEowIBAAKCAQEAt2gawjoybf0mAz0mSX0cq1ah5F9cPazZdCwLnFBhRufxaZB8
    /// NLTdc9xfPIOK8l/xGrN7Nd63J4cTATqZukumczkA46O8YKHwa53pNT6NYwCNtDUL
    /// eBu+7xUW18GmDzkIFkxGO2R5kkTeWPlKvKpEiicIMfl0OmyW/fI3AbtM7e/gmqQ4
    /// kEYIO0mTjPT+jTgWE4JIi5KUTHudUBtfMKcSFyM2HkUOExl1c9+A4epjRFQwEXMA
    /// hM5GrqZoOdUm4fIpvGpLIGIxFgHPpZYbyq6yJZzH3+5aKyCHrsHawPuPiCD45zsU
    /// re31zCE6b6k1sDiiBR4CaRHnbL7hxFp0aNLOVQIDAQABAoIBAGMK3gBrKxaIcUGo
    /// gQeIf7XrJ6vK72YC9L8uleqI4a9Hy++E7f4MedZ6eBeWta8jrnEL4Yp6xg+beuDc
    /// A24+Mhng+6Dyp+TLLqj+8pQlPnbrMprRVms7GIXFrrs+wO1RkBNyhy7FmH0roaMM
    /// pJZzoGW2pE9QdbqjL3rdlWTi/60xRX9eZ42nNxYnbc+RK03SBd46c3UBha6Y9iQX
    /// 562yWilDnB5WCX2tBoSN39bEhJvuZDzMwOuGw68Q96Hdz82Iz1xVBnRhH+uNStjR
    /// VnAssSHVxPSpwWrm3sHlhjBHWPnNIaOKIKl1lbL+qWfVQCj/6a5DquC+vYAeYR6L
    /// 3mA0z0ECgYEA5YkNYcILSXyE0hZ8eA/t58h8eWvYI5iqt3nT4fznCoYJJ74Vukeg
    /// 6BTlq/CsanwT1lDtvDKrOaJbA7DPTES/bqT0HoeIdOvAw9w/AZI5DAqYp61i6RMK
    /// xfAQL/Ik5MDFN8gEMLLXRVMe/aR27f6JFZpShJOK/KCzHqikKfYVJ+UCgYEAzI2F
    /// ZlTyittWSyUSl5UKyfSnFOx2+6vNy+lu5DeMJu8Wh9rqBk388Bxq98CfkCseWESN
    /// pTCGdYltz9DvVNBdBLwSMdLuYJAI6U+Zd70MWyuNdHFPyWVHUNqMUBvbUtj2w74q
    /// Hzu0GI0OrRjdX6C63S17PggmT/N2R9X7P4STxbECgYA+AZAD4I98Ao8+0aQ+Ks9x
    /// 1c8KXf+9XfiAKAD9A3zGcv72JXtpHwBwsXR5xkJNYcdaFfKi7G0k3J8JmDHnwIqW
    /// MSlhNeu+6hDg2BaNLhsLDbG/Wi9mFybJ4df9m8Qrp4efUgEPxsAwkgvFKTCXijMu
    /// CspP1iutoxvAJH50d22voQKBgDIsSFtIXNGYaTs3Va8enK3at5zXP3wNsQXiNRP/
    /// V/44yNL77EktmewfXFF2yuym1uOZtRCerWxpEClYO0wXa6l8pA3aiiPfUIBByQfo
    /// s/4s2Z6FKKfikrKPWLlRi+NvWl+65kQQ9eTLvJzSq4IIP61+uWsGvrb/pbSLFPyI
    /// fWKRAoGBALFCStBXvdMptjq4APUzAdJ0vytZzXkOZHxgmc+R0fQn22OiW0huW6iX
    /// JcaBbL6ZSBIMA3AdaIjtvNRiomueHqh0GspTgOeCE2585TSFnw6vEOJ8RlR4A0Mw
    /// I45fbR4l+3D/30WMfZlM6bzZbwPXEnr2s1mirmuQpjumY9wLhK25
    /// -----END RSA PRIVATE KEY-----";
    /// let signing_key = DkimSigningKey::new(key, DkimSigningAlgorithm::Rsa).unwrap();
    /// message.sign(&DkimConfig::default_config(
    ///     "dkimtest".to_owned(),
    ///     "example.org".to_owned(),
    ///     signing_key,
    /// ));
    /// println!(
    ///     "message: {}",
    ///     std::str::from_utf8(&message.formatted()).unwrap()
    /// );
    /// ```
    #[cfg(feature = "dkim")]
    pub fn sign(&mut self, dkim_config: &DkimConfig) {
        dkim_sign(self, dkim_config);
    }
}

impl EmailFormat for Message {
    fn format(&self, out: &mut Vec<u8>) {
        write!(out, "{}", self.headers)
            .expect("A Write implementation panicked while formatting headers");

        match &self.body {
            MessageBody::Mime(p) => p.format(out),
            MessageBody::Raw(r) => {
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(r)
            }
        }
    }
}

impl Default for MessageBuilder {
    fn default() -> Self {
        MessageBuilder::new()
    }
}

/// Create a random message id.
/// (Not cryptographically random)
fn make_message_id() -> String {
    iter::repeat_with(fastrand::alphanumeric).take(36).collect()
}

#[cfg(test)]
mod test {
    use std::time::{Duration, SystemTime};

    use pretty_assertions::assert_eq;

    use super::{header, mailbox::Mailbox, make_message_id, Message, MultiPart, SinglePart};

    #[test]
    fn email_missing_originator() {
        assert!(Message::builder()
            .body(String::from("Happy new year!"))
            .is_err());
    }

    #[test]
    fn email_minimal_message() {
        assert!(Message::builder()
            .from("NoBody <nobody@domain.tld>".parse().unwrap())
            .to("NoBody <nobody@domain.tld>".parse().unwrap())
            .body(String::from("Happy new year!"))
            .is_ok());
    }

    #[test]
    fn email_missing_sender() {
        assert!(Message::builder()
            .from("NoBody <nobody@domain.tld>".parse().unwrap())
            .from("AnyBody <anybody@domain.tld>".parse().unwrap())
            .body(String::from("Happy new year!"))
            .is_err());
    }

    #[test]
    fn email_message_no_bcc() {
        // Tue, 15 Nov 1994 08:12:31 GMT
        let date = SystemTime::UNIX_EPOCH + Duration::from_secs(784887151);

        let email = Message::builder()
            .date(date)
            .bcc("hidden@example.com".parse().unwrap())
            .header(header::From(
                vec![Mailbox::new(
                    Some("Каи".into()),
                    "kayo@example.com".parse().unwrap(),
                )]
                .into(),
            ))
            .header(header::To(
                vec!["Pony O.P. <pony@domain.tld>".parse().unwrap()].into(),
            ))
            .header(header::Subject::from(String::from("яңа ел белән!")))
            .body(String::from("Happy new year!"))
            .unwrap();

        assert_eq!(
            String::from_utf8(email.formatted()).unwrap(),
            concat!(
                "Date: Tue, 15 Nov 1994 08:12:31 +0000\r\n",
                "From: =?utf-8?b?0JrQsNC4?= <kayo@example.com>\r\n",
                "To: \"Pony O.P.\" <pony@domain.tld>\r\n",
                "Subject: =?utf-8?b?0Y/So9CwINC10Lsg0LHQtdC705nQvSE=?=\r\n",
                "Content-Transfer-Encoding: 7bit\r\n",
                "\r\n",
                "Happy new year!"
            )
        );
    }

    #[test]
    fn email_message_keep_bcc() {
        // Tue, 15 Nov 1994 08:12:31 GMT
        let date = SystemTime::UNIX_EPOCH + Duration::from_secs(784887151);

        let email = Message::builder()
            .date(date)
            .bcc("hidden@example.com".parse().unwrap())
            .keep_bcc()
            .header(header::From(
                vec![Mailbox::new(
                    Some("Каи".into()),
                    "kayo@example.com".parse().unwrap(),
                )]
                .into(),
            ))
            .header(header::To(
                vec!["Pony O.P. <pony@domain.tld>".parse().unwrap()].into(),
            ))
            .header(header::Subject::from(String::from("яңа ел белән!")))
            .body(String::from("Happy new year!"))
            .unwrap();

        assert_eq!(
            String::from_utf8(email.formatted()).unwrap(),
            concat!(
                "Date: Tue, 15 Nov 1994 08:12:31 +0000\r\n",
                "Bcc: hidden@example.com\r\n",
                "From: =?utf-8?b?0JrQsNC4?= <kayo@example.com>\r\n",
                "To: \"Pony O.P.\" <pony@domain.tld>\r\n",
                "Subject: =?utf-8?b?0Y/So9CwINC10Lsg0LHQtdC705nQvSE=?=\r\n",
                "Content-Transfer-Encoding: 7bit\r\n",
                "\r\n",
                "Happy new year!"
            )
        );
    }

    #[test]
    fn email_with_png() {
        // Tue, 15 Nov 1994 08:12:31 GMT
        let date = SystemTime::UNIX_EPOCH + Duration::from_secs(784887151);
        let img = std::fs::read("./docs/lettre.png").unwrap();
        let m = Message::builder()
            .date(date)
            .from("NoBody <nobody@domain.tld>".parse().unwrap())
            .reply_to("Yuin <yuin@domain.tld>".parse().unwrap())
            .to("Hei <hei@domain.tld>".parse().unwrap())
            .subject("Happy new year")
            .multipart(
                MultiPart::related()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(String::from(
                                "<p><b>Hello</b>, <i>world</i>! <img src=cid:123></p>",
                            )),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::parse("image/png").unwrap())
                            .header(header::ContentDisposition::inline())
                            .header(header::ContentId::from(String::from("<123>")))
                            .body(img),
                    ),
            )
            .unwrap();

        let output = String::from_utf8(m.formatted()).unwrap();
        let file_expected = std::fs::read("./testdata/email_with_png.eml").unwrap();
        let expected = String::from_utf8(file_expected).unwrap();

        for (i, line) in output.lines().zip(expected.lines()).enumerate() {
            if i == 7 || i == 9 || i == 14 || i == 233 {
                continue;
            }

            assert_eq!(line.0, line.1)
        }
    }

    #[test]
    fn test_make_message_id() {
        let mut ids = std::collections::HashSet::with_capacity(10);
        for _ in 0..1000 {
            ids.insert(make_message_id());
        }

        // Ensure there are no duplicates
        assert_eq!(1000, ids.len());

        // Ensure correct length
        for id in ids {
            assert_eq!(36, id.len());
        }
    }
}
