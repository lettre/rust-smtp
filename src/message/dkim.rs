use std::{
    borrow::Cow,
    error::Error as StdError,
    fmt::{self, Display},
    time::SystemTime,
};

use ed25519_dalek::Signer;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1v15::Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

use crate::message::{
    header::{HeaderName, HeaderValue},
    Headers, Message,
};

/// Describe Dkim Canonicalization to apply to either body or headers
#[derive(Copy, Clone, Debug)]
pub enum DkimCanonicalizationType {
    Simple,
    Relaxed,
}

impl Display for DkimCanonicalizationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DkimCanonicalizationType::Simple => "simple",
            DkimCanonicalizationType::Relaxed => "relaxed",
        })
    }
}

/// Describe Canonicalization to be applied before signing
#[derive(Copy, Clone, Debug)]
pub struct DkimCanonicalization {
    pub header: DkimCanonicalizationType,
    pub body: DkimCanonicalizationType,
}

impl Default for DkimCanonicalization {
    fn default() -> Self {
        DkimCanonicalization {
            header: DkimCanonicalizationType::Simple,
            body: DkimCanonicalizationType::Relaxed,
        }
    }
}

/// Format canonicalization to be shown in Dkim header
impl Display for DkimCanonicalization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.header, self.body)
    }
}

/// Describe the algorithm used for signing the message
#[derive(Copy, Clone, Debug)]
pub enum DkimSigningAlgorithm {
    Rsa,
    Ed25519,
}

impl Display for DkimSigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DkimSigningAlgorithm::Rsa => "rsa",
            DkimSigningAlgorithm::Ed25519 => "ed25519",
        })
    }
}

/// Describe DkimSigning key error
#[derive(Debug)]
pub struct DkimSigningKeyError(InnerDkimSigningKeyError);

#[derive(Debug)]
enum InnerDkimSigningKeyError {
    Base64(base64::DecodeError),
    Rsa(rsa::pkcs1::Error),
    Ed25519(ed25519_dalek::ed25519::Error),
}

impl Display for DkimSigningKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match &self.0 {
            InnerDkimSigningKeyError::Base64(_err) => "base64 decode error",
            InnerDkimSigningKeyError::Rsa(_err) => "rsa decode error",
            InnerDkimSigningKeyError::Ed25519(_err) => "ed25519 decode error",
        })
    }
}

impl StdError for DkimSigningKeyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(match &self.0 {
            InnerDkimSigningKeyError::Base64(err) => err,
            InnerDkimSigningKeyError::Rsa(err) => err,
            InnerDkimSigningKeyError::Ed25519(err) => err,
        })
    }
}

/// Describe a signing key to be carried by DkimConfig struct
#[derive(Debug)]
pub struct DkimSigningKey(InnerDkimSigningKey);

#[derive(Debug)]
enum InnerDkimSigningKey {
    Rsa(RsaPrivateKey),
    Ed25519(ed25519_dalek::SigningKey),
    #[cfg(feature = "gpgme")]
    Gnupg(DkimSigningAlgorithm, gpgme::Key),
}

impl DkimSigningKey {
    #[cfg(feature = "gpgme")]
    /// Retrieve the secret key from gnupg using the fingerprint.
    ///
    /// Note that even if subkey fingerprint is provided,
    /// the **key** will be retrieved instead of **subkey**,
    /// and gpg will select the newest available subkey
    /// of the key to sign data.
    pub fn new_gpg(
        key_fingerprint: impl cstr_argument::CStrArgument,
    ) -> Result<Self, super::gnupg::GpgGetKeyError> {
        use super::gnupg::{gpg_key_algorithm, GpgGetKeyError};
        use gpgme::{Context, Protocol};
        let mut gpg =
            Context::from_protocol(Protocol::OpenPgp).map_err(GpgGetKeyError::GpgError)?;
        let key = gpg
            .get_secret_key(key_fingerprint)
            .map_err(GpgGetKeyError::GpgError)?;
        Ok(DkimSigningKey(InnerDkimSigningKey::Gnupg(
            gpg_key_algorithm(&key)?,
            key,
        )))
    }
    pub fn new(
        private_key: &str,
        algorithm: DkimSigningAlgorithm,
    ) -> Result<DkimSigningKey, DkimSigningKeyError> {
        Ok(Self(match algorithm {
            DkimSigningAlgorithm::Rsa => InnerDkimSigningKey::Rsa(
                RsaPrivateKey::from_pkcs1_pem(private_key)
                    .map_err(|err| DkimSigningKeyError(InnerDkimSigningKeyError::Rsa(err)))?,
            ),
            DkimSigningAlgorithm::Ed25519 => {
                InnerDkimSigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                    &crate::base64::decode(private_key)
                        .map_err(|err| DkimSigningKeyError(InnerDkimSigningKeyError::Base64(err)))?
                        .try_into()
                        .map_err(|_| {
                            DkimSigningKeyError(InnerDkimSigningKeyError::Ed25519(
                                ed25519_dalek::ed25519::Error::new(),
                            ))
                        })?,
                ))
            }
        }))
    }
    fn get_signing_algorithm(&self) -> DkimSigningAlgorithm {
        match self.0 {
            InnerDkimSigningKey::Rsa(_) => DkimSigningAlgorithm::Rsa,
            InnerDkimSigningKey::Ed25519(_) => DkimSigningAlgorithm::Ed25519,
            #[cfg(feature = "gpgme")]
            InnerDkimSigningKey::Gnupg(algo, _) => algo,
        }
    }
}

/// A struct to describe Dkim configuration applied when signing a message
#[derive(Debug)]
pub struct DkimConfig {
    /// The name of the key published in DNS
    selector: String,
    /// The domain for which we sign the message
    domain: String,
    /// The private key in PKCS1 string format
    private_key: DkimSigningKey,
    /// A list of header names to be included in the signature. Signing of more than one
    /// header with the same name is not supported
    headers: Vec<HeaderName>,
    /// The signing algorithm to be used when signing
    canonicalization: DkimCanonicalization,
}

impl DkimConfig {
    /// Create a default signature configuration with a set of headers and "simple/relaxed"
    /// canonicalization
    pub fn default_config(
        selector: String,
        domain: String,
        private_key: DkimSigningKey,
    ) -> DkimConfig {
        DkimConfig {
            selector,
            domain,
            private_key,
            headers: vec![
                HeaderName::new_from_ascii_str("From"),
                HeaderName::new_from_ascii_str("Subject"),
                HeaderName::new_from_ascii_str("To"),
                HeaderName::new_from_ascii_str("Date"),
            ],
            canonicalization: DkimCanonicalization {
                header: DkimCanonicalizationType::Simple,
                body: DkimCanonicalizationType::Relaxed,
            },
        }
    }

    /// Create a DkimConfig
    pub fn new(
        selector: String,
        domain: String,
        private_key: DkimSigningKey,
        headers: Vec<HeaderName>,
        canonicalization: DkimCanonicalization,
    ) -> DkimConfig {
        DkimConfig {
            selector,
            domain,
            private_key,
            headers,
            canonicalization,
        }
    }
}

/// Create a Headers struct with a Dkim-Signature Header created from given parameters
fn dkim_header_format(
    config: &DkimConfig,
    timestamp: u64,
    headers_list: &str,
    body_hash: &str,
    signature: &str,
) -> Headers {
    let mut headers = Headers::new();
    let header_name =
        dkim_canonicalize_header_tag("DKIM-Signature", config.canonicalization.header);
    let header_name = HeaderName::new_from_ascii(header_name.into()).unwrap();
    headers.insert_raw(HeaderValue::new(header_name, format!("v=1; a={signing_algorithm}-sha256; d={domain}; s={selector}; c={canon}; q=dns/txt; t={timestamp}; h={headers_list}; bh={body_hash}; b={signature}",domain=config.domain, selector=config.selector,canon=config.canonicalization,timestamp=timestamp,headers_list=headers_list,body_hash=body_hash,signature=signature,signing_algorithm=config.private_key.get_signing_algorithm())));
    headers
}

/// Canonicalize the body of an email
fn dkim_canonicalize_body(
    mut body: &[u8],
    canonicalization: DkimCanonicalizationType,
) -> Cow<'_, [u8]> {
    match canonicalization {
        DkimCanonicalizationType::Simple => {
            // Remove empty lines at end
            while body.ends_with(b"\r\n\r\n") {
                body = &body[..body.len() - 2];
            }
            Cow::Borrowed(body)
        }
        DkimCanonicalizationType::Relaxed => {
            let mut out = Vec::with_capacity(body.len());
            loop {
                match body {
                    [b' ' | b'\t', b'\r', b'\n', ..] => {}
                    [b' ' | b'\t', b' ' | b'\t', ..] => {}
                    [b' ' | b'\t', ..] => out.push(b' '),
                    [c, ..] => out.push(*c),
                    [] => break,
                }
                body = &body[1..];
            }
            // Remove empty lines at end
            while out.ends_with(b"\r\n\r\n") {
                out.truncate(out.len() - 2);
            }
            Cow::Owned(out)
        }
    }
}

fn dkim_canonicalize_headers_relaxed(headers: &str) -> String {
    let mut r = String::with_capacity(headers.len());

    fn skip_whitespace(h: &str) -> &str {
        match h.as_bytes().first() {
            Some(b' ' | b'\t') => skip_whitespace(&h[1..]),
            _ => h,
        }
    }

    fn name(h: &str, out: &mut String) {
        if let Some(name_end) = h.bytes().position(|c| c == b':') {
            let (name, rest) = h.split_at(name_end + 1);
            *out += name;
            // Space after header colon is stripped.
            value(skip_whitespace(rest), out);
        } else {
            // This should never happen.
            *out += h;
        }
    }

    fn value(h: &str, out: &mut String) {
        match h.as_bytes() {
            // Continuation lines.
            [b'\r', b'\n', b' ' | b'\t', ..] => {
                out.push(' ');
                value(skip_whitespace(&h[2..]), out);
            }
            // End of header.
            [b'\r', b'\n', ..] => {
                *out += "\r\n";
                name(&h[2..], out)
            }
            // Sequential whitespace.
            [b' ' | b'\t', b' ' | b'\t' | b'\r', ..] => value(&h[1..], out),
            // All whitespace becomes spaces.
            [b'\t', ..] => {
                out.push(' ');
                value(&h[1..], out)
            }
            [_, ..] => {
                let mut chars = h.chars();
                out.push(chars.next().unwrap());
                value(chars.as_str(), out)
            }
            [] => {}
        }
    }

    name(headers, &mut r);

    r
}

/// Canonicalize header tag
fn dkim_canonicalize_header_tag(
    name: &str,
    canonicalization: DkimCanonicalizationType,
) -> Cow<'_, str> {
    match canonicalization {
        DkimCanonicalizationType::Simple => Cow::Borrowed(name),
        DkimCanonicalizationType::Relaxed => Cow::Owned(name.to_lowercase()),
    }
}

/// Canonicalize signed headers passed as headers_list among mail_headers using canonicalization
fn dkim_canonicalize_headers<'a>(
    headers_list: impl IntoIterator<Item = &'a str>,
    mail_headers: &Headers,
    canonicalization: DkimCanonicalizationType,
) -> String {
    let mut covered_headers = Headers::new();
    for name in headers_list {
        if let Some(h) = mail_headers.find_header(name) {
            let name = dkim_canonicalize_header_tag(name, canonicalization);
            covered_headers.insert_raw(HeaderValue::dangerous_new_pre_encoded(
                HeaderName::new_from_ascii(name.into()).unwrap(),
                h.get_raw().into(),
                h.get_encoded().into(),
            ));
        }
    }

    let serialized = covered_headers.to_string();

    match canonicalization {
        DkimCanonicalizationType::Simple => serialized,
        DkimCanonicalizationType::Relaxed => dkim_canonicalize_headers_relaxed(&serialized),
    }
}

/// Sign with Dkim a message by adding Dkim-Signature header created with configuration expressed by
/// dkim_config
pub fn dkim_sign(message: &mut Message, dkim_config: &DkimConfig) {
    dkim_sign_fixed_time(message, dkim_config, SystemTime::now())
}

fn dkim_sign_fixed_time(message: &mut Message, dkim_config: &DkimConfig, timestamp: SystemTime) {
    let timestamp = timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let headers = message.headers();
    let body_hash = Sha256::digest(dkim_canonicalize_body(
        &message.body_raw(),
        dkim_config.canonicalization.body,
    ));
    let bh = crate::base64::encode(body_hash);
    let mut signed_headers_list =
        dkim_config
            .headers
            .iter()
            .fold(String::new(), |mut list, header| {
                if !list.is_empty() {
                    list.push(':');
                }

                list.push_str(header);
                list
            });
    if let DkimCanonicalizationType::Relaxed = dkim_config.canonicalization.header {
        signed_headers_list.make_ascii_lowercase();
    }
    let dkim_header = dkim_header_format(dkim_config, timestamp, &signed_headers_list, &bh, "");
    let signed_headers = dkim_canonicalize_headers(
        dkim_config.headers.iter().map(|h| h.as_ref()),
        headers,
        dkim_config.canonicalization.header,
    );
    let canonicalized_dkim_header = dkim_canonicalize_headers(
        ["DKIM-Signature"],
        &dkim_header,
        dkim_config.canonicalization.header,
    );
    let mut hashed_headers = Sha256::new();
    hashed_headers.update(signed_headers.as_bytes());
    hashed_headers.update(canonicalized_dkim_header.trim_end().as_bytes());
    let hashed_headers = hashed_headers.finalize();
    let signature = match &dkim_config.private_key.0 {
        InnerDkimSigningKey::Rsa(private_key) => crate::base64::encode(
            private_key
                .sign(Pkcs1v15Sign::new::<Sha256>(), &hashed_headers)
                .unwrap(),
        ),
        InnerDkimSigningKey::Ed25519(private_key) => {
            crate::base64::encode(private_key.sign(&hashed_headers).to_bytes())
        }
        #[cfg(feature = "gpgme")]
        InnerDkimSigningKey::Gnupg(_, key) => crate::base64::encode(
            super::gnupg::gpg_sign(key, &hashed_headers).expect("signing failed"),
        ),
    };
    let dkim_header = dkim_header_format(
        dkim_config,
        timestamp,
        &signed_headers_list,
        &bh,
        &signature,
    );
    message.headers.insert_raw(HeaderValue::new(
        HeaderName::new_from_ascii_str("DKIM-Signature"),
        dkim_header.get_raw("DKIM-Signature").unwrap().to_owned(),
    ));
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use super::{
        super::{
            header::{HeaderName, HeaderValue},
            Header, Message,
        },
        dkim_canonicalize_body, dkim_canonicalize_headers, dkim_sign_fixed_time,
        DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningAlgorithm,
        DkimSigningKey,
    };
    use crate::StdError;

    const KEY_RSA: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwOsW7UFcWn1ch3UM8Mll5qZH5hVHKJQ8Z0tUlebUECq0vjw6
VcsIucZ/B70VpCN63whyi7oApdCIS1o0zad7f0UaW/BfxXADqdcFL36uMaG0RHer
uSASjQGnsl9Kozt/dXiDZX5ngjr/arLJhNZSNR4/9VSwqbE2OPXaSaQ9BsqneD0P
8dCVSfkkDZCcfC2864z7hvC01lFzWQKF36ZAoGBERHScHtFMAzUOgGuqqPiP5khw
DQB3Ffccf+BsWLU2OOteshUwTGjpoangbPCYj6kckwNm440lQwuqTinpC92yyIE5
Ol8psNMW49DLowAeZb6JrjLhD+wY9bghTaOkcwIDAQABAoIBAHTZ8LkkrdvhsvoZ
XA088AwVC9fBa6iYoT2v0zw45JomQ/Q2Zt8wa8ibAradQU56byJI65jWwS2ucd+y
c+ldWOBt6tllb50XjCCDrRBnmvtVBuux0MIBOztNlVXlgj/8+ecdZ/lB51Bqi+sF
ACsF5iVmfTcMZTVjsYQu5llUseI6Lwgqpx6ktaXD2PVsVo9Gf01ssZ4GCy69wB/3
20CsOz4LEpSYkq1oE98lMMGCfD7py3L9kWHYNNisam78GM+1ynRxRGwEDUbz6pxs
fGPIAwHLaZsOmibPkBB0PJTW742w86qQ8KAqC6ZbRYOF19rSMj3oTfRnPMHn9Uu5
N8eQcoECgYEA97SMUrz2hqII5i8igKylO9kV8pjcIWKI0rdt8MKj4FXTNYjjO9I+
41ONOjhUOpFci/G3YRKi8UiwbKxIRTvIxNMh2xj6Ws3iO9gQHK1j8xTWxJdjEBEz
EuZI59Mi5H7fxSL1W+n8nS8JVsaH93rvQErngqTUAsihAzjxHWdFwm0CgYEAx2Dh
claESJP2cOKgYp+SUNwc26qMaqnl1f37Yn+AflrQOfgQqJe5TRbicEC+nFlm6XUt
3st1Nj29H0uOMmMZDmDCO+cOs5Qv5A9pG6jSC6wM+2KNHQDtrxlakBFygePEPVVy
GXaY9DRa9Q4/4ataxDR2/VvIAWfEEtMTJIBDtl8CgYAIXEuwLziS6r0qJ8UeWrVp
A7a97XLgnZbIpfBMBAXL+JmcYPZqenos6hEGOgh9wZJCFvJ9kEd3pWBvCpGV5KKu
IgIuhvVMQ06zfmNs1F1fQwDMud9aF3qF1Mf5KyMuWynqWXe2lns0QvYpu6GzNK8G
mICf5DhTr7nfhfh9aZLtMQKBgCxKsmqzG5n//MxhHB4sstVxwJtwDNeZPKzISnM8
PfBT/lQSbqj1Y73japRjXbTgC4Ore3A2JKjTGFN+dm1tJGDUT/H8x4BPWEBCyCfT
3i2noA6sewrJbQPsDvlYVubSEYNKmxlbBmmhw98StlBMv9I8kX6BSDI/uggwid0e
/WvjAoGBAKpZ0UOKQyrl9reBiUfrpRCvIMakBMd79kNiH+5y0Soq/wCAnAuABayj
XEIBhFv+HxeLEnT7YV+Zzqp5L9kKw/EU4ik3JX/XsEihdSxEuGX00ZYOw05FEfpW
cJ5Ku0OTwRtSMaseRPX+T4EfG1Caa/eunPPN4rh+CSup2BVVarOT
-----END RSA PRIVATE KEY-----";

    #[derive(Clone)]
    struct TestHeader(String);

    impl Header for TestHeader {
        fn name() -> HeaderName {
            HeaderName::new_from_ascii_str("Test")
        }

        fn parse(s: &str) -> Result<Self, Box<dyn StdError + Send + Sync>> {
            Ok(Self(s.into()))
        }

        fn display(&self) -> HeaderValue {
            HeaderValue::new(Self::name(), self.0.clone())
        }
    }

    fn test_message() -> Message {
        Message::builder()
            .from("Test O'Leary <test+ezrz@example.net>".parse().unwrap())
            .to("Test2 <test2@example.org>".parse().unwrap())
            .date(std::time::UNIX_EPOCH)
            .header(TestHeader("test  test very very long with spaces and extra spaces   \twill be folded to several lines ".to_owned()))
            .subject("Test with utf-8 ë")
            .body("test\r\n\r\ntest   \ttest\r\n\r\n\r\n".to_owned()).unwrap()
    }

    #[test]
    fn test_headers_simple_canonicalize() {
        let message = test_message();
        dbg!(message.headers.to_string());
        assert_eq!(dkim_canonicalize_headers(["From", "Test"], &message.headers, DkimCanonicalizationType::Simple), "From: =?utf-8?b?VGVzdCBPJ0xlYXJ5?= <test+ezrz@example.net>\r\nTest: test  test very very long with spaces and extra spaces   \twill be\r\n folded to several lines \r\n")
    }

    #[test]
    fn test_headers_relaxed_canonicalize() {
        let message = test_message();
        dbg!(message.headers.to_string());
        assert_eq!(dkim_canonicalize_headers(["From", "Test"], &message.headers, DkimCanonicalizationType::Relaxed),"from:=?utf-8?b?VGVzdCBPJ0xlYXJ5?= <test+ezrz@example.net>\r\ntest:test test very very long with spaces and extra spaces will be folded to several lines\r\n")
    }

    #[test]
    fn test_body_simple_canonicalize() {
        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(
            dkim_canonicalize_body(body, DkimCanonicalizationType::Simple).into_owned(),
            b" C \r\nD \t E\r\n"
        );
    }

    #[test]
    fn test_body_relaxed_canonicalize() {
        let body = b" C \r\nD \t E\r\n\tF\r\n\t\r\n\r\n\r\n";
        assert_eq!(
            dkim_canonicalize_body(body, DkimCanonicalizationType::Relaxed).into_owned(),
            b" C\r\nD E\r\n F\r\n"
        );
    }

    #[test]
    fn test_signature_rsa_simple() {
        let mut message = test_message();
        let signing_key = DkimSigningKey::new(KEY_RSA, DkimSigningAlgorithm::Rsa).unwrap();
        dkim_sign_fixed_time(
            &mut message,
            &DkimConfig::new(
                "dkimtest".to_owned(),
                "example.org".to_owned(),
                signing_key,
                vec![
                    HeaderName::new_from_ascii_str("Date"),
                    HeaderName::new_from_ascii_str("From"),
                    HeaderName::new_from_ascii_str("Subject"),
                    HeaderName::new_from_ascii_str("To"),
                ],
                DkimCanonicalization {
                    header: DkimCanonicalizationType::Simple,
                    body: DkimCanonicalizationType::Simple,
                },
            ),
            std::time::UNIX_EPOCH,
        );
        let signed = message.formatted();
        let signed = std::str::from_utf8(&signed).unwrap();
        assert_eq!(
            signed,
            std::concat!(
                "From: =?utf-8?b?VGVzdCBPJ0xlYXJ5?= <test+ezrz@example.net>\r\n",
                "To: Test2 <test2@example.org>\r\n",
                "Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n",
                "Test: test  test very very long with spaces and extra spaces   \twill be\r\n",
                " folded to several lines \r\n",
                "Subject: Test with utf-8 =?utf-8?b?w6s=?=\r\n",
                "Content-Transfer-Encoding: 7bit\r\n",
                "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=dkimtest;\r\n",
                " c=simple/simple; q=dns/txt; t=0; h=Date:From:Subject:To;\r\n",
                " bh=f3Zksdcjqa/xRBwdyFzIXWCcgP7XTgxjCgYsXOMKQl4=;\r\n",
                " b=NhoIMMAALoSgu5lKAR0+MUQunOWnU7wpF9ORUFtpxq9sGZDo9AX43AMhFemyM5W204jpFwMU6pm7AMR1nOYBdSYye4yUALtvT2nqbJBwSh7JeYu+z22t1RFKp7qQR1il8aSrkbZuNMFHYuSEwW76QtKwcNqP4bQOzS9CzgQp0ABu8qwYPBr/EypykPTfqjtyN+ywrfdqjjGOzTpRGolH0hc3CrAETNjjHbNBgKgucXmXTN7hMRdzqWjeFPxizXwouwNAavFClPG0l33gXVArFWn+CkgA84G/s4zuJiF7QPZR87Pu4pw/vIlSXxH4a42W3tT19v9iBTH7X7ldYegtmQ==\r\n",
                "\r\n",
                "test\r\n",
                "\r\n",
                "test   \ttest\r\n",
                "\r\n",
                "\r\n",
            )
        );
    }

    #[test]
    fn test_signature_rsa_relaxed() {
        let mut message = test_message();
        let signing_key = DkimSigningKey::new(KEY_RSA, DkimSigningAlgorithm::Rsa).unwrap();
        dkim_sign_fixed_time(
            &mut message,
            &DkimConfig::new(
                "dkimtest".to_owned(),
                "example.org".to_owned(),
                signing_key,
                vec![
                    HeaderName::new_from_ascii_str("Date"),
                    HeaderName::new_from_ascii_str("From"),
                    HeaderName::new_from_ascii_str("Subject"),
                    HeaderName::new_from_ascii_str("To"),
                ],
                DkimCanonicalization {
                    header: DkimCanonicalizationType::Relaxed,
                    body: DkimCanonicalizationType::Relaxed,
                },
            ),
            std::time::UNIX_EPOCH,
        );
        let signed = message.formatted();
        let signed = std::str::from_utf8(&signed).unwrap();
        println!("{signed}");
        assert_eq!(
            signed,
            std::concat!(
                "From: =?utf-8?b?VGVzdCBPJ0xlYXJ5?= <test+ezrz@example.net>\r\n",
                "To: Test2 <test2@example.org>\r\n",
                "Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n",
                "Test: test  test very very long with spaces and extra spaces   \twill be\r\n",
                " folded to several lines \r\n","Subject: Test with utf-8 =?utf-8?b?w6s=?=\r\n",
                "Content-Transfer-Encoding: 7bit\r\n",
                "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=dkimtest;\r\n",
                " c=relaxed/relaxed; q=dns/txt; t=0; h=date:from:subject:to;\r\n",
                " bh=qN8je6qJgWFGSnN2MycC/XKPbN6BOrMJyAX2h4m19Ss=;\r\n",
                " b=YaVfmH8dbGEywoLJ4uhbvYqDyQG1UGKFH3PE7zXGgk+YFxUgkwWjoA3aQupDNQtfTjfUsNe0dnrjyZP+ylnESpZBpbCIf5/n3FEh6j3RQthqNbQblcfH/U8mazTuRbVjYBbTZQDaQCMPTz+8D+ZQfXo2oq6dGzTuGvmuYft0CVsq/BIp/EkhZHqiphDeVJSHD4iKW8+L2XwEWThoY92xOYc1G0TtBwz2UJgtiHX2YulH/kRBHeK3dKn9RTNVL3VZ+9ZrnFwIhET9TPGtU2I+q0EMSWF9H9bTrASMgW/U+E0VM2btqJlrTU6rQ7wlQeHdwecLnzXcyhCUInF1+veMNw==\r\n",
                "\r\n",
                "test\r\n",
                "\r\n",
                "test   \ttest\r\n",
                "\r\n",
                "\r\n",
            )
        );
    }
}
