use std::{error::Error, fmt::Display};

use super::DkimSigningAlgorithm;

#[derive(Debug)]
#[non_exhaustive]
pub enum GpgGetKeyError {
    NoValidKey,
    NotValidAlgorithm,
    GpgError(gpgme::Error),
}

impl Display for GpgGetKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:#?}")
    }
}

impl Error for GpgGetKeyError {}

pub(super) fn gpg_key_algorithm(key: &gpgme::Key) -> Result<DkimSigningAlgorithm, GpgGetKeyError> {
    use gpgme::Subkey;
    let subkey = key.subkeys().fold(None, |acc: Option<Subkey<'_>>, key| {
        if !key.can_sign() {
            acc
        } else if let Some(old) = acc {
            if old.creation_time() < key.creation_time() {
                Some(key)
            } else {
                Some(old)
            }
        } else {
            Some(key)
        }
    });

    let Some(subkey) = subkey else {
        return Err(GpgGetKeyError::NoValidKey);
    };

    match subkey.algorithm_name() {
        Ok(algo) => {
            if algo == "ed25519" {
                Ok(DkimSigningAlgorithm::Ed25519)
            } else if algo.starts_with("rsa") {
                Ok(DkimSigningAlgorithm::Rsa)
            } else {
                Err(GpgGetKeyError::NotValidAlgorithm)
            }
        }
        Err(e) => Err(GpgGetKeyError::GpgError(e)),
    }
}

pub(super) fn gpg_sign(key: &gpgme::Key, hash: &[u8]) -> Result<Vec<u8>, gpgme::Error> {
    use gpgme::{Context, Protocol};
    let mut gpg = Context::from_protocol(Protocol::OpenPgp)?;

    gpg.set_armor(false);
    gpg.add_signer(key)?;
    let mut sign = Vec::<u8>::new();
    gpg.sign_detached(hash, &mut sign)?;
    Ok(sign)
}
