#![forbid(unsafe_code)]

//! The rpgp `OpenPGP` engine — a technology of `xmip-core-prepare`, the first
//! engine Encryption and Signature choose among for `OpenPGP` (RFC 9580).
//! `rpgp` (MIT or Apache-2.0) is `OpenPGP` in Rust, read and written a piece
//! at a time: a message is decrypted, encrypted, signed and verified as it
//! streams, its packets cut into partial bodies, never held whole.
//!
//! Keys are the step's files, armored or binary, each key's binding
//! signatures checked when the step is opened. A key protected by a
//! passphrase is not opened yet: where a passphrase is kept is the secret
//! capability's, not designed (open problem 29).
//!
//! Offline (ADR-0045, amendment 2026-10-22): `rpgp` holds no key-server,
//! directory or network code; a key's preferred key server is data it
//! reads, never an address it reaches.

use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use pgp::composed::{Deserializable, Message, MessageBuilder, SignedPublicKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyDetails, Password};
use prepare::protection::{Keys, ProtectionEngine};
use prepare::{Direction, Prepare, PrepareError};
use rand::thread_rng;

/// The engine, as a step's `engine` names it: `rpgp`.
pub struct Rpgp;

const NAME: &str = "rpgp";

impl ProtectionEngine for Rpgp {
    fn name(&self) -> &'static str {
        NAME
    }

    fn format(&self) -> &'static str {
        "openpgp"
    }

    fn encryption(&self, direction: Direction, keys: &Keys) -> Result<Box<dyn Prepare>, String> {
        Ok(match direction {
            Direction::Inward => Box::new(Decrypting(secret(keys)?)),
            Direction::Outward => Box::new(Encrypting(public(keys)?)),
        })
    }

    fn signature(&self, direction: Direction, keys: &Keys) -> Result<Box<dyn Prepare>, String> {
        Ok(match direction {
            Direction::Inward => Box::new(Verifying(public(keys)?)),
            Direction::Outward => Box::new(Signing(secret(keys)?)),
        })
    }
}

fn opened(place: &Path) -> Result<BufReader<File>, String> {
    File::open(place).map(BufReader::new).map_err(|failed| {
        format!(
            "{NAME}: the key '{}' cannot be read: {failed}",
            place.display()
        )
    })
}

/// This end's own key, its bindings checked.
fn secret(keys: &Keys) -> Result<SignedSecretKey, String> {
    let place = keys
        .own
        .as_deref()
        .ok_or_else(|| format!("{NAME}: no key is named"))?;
    let (key, _) = SignedSecretKey::from_reader_single(opened(place)?).map_err(|failed| {
        format!(
            "{NAME}: '{}' is no OpenPGP private key: {failed}",
            place.display()
        )
    })?;
    key.verify_bindings().map_err(|failed| {
        format!(
            "{NAME}: '{}' does not hold together: {failed}",
            place.display()
        )
    })?;
    Ok(key)
}

/// The far ends' keys, each's bindings checked.
fn public(keys: &Keys) -> Result<Vec<SignedPublicKey>, String> {
    keys.theirs
        .iter()
        .map(|place| {
            let (key, _) =
                SignedPublicKey::from_reader_single(opened(place)?).map_err(|failed| {
                    format!(
                        "{NAME}: '{}' is no OpenPGP public key: {failed}",
                        place.display()
                    )
                })?;
            key.verify_bindings().map_err(|failed| {
                format!(
                    "{NAME}: '{}' does not hold together: {failed}",
                    place.display()
                )
            })?;
            Ok(key)
        })
        .collect()
}

fn refused(why: impl fmt::Display) -> PrepareError {
    PrepareError::new(format!("{NAME}: {why}"))
}

/// The Stream as the parser reads it: buffered, said in a word where it is
/// printed.
struct Source<'a>(BufReader<&'a mut (dyn Read + Send)>);

impl fmt::Debug for Source<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the Stream")
    }
}

impl Read for Source<'_> {
    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(into)
    }
}

impl BufRead for Source<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.0.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.0.consume(amount);
    }
}

/// The message a Stream holds, its outer layers taken off: decrypted with
/// `key` where it is encrypted, decompressed where it is compressed.
fn message<'a>(
    input: &'a mut (dyn Read + Send),
    key: Option<&SignedSecretKey>,
) -> Result<Message<'a>, PrepareError> {
    let (mut message, _) = Message::from_reader(Source(BufReader::new(input)))
        .map_err(|failed| refused(format!("the Stream is no OpenPGP message: {failed}")))?;
    if message.is_encrypted() {
        let key = key.ok_or_else(|| refused("the message is encrypted; Encryption decrypts it"))?;
        message = message
            .decrypt(&Password::empty(), key)
            .map_err(|failed| refused(format!("the message is not for this key: {failed}")))?;
    }
    if message.is_compressed() {
        message = message
            .decompress()
            .map_err(|failed| refused(format!("the message cannot be decompressed: {failed}")))?;
    }
    Ok(message)
}

fn copied(from: &mut impl Read, output: &mut dyn Write) -> Result<(), PrepareError> {
    std::io::copy(from, output).map_err(refused)?;
    output.flush().map_err(refused)
}

struct Decrypting(SignedSecretKey);

impl Prepare for Decrypting {
    fn prepare(
        &self,
        input: &mut (dyn Read + Send),
        output: &mut dyn Write,
    ) -> Result<(), PrepareError> {
        let mut message = message(input, Some(&self.0))?;
        copied(&mut message, output)
    }
}

struct Encrypting(Vec<SignedPublicKey>);

impl Prepare for Encrypting {
    fn prepare(
        &self,
        input: &mut (dyn Read + Send),
        output: &mut dyn Write,
    ) -> Result<(), PrepareError> {
        let mut builder = MessageBuilder::from_reader("", input)
            .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
        for key in &self.0 {
            let encrypting = key
                .public_subkeys
                .iter()
                .find(|subkey| subkey.algorithm().can_encrypt())
                .ok_or_else(|| refused("a recipient's key has no subkey that encrypts"))?;
            builder
                .encrypt_to_key(thread_rng(), encrypting)
                .map_err(refused)?;
        }
        builder.to_writer(thread_rng(), output).map_err(refused)
    }
}

struct Signing(SignedSecretKey);

impl Prepare for Signing {
    fn prepare(
        &self,
        input: &mut (dyn Read + Send),
        output: &mut dyn Write,
    ) -> Result<(), PrepareError> {
        let mut builder = MessageBuilder::from_reader("", input);
        builder.sign(
            &self.0.primary_key,
            Password::empty(),
            HashAlgorithm::Sha256,
        );
        builder.to_writer(thread_rng(), output).map_err(refused)
    }
}

struct Verifying(Vec<SignedPublicKey>);

impl Prepare for Verifying {
    /// The signed content is written as it is read, and the signature
    /// checked once it is all read: a message no signer signed fails the
    /// step, and what was written is not handed on.
    fn prepare(
        &self,
        input: &mut (dyn Read + Send),
        output: &mut dyn Write,
    ) -> Result<(), PrepareError> {
        let mut message = message(input, None)?;
        if !message.is_signed() {
            return Err(refused("the message is not signed"));
        }
        copied(&mut message, output)?;
        let signed = self.0.iter().any(|key| {
            message.verify(&key.primary_key).is_ok()
                || key
                    .public_subkeys
                    .iter()
                    .any(|subkey| message.verify(subkey).is_ok())
        });
        if signed {
            Ok(())
        } else {
            Err(refused("no signer named signed the message"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::ser::Serialize;
    use std::path::PathBuf;

    /// A key that signs with its primary and encrypts with its subkey,
    /// written as files: the private one and the public one.
    fn keys(name: &str) -> (PathBuf, PathBuf) {
        let mut encrypting = SubkeyParamsBuilder::default();
        encrypting
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_sign(false)
            .can_encrypt(EncryptionCaps::All)
            .can_authenticate(false);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(format!("{name} <{name}@example.test>"))
            .subkeys(vec![encrypting.build().expect("subkey")]);
        let secret = params
            .build()
            .expect("parameters")
            .generate(thread_rng())
            .expect("generated");
        let folder = std::env::temp_dir().join(format!("xmip-rpgp-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("a folder");
        let (private, public) = (folder.join("key.priv"), folder.join("key.pub"));
        secret
            .to_writer(&mut File::create(&private).expect("created"))
            .expect("written");
        SignedPublicKey::from(secret)
            .to_writer(&mut File::create(&public).expect("created"))
            .expect("written");
        (private, public)
    }

    fn run(prepare: &dyn Prepare, input: &[u8]) -> Result<Vec<u8>, PrepareError> {
        let mut output = Vec::new();
        prepare.prepare(&mut &input[..], &mut output)?;
        Ok(output)
    }

    #[test]
    fn a_message_is_encrypted_to_a_recipient_and_decrypted_by_its_key() {
        let (private, public) = keys("encrypt");
        let encrypting = Rpgp
            .encryption(
                Direction::Outward,
                &Keys {
                    own: None,
                    theirs: vec![public],
                },
            )
            .expect("opens");
        let decrypting = Rpgp
            .encryption(
                Direction::Inward,
                &Keys {
                    own: Some(private),
                    theirs: Vec::new(),
                },
            )
            .expect("opens");
        let sealed = run(&*encrypting, b"<Order>secret</Order>").expect("encrypted");
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(
            run(&*decrypting, &sealed).expect("decrypted"),
            b"<Order>secret</Order>"
        );
        let (other, _) = keys("other");
        let stranger = Rpgp
            .encryption(
                Direction::Inward,
                &Keys {
                    own: Some(other),
                    theirs: Vec::new(),
                },
            )
            .expect("opens");
        assert!(run(&*stranger, &sealed).is_err(), "not for this key");
    }

    #[test]
    fn a_message_is_signed_and_verified_and_a_stranger_s_signature_refused() {
        let (private, public) = keys("sign");
        let signing = Rpgp
            .signature(
                Direction::Outward,
                &Keys {
                    own: Some(private),
                    theirs: Vec::new(),
                },
            )
            .expect("opens");
        let verifying = Rpgp
            .signature(
                Direction::Inward,
                &Keys {
                    own: None,
                    theirs: vec![public],
                },
            )
            .expect("opens");
        let signed = run(&*signing, b"<Order/>").expect("signed");
        assert_eq!(run(&*verifying, &signed).expect("verified"), b"<Order/>");
        let (stranger, _) = keys("stranger");
        let foreign = Rpgp
            .signature(
                Direction::Outward,
                &Keys {
                    own: Some(stranger),
                    theirs: Vec::new(),
                },
            )
            .expect("opens");
        let forged = run(&*foreign, b"<Order/>").expect("signed");
        let refused = run(&*verifying, &forged).expect_err("refused");
        assert!(refused.to_string().contains("no signer named"), "{refused}");
    }

    #[test]
    fn a_key_that_is_not_one_is_refused_when_the_step_opens() {
        let folder = std::env::temp_dir().join(format!("xmip-rpgp-none-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("a folder");
        let place = folder.join("not-a-key");
        std::fs::write(&place, b"plain text").expect("written");
        let refused = Rpgp
            .encryption(
                Direction::Inward,
                &Keys {
                    own: Some(place),
                    theirs: Vec::new(),
                },
            )
            .err()
            .expect("refused");
        assert!(refused.contains("is no OpenPGP private key"), "{refused}");
    }
}
