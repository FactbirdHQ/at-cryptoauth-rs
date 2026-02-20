//! TLS integration with embedded-tls via ATECC608 hardware verification.
//!
//! Provides [`AteccProvider`] implementing [`embedded_tls::CryptoProvider`] with
//! hardware-backed ECDSA verification and signing through the ATECC608 secure element.

use crate::AtCaClient;
use crate::cert::compressed::CertificateDefinition;
use crate::command::PublicKey;
use crate::memory::Slot;

use der::asn1::{
    AnyRef, BitStringRef, GeneralizedTime, IntRef, ObjectIdentifier, SequenceOf, SetOf, UtcTime,
};
use der::{Choice, Decode, Enumerated, Reader, Sequence, SliceReader, ValueOrd};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embedded_tls::{
    Aes128GcmSha256, Certificate, CertificateEntryRef, CertificateRef, CertificateVerifyRef,
    SignatureScheme, TlsError, TlsVerifier,
};
use heapless::Vec;
use sha2::Digest as _;

use core::cmp::Ordering;

// ---------------------------------------------------------------------------
// X.509 DER parsing types (local copy — embedded-tls's are private/feature-gated)
// ---------------------------------------------------------------------------

const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

const ECDSA_SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
struct AlgorithmIdentifier<'a> {
    oid: ObjectIdentifier,
    parameters: Option<AnyRef<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
enum Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}

impl ValueOrd for Version {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        (*self as u8).value_cmp(&(*other as u8))
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

#[derive(Debug, Choice, ValueOrd)]
enum Time {
    #[asn1(type = "UTCTime")]
    UtcTime(UtcTime),
    #[asn1(type = "GeneralizedTime")]
    GeneralTime(GeneralizedTime),
}

#[derive(Debug, Sequence, ValueOrd)]
struct Validity {
    not_before: Time,
    not_after: Time,
}

#[derive(Debug, Sequence, ValueOrd)]
struct AttributeTypeAndValue<'a> {
    oid: ObjectIdentifier,
    value: AnyRef<'a>,
}

#[derive(Debug, Sequence, ValueOrd)]
struct SubjectPublicKeyInfoRef<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    public_key: BitStringRef<'a>,
}

#[derive(Debug, Sequence, ValueOrd)]
struct TbsCertificate<'a> {
    #[asn1(context_specific = "0", default = "Default::default")]
    version: Version,

    serial_number: IntRef<'a>,
    signature: AlgorithmIdentifier<'a>,
    issuer: SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 7>,

    validity: Validity,
    subject: SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 7>,
    subject_public_key_info: SubjectPublicKeyInfoRef<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    issuer_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    subject_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<AnyRef<'a>>,
}

#[derive(Sequence, ValueOrd)]
struct DecodedCertificate<'a> {
    tbs_certificate: TbsCertificate<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: BitStringRef<'a>,
}

/// Extract the TBS (to-be-signed) portion as raw TLV bytes from a DER certificate.
fn get_certificate_tlv_bytes(input: &[u8]) -> Result<&[u8], TlsError> {
    let mut reader = SliceReader::new(input).map_err(|_| TlsError::DecodeError)?;
    let top_header = der::Header::decode(&mut reader).map_err(|_| TlsError::DecodeError)?;
    top_header
        .tag
        .assert_eq(der::Tag::Sequence)
        .map_err(|_| TlsError::DecodeError)?;

    reader.tlv_bytes().map_err(|_| TlsError::DecodeError)
}

/// Extract the Common Name from a certificate's subject field.
fn extract_common_name<'a>(
    subject: &SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 7>,
) -> Option<heapless::String<64>> {
    for elems in subject.iter() {
        if let Some(attr) = elems.get(0) {
            if attr.oid == COMMON_NAME_OID {
                let mut v: Vec<u8, 64> = Vec::new();
                v.extend_from_slice(attr.value.value()).ok()?;
                return heapless::String::from_utf8(v).ok();
            }
        }
    }
    None
}

/// Convert a SEC1 uncompressed public key (65 bytes, 0x04 prefix) to raw X||Y (64 bytes).
fn sec1_to_raw_pubkey(sec1: &[u8]) -> Result<PublicKey, TlsError> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return Err(TlsError::DecodeError);
    }
    PublicKey::try_from(&sec1[1..]).map_err(|_| TlsError::DecodeError)
}

// ---------------------------------------------------------------------------
// Flexible certificate and CA key sources
// ---------------------------------------------------------------------------

/// Source for the client certificate presented during mutual TLS.
pub enum CertSource<'a> {
    /// Pre-built DER-encoded X.509 certificate.
    Der(&'a [u8]),
    /// Compressed certificate reconstructed from ATECC608 at handshake time.
    Compressed(CertificateDefinition<'a>),
}

impl<'a> From<&'a [u8]> for CertSource<'a> {
    fn from(der: &'a [u8]) -> Self {
        Self::Der(der)
    }
}

impl<'a> From<CertificateDefinition<'a>> for CertSource<'a> {
    fn from(def: CertificateDefinition<'a>) -> Self {
        Self::Compressed(def)
    }
}

/// Source for the root CA public key used to verify the server certificate chain.
pub enum RootCaSource {
    /// Raw 64-byte X||Y public key (provided directly or extracted from DER).
    Key(PublicKey),
    /// Public key read from an ATECC slot at verification time.
    Stored(Slot),
}

impl From<PublicKey> for RootCaSource {
    fn from(key: PublicKey) -> Self {
        Self::Key(key)
    }
}

impl From<Slot> for RootCaSource {
    fn from(slot: Slot) -> Self {
        Self::Stored(slot)
    }
}

impl TryFrom<&[u8]> for RootCaSource {
    type Error = TlsError;

    /// Parse a DER-encoded X.509 certificate and extract the subject public key.
    fn try_from(der: &[u8]) -> Result<Self, TlsError> {
        let parsed = DecodedCertificate::from_der(der).map_err(|_| TlsError::DecodeError)?;
        let spki_bytes = parsed
            .tbs_certificate
            .subject_public_key_info
            .public_key
            .as_bytes()
            .ok_or(TlsError::DecodeError)?;
        Ok(Self::Key(sec1_to_raw_pubkey(spki_bytes)?))
    }
}

// ---------------------------------------------------------------------------
// AteccVerifier
// ---------------------------------------------------------------------------

pub struct AteccVerifier<'a, M: RawMutex, PHY> {
    atca: &'a AtCaClient<M, PHY>,
    ca_pubkey_source: RootCaSource,
    host: Option<heapless::String<64>>,
    certificate_transcript: Option<[u8; 32]>,
    server_public_key: Option<PublicKey>,
}

impl<'a, M: RawMutex, PHY> AteccVerifier<'a, M, PHY> {
    fn new(atca: &'a AtCaClient<M, PHY>, ca_pubkey_source: impl Into<RootCaSource>) -> Self {
        Self {
            atca,
            ca_pubkey_source: ca_pubkey_source.into(),
            host: None,
            certificate_transcript: None,
            server_public_key: None,
        }
    }
}

impl<M, PHY> TlsVerifier<Aes128GcmSha256> for AteccVerifier<'_, M, PHY>
where
    M: RawMutex,
    PHY: embedded_hal::i2c::I2c,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        self.host.replace(
            heapless::String::try_from(hostname).map_err(|_| TlsError::InsufficientSpace)?,
        );
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &sha2::Sha256,
        cert: CertificateRef,
    ) -> Result<(), TlsError> {
        // Resolve CA public key from the configured source
        let mut ca_pubkey = match &self.ca_pubkey_source {
            RootCaSource::Key(key) => *key,
            RootCaSource::Stored(slot) => self
                .atca
                .memory()
                .pubkey_blocking(*slot)
                .map_err(|_| TlsError::InvalidCertificate)?,
        };

        let mut cn = None;

        // Walk the chain from the entry closest to CA (last) down to the leaf (first).
        // Each entry is verified against the current verifier public key.
        let num_entries = cert.entries.len();
        for i in (0..num_entries).rev() {
            let cert_data = match &cert.entries[i] {
                CertificateEntryRef::X509(data) => *data,
                _ => return Err(TlsError::DecodeError),
            };

            let parsed =
                DecodedCertificate::from_der(cert_data).map_err(|_| TlsError::DecodeError)?;

            // Only ECDSA P-256 SHA-256 is supported by the ATECC608
            if parsed.signature_algorithm.oid != ECDSA_SHA256_OID {
                return Err(TlsError::InvalidSignatureScheme);
            }

            // Hash the TBS data with software SHA-256
            let tbs_data = get_certificate_tlv_bytes(cert_data)?;
            let hash = sha2::Sha256::digest(tbs_data);

            // Convert hash to ATECC Digest
            let digest =
                crate::Digest::try_from(hash.as_slice()).map_err(|_| TlsError::CryptoError)?;

            // Convert DER signature to p256::ecdsa::Signature (raw R||S internally)
            let sig_bytes = parsed.signature.as_bytes().ok_or(TlsError::DecodeError)?;
            let signature = p256::ecdsa::Signature::from_der(sig_bytes)
                .map_err(|_| TlsError::InvalidSignature)?;

            // Verify using ATECC hardware
            self.atca
                .verify_external_blocking(&digest, &signature, &ca_pubkey)
                .map_err(|_| TlsError::InvalidCertificate)?;

            // Extract this cert's public key for the next iteration (or as server key for leaf)
            let spki_bytes = parsed
                .tbs_certificate
                .subject_public_key_info
                .public_key
                .as_bytes()
                .ok_or(TlsError::DecodeError)?;
            let cert_pubkey = sec1_to_raw_pubkey(spki_bytes)?;

            if i == 0 {
                // Leaf certificate — extract CN and store server public key
                cn = extract_common_name(&parsed.tbs_certificate.subject);
                self.server_public_key = Some(cert_pubkey);
            } else {
                // Intermediate — use its public key to verify the next cert down
                ca_pubkey = cert_pubkey;
            }
        }

        // Hostname verification
        if self.host.is_some() && self.host != cn {
            return Err(TlsError::InvalidCertificate);
        }

        self.certificate_transcript = Some(transcript.clone().finalize().into());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        if verify.signature_scheme != SignatureScheme::EcdsaSecp256r1Sha256 {
            return Err(TlsError::InvalidSignatureScheme);
        }

        let server_pubkey = self
            .server_public_key
            .as_ref()
            .ok_or(TlsError::InvalidCertificate)?;

        // Build the verification message per RFC 8446 §4.4.3
        let handshake_hash = self
            .certificate_transcript
            .take()
            .ok_or(TlsError::InvalidHandshake)?;

        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg: Vec<u8, 146> = Vec::new();
        msg.resize(64, 0x20)
            .map_err(|_| TlsError::InsufficientSpace)?;
        msg.extend_from_slice(ctx_str)
            .map_err(|_| TlsError::InsufficientSpace)?;
        msg.extend_from_slice(&handshake_hash)
            .map_err(|_| TlsError::InsufficientSpace)?;

        // Hash the verification message with software SHA-256
        let hash = sha2::Sha256::digest(&msg);
        let digest = crate::Digest::try_from(hash.as_slice()).map_err(|_| TlsError::CryptoError)?;

        // Convert DER signature
        let signature = p256::ecdsa::Signature::from_der(verify.signature)
            .map_err(|_| TlsError::InvalidSignature)?;

        // Verify using ATECC hardware
        self.atca
            .verify_external_blocking(&digest, &signature, server_pubkey)
            .map_err(|_| TlsError::InvalidSignature)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AteccProvider
// ---------------------------------------------------------------------------

pub struct AteccProvider<'a, M: RawMutex, PHY, const CERT_SIZE: usize = 0> {
    atca: &'a AtCaClient<M, PHY>,
    sign_key: Slot,
    client_cert_source: Option<CertSource<'a>>,
    verifier: AteccVerifier<'a, M, PHY>,
}

impl<'a, M: RawMutex, PHY> AteccProvider<'a, M, PHY, 0> {
    pub fn new(
        atca: &'a AtCaClient<M, PHY>,
        sign_key: Slot,
        ca_pubkey_source: impl Into<RootCaSource>,
    ) -> Self {
        Self {
            atca,
            sign_key,
            client_cert_source: None,
            verifier: AteccVerifier::new(atca, ca_pubkey_source),
        }
    }

    /// Enable client certificate authentication for mutual TLS.
    ///
    /// `CERT_SIZE` controls the temporary stack buffer used when
    /// reconstructing a compressed certificate, or copying a DER certificate.
    pub fn with_client_cert<const N: usize>(
        self,
        cert: impl Into<CertSource<'a>>,
    ) -> AteccProvider<'a, M, PHY, N> {
        AteccProvider {
            atca: self.atca,
            sign_key: self.sign_key,
            client_cert_source: Some(cert.into()),
            verifier: self.verifier,
        }
    }
}

impl<'a, M, PHY, const CERT_SIZE: usize> embedded_tls::CryptoProvider
    for AteccProvider<'a, M, PHY, CERT_SIZE>
where
    M: RawMutex,
    PHY: embedded_hal::i2c::I2c,
{
    type CipherSuite = Aes128GcmSha256;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl signature::rand_core::CryptoRngCore {
        self.atca.random()
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, TlsError> {
        Ok(&mut self.verifier)
    }

    fn signer(
        &mut self,
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), TlsError> {
        Ok((
            self.atca.signer(self.sign_key),
            SignatureScheme::EcdsaSecp256r1Sha256,
        ))
    }

    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        let source = self.client_cert_source.as_ref()?;
        match source {
            CertSource::Der(der) => Some(Certificate::X509(
                heapless::Vec::<u8, CERT_SIZE>::from_slice(der).ok()?,
            )),
            CertSource::Compressed(def) => {
                let mut buf = [0u8; CERT_SIZE];
                let len = self
                    .atca
                    .memory()
                    .read_certificate_blocking(def, &mut buf)
                    .ok()?;
                Some(Certificate::X509(
                    heapless::Vec::<u8, CERT_SIZE>::from_slice(&buf[..len]).ok()?,
                ))
            }
        }
    }
}
