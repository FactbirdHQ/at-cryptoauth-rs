//! PKCS#10 Certification Request types

use crate::PublicKey;

use super::{attr::Attributes, name::Name, pem::PemWriter};

use der::{
    Decode, DecodeValue, Encode as _, EncodeValue, Enumerated, FixedTag, Header, Length, Reader,
    Sequence, Writer,
};
use p256::{EncodedPoint, ecdsa::DerSignature};
use pem_rfc7468::PemLabel;
use spki::{AlgorithmIdentifierRef, ObjectIdentifier};

/// Version identifier for certification request information.
///
/// (RFC 2986 designates `0` as the only valid version)
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated, Default)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Denotes PKCS#8 v1
    #[default]
    V1 = 0,
}

/// PKCS#10 `CertificationRequestInfo` as defined in [RFC 2986 Section 4].
///
/// ```text
/// CertificationRequestInfo ::= SEQUENCE {
///     version       INTEGER { v1(0) } (v1,...),
///     subject       Name,
///     subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
///     attributes    [0] Attributes{{ CRIAttributes }}
/// }
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
#[derive(Clone, Debug, Sequence)]
pub struct CertReqInfo<'a> {
    /// Certification request version.
    pub version: Version,

    /// Subject name.
    pub subject: Name<'a>,

    /// Subject public key info.
    pub public_key: spki::SubjectPublicKeyInfo<ObjectIdentifier, PublicKeyBitString>,

    /// Request attributes.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    pub attributes: Attributes<'a>,
}

/// PKCS#10 `CertificationRequest` as defined in [RFC 2986 Section 4].
///
/// ```text
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo CertificationRequestInfo,
///     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
///     signature          BIT STRING
/// }
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
#[derive(Clone, Debug, Sequence)]
pub struct CertReq<'a> {
    /// Certification request information.
    pub info: CertReqInfo<'a>,

    /// Signature algorithm identifier.
    pub algorithm: AlgorithmIdentifierRef<'a>,

    /// Signature.
    pub signature: SignatureBitString,
}

impl<'a> CertReq<'a> {
    pub fn to_pem_slice(
        &self,
        buf: &mut [u8],
        line_ending: pem_rfc7468::LineEnding,
    ) -> der::Result<usize> {
        let der_len = usize::try_from(self.encoded_len()?)?;
        let pem_len = pem_rfc7468::encapsulated_len(Self::PEM_LABEL, line_ending, der_len)
            .map_err(|_| der::ErrorKind::Failed)?;

        if buf.len() < pem_len {
            return Err(der::ErrorKind::Overflow.into());
        }

        let mut writer = PemWriter::new(Self::PEM_LABEL, line_ending, buf)?;
        self.encode(&mut writer)?;

        Ok(writer.finish()?)
    }
}

#[derive(Clone)]
pub struct SignatureBitString(pub DerSignature);

impl core::fmt::Debug for SignatureBitString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BitString")
            .field("unused_bites", &0u8)
            .field("bit_length", &((self.0.len()) * 8))
            .field("inner", &self.0.as_bytes())
            .finish()
    }
}

impl FixedTag for SignatureBitString {
    const TAG: der::Tag = der::Tag::BitString;
}

impl<'a> DecodeValue<'a> for SignatureBitString {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let inner_len = (header.length - Length::ONE)?;
        let unused_bits = reader.read_byte()?;

        // BIT STRING must have 0 unused bits for a valid DER signature
        if unused_bits != 0 {
            return Err(der::Tag::BitString.value_error());
        }

        // Read the DER-encoded signature bytes
        let mut sig_bytes = [0u8; 128]; // Max DER signature size for P-256
        let len = usize::try_from(inner_len)?;
        if len > sig_bytes.len() {
            return Err(der::ErrorKind::Length {
                tag: der::Tag::BitString,
            }
            .into());
        }
        reader.read_into(&mut sig_bytes[..len])?;

        // Parse as DER signature
        let signature = DerSignature::from_der(&sig_bytes[..len])
            .map_err(|_| der::Tag::BitString.value_error())?;

        Ok(Self(signature))
    }
}

impl EncodeValue for SignatureBitString {
    fn value_len(&self) -> der::Result<Length> {
        Length::ONE + Length::try_from(self.0.len())?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write(&[0u8])?;
        writer.write(&self.0.as_bytes())
    }
}

#[derive(Clone)]
pub struct PublicKeyBitString(pub PublicKey);

impl core::fmt::Debug for PublicKeyBitString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BitString")
            .field("unused_bites", &0u8)
            .field("bit_length", &((self.0.as_ref().len()) * 8))
            .field("inner", &self.0.as_ref())
            .finish()
    }
}

impl FixedTag for PublicKeyBitString {
    const TAG: der::Tag = der::Tag::BitString;
}

impl<'a> DecodeValue<'a> for PublicKeyBitString {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let inner_len = (header.length - Length::ONE)?;
        let unused_bits = reader.read_byte()?;

        // BIT STRING must have 0 unused bits for a valid public key
        if unused_bits != 0 {
            return Err(der::Tag::BitString.value_error());
        }

        // Read the SEC1-encoded public key bytes (uncompressed: 0x04 || X || Y)
        let len = usize::try_from(inner_len)?;
        let mut point_bytes = [0u8; 65]; // 1 byte tag + 32 bytes X + 32 bytes Y
        if len > point_bytes.len() {
            return Err(der::ErrorKind::Length {
                tag: der::Tag::BitString,
            }
            .into());
        }
        reader.read_into(&mut point_bytes[..len])?;

        // Parse SEC1 encoded point
        let point = EncodedPoint::from_bytes(&point_bytes[..len])
            .map_err(|_| der::Tag::BitString.value_error())?;

        // Extract X and Y coordinates into PublicKey
        let x = point.x().ok_or_else(|| der::Tag::BitString.value_error())?;
        let y = point.y().ok_or_else(|| der::Tag::BitString.value_error())?;

        let mut pubkey = PublicKey::default();
        pubkey.as_mut()[..32].copy_from_slice(x.as_slice());
        pubkey.as_mut()[32..].copy_from_slice(y.as_slice());

        Ok(Self(pubkey))
    }
}

impl EncodeValue for PublicKeyBitString {
    fn value_len(&self) -> der::Result<Length> {
        let point = EncodedPoint::from_untagged_bytes(&self.0.value);

        Length::ONE + Length::try_from(point.as_bytes().len())?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        let point = EncodedPoint::from_untagged_bytes(&self.0.value);

        writer.write(&[0u8])?;
        writer.write(&point.as_bytes())
    }
}

#[cfg(feature = "pem")]
impl<'a> PemLabel for CertReq<'a> {
    const PEM_LABEL: &'static str = "CERTIFICATE REQUEST";
}

impl<'a> TryFrom<&'a [u8]> for CertReq<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_der(bytes)
    }
}
