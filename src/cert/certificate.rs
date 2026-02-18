use core::cmp::Ordering;

use der::{Decode, Enumerated, Sequence, ValueOrd, asn1::BitStringRef};
use pem_rfc7468::PemLabel;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

use super::{name::Name, serial_number::SerialNumber, time::Validity};

/// X.509 certificates are defined in [RFC 5280 Section 4.1].
///
/// ```text
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signature            BIT STRING
/// }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,
}

#[cfg(feature = "pem")]
impl<'a> pem_rfc7468::PemLabel for Certificate<'a> {
    const PEM_LABEL: &'static str = "CERTIFICATE";
}

impl<'a> Certificate<'a> {
    pub fn from_pem(pem_bytes: &[u8], buf: &'a mut [u8]) -> der::Result<Self> {
        let (label, der_bytes) =
            pem_rfc7468::decode(pem_bytes, buf).map_err(|_| der::ErrorKind::Failed)?;
        Self::validate_pem_label(label).map_err(|_| der::ErrorKind::Failed)?;
        Self::from_der(der_bytes)
    }
}

/// X.509 `TbsCertificate` as defined in [RFC 5280 Section 4.1]
///
/// ASN.1 structure containing the names of the subject and issuer, a public
/// key associated with the subject, a validity period, and other associated
/// information.
///
/// ```text
/// TBSCertificate  ::=  SEQUENCE  {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                          -- If present, version MUST be v2 or v3
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                          -- If present, version MUST be v2 or v3
///     extensions      [3]  Extensions OPTIONAL
///                          -- If present, version MUST be v3 --
/// }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct TbsCertificate<'a> {
    /// The certificate version
    ///
    /// Note that this value defaults to Version 1 per the RFC. However,
    /// fields such as `issuer_unique_id`, `subject_unique_id` and `extensions`
    /// require later versions. Care should be taken in order to ensure
    /// standards compliance.
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,

    pub serial_number: SerialNumber<'a>,
    pub signature: AlgorithmIdentifierRef<'a>,
    pub issuer: Name<'a>,
    pub validity: Validity,
    pub subject: Name<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfoRef<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitStringRef<'a>>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<super::ext::Extensions<'a, 5>>,
}

/// Certificate `Version` as defined in [RFC 5280 Section 4.1].
///
/// ```text
/// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    V1 = 0,

    /// Version 2
    V2 = 1,

    /// Version 3
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

#[cfg(test)]
mod tests {
    use der::Encode;

    use super::Certificate;

    const X509_CERT_PEM: &[u8] = include_bytes!(
        "/home/mathias/Downloads/0c4633573cf31127fc330fe6c57ad1e55e034c41aedbeafa8bf77bb0fdf1de80-certificate.pem.crt"
    );
    const X509_CERT_DER: &[u8] = include_bytes!(
        "/home/mathias/Downloads/0c4633573cf31127fc330fe6c57ad1e55e034c41aedbeafa8bf77bb0fdf1de80-certificate.der.crt"
    );

    #[test]
    fn decode_pem_cert() {
        let mut decode_buf = [0u8; 1024];
        let mut encode_buf = [0u8; 1024];
        let cert = Certificate::from_pem(X509_CERT_PEM, &mut decode_buf).unwrap();

        println!("{:#?}", cert);
        let der_bytes = cert.encode_to_slice(&mut encode_buf).unwrap();
        assert_eq!(X509_CERT_DER, der_bytes);
    }
}
