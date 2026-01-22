use core::cmp::Ordering;

use der::{asn1::BitStringRef, Decode, Enumerated, Sequence, ValueOrd};
use pem_rfc7468::PemLabel;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

use super::{name::Name, serial_number::SerialNumber, time::Validity};

// pub enum SerialSource {
//     /// Cert serial is stored on the device.
//     Stored(Location),
//     /// Cert serial is stored on the device with the first byte being the DER
//     /// size (X509 certs only).
//     StoredDynamic(Location),
//     /// Cert serial number is 0x40(MSB) + 9-byte device serial number. Only
//     /// applies to device certificates.
//     DeviceSN,
//     /// Cert serial number is 0x40(MSB) + 2-byte signer ID. Only applies to
//     /// signer certificates.
//     SignerID,
//     /// Cert serial number is the SHA256(Subject public key + Encoded dates),
//     /// with uppermost 2 bits set to 01.
//     PubKeyHash,
//     /// Cert serial number is the SHA256(Device SN + Encoded dates), with
//     /// uppermost 2 bits set to 01. Only applies to device certificates.
//     DeviceSNHash,
// }

// pub enum DateFormat {
//     /// ISO8601 full date YYYY-MM-DDThh:mm:ssZ
//     ISO8601SEP,
//     /// RFC 5280 (X.509) 4.1.2.5.1 UTCTime format YYMMDDhhmmssZ
//     RFC5280UTC,
//     /// POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, big endian.
//     POSIXUINT32BE,
//     /// POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, little endian.
//     POSIXUINT32LE,
//     /// RFC 5280 (X.509) 4.1.2.5.2 GeneralizedTime format YYYYMMDDhhmmssZ
//     RFC5280GEN,
// }

// pub enum Location {
//     Stored(Slot, Range<u16>),
//     GenKey(Slot),
// }

// pub struct CertificateDefinition {
//     pub private_key_slot: Option<Slot>,
//     pub signer_id: Slot,
//     pub public_key_location: Location,
//     pub cert_location: (Slot, Range<u16>),
//     pub serial_source: SerialSource,
//     pub issue_date_format: DateFormat,
//     pub expire_date_format: DateFormat,
//     pub expire_years: u8,
// }

// #[bitfield(u32)]
// pub struct CompressedDate {
//     #[bits(5)]
//     year: u8,
//     #[bits(4)]
//     month: u8,
//     #[bits(5)]
//     day: u8,
//     #[bits(5)]
//     hour: u8,
//     #[bits(5)]
//     expire: u8,
//     #[bits(8)]
//     _unused: u8,
// }

// impl CompressedDate {
//     fn from_validity(validity: Validity) -> Result<Self, Error> {
//         let issue_date = validity.not_before.to_date_time();
//         let expire_date = validity.not_after.to_date_time();

//         // TODO: Check that: `0 <= expire_years < 32`
//         let expire_years = expire_date
//             .year()
//             .checked_sub(issue_date.year())
//             .ok_or(ErrorKind::BadParam)?;

//         Ok(Self::new()
//             .with_year((issue_date.year() - 2000) as u8)
//             .with_month(issue_date.month())
//             .with_day(issue_date.day())
//             .with_hour(issue_date.hour())
//             .with_expire(expire_years as u8))
//     }
// }

// impl CertificateDefinition {
//     pub async fn construct_certificate<PHY: embedded_hal_async::i2c::I2c>(
//         at_client: AtCaClient<PHY>,
//         buf: &mut [u8],
//     ) -> Result<Certificate<'_>, ()> {
//         Err(())
//     }

//     /// Deconstructs a certificate into parts, and stores them according to what
//     /// is defined in the `CertificateDefinition`.
//     pub async fn deconstruct_certificate<PHY: embedded_hal_async::i2c::I2c>(
//         at_client: &mut AtCaClient<PHY>,
//         definition: CertificateDefinition,
//         cert: &Certificate<'_>,
//     ) -> Result<(), Error> {
//         match definition.cert_location {
//             (slot, range) => {
//                 let signature = cert.signature.as_bytes().unwrap();
//                 let date = CompressedDate::from_validity(cert.tbs_certificate.validity)?;
//                 let signer_id = definition.signer_id as u16; // FIXME:
//             }
//         }

//         // match definition.serial_source {
//         //     SerialSource::Stored(_) => todo!(),
//         //     SerialSource::StoredDynamic(_) => todo!(),
//         //     SerialSource::DeviceSN => todo!(),
//         //     SerialSource::SignerID => todo!(),
//         //     SerialSource::PubKeyHash => todo!(),
//         //     SerialSource::DeviceSNHash => todo!(),
//         // }

//         match definition.public_key_location {
//             Location::Stored(slot, range) => {
//                 at_client
//                     .memory()
//                     .write_pubkey(
//                         slot,
//                         cert.tbs_certificate
//                             .subject_public_key_info
//                             .subject_public_key
//                             .as_bytes()
//                             .unwrap(),
//                     )
//                     .await?;
//             }
//             Location::GenKey(_) => {
//                 // Public key is generated not written
//             }
//         }

//         Ok(())
//     }
// }

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

    const X509_CERT_PEM: &[u8] = include_bytes!("/home/mathias/Downloads/0c4633573cf31127fc330fe6c57ad1e55e034c41aedbeafa8bf77bb0fdf1de80-certificate.pem.crt");
    const X509_CERT_DER: &[u8] = include_bytes!("/home/mathias/Downloads/0c4633573cf31127fc330fe6c57ad1e55e034c41aedbeafa8bf77bb0fdf1de80-certificate.der.crt");

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
