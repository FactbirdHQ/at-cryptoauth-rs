//! PKCS#10 Certification Request types

use crate::PublicKey;

use super::{attr::Attributes, name::Name, pem::PemWriter};
use core::convert::{TryFrom, TryInto};

use der::{
    Decode, DecodeValue, Encode as _, EncodeValue, Enumerated, FixedTag, Header, Length, Reader,
    Sequence, Writer,
};
use p256::{ecdsa::DerSignature, EncodedPoint};
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
    fn decode_value<R: Reader<'a>>(_reader: &mut R, _header: Header) -> der::Result<Self> {
        // let inner_len = (header.length - Length::ONE)?;
        // let unused_bits = reader.read_byte()?;
        // let inner = reader.read_vec(inner_len)?;
        // Self::new(unused_bits, inner)

        todo!()
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
    fn decode_value<R: Reader<'a>>(_reader: &mut R, _header: Header) -> der::Result<Self> {
        // let inner_len = (header.length - Length::ONE)?;
        // let unused_bits = reader.read_byte()?;
        // let inner = reader.read_vec(inner_len)?;
        // Self::new(unused_bits, inner)

        todo!()
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

// /// `ExtensionReq` as defined in [RFC 5272 Section 3.1].
// ///
// /// ```text
// /// ExtensionReq ::= SEQUENCE SIZE (1..MAX) OF Extension
// /// ```
// ///
// /// [RFC 5272 Section 3.1]: https://datatracker.ietf.org/doc/html/rfc5272#section-3.1
// #[derive(Clone, Debug, PartialEq, Eq, Default)]
// pub struct ExtensionReq<'a>(pub SequenceOf<Extension<'a>, MAX_EXTENSIONS>);

// impl AssociatedOid for ExtensionReq {
//     const OID: ObjectIdentifier = ID_EXTENSION_REQ;
// }

// impl_newtype!(ExtensionReq, SequenceOf<Extension, MAX_EXTENSIONS>);

// impl<'a> TryFrom<ExtensionReq> for Attribute<'a> {
//     type Error = der::Error;

//     fn try_from(extension_req: ExtensionReq) -> der::Result<Attribute<'a>> {
//         let mut values: SetOf<AttributeValue> = Default::default();
//         values.insert(AnyRef::encode_from(&extension_req.0)?)?;

//         Ok(Attribute {
//             oid: ExtensionReq::OID,
//             values,
//         })
//     }
// }

// pub mod attributes {
//     //! Set of attributes that may be associated to a request

//     use const_oid::AssociatedOid;
//     use der::{
//         asn1::{AnyRef, ObjectIdentifier, SetOf},
//         EncodeValue, Length, Result, Tag, Tagged, Writer,
//     };

//     use crate::cert::attr::Attribute;

//     /// Trait to be implement by request attributes
//     pub trait AsAttribute: AssociatedOid + Tagged + EncodeValue + Sized {
//         /// Returns the Attribute with the content encoded.
//         fn to_attribute(&self) -> Result<Attribute> {
//             let inner = AnyRef::encode_from(self)?;

//             let values = SetOf::try_from(&[inner])?;

//             Ok(Attribute {
//                 oid: Self::OID,
//                 values,
//             })
//         }
//     }

//     // /// `ChallengePassword` as defined in [RFC 2985 Section 5.4.1]
//     // ///
//     // /// ```text
//     // /// challengePassword ATTRIBUTE ::= {
//     // ///          WITH SYNTAX DirectoryString {pkcs-9-ub-challengePassword}
//     // ///          EQUALITY MATCHING RULE caseExactMatch
//     // ///          SINGLE VALUE TRUE
//     // ///          ID pkcs-9-at-challengePassword
//     // ///  }
//     // /// ```
//     // ///
//     // /// [RFC 2985 Section 5.4.1]: https://www.rfc-editor.org/rfc/rfc2985#page-16
//     // pub struct ChallengePassword(pub DirectoryString);

//     // impl AsAttribute for ChallengePassword {}

//     // impl AssociatedOid for ChallengePassword {
//     //     const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.7");
//     // }

//     // impl Tagged for ChallengePassword {
//     //     fn tag(&self) -> Tag {
//     //         self.0.tag()
//     //     }
//     // }

//     // impl EncodeValue for ChallengePassword {
//     //     fn value_len(&self) -> Result<Length> {
//     //         self.0.value_len()
//     //     }

//     //     fn encode_value(&self, encoder: &mut impl Writer) -> Result<()> {
//     //         self.0.encode_value(encoder)
//     //     }
//     // }
// }

// #[cfg(test)]
// mod tests {
//     use der::{
//         asn1::{SequenceOf, SetOf},
//         AnyRef,
//     };
//     use p256::{ecdsa::DerSignature, pkcs8::DecodePrivateKey};
//     use signature::KeypairRef;

//     use crate::{cert::{
//         attr::AttributeTypeAndValue,
//         name::{Name, RdnSequence, RelativeDistinguishedName},
//     }, PublicKey};

//     const PKCS8_PRIVATE_KEY_DER: &[u8] =
//         include_bytes!("../../../formats/x509-cert/tests/examples/p256-priv.der");

//     pub struct TestSigner(p256::ecdsa::SigningKey);

//     impl signature::Signer<DerSignature> for TestSigner {
//         fn try_sign(&self, msg: &[u8]) -> Result<DerSignature, signature::Error> {
//             self.0.try_sign(msg)
//         }
//     }

//     impl signature::Keypair for TestSigner {
//         type VerifyingKey = PublicKey;

//         fn verifying_key(&self) -> Self::VerifyingKey {
//             self.0.verifying_key()
//             PublicKey::try_from(&hex_literal::hex!("b2be345ad7899383a9aab4fb968b1c7835cb2cd42c7e97c26f85df8e201f3be8a82983f0a11d6ff31d66ce9932466f0f2cca21ef96bec9ce235b3d87b0f8fa9e")[..]).unwrap()
//         }
//     }

//     fn ecdsa_signer() -> TestSigner {
//         let secret_key = p256::SecretKey::from_pkcs8_der(PKCS8_PRIVATE_KEY_DER).unwrap();
//         TestSigner(p256::ecdsa::SigningKey::from(secret_key))
//     }

//     #[test]
//     fn certificate_request() {
//         // let subject = Name::from_str("CN=service.domination.world").unwrap();

//         let mut cn = SetOf::new();
//         cn.insert(AttributeTypeAndValue {
//             oid: const_oid::db::rfc4519::CN,
//             value: AnyRef::new(der::Tag::Utf8String, b"factbird").unwrap(),
//         })
//         .unwrap();

//         let mut rdn_seq = SequenceOf::new();
//         rdn_seq.add(RelativeDistinguishedName(cn)).unwrap();
//         let subject = RdnSequence(rdn_seq);

//         let signer = ecdsa_signer();
//         let builder =
//             crate::cert::builder::RequestBuilder::new(subject).expect("Create certificate request");

//         let mut buf = [0u8; 1024];
//         let cert_req =
//             crate::cert::builder::Builder::build::<_>(builder, &mut buf, &signer).unwrap();

//         println!("{:#?}", cert_req);

//         let mut pem_buf = [0u8; 1024];

//         let pem_len = cert_req
//             .to_pem_slice(&mut pem_buf, pem_rfc7468::LineEnding::LF)
//             .expect("generate pem");

//         println!("{}", core::str::from_utf8(&pem_buf[..pem_len]).unwrap());
//     }
// }
