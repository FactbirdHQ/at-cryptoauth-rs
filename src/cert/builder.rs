//! X509 Certificate builder

// use async_signature::{AsyncRandomizedSigner, AsyncSigner};
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, SECP_256_R_1};
use core::fmt;
use der::Encode;
use p256::ecdsa::DerSignature;
use signature::{rand_core::CryptoRngCore, Keypair, RandomizedSigner, Signer};
use spki::{AlgorithmIdentifier, AlgorithmIdentifierWithOid, ObjectIdentifier};

use crate::PublicKey;

use super::{
    name::Name,
    request::{CertReq, CertReqInfo, PublicKeyBitString, SignatureBitString},
};

const NULL_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.0.0");

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Public key errors propagated from the [`spki::Error`] type.
    PublicKey(spki::Error),

    /// Signing error propagated for the [`signature::Error`] type.
    Signature(signature::Error),

    Device(crate::error::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {}", err),
            Error::PublicKey(err) => write!(f, "public key error: {}", err),
            Error::Signature(err) => write!(f, "signature error: {}", err),
            Error::Device(err) => write!(f, "device error: {}", err),
        }
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

impl From<spki::Error> for Error {
    fn from(err: spki::Error) -> Error {
        Error::PublicKey(err)
    }
}

impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Error {
        Error::Signature(err)
    }
}

impl From<crate::error::Error> for Error {
    fn from(err: crate::error::Error) -> Error {
        Error::Device(err)
    }
}

/// Result type
pub type Result<T> = core::result::Result<T, Error>;

// /// X509 Certificate builder
// ///
// /// ```
// /// use der::Decode;
// /// use x509_cert::spki::SubjectPublicKeyInfoOwned;
// /// use x509_cert::builder::{CertificateBuilder, Profile, Builder};
// /// use x509_cert::name::Name;
// /// use x509_cert::serial_number::SerialNumber;
// /// use x509_cert::time::Validity;
// /// use std::str::FromStr;
// ///
// /// # const RSA_2048_DER: &[u8] = include_bytes!("../tests/examples/rsa2048-pub.der");
// /// # const RSA_2048_PRIV_DER: &[u8] = include_bytes!("../tests/examples/rsa2048-priv.der");
// /// # use rsa::{pkcs1v15::SigningKey, pkcs1::DecodeRsaPrivateKey};
// /// # use sha2::Sha256;
// /// # use std::time::Duration;
// /// # use der::referenced::RefToOwned;
// /// # fn rsa_signer() -> SigningKey<Sha256> {
// /// #     let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER).unwrap();
// /// #     let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);
// /// #     signing_key
// /// # }
// ///
// /// let serial_number = SerialNumber::from(42u32);
// /// let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
// /// let profile = Profile::Root;
// /// let subject = Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
// ///
// /// let pub_key = SubjectPublicKeyInfoOwned::try_from(RSA_2048_DER).expect("get rsa pub key");
// ///
// /// let mut signer = rsa_signer();
// /// let mut builder = CertificateBuilder::new(
// ///     profile,
// ///     serial_number,
// ///     validity,
// ///     subject,
// ///     pub_key,
// /// )
// /// .expect("Create certificate builder");
// ///
// /// let cert = builder.build(&signer).expect("Create certificate");
// /// ```
// pub struct CertificateBuilder {
//     tbs: TbsCertificate,
//     extensions: Extensions,
//     profile: Profile,
// }

// impl CertificateBuilder {
//     /// Creates a new certificate builder
//     pub fn new(
//         profile: Profile,
//         serial_number: SerialNumber,
//         mut validity: Validity,
//         subject: Name,
//         subject_public_key_info: SubjectPublicKeyInfoOwned,
//     ) -> Result<Self> {
//         let signature_alg = AlgorithmIdentifier {
//             oid: NULL_OID,
//             parameters: None,
//         };

//         let issuer = profile.get_issuer(&subject);

//         validity.not_before.rfc5280_adjust_utc_time()?;
//         validity.not_after.rfc5280_adjust_utc_time()?;

//         let tbs = TbsCertificate {
//             version: Version::V3,
//             serial_number,
//             signature: signature_alg,
//             issuer,
//             validity,
//             subject,
//             subject_public_key_info,
//             extensions: None,

//             // We will not generate unique identifier because as per RFC5280 Section 4.1.2.8:
//             //   CAs conforming to this profile MUST NOT generate
//             //   certificates with unique identifiers.
//             //
//             // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.8
//             issuer_unique_id: None,
//             subject_unique_id: None,
//         };

//         let extensions = Extensions::default();
//         Ok(Self {
//             tbs,
//             extensions,
//             profile,
//         })
//     }

//     /// Add an extension to this certificate
//     pub fn add_extension<E: AsExtension>(&mut self, extension: &E) -> Result<()> {
//         let ext = extension.to_extension(&self.tbs.subject, &self.extensions)?;
//         self.extensions.push(ext);

//         Ok(())
//     }
// }

/// Builder for X509 Certificate Requests
pub struct RequestBuilder<'a> {
    info: CertReqInfo<'a>,
    // extension_req: ExtensionReq,
}

impl<'a> RequestBuilder<'a> {
    /// Creates a new certificate request builder
    pub fn new(subject: Name<'a>) -> Result<Self> {
        let version = Default::default();

        let algorithm = AlgorithmIdentifier {
            oid: NULL_OID,
            parameters: None,
        };
        let public_key = spki::SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: PublicKeyBitString(PublicKey::default()),
        };

        let attributes = Default::default();
        // let extension_req = Default::default();

        Ok(Self {
            info: CertReqInfo {
                version,
                subject,
                public_key,
                attributes,
            },
            // extension_req,
        })
    }

    // /// Add an extension to this certificate request
    // pub fn add_extension<E: AsExtension>(&mut self, extension: &E) -> Result<()> {
    //     let ext = extension.to_extension(&self.info.subject, &self.extension_req.0)?;

    //     self.extension_req.0.push(ext);

    //     Ok(())
    // }

    // /// Add an attribute to this certificate request
    // pub fn add_attribute<A: AsAttribute>(&mut self, attribute: &A) -> Result<()> {
    //     let attr = attribute.to_attribute()?;

    //     self.info.attributes.insert(attr)?;
    //     Ok(())
    // }
}

/// Trait for X509 builders
///
/// This trait defines the interface between builder and the signers.
pub trait Builder: Sized {
    /// Type built by this builder
    type Output: Sized;

    /// Assemble the final object from signature.
    fn assemble(self, signature: DerSignature) -> Result<Self::Output>;

    /// Finalize and return a serialization of the object for signature.
    fn finalize<S>(&mut self, buf: &mut [u8], signer: &S) -> Result<usize>
    where
        S: Keypair,
        S: Keypair<VerifyingKey = PublicKey>;

    /// Run the object through the signer and build it.
    fn build<S>(mut self, buf: &mut [u8], signer: &S) -> Result<Self::Output>
    where
        S: Signer<DerSignature>,
        S: Keypair<VerifyingKey = PublicKey>,
    {
        let len = self.finalize(buf, signer)?;
        let signature = signer.try_sign(&buf[..len])?;

        self.assemble(signature)
    }

    /// Run the object through the signer and build it.
    fn build_with_rng<S>(
        mut self,
        buf: &mut [u8],
        signer: &S,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Output>
    where
        S: RandomizedSigner<DerSignature>,
        S: Keypair<VerifyingKey = PublicKey>,
    {
        let len = self.finalize(buf, signer)?;
        let signature = signer.try_sign_with_rng(rng, &buf[..len])?;

        self.assemble(signature)
    }
}

// impl Builder for CertificateBuilder {
//     type Output = Certificate;

//     fn finalize<S>(&mut self, cert_signer: &S) -> Result<vec::Vec<u8>>
//     where
//         S: Keypair + DynSignatureAlgorithmIdentifier,
//         S::VerifyingKey: EncodePublicKey,
//     {
//         let verifying_key = cert_signer.verifying_key();
//         let signer_pub = SubjectPublicKeyInfoOwned::from_key(&verifying_key)?;

//         self.tbs.signature = cert_signer.signature_algorithm_identifier()?;

//         let mut default_extensions = self.profile.build_extensions(
//             self.tbs.subject_public_key_info.owned_to_ref(),
//             signer_pub.owned_to_ref(),
//             &self.tbs,
//         )?;

//         self.extensions.append(&mut default_extensions);

//         if !self.extensions.is_empty() {
//             self.tbs.extensions = Some(self.extensions.clone());
//         }

//         if self.tbs.extensions.is_none() {
//             if self.tbs.issuer_unique_id.is_some() || self.tbs.subject_unique_id.is_some() {
//                 self.tbs.version = Version::V2;
//             } else {
//                 self.tbs.version = Version::V1;
//             }
//         }

//         self.tbs.to_der().map_err(Error::from)
//     }

//     fn assemble<S>(self, signature: BitString, _signer: &S) -> Result<Self::Output>
//     where
//         S: Keypair + DynSignatureAlgorithmIdentifier,
//         S::VerifyingKey: EncodePublicKey,
//     {
//         let signature_algorithm = self.tbs.signature.clone();

//         Ok(Certificate {
//             tbs_certificate: self.tbs,
//             signature_algorithm,
//             signature,
//         })
//     }
// }

impl<'a> Builder for RequestBuilder<'a> {
    type Output = CertReq<'a>;

    fn finalize<S>(&mut self, buf: &mut [u8], signer: &S) -> Result<usize>
    where
        S: Keypair<VerifyingKey = PublicKey>,
    {
        self.info.public_key = spki::SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifierWithOid {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(SECP_256_R_1),
            },
            subject_public_key: PublicKeyBitString(signer.verifying_key()),
        };

        // self.info
        //     .attributes
        //     .insert(self.extension_req.clone().try_into()?)?;

        let res = self.info.encode_to_slice(buf).map_err(Error::from)?;
        Ok(res.len())
    }

    fn assemble(self, signature: DerSignature) -> Result<Self::Output> {
        Ok(CertReq {
            info: self.info,
            algorithm: AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: SignatureBitString(signature),
        })
    }
}

// /// Trait for async X509 builders
// ///
// /// This trait defines the interface between builder and the signers.
// ///
// /// This is the async counterpart of [`Builder`].
// #[allow(async_fn_in_trait)]
// pub trait AsyncBuilder: Sized {
//     /// Type built by this builder
//     type Output: Sized;

//     /// Assemble the final object from signature.
//     fn assemble(self, signature: DerSignature) -> Result<Self::Output>;

//     /// Finalize and return a serialization of the object for signature.
//     fn finalize<S>(&mut self, buf: &mut [u8], signer: &S) -> Result<usize>
//     where
//         S: Keypair,
//         S: Keypair<VerifyingKey = PublicKey>;

//     /// Run the object through the signer and build it.
//     async fn build_async<S>(mut self, buf: &mut [u8], signer: &S) -> Result<Self::Output>
//     where
//         S: AsyncSigner<DerSignature>,
//         S: Keypair,
//         S: Keypair<VerifyingKey = PublicKey>,
//     {
//         let len = self.finalize(buf, signer)?;

//         let signature = signer.sign_async(&buf[..len]).await?;

//         self.assemble(signature)
//     }

//     /// Run the object through the signer and build it.
//     async fn build_with_rng_async<S>(
//         mut self,
//         buf: &mut [u8],
//         signer: &S,
//         rng: &mut impl CryptoRngCore,
//     ) -> Result<Self::Output>
//     where
//         S: AsyncRandomizedSigner<DerSignature>,
//         S: Keypair,
//         S: Keypair<VerifyingKey = PublicKey>,
//     {
//         let len = self.finalize(buf, signer)?;

//         let signature = signer.try_sign_with_rng_async(rng, &buf[..len]).await?;

//         self.assemble(signature)
//     }
// }

// impl<T> AsyncBuilder for T
// where
//     T: Builder,
// {
//     type Output = <T as Builder>::Output;

//     fn assemble(self, signature: DerSignature) -> Result<Self::Output> {
//         <T as Builder>::assemble(self, signature)
//     }

//     fn finalize<S>(&mut self, buf: &mut [u8], signer: &S) -> Result<usize>
//     where
//         S: Keypair,
//         S: Keypair<VerifyingKey = PublicKey>,
//     {
//         <T as Builder>::finalize(self, buf, signer)
//     }
// }
