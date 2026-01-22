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

use super::{
    certificate::{TbsCertificate, Version},
    ext::Extensions,
    serial_number::SerialNumber,
    time::Validity,
};
use der::asn1::BitStringRef;
use spki::SubjectPublicKeyInfoRef;

/// X509 Certificate builder
///
/// This builder creates X.509 certificates using borrowed types for no_std/no_alloc
/// compatibility. The builder accumulates certificate parameters and then signs
/// the TBS (To-Be-Signed) certificate using a provided signer.
///
/// Unlike `RequestBuilder`, this builder outputs the DER-encoded certificate directly
/// to a buffer rather than returning a parsed structure. This avoids lifetime issues
/// with borrowed signature data.
///
/// # Example
///
/// ```ignore
/// let builder = CertificateBuilder::new(
///     serial_number,
///     validity,
///     issuer,
///     subject,
///     subject_public_key_info,
/// )?;
///
/// let cert_len = builder.build_to_slice(&mut buf, &signer)?;
/// let cert_der = &buf[..cert_len];
/// ```
pub struct CertificateBuilder<'a> {
    serial_number: SerialNumber<'a>,
    validity: Validity,
    issuer: Name<'a>,
    subject: Name<'a>,
    subject_public_key_info: SubjectPublicKeyInfoRef<'a>,
    extensions: Option<Extensions<'a, 5>>,
}

impl<'a> CertificateBuilder<'a> {
    /// Creates a new certificate builder
    ///
    /// # Arguments
    ///
    /// * `serial_number` - Unique serial number for the certificate
    /// * `validity` - Not before and not after times
    /// * `issuer` - Distinguished name of the issuer
    /// * `subject` - Distinguished name of the subject
    /// * `subject_public_key_info` - Subject's public key info
    pub fn new(
        serial_number: SerialNumber<'a>,
        validity: Validity,
        issuer: Name<'a>,
        subject: Name<'a>,
        subject_public_key_info: SubjectPublicKeyInfoRef<'a>,
    ) -> Result<Self> {
        Ok(Self {
            serial_number,
            validity,
            issuer,
            subject,
            subject_public_key_info,
            extensions: None,
        })
    }

    /// Creates a self-signed certificate builder (issuer = subject)
    pub fn new_self_signed(
        serial_number: SerialNumber<'a>,
        validity: Validity,
        subject: Name<'a>,
        subject_public_key_info: SubjectPublicKeyInfoRef<'a>,
    ) -> Result<Self> {
        Ok(Self {
            serial_number,
            validity,
            issuer: subject.clone(),
            subject,
            subject_public_key_info,
            extensions: None,
        })
    }

    /// Set the certificate extensions
    pub fn with_extensions(mut self, extensions: Extensions<'a, 5>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Build the TBS certificate structure
    fn build_tbs(&self) -> TbsCertificate<'a> {
        let version = if self.extensions.is_some() {
            Version::V3
        } else {
            Version::V1
        };

        TbsCertificate {
            version,
            serial_number: self.serial_number.clone(),
            signature: AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            issuer: self.issuer.clone(),
            validity: self.validity,
            subject: self.subject.clone(),
            subject_public_key_info: self.subject_public_key_info.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: self.extensions.clone(),
        }
    }

    /// Build and sign the certificate, encoding directly to DER in the provided buffer
    ///
    /// This method:
    /// 1. Builds the TBS certificate
    /// 2. Signs it using the provided signer
    /// 3. Encodes the complete certificate as DER into the buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to write the DER-encoded certificate
    /// * `signer` - Signer implementing `Signer<DerSignature>` and `Keypair`
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer
    pub fn build_to_slice<S>(self, buf: &mut [u8], signer: &S) -> Result<usize>
    where
        S: Signer<DerSignature>,
        S: Keypair,
        S: Keypair<VerifyingKey = PublicKey>,
    {
        use der::Encode;

        // Build the TBS certificate
        let tbs = self.build_tbs();

        // Encode TBS to get bytes for signing
        // We need a temporary buffer for the TBS encoding
        let mut tbs_buf = [0u8; 512];
        let tbs_der = tbs.encode_to_slice(&mut tbs_buf).map_err(Error::from)?;

        // Sign the TBS certificate
        let signature = signer.try_sign(tbs_der)?;

        // Build the full certificate manually
        // Certificate ::= SEQUENCE {
        //     tbsCertificate       TBSCertificate,
        //     signatureAlgorithm   AlgorithmIdentifier,
        //     signatureValue       BIT STRING
        // }

        let sig_algorithm: AlgorithmIdentifier<()> = AlgorithmIdentifier {
            oid: ECDSA_WITH_SHA_256,
            parameters: None,
        };

        // Create BitStringRef from signature bytes (0 unused bits)
        let sig_bits = BitStringRef::new(0, signature.as_bytes())
            .map_err(|_| Error::Asn1(der::Tag::BitString.value_error()))?;

        // Calculate total length
        let tbs_len = tbs.encoded_len().map_err(Error::from)?;
        let alg_len = sig_algorithm.encoded_len().map_err(Error::from)?;
        let sig_len = sig_bits.encoded_len().map_err(Error::from)?;
        let inner_len = (tbs_len + alg_len + sig_len).map_err(Error::from)?;

        // Encode as SEQUENCE
        let header = der::Header::new(der::Tag::Sequence, inner_len).map_err(Error::from)?;

        let mut writer = der::SliceWriter::new(buf);
        header.encode(&mut writer).map_err(Error::from)?;
        tbs.encode(&mut writer).map_err(Error::from)?;
        sig_algorithm.encode(&mut writer).map_err(Error::from)?;
        sig_bits.encode(&mut writer).map_err(Error::from)?;

        Ok(writer.finish().map_err(Error::from)?.len())
    }
}

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
        S: Keypair,
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
        S: Keypair,
        S: Keypair<VerifyingKey = PublicKey>,
    {
        let len = self.finalize(buf, signer)?;
        let signature = signer.try_sign_with_rng(rng, &buf[..len])?;

        self.assemble(signature)
    }
}

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
