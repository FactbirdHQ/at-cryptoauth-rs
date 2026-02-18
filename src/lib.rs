//! # at-cryptoauth
//!
//! A `no_std` Rust driver for Microchip ATECC608 CryptoAuthentication secure elements.
//!
//! This crate provides both async and blocking APIs for communicating with ATECC608
//! devices over I2C, supporting cryptographic operations, secure key storage, and
//! X.509 certificate handling.
//!
//! ## Features
//!
//! - **Cryptographic Operations**: ECDSA signing/verification, ECDH key exchange, SHA-256 hashing, AES encryption
//! - **Secure Key Storage**: Generate, store, and use private keys that never leave the device
//! - **Certificate Support**: Parse and generate compressed X.509 certificates in ATECC format
//! - **Dual API**: Both async (embassy) and blocking variants for all operations
//! - **Trust&Go Support**: Pre-provisioned device configuration via [`tngtls`] module
//!
//! ## Quick Start
//!
//! ```ignore
//! use at_cryptoauth::{AtCaClient, I2cConfig};
//! use embassy_sync::blocking_mutex::raw::NoopRawMutex;
//!
//! // Create client with default I2C configuration
//! let client: AtCaClient<NoopRawMutex, _> = AtCaClient::new(i2c);
//!
//! // Or with custom configuration
//! let config = I2cConfig {
//!     address: 0x60,
//!     wake_delay_us: 1500,
//!     max_retries: 20,
//! };
//! let client: AtCaClient<NoopRawMutex, _> = AtCaClient::with_config(i2c, config);
//!
//! // Async: Sign data with stored private key
//! let signature = client.signer(Slot::PrivateKey0).sign(b"message").await?;
//!
//! // Blocking: Same operation
//! let signature = client.signer(Slot::PrivateKey0).sign_blocking(b"message")?;
//! ```
//!
//! ## Error Handling
//!
//! All operations return `Result<T, Error>`. The [`error::ErrorKind`] enum provides
//! detailed error information including device status codes and communication failures.
//!
//! Blocking operations may return [`error::ErrorKind::MutexLocked`] if the client is
//! already in use by another operation.

#![cfg_attr(not(test), no_std)]
mod fmt;

pub mod cert;
mod client;
mod clock_divider;
mod command;
mod datalink;
pub mod error;
pub mod memory;
mod packet;
pub mod tngtls;

pub use client::{Aes, AtCaClient, Memory, Random, Sha, SigningKey, VerifyingKey};
pub use command::{Block, Digest, PublicKey};
pub use datalink::I2cConfig;
pub use packet::CRC16;
pub use signature;

pub use der;
pub use pem_rfc7468;
pub use spki;

pub use p256::ecdsa::Signature;

#[cfg(feature = "embedded-tls")]
pub use embedded_tls_impl::AteccProvider;

#[cfg(feature = "embedded-tls")]
mod embedded_tls_impl {
    use embassy_sync::blocking_mutex::raw::RawMutex;

    pub struct AteccProvider<'a, M: RawMutex, PHY> {
        atca: &'a crate::AtCaClient<M, PHY>,
        sign_key: crate::memory::Slot,
    }

    impl<'a, M: RawMutex, PHY> AteccProvider<'a, M, PHY> {
        pub fn new(atca: &'a crate::AtCaClient<M, PHY>, sign_key: crate::memory::Slot) -> Self {
            Self { atca, sign_key }
        }
    }

    impl<'a, M: RawMutex, PHY> embedded_tls::CryptoProvider for AteccProvider<'a, M, PHY>
    where
        PHY: embedded_hal::i2c::I2c,
    {
        type CipherSuite = embedded_tls::Aes128GcmSha256;
        type Signature = p256::ecdsa::DerSignature;

        fn rng(&mut self) -> impl signature::rand_core::CryptoRngCore {
            self.atca.random()
        }

        fn verifier(
            &mut self,
        ) -> Result<&mut impl embedded_tls::TlsVerifier<Self::CipherSuite>, embedded_tls::TlsError>
        {
            Err::<&mut embedded_tls::NoVerify, _>(embedded_tls::TlsError::Unimplemented)
        }

        fn signer(
            &mut self,
            _key_der: &[u8],
        ) -> core::result::Result<
            (
                impl signature::SignerMut<Self::Signature>,
                embedded_tls::SignatureScheme,
            ),
            embedded_tls::TlsError,
        > {
            Ok((
                self.atca.signer(self.sign_key),
                embedded_tls::SignatureScheme::EcdsaSecp256r1Sha256,
            ))
        }
    }
}
