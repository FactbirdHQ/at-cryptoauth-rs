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

pub use client::{AtCaClient, Memory, Random, Sign, SigningKey, Verify, VerifyingKey};
pub use command::{Block, Digest, PublicKey};
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
