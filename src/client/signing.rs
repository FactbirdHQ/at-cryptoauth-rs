//! ECDSA signing operations

use crate::command::{self, PublicKey};
use crate::error::{Error, ErrorKind};
use crate::memory::Slot;
use crate::{Digest, Signature};
use embassy_sync::blocking_mutex::raw::RawMutex;
use p256::ecdsa::DerSignature;
use signature::Keypair;
use signature::hazmat::PrehashSigner;

use super::{AtCaClient, VerifyingKey};

pub struct SigningKey<'a, M: RawMutex, PHY> {
    pub(crate) atca: &'a AtCaClient<M, PHY>,
    pub(crate) key_id: Slot,
}

impl<'a, M: RawMutex, PHY> SigningKey<'a, M, PHY> {
    pub fn verifying_key(&'a mut self) -> VerifyingKey<'a, M, PHY> {
        VerifyingKey {
            atca: self.atca,
            key_id: self.key_id,
        }
    }
}

impl<'a, M, PHY> SigningKey<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    /// Takes a 32-byte message to be signed, typically the SHA256 hash of the full message.
    pub async fn sign_digest(&self, digest: &Digest) -> Result<Signature, Error> {
        // 1. Update RNG seed
        self.atca.update_seed().await?;
        // 2. Nonce load
        self.atca.write_message_digest_buffer(digest).await?;
        // 3. Sign
        let mut inner = self.atca.inner.lock().await;
        let packet = command::Sign::new(inner.packet_builder()).external(self.key_id)?;
        let response = inner.execute(packet).await?;
        Signature::from_bytes(response.as_ref().into()).map_err(|_| ErrorKind::BadParam.into())
    }

    pub async fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let digest = self.atca.sha().digest(msg).await?;
        self.sign_digest(&digest).await
    }
}

impl<'a, M, PHY> SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    /// Takes a 32-byte message to be signed, typically the SHA256 hash of the full message.
    pub fn sign_digest_blocking(&self, digest: &Digest) -> Result<Signature, Error> {
        // 1. Update RNG seed
        self.atca.update_seed_blocking()?;
        // 2. Nonce load
        self.atca.write_message_digest_buffer_blocking(digest)?;
        // 3. Sign
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
        let packet = command::Sign::new(inner.packet_builder()).external(self.key_id)?;
        let response = inner.execute_blocking(packet)?;
        Signature::from_bytes(response.as_ref().into()).map_err(|_| ErrorKind::BadParam.into())
    }

    pub fn sign_blocking(&self, msg: &[u8]) -> Result<Signature, Error> {
        let digest = self.atca.sha().digest_blocking(msg)?;
        self.sign_digest_blocking(&digest)
    }
}

impl<'a, M, PHY> Keypair for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    type VerifyingKey = PublicKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        let key_id = self.key_id;
        self.atca.generate_pubkey_blocking(key_id).unwrap()
    }
}

impl<'a, M, PHY> PrehashSigner<Signature> for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        let digest = self
            .atca
            .sha()
            .digest_blocking(prehash)
            .map_err(|_| signature::Error::new())?;
        self.sign_digest_blocking(&digest)
            .map_err(|_| signature::Error::new())
    }
}

impl<'a, M, PHY, D> signature::DigestSigner<D, Signature> for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    D: signature::digest::Digest,
    M: RawMutex,
{
    fn try_sign_digest(&self, digest: D) -> signature::Result<Signature> {
        self.sign_prehash(&digest.finalize())
    }
}

impl<'a, M, PHY> signature::Signer<Signature> for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        let digest = self
            .atca
            .sha()
            .digest_blocking(msg)
            .map_err(|_| signature::Error::new())?;
        self.sign_digest_blocking(&digest)
            .map_err(|_| signature::Error::new())
    }
}

impl<'a, M, PHY> PrehashSigner<DerSignature> for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<DerSignature> {
        PrehashSigner::<Signature>::sign_prehash(self, prehash).map(Into::into)
    }
}

impl<'a, M, PHY, D> signature::DigestSigner<D, DerSignature> for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    D: signature::digest::Digest,
    M: RawMutex,
{
    fn try_sign_digest(&self, digest: D) -> signature::Result<DerSignature> {
        signature::DigestSigner::<D, Signature>::try_sign_digest(self, digest).map(Into::into)
    }
}

impl<'a, M, PHY> signature::Signer<DerSignature> for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<DerSignature> {
        signature::Signer::<Signature>::try_sign(self, msg).map(Into::into)
    }
}
