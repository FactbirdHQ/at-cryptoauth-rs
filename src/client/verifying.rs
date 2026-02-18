//! ECDSA signature verification operations

use crate::command::{self, PublicKey};
use crate::error::{Error, ErrorKind};
use crate::memory::Slot;
use crate::{Digest, Signature};
use embassy_sync::blocking_mutex::raw::RawMutex;

use super::AtCaClient;

pub struct VerifyingKey<'a, M: RawMutex, PHY> {
    pub(crate) atca: &'a AtCaClient<M, PHY>,
    pub(crate) key_id: Slot,
}

impl<'a, M, PHY> VerifyingKey<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    /// Takes a 32-byte message to be signed, typically the SHA256 hash of the
    /// full message and signature.
    pub async fn verify_digest(
        &self,
        digest: &Digest,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        let mut inner = self.atca.inner.lock().await;

        // 1. Nonce load
        self.atca.write_message_digest_buffer(digest).await?;
        // 2. Verify
        let packet =
            command::Verify::new(inner.packet_builder()).external(signature, public_key)?;
        inner.execute(packet).await?;

        Ok(())
    }

    pub async fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let digest = self.atca.sha().digest(msg).await?;
        let key_id = self.key_id.clone();
        let public_key = self.atca.generate_pubkey(key_id).await?;
        self.verify_digest(&digest, signature, &public_key).await
    }
}

impl<'a, M, PHY> VerifyingKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    /// Takes a 32-byte message to be signed, typically the SHA256 hash of the
    /// full message and signature.
    pub fn verify_digest_blocking(
        &self,
        digest: &Digest,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        // 1. Nonce load
        self.atca.write_message_digest_buffer_blocking(digest)?;
        // 2. Verify
        let packet =
            command::Verify::new(inner.packet_builder()).external(signature, public_key)?;
        inner.execute_blocking(packet)?;

        Ok(())
    }

    pub fn verify_blocking(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let digest = self.atca.sha().digest_blocking(msg)?;
        let key_id = self.key_id.clone();
        let public_key = self.atca.generate_pubkey_blocking(key_id)?;
        self.verify_digest_blocking(&digest, signature, &public_key)
    }
}

impl<'a, M, PHY> signature::Verifier<Signature> for VerifyingKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn verify(&self, msg: &[u8], signature: &Signature) -> signature::Result<()> {
        self.verify_blocking(msg, signature)
            .map_err(|_| signature::Error::new())
    }
}
