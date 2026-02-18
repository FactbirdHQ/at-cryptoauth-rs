//! AES encryption/decryption operations

use crate::command;
use crate::error::{Error, ErrorKind};
use crate::memory::Slot;
use embassy_sync::blocking_mutex::raw::RawMutex;

use super::AtCaClient;

pub struct Aes<'a, M: RawMutex, PHY> {
    pub(crate) atca: &'a AtCaClient<M, PHY>,
    pub(crate) key_id: Slot,
}

impl<'a, M, PHY> Aes<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    pub async fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), Error> {
        use command::Aes as AesCmd;

        if plaintext.len() != ciphertext.len() {
            return Err(ErrorKind::BadParam.into());
        }

        for (plain, cipher) in plaintext
            .chunks(AesCmd::DATA_SIZE)
            .zip(ciphertext.chunks_mut(AesCmd::DATA_SIZE))
        {
            let mut inner = self.atca.inner.lock().await;

            // Input length should be exactly 16 bytes. Otherwise the device
            // couldn't recognize the command properly. If the length is not
            // enough, sufficient number of 0s are padded.
            let packet = AesCmd::new(inner.packet_builder()).encrypt(self.key_id, plain)?;

            // Encrypt plain bytes and write the result to cipher.
            let response = inner.execute(packet).await?;
            if response.as_ref().len() != AesCmd::DATA_SIZE {
                return Err(ErrorKind::InvalidSize.into());
            }
            cipher.copy_from_slice(response.as_ref());
        }
        Ok(())
    }

    pub async fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), Error> {
        use command::Aes as AesCmd;

        if ciphertext.len() != plaintext.len() {
            return Err(ErrorKind::BadParam.into());
        }

        for (cipher, plain) in ciphertext
            .chunks(AesCmd::DATA_SIZE)
            .zip(plaintext.chunks_mut(AesCmd::DATA_SIZE))
        {
            let mut inner = self.atca.inner.lock().await;

            // Input length should be exactly 16 bytes. Otherwise the device
            // couldn't recognize the command properly. If the length is not
            // enough, sufficient number of 0s are padded.
            let packet = AesCmd::new(inner.packet_builder()).decrypt(self.key_id, cipher)?;

            // Decrypt cipher bytes and write the result to plain.
            let response = inner.execute(packet).await?;
            if response.as_ref().len() != AesCmd::DATA_SIZE {
                return Err(ErrorKind::InvalidSize.into());
            }
            plain.copy_from_slice(response.as_ref());
        }
        Ok(())
    }
}

impl<'a, M, PHY> Aes<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    pub fn encrypt_blocking(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        use command::Aes as AesCmd;

        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        if plaintext.len() != ciphertext.len() {
            return Err(ErrorKind::BadParam.into());
        }

        for (plain, cipher) in plaintext
            .chunks(AesCmd::DATA_SIZE)
            .zip(ciphertext.chunks_mut(AesCmd::DATA_SIZE))
        {
            // Input length should be exactly 16 bytes. Otherwise the device
            // couldn't recognize the command properly. If the length is not
            // enough, sufficient number of 0s are padded.
            let packet = AesCmd::new(inner.packet_builder()).encrypt(self.key_id, plain)?;

            // Encrypt plain bytes and write the result to cipher.
            let response = inner.execute_blocking(packet)?;
            if response.as_ref().len() != AesCmd::DATA_SIZE {
                return Err(ErrorKind::InvalidSize.into());
            }
            cipher.copy_from_slice(response.as_ref());
        }
        Ok(())
    }

    pub fn decrypt_blocking(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        use command::Aes as AesCmd;

        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        if ciphertext.len() != plaintext.len() {
            return Err(ErrorKind::BadParam.into());
        }

        for (cipher, plain) in ciphertext
            .chunks(AesCmd::DATA_SIZE)
            .zip(plaintext.chunks_mut(AesCmd::DATA_SIZE))
        {
            // Input length should be exactly 16 bytes. Otherwise the device
            // couldn't recognize the command properly. If the length is not
            // enough, sufficient number of 0s are padded.
            let packet = AesCmd::new(inner.packet_builder()).decrypt(self.key_id, cipher)?;

            // Decrypt cipher bytes and write the result to plain.
            let response = inner.execute_blocking(packet)?;
            if response.as_ref().len() != AesCmd::DATA_SIZE {
                return Err(ErrorKind::InvalidSize.into());
            }
            plain.copy_from_slice(response.as_ref());
        }
        Ok(())
    }
}
