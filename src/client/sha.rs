//! SHA-256 hashing operations

use crate::Digest;
use crate::command;
use crate::error::{Error, ErrorKind};
use embassy_sync::blocking_mutex::raw::RawMutex;
use heapless::Vec;

use super::AtCaClient;

pub struct Sha<'a, M: RawMutex, PHY> {
    pub(crate) atca: &'a AtCaClient<M, PHY>,
    pub(crate) remaining_bytes: Vec<u8, 64>,
}

impl<'a, M, PHY> signature::digest::OutputSizeUser for Sha<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    type OutputSize = signature::digest::generic_array::typenum::U32;
}

impl<'a, M, PHY> signature::digest::FixedOutput for Sha<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn finalize_into(self, out: &mut signature::digest::Output<Self>) {
        let response = self.finalize_blocking().unwrap();
        out.as_mut_slice().copy_from_slice(response.as_ref());
    }

    fn finalize_fixed(self) -> signature::digest::Output<Self> {
        let response = self.finalize_blocking().unwrap();
        response.value
    }
}

impl<'a, M, PHY> signature::digest::Update for Sha<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn update(&mut self, data: &[u8]) {
        self.update_blocking(data).unwrap()
    }
}

impl<'a, M, PHY> signature::digest::HashMarker for Sha<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
}

impl<'a, M, PHY> Sha<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    pub async fn init(&mut self) -> Result<(), Error> {
        let mut inner = self.atca.inner.lock().await;

        let packet = command::Sha::new(inner.packet_builder()).start()?;
        inner.execute(packet).await?;

        Ok(())
    }

    pub async fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let capacity = 0x40;
        let length = data.len();

        // Store remaining bytes for later processing
        let remainder_length = data.len() % capacity;
        let (bytes, remainder) = data.split_at(length - remainder_length);
        self.remaining_bytes.extend_from_slice(remainder).ok();

        // Execute update command
        for chunk in bytes.chunks(capacity) {
            let mut inner = self.atca.inner.lock().await;

            let packet = command::Sha::new(inner.packet_builder()).update(chunk)?;
            inner.execute(packet).await?;
        }

        Ok(())
    }

    pub async fn chain(&mut self, data: &[u8]) -> Result<&mut Self, Error> {
        if self.remaining_bytes.len() != 0 {
            // TODO: Concatenate remaining bytes and input data.
        }

        self.update(data).await?;
        Ok(self)
    }

    pub async fn finalize(&mut self) -> Result<Digest, Error> {
        let mut inner = self.atca.inner.lock().await;

        let packet = command::Sha::new(inner.packet_builder()).end(&self.remaining_bytes)?;
        inner.execute(packet).await?.as_ref().try_into()
    }

    pub async fn digest(&mut self, data: &[u8]) -> Result<Digest, Error> {
        self.init().await?;
        self.update(data).await?;
        self.finalize().await
    }
}

impl<'a, M, PHY> Sha<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    pub fn init_blocking(&mut self) -> Result<(), Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        let packet = command::Sha::new(inner.packet_builder()).start()?;
        inner.execute_blocking(packet)?;

        Ok(())
    }

    pub fn update_blocking(&mut self, data: &[u8]) -> Result<(), Error> {
        let capacity = 0x40;
        let length = data.len();

        // Store remaining bytes for later processing
        let remainder_length = data.len() % capacity;
        let (bytes, remainder) = data.split_at(length - remainder_length);
        self.remaining_bytes.extend_from_slice(remainder).ok();

        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        // Execute update command
        for chunk in bytes.chunks(capacity) {
            let packet = command::Sha::new(inner.packet_builder()).update(chunk)?;
            inner.execute_blocking(packet)?;
        }

        Ok(())
    }

    pub fn chain_blocking(&mut self, data: &[u8]) -> Result<&mut Self, Error> {
        if self.remaining_bytes.len() != 0 {
            // TODO: Concatenate remaining bytes and input data.
        }

        self.update_blocking(data)?;
        Ok(self)
    }

    pub fn finalize_blocking(self) -> Result<Digest, Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        let packet = command::Sha::new(inner.packet_builder()).end(&self.remaining_bytes)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    pub fn digest_blocking(mut self, data: &[u8]) -> Result<Digest, Error> {
        self.init_blocking()?;
        self.update_blocking(data)?;
        self.finalize_blocking()
    }
}
