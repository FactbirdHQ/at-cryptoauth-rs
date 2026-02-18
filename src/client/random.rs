//! Random number generation

use crate::command;
use crate::error::{Error, ErrorKind};
use core::num::NonZeroU32;
use embassy_sync::blocking_mutex::raw::RawMutex;
use signature::rand_core;

use super::AtCaClient;

pub struct Random<'a, M: RawMutex, PHY> {
    pub(crate) atca: &'a AtCaClient<M, PHY>,
}

impl<'a, M: RawMutex, PHY> Random<'a, M, PHY> {
    pub fn new(atca: &'a AtCaClient<M, PHY>) -> Self {
        Self { atca }
    }
}

impl<'a, M, PHY> Random<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    pub async fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        for c in dest.chunks_mut(32) {
            let mut inner = self.atca.inner.lock().await;

            let packet = command::Random::new(inner.packet_builder()).random()?;
            let resp = inner.execute(packet).await?;
            let len = c.len().min(resp.as_ref().len());
            c[..len].copy_from_slice(&resp.as_ref()[..len]);
        }
        Ok(())
    }
}

impl<'a, M, PHY> Random<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    pub fn try_fill_bytes_blocking(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        for c in dest.chunks_mut(32) {
            let packet = command::Random::new(inner.packet_builder()).random()?;
            let resp = inner.execute_blocking(packet)?;
            let len = c.len().min(resp.as_ref().len());
            c[..len].copy_from_slice(&resp.as_ref()[..len]);
        }
        Ok(())
    }
}

impl<'a, M, PHY> rand_core::RngCore for Random<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::RngCore::try_fill_bytes(self, dest).unwrap()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.try_fill_bytes_blocking(dest)
            .map_err(|e| NonZeroU32::new(e.code()).unwrap())?;

        Ok(())
    }
}

impl<'a, M, PHY> rand_core::CryptoRng for Random<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
}
