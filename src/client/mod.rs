//! Client module for ATECC608 communication.
//!
//! The [`AtCaClient`] is the main entry point for interacting with ATECC608 devices.
//! It provides methods for cryptographic operations, key management, and device control.
//!
//! ## Sub-modules
//!
//! Specialized operations are organized into sub-modules accessible via client methods:
//!
//! - [`Aes`]: AES-128 encryption and decryption via [`AtCaClient::aes`]
//! - [`Sha`]: SHA-256 hashing via [`AtCaClient::sha`]
//! - [`SigningKey`]: ECDSA signing via [`AtCaClient::signer`]
//! - [`VerifyingKey`]: ECDSA verification via [`AtCaClient::verifier`]
//! - [`Memory`]: Device memory read/write/lock via [`AtCaClient::memory`]
//! - [`Random`]: Cryptographic random number generation via [`AtCaClient::random`]
//!
//! ## Async vs Blocking
//!
//! All operations have both async and blocking variants. Async methods require
//! `embedded_hal_async::i2c::I2c`, while blocking methods require `embedded_hal::i2c::I2c`.
//! Blocking methods have a `_blocking` suffix (e.g., `sign` vs `sign_blocking`).

mod aes;
mod memory;
mod random;
mod sha;
mod signing;
mod verifying;

pub use aes::Aes;
pub use memory::Memory;
pub use random::Random;
pub use sha::Sha;
pub use signing::SigningKey;
pub use verifying::VerifyingKey;

use crate::clock_divider::ClockDivider;
use crate::command::{Ecdh, GenKey, Info, NonceCtx, PrivWrite, PublicKey, SharedSecret, Word};
use crate::datalink::{I2c, I2cConfig};
use crate::error::{Error, ErrorKind};
use crate::memory::{Slot, Zone};
use crate::packet::{Packet, PacketBuilder, Response};
use crate::tngtls::TrustAndGo;
use crate::{Block, Digest};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use heapless::Vec;

pub(crate) struct Inner<PHY> {
    pub i2c: I2c<PHY>,
    pub buffer: Vec<u8, 192>,
    pub clock_divider: ClockDivider,
}

impl<PHY> Inner<PHY> {
    pub(crate) fn packet_builder(&mut self) -> PacketBuilder<'_> {
        let capacity = self.buffer.capacity();
        self.buffer.clear();
        self.buffer
            .resize(capacity, 0x00u8)
            .unwrap_or_else(|()| unreachable!("Input length equals to the current capacity."));
        PacketBuilder::new(&mut self.buffer)
    }
}

impl<PHY> Inner<PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
{
    pub(crate) async fn execute(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        let exec_time = self.clock_divider.execution_time(packet.opcode());
        self.i2c.execute(&mut self.buffer, packet, exec_time).await
    }
}

impl<PHY> Inner<PHY>
where
    PHY: embedded_hal::i2c::I2c,
{
    pub(crate) fn execute_blocking(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        let exec_time = self.clock_divider.execution_time(packet.opcode());
        self.i2c
            .execute_blocking(&mut self.buffer, packet, exec_time)
    }
}

pub struct AtCaClient<M: RawMutex, PHY> {
    pub(crate) inner: Mutex<M, Inner<PHY>>,
}

impl<M: RawMutex, PHY> AtCaClient<M, PHY> {
    /// Create a new client with default I2C configuration
    pub fn new(phy: PHY) -> Self {
        Self::with_config(phy, I2cConfig::default())
    }

    /// Create a new client with custom I2C configuration
    pub fn with_config(phy: PHY, config: I2cConfig) -> Self {
        let i2c = I2c::with_config(phy, config);
        let buffer = Vec::new();

        Self {
            inner: Mutex::new(Inner {
                i2c,
                buffer,
                clock_divider: ClockDivider::Zero,
            }),
        }
    }

    pub fn memory(&self) -> Memory<'_, M, PHY> {
        Memory { atca: self }
    }

    pub fn aes(&self, key_id: Slot) -> Aes<'_, M, PHY> {
        Aes { atca: self, key_id }
    }

    pub fn sha(&self) -> Sha<'_, M, PHY> {
        let remaining_bytes = Vec::new();
        Sha {
            atca: self,
            remaining_bytes,
        }
    }

    pub fn signer(&self, key_id: Slot) -> SigningKey<'_, M, PHY> {
        SigningKey { atca: self, key_id }
    }

    pub fn verifier(&self, key_id: Slot) -> VerifyingKey<'_, M, PHY> {
        VerifyingKey { atca: self, key_id }
    }

    pub fn random(&self) -> Random<'_, M, PHY> {
        Random::new(self)
    }
}

impl<M, PHY> AtCaClient<M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    pub async fn tng(&self) -> Result<TrustAndGo<'_, M, PHY>, Error> {
        let mut tng = TrustAndGo { atca: self };
        // Check if configuration zone is locked.
        if !tng.atca.memory().is_locked(Zone::Config).await? {
            tng.configure_permissions().await?;
            tng.configure_chip_options().await?;
            tng.configure_key_types().await?;
            // Lock config zone
            tng.atca.memory().lock(Zone::Config).await?;
        }

        // Check if data zone is locked.
        if !tng.atca.memory().is_locked(Zone::Data).await? {
            // Only lock the data zone for release build
            #[cfg(not(debug_assertions))]
            tng.atca.memory().lock(Zone::Data).await?;
        }

        Ok(tng)
    }

    pub async fn sleep(&self) -> Result<(), Error> {
        self.inner.lock().await.i2c.sleep().await
    }

    pub async fn info(&self) -> Result<Word, Error> {
        let mut inner = self.inner.lock().await;
        let packet = Info::new(inner.packet_builder()).revision()?;
        inner.execute(packet).await?.as_ref().try_into()
    }

    /// Write to device's digest message buffer
    pub async fn write_message_digest_buffer(&self, msg: &Digest) -> Result<(), Error> {
        let mut inner = self.inner.lock().await;
        let packet = NonceCtx::new(inner.packet_builder()).message_digest_buffer(msg)?;
        inner.execute(packet).await.map(drop)
    }

    /// Create private key and output its public key
    pub async fn create_private_key(&self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut inner = self.inner.lock().await;
        let packet = GenKey::new(inner.packet_builder()).private_key(key_id)?;
        inner.execute(packet).await?.as_ref().try_into()
    }

    /// Write private key to device
    pub async fn write_private_key(&self, key_id: Slot, private_key: &Block) -> Result<(), Error> {
        let mut inner = self.inner.lock().await;
        let packet = PrivWrite::new(inner.packet_builder()).write_private_key(key_id, private_key)?;
        inner.execute(packet).await.map(drop)
    }

    /// Given a private key created and stored in advance, calculate its public key
    pub async fn generate_pubkey(&self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut inner = self.inner.lock().await;
        let packet = GenKey::new(inner.packet_builder()).public_key(key_id)?;
        inner.execute(packet).await?.as_ref().try_into()
    }

    /// Perform Diffie-Hellman key exchange
    pub async fn diffie_hellman(
        &self,
        key_id: Slot,
        public_key: PublicKey,
    ) -> Result<SharedSecret, Error> {
        let mut inner = self.inner.lock().await;
        let packet = Ecdh::new(inner.packet_builder()).diffie_hellman(key_id, public_key)?;
        inner.execute(packet).await?.as_ref().try_into()
    }
}

impl<M, PHY> AtCaClient<M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    pub fn sleep_blocking(&self) -> Result<(), Error> {
        let mut inner = self.inner.try_lock().map_err(|_| ErrorKind::MutexLocked)?;
        inner.i2c.sleep_blocking()
    }

    pub fn info_blocking(&self) -> Result<Word, Error> {
        let mut inner = self.inner.try_lock().map_err(|_| ErrorKind::MutexLocked)?;
        let packet = Info::new(inner.packet_builder()).revision()?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    /// Write to device's digest message buffer
    pub fn write_message_digest_buffer_blocking(&self, msg: &Digest) -> Result<(), Error> {
        let mut inner = self.inner.try_lock().map_err(|_| ErrorKind::MutexLocked)?;
        let packet = NonceCtx::new(inner.packet_builder()).message_digest_buffer(msg)?;
        inner.execute_blocking(packet).map(drop)
    }

    /// Create private key and output its public key
    pub fn create_private_key_blocking(&self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut inner = self.inner.try_lock().map_err(|_| ErrorKind::MutexLocked)?;
        let packet = GenKey::new(inner.packet_builder()).private_key(key_id)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    /// Write private key to device
    pub fn write_private_key_blocking(
        &self,
        key_id: Slot,
        private_key: &Block,
    ) -> Result<(), Error> {
        let mut inner = self.inner.try_lock().map_err(|_| ErrorKind::MutexLocked)?;
        let packet = PrivWrite::new(inner.packet_builder()).write_private_key(key_id, private_key)?;
        inner.execute_blocking(packet).map(drop)
    }

    /// Given a private key created and stored in advance, calculate its public key
    pub fn generate_pubkey_blocking(&self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut inner = self.inner.try_lock().map_err(|_| ErrorKind::MutexLocked)?;
        let packet = GenKey::new(inner.packet_builder()).public_key(key_id)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman_blocking(
        &self,
        key_id: Slot,
        public_key: PublicKey,
    ) -> Result<SharedSecret, Error> {
        let mut inner = self.inner.try_lock().map_err(|_| ErrorKind::MutexLocked)?;
        let packet = Ecdh::new(inner.packet_builder()).diffie_hellman(key_id, public_key)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }
}
