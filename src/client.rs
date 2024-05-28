use crate::command::{Ecdh, SharedSecret};

use super::clock_divider::ClockDivider;
use super::command::{self, GenKey, Info, Lock, NonceCtx, PrivWrite, PublicKey, Serial, Word};
use super::datalink::I2c;
use super::error::{Error, ErrorKind};
use super::memory::{CertificateRepr, Size, Slot, Zone};
use super::packet::{Packet, PacketBuilder, Response};
use super::tngtls::TrustAndGo;
use super::{Block, Digest, Signature};
use core::cell::RefCell;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::num::NonZeroU32;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use heapless::Vec;
use p256::ecdsa::DerSignature;
use signature::hazmat::PrehashSigner;
use signature::{rand_core, Keypair};

pub struct VerifyingKey<'a, M: RawMutex, PHY>(RefCell<Verify<'a, M, PHY>>);

impl<'a, M: RawMutex, PHY> From<Verify<'a, M, PHY>> for VerifyingKey<'a, M, PHY> {
    fn from(verify: Verify<'a, M, PHY>) -> Self {
        Self(RefCell::new(verify))
    }
}

impl<'a, M, PHY> VerifyingKey<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    pub async fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let digest = self.0.borrow_mut().atca.sha().digest(msg).await?;
        let key_id = self.0.borrow_mut().key_id.clone();
        let public_key = self.0.borrow_mut().atca.generate_pubkey(key_id).await?;
        self.0
            .borrow_mut()
            .verify_digest(&digest, signature, &public_key)
            .await
    }
}

impl<'a, M, PHY> VerifyingKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    pub fn verify_blocking(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let digest = self.0.borrow_mut().atca.sha().digest_blocking(msg)?;
        let key_id = self.0.borrow_mut().key_id.clone();
        let public_key = self.0.borrow_mut().atca.generate_pubkey_blocking(key_id)?;
        self.0
            .borrow_mut()
            .verify_digest_blocking(&digest, signature, &public_key)
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

pub struct SigningKey<'a, M: RawMutex, PHY>(RefCell<Sign<'a, M, PHY>>);

impl<'a, M, PHY> Keypair for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    type VerifyingKey = PublicKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        let signer = self.0.borrow_mut();
        let key_id = signer.key_id;
        signer.atca.generate_pubkey_blocking(key_id).unwrap()
    }
}

impl<'a, M: RawMutex, PHY> From<Sign<'a, M, PHY>> for SigningKey<'a, M, PHY> {
    fn from(sign: Sign<'a, M, PHY>) -> Self {
        Self(RefCell::new(sign))
    }
}

impl<'a, M, PHY> SigningKey<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    pub async fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let digest = self.0.borrow_mut().atca.sha().digest(msg).await?;
        self.0.borrow_mut().sign_digest(&digest).await
    }
}

impl<'a, M, PHY> SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    pub fn sign_blocking(&self, msg: &[u8]) -> Result<Signature, Error> {
        let digest = self.0.borrow_mut().atca.sha().digest_blocking(msg)?;
        self.0.borrow_mut().sign_digest_blocking(&digest)
    }
}

impl<'a, M, PHY> PrehashSigner<Signature> for SigningKey<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        let digest = self
            .0
            .borrow_mut()
            .atca
            .sha()
            .digest_blocking(prehash)
            .map_err(|_| signature::Error::new())?;
        self.0
            .borrow_mut()
            .sign_digest_blocking(&digest)
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
            .0
            .borrow_mut()
            .atca
            .sha()
            .digest_blocking(msg)
            .map_err(|_| signature::Error::new())?;
        self.0
            .borrow_mut()
            .sign_digest_blocking(&digest)
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

struct Inner<PHY> {
    pub i2c: I2c<PHY>,
    pub buffer: Vec<u8, 192>,
    pub clock_divider: ClockDivider,
}

impl<PHY> Inner<PHY> {
    fn packet_builder(&mut self) -> PacketBuilder<'_> {
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
    async fn execute(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        let exec_time = self.clock_divider.execution_time(packet.opcode());
        self.i2c.execute(&mut self.buffer, packet, exec_time).await
    }
}

impl<PHY> Inner<PHY>
where
    PHY: embedded_hal::i2c::I2c,
{
    fn execute_blocking(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        let exec_time = self.clock_divider.execution_time(packet.opcode());
        self.i2c
            .execute_blocking(&mut self.buffer, packet, exec_time)
    }
}

pub struct AtCaClient<M: RawMutex, PHY> {
    inner: Mutex<M, Inner<PHY>>,
}

impl<M: RawMutex, PHY> AtCaClient<M, PHY> {
    pub fn new(phy: PHY) -> Self {
        let i2c = I2c::new(phy);
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

    pub fn sign(&self, key_id: Slot) -> Sign<'_, M, PHY> {
        Sign { atca: self, key_id }
    }

    pub fn verify(&self, key_id: Slot) -> Verify<'_, M, PHY> {
        Verify { atca: self, key_id }
    }

    pub fn signer(&self, key_id: Slot) -> SigningKey<'_, M, PHY> {
        self.sign(key_id).into()
    }

    pub fn verifier(&self, key_id: Slot) -> VerifyingKey<'_, M, PHY> {
        self.verify(key_id).into()
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

    // Write to device's digest message buffer.
    pub async fn write_message_digest_buffer(&self, msg: &Digest) -> Result<(), Error> {
        let mut inner = self.inner.lock().await;
        let packet = NonceCtx::new(inner.packet_builder()).message_digest_buffer(msg)?;
        inner.execute(packet).await.map(drop)
    }

    // Create private key and output its public key.
    pub async fn create_private_key(&self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut inner = self.inner.lock().await;

        let packet = GenKey::new(inner.packet_builder()).private_key(key_id)?;
        inner.execute(packet).await?.as_ref().try_into()
    }

    // Write private key.
    pub async fn write_private_key(&self, key_id: Slot, private_key: &Block) -> Result<(), Error> {
        let mut inner = self.inner.lock().await;
        let packet =
            PrivWrite::new(inner.packet_builder()).write_private_key(key_id, private_key)?;
        inner.execute(packet).await.map(drop)
    }

    // Given a private key created and stored in advance, calculate its public key.
    pub async fn generate_pubkey(&self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut inner = self.inner.lock().await;

        let packet = GenKey::new(inner.packet_builder()).public_key(key_id)?;
        inner.execute(packet).await?.as_ref().try_into()
    }

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
    // pub fn tng_blocking(&self) -> Result<TrustAndGo<'_, PHY>, Error> {
    //     let mut tng = TrustAndGo { atca: self };
    //     // Check if configuration zone is locked.
    //     if !tng.atca.memory().is_locked(Zone::Config)? {
    //         tng.configure_permissions()?;
    //         tng.configure_chip_options()?;
    //         tng.configure_key_types()?;
    //         // Lock config zone
    //         tng.atca.memory().lock(Zone::Config)?;
    //     }

    //     // Check if data zone is locked.
    //     if !tng.atca.memory().is_locked(Zone::Data)? {
    //         // Only lock the data zone for release build
    //         #[cfg(not(debug_assertions))]
    //         tng.atca.memory().lock(Zone::Data)?;
    //     }

    //     Ok(tng)
    // }

    pub fn sleep_blocking(&self) -> Result<(), Error> {
        let mut inner = self.inner.try_lock().unwrap();
        inner.i2c.sleep_blocking()
    }

    pub fn info_blocking(&self) -> Result<Word, Error> {
        let mut inner = self.inner.try_lock().unwrap();
        let packet = Info::new(inner.packet_builder()).revision()?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    // Write to device's digest message buffer.
    pub fn write_message_digest_buffer_blocking(&self, msg: &Digest) -> Result<(), Error> {
        let mut inner = self.inner.try_lock().unwrap();
        let packet = NonceCtx::new(inner.packet_builder()).message_digest_buffer(msg)?;
        inner.execute_blocking(packet).map(drop)
    }

    // Create private key and output its public key.
    pub fn create_private_key_blocking(&self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut inner = self.inner.try_lock().unwrap();
        let packet = GenKey::new(inner.packet_builder()).private_key(key_id)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    // Write private key.
    pub fn write_private_key_blocking(
        &self,
        key_id: Slot,
        private_key: &Block,
    ) -> Result<(), Error> {
        let mut inner = self.inner.try_lock().unwrap();
        let packet =
            PrivWrite::new(inner.packet_builder()).write_private_key(key_id, private_key)?;
        inner.execute_blocking(packet).map(drop)
    }

    // Given a private key created and stored in advance, calculate its public key.
    pub fn generate_pubkey_blocking(&self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut inner = self.inner.try_lock().unwrap();
        let packet = GenKey::new(inner.packet_builder()).public_key(key_id)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    pub fn diffie_hellman_blocking(
        &self,
        key_id: Slot,
        public_key: PublicKey,
    ) -> Result<SharedSecret, Error> {
        let mut inner = self.inner.try_lock().unwrap();
        let packet = Ecdh::new(inner.packet_builder()).diffie_hellman(key_id, public_key)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }
}

// Memory zones consist of configata and OTP.
pub struct Memory<'a, M: RawMutex, PHY> {
    atca: &'a AtCaClient<M, PHY>,
}

impl<'a, M: RawMutex, PHY> Memory<'a, M, PHY> {
    pub(crate) const SLOT_CONFIG_INDEX: usize = 20;
    pub(crate) const CHIP_OPTIONS_INDEX: usize = 90;
    pub(crate) const KEY_CONFIG_INDEX: usize = 96;
}

impl<'a, M, PHY> Memory<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    pub async fn serial_number(&self) -> Result<Serial, Error> {
        let mut inner = self.atca.inner.lock().await;

        let packet =
            command::Read::new(inner.packet_builder()).read(Zone::Config, Size::Block, 0, 0)?;
        inner.execute(packet).await?.as_ref().try_into()
    }

    pub async fn pubkey(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut pubkey = PublicKey::default();

        let mut offset = 0;

        for (i, ranges) in CertificateRepr::new().enumerate() {
            let mut inner = self.atca.inner.lock().await;
            let packet = command::Read::new(inner.packet_builder()).slot(key_id, i as u8)?;

            let response = inner.execute(packet).await?;
            for range in ranges {
                let dst = offset..offset + range.len();
                pubkey.as_mut()[dst].copy_from_slice(&response.as_ref()[range.clone()]);
                offset += range.len();
            }
        }

        Ok(pubkey)
    }

    pub async fn write_pubkey(
        &mut self,
        key_id: Slot,
        pubkey: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut data = Block::default();
        let mut offset = 0;

        for (i, ranges) in CertificateRepr::new().enumerate() {
            let mut inner = self.atca.inner.lock().await;
            // Initialize block sized buffer
            data.as_mut().iter_mut().for_each(|value| *value = 0);

            for range in ranges {
                let src = offset..offset + range.len();
                data.as_mut()[range.clone()].copy_from_slice(&pubkey.as_ref()[src]);
                offset += range.len();
            }

            let packet =
                command::Write::new(inner.packet_builder()).slot(key_id, i as u8, &data)?;

            inner.execute(packet).await?;
        }
        Ok(())
    }

    pub async fn write_aes_key(
        &mut self,
        key_id: Slot,
        aes_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut inner = self.atca.inner.lock().await;

        let mut data = Block::default();
        data.as_mut()[..0x10].copy_from_slice(aes_key.as_ref());
        let packet = command::Write::new(inner.packet_builder()).slot(key_id, 0 as u8, &data)?;
        inner.execute(packet).await.map(drop)
    }

    pub async fn is_slot_locked(&mut self, slot: Slot) -> Result<bool, Error> {
        let mut inner = self.atca.inner.lock().await;

        let zone = Zone::Config;
        let size = Size::Word;
        let block = 2;
        let word_offset = 6;
        let packet =
            command::Read::new(inner.packet_builder()).read(zone, size, block, word_offset)?;
        let response = inner.execute(packet).await?;
        let word = Word::try_from(response.as_ref())?;
        let slot_locked_bytes = word.as_ref()[..2]
            .try_into()
            .map(u16::from_le_bytes)
            .unwrap_or_else(|_| unreachable!());
        Ok(slot_locked_bytes & (0x01u16 << slot as u32) == 0x00)
    }

    pub async fn is_locked(&mut self, zone: Zone) -> Result<bool, Error> {
        let mut inner = self.atca.inner.lock().await;

        let size = Size::Word;
        let block = 2;
        let word_offset = 5;
        let packet = command::Read::new(inner.packet_builder()).read(
            Zone::Config,
            size,
            block,
            word_offset,
        )?;
        let response = inner.execute(packet).await?;
        let word = Word::try_from(response.as_ref())?;
        match zone {
            Zone::Config => Ok(word.as_ref()[3] != 0x55),
            Zone::Data => Ok(word.as_ref()[2] != 0x55),
            Zone::Otp => Err(ErrorKind::BadParam.into()),
        }
    }

    pub async fn lock_slot(&mut self, key_id: Slot) -> Result<(), Error> {
        let mut inner = self.atca.inner.lock().await;

        let packet = Lock::new(inner.packet_builder()).slot(key_id)?;
        inner.execute(packet).await.map(drop)
    }

    pub async fn lock(&mut self, zone: Zone) -> Result<(), Error> {
        let mut inner = self.atca.inner.lock().await;

        let packet = Lock::new(inner.packet_builder()).zone(zone, None)?;
        inner.execute(packet).await.map(drop)
    }

    pub async fn lock_crc(&mut self, zone: Zone, crc: u16) -> Result<(), Error> {
        let mut inner = self.atca.inner.lock().await;

        let packet = Lock::new(inner.packet_builder()).zone(zone, Some(crc))?;
        inner.execute(packet).await.map(drop)
    }

    pub async fn chip_options(&mut self) -> Result<u16, Error> {
        let (block, offset, pos) = Zone::locate_index(Self::CHIP_OPTIONS_INDEX);
        let range = pos as usize..pos as usize + 2;
        let mut inner = self.atca.inner.lock().await;
        let packet = command::Read::new(inner.packet_builder()).read(
            Zone::Config,
            Size::Word,
            block,
            offset,
        )?;
        inner.execute(packet).await.map(|resp| {
            resp.as_ref()[range]
                .try_into()
                .map(u16::from_le_bytes)
                .unwrap_or_else(|_| unreachable!())
        })
    }

    pub async fn permission(&mut self, slot: Slot) -> Result<u16, Error> {
        let index = Self::SLOT_CONFIG_INDEX + (slot as usize * 2);
        let (block, offset, pos) = Zone::locate_index(index);
        let range = pos as usize..pos as usize + 2;

        let mut inner = self.atca.inner.lock().await;
        let packet = command::Read::new(inner.packet_builder()).read(
            Zone::Config,
            Size::Word,
            block,
            offset,
        )?;
        inner.execute(packet).await.map(|resp| {
            resp.as_ref()[range]
                .try_into()
                .map(u16::from_le_bytes)
                .unwrap_or_else(|_| unreachable!())
        })
    }

    pub async fn key_type(&mut self, slot: Slot) -> Result<u16, Error> {
        let index = Self::KEY_CONFIG_INDEX + (slot as usize * 2);
        let (block, offset, pos) = Zone::locate_index(index);
        let range = pos as usize..pos as usize + 2;
        let mut inner = self.atca.inner.lock().await;
        let packet = command::Read::new(inner.packet_builder()).read(
            Zone::Config,
            Size::Word,
            block,
            offset,
        )?;
        inner.execute(packet).await.map(|resp| {
            resp.as_ref()[range]
                .try_into()
                .map(u16::from_le_bytes)
                .unwrap_or_else(|_| unreachable!())
        })
    }

    pub async fn write_config(
        &mut self,
        size: Size,
        block: u8,
        offset: u8,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut inner = self.atca.inner.lock().await;

        let packet = command::Write::new(inner.packet_builder()).write(
            Zone::Config,
            size,
            block,
            offset,
            data,
        )?;
        inner.execute(packet).await.map(drop)
    }
}

impl<'a, M, PHY> Memory<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    pub fn serial_number_blocking(&mut self) -> Result<Serial, Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();
        let packet =
            command::Read::new(inner.packet_builder()).read(Zone::Config, Size::Block, 0, 0)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    pub fn pubkey_blocking(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut pubkey = PublicKey::default();

        let mut offset = 0;

        let mut inner = self.atca.inner.try_lock().unwrap();

        for (i, ranges) in CertificateRepr::new().enumerate() {
            let packet = command::Read::new(inner.packet_builder()).slot(key_id, i as u8)?;

            let response = inner.execute_blocking(packet)?;
            for range in ranges {
                let dst = offset..offset + range.len();
                pubkey.as_mut()[dst].copy_from_slice(&response.as_ref()[range.clone()]);
                offset += range.len();
            }
        }

        Ok(pubkey)
    }

    pub fn write_pubkey_blocking(
        &mut self,
        key_id: Slot,
        pubkey: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut data = Block::default();
        let mut offset = 0;
        let mut inner = self.atca.inner.try_lock().unwrap();

        for (i, ranges) in CertificateRepr::new().enumerate() {
            // Initialize block sized buffer
            data.as_mut().iter_mut().for_each(|value| *value = 0);

            for range in ranges {
                let src = offset..offset + range.len();
                data.as_mut()[range.clone()].copy_from_slice(&pubkey.as_ref()[src]);
                offset += range.len();
            }

            let packet =
                command::Write::new(inner.packet_builder()).slot(key_id, i as u8, &data)?;

            inner.execute_blocking(packet)?;
        }
        Ok(())
    }

    pub fn write_aes_key_blocking(
        &mut self,
        key_id: Slot,
        aes_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        let mut data = Block::default();
        data.as_mut()[..0x10].copy_from_slice(aes_key.as_ref());
        let packet = command::Write::new(inner.packet_builder()).slot(key_id, 0 as u8, &data)?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn is_slot_locked_blocking(&mut self, slot: Slot) -> Result<bool, Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        let zone = Zone::Config;
        let size = Size::Word;
        let block = 2;
        let word_offset = 6;
        let packet =
            command::Read::new(inner.packet_builder()).read(zone, size, block, word_offset)?;
        let response = inner.execute_blocking(packet)?;
        let word = Word::try_from(response.as_ref())?;
        let slot_locked_bytes = word.as_ref()[..2]
            .try_into()
            .map(u16::from_le_bytes)
            .unwrap_or_else(|_| unreachable!());
        Ok(slot_locked_bytes & (0x01u16 << slot as u32) == 0x00)
    }

    pub fn is_locked_blocking(&mut self, zone: Zone) -> Result<bool, Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        let size = Size::Word;
        let block = 2;
        let word_offset = 5;
        let packet = command::Read::new(inner.packet_builder()).read(
            Zone::Config,
            size,
            block,
            word_offset,
        )?;
        let response = inner.execute_blocking(packet)?;
        let word = Word::try_from(response.as_ref())?;
        match zone {
            Zone::Config => Ok(word.as_ref()[3] != 0x55),
            Zone::Data => Ok(word.as_ref()[2] != 0x55),
            Zone::Otp => Err(ErrorKind::BadParam.into()),
        }
    }

    pub fn lock_slot_blocking(&mut self, key_id: Slot) -> Result<(), Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = Lock::new(inner.packet_builder()).slot(key_id)?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn lock_blocking(&mut self, zone: Zone) -> Result<(), Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = Lock::new(inner.packet_builder()).zone(zone, None)?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn lock_crc_blocking(&mut self, zone: Zone, crc: u16) -> Result<(), Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = Lock::new(inner.packet_builder()).zone(zone, Some(crc))?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn chip_options_blocking(&mut self) -> Result<u16, Error> {
        let (block, offset, pos) = Zone::locate_index(Self::CHIP_OPTIONS_INDEX);
        let range = pos as usize..pos as usize + 2;
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = command::Read::new(inner.packet_builder()).read(
            Zone::Config,
            Size::Word,
            block,
            offset,
        )?;
        inner.execute_blocking(packet).map(|resp| {
            resp.as_ref()[range]
                .try_into()
                .map(u16::from_le_bytes)
                .unwrap_or_else(|_| unreachable!())
        })
    }

    pub fn permission_blocking(&mut self, slot: Slot) -> Result<u16, Error> {
        let index = Self::SLOT_CONFIG_INDEX + (slot as usize * 2);
        let (block, offset, pos) = Zone::locate_index(index);
        let range = pos as usize..pos as usize + 2;
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = command::Read::new(inner.packet_builder()).read(
            Zone::Config,
            Size::Word,
            block,
            offset,
        )?;
        inner.execute_blocking(packet).map(|resp| {
            resp.as_ref()[range]
                .try_into()
                .map(u16::from_le_bytes)
                .unwrap_or_else(|_| unreachable!())
        })
    }

    pub fn key_type_blocking(&mut self, slot: Slot) -> Result<u16, Error> {
        let index = Self::KEY_CONFIG_INDEX + (slot as usize * 2);
        let (block, offset, pos) = Zone::locate_index(index);
        let range = pos as usize..pos as usize + 2;
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = command::Read::new(inner.packet_builder()).read(
            Zone::Config,
            Size::Word,
            block,
            offset,
        )?;
        inner.execute_blocking(packet).map(|resp| {
            resp.as_ref()[range]
                .try_into()
                .map(u16::from_le_bytes)
                .unwrap_or_else(|_| unreachable!())
        })
    }

    pub fn write_config_blocking(
        &mut self,
        size: Size,
        block: u8,
        offset: u8,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = command::Write::new(inner.packet_builder()).write(
            Zone::Config,
            size,
            block,
            offset,
            data,
        )?;
        inner.execute_blocking(packet).map(drop)
    }
}

// Method signature is taken from cipher::block::BlockCipher.
// AES
pub struct Aes<'a, M: RawMutex, PHY> {
    atca: &'a AtCaClient<M, PHY>,
    key_id: Slot,
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

        let mut inner = self.atca.inner.try_lock().unwrap();

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

        let mut inner = self.atca.inner.try_lock().unwrap();

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

// SHA
pub struct Sha<'a, M: RawMutex, PHY> {
    atca: &'a AtCaClient<M, PHY>,
    remaining_bytes: Vec<u8, 64>,
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

    // See digest::Update
    pub async fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        let capacity = 0x40;
        let length = data.as_ref().len();

        // Store remainging bytes for later processing
        let remainder_length = data.as_ref().len() % capacity;
        let (bytes, remainder) = data.as_ref().split_at(length - remainder_length);
        self.remaining_bytes.extend_from_slice(remainder).ok();

        // Execute update command
        for chunk in bytes.chunks(capacity) {
            let mut inner = self.atca.inner.lock().await;

            let packet = command::Sha::new(inner.packet_builder()).update(chunk)?;
            inner.execute(packet).await?;
        }

        Ok(())
    }

    pub async fn chain(&mut self, data: impl AsRef<[u8]>) -> Result<&mut Self, Error> {
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
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = command::Sha::new(inner.packet_builder()).start()?;
        inner.execute_blocking(packet)?;

        Ok(())
    }

    // See digest::Update
    pub fn update_blocking(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        let capacity = 0x40;
        let length = data.as_ref().len();

        // Store remainging bytes for later processing
        let remainder_length = data.as_ref().len() % capacity;
        let (bytes, remainder) = data.as_ref().split_at(length - remainder_length);
        self.remaining_bytes.extend_from_slice(remainder).ok();

        let mut inner = self.atca.inner.try_lock().unwrap();

        // Execute update command
        for chunk in bytes.chunks(capacity) {
            let packet = command::Sha::new(inner.packet_builder()).update(chunk)?;
            inner.execute_blocking(packet)?;
        }

        Ok(())
    }

    pub fn chain_blocking(&mut self, data: impl AsRef<[u8]>) -> Result<&mut Self, Error> {
        if self.remaining_bytes.len() != 0 {
            // TODO: Concatenate remaining bytes and input data.
        }

        self.update_blocking(data)?;
        Ok(self)
    }

    pub fn finalize_blocking(self) -> Result<Digest, Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        let packet = command::Sha::new(inner.packet_builder()).end(&self.remaining_bytes)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    pub fn digest_blocking(mut self, data: &[u8]) -> Result<Digest, Error> {
        self.init_blocking()?;
        self.update_blocking(data)?;
        self.finalize_blocking()
    }
}

// Method signatures are taken from signature::DigestSigner.
// Sign
pub struct Sign<'a, M: RawMutex, PHY> {
    atca: &'a AtCaClient<M, PHY>,
    key_id: Slot,
}

impl<'a, M: RawMutex, PHY> Sign<'a, M, PHY> {
    pub fn verifying_key(&'a mut self) -> Verify<'a, M, PHY> {
        Verify {
            atca: self.atca,
            key_id: self.key_id,
        }
    }
}

impl<'a, M, PHY> Sign<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    // Takes a 32-byte message to be signed, typically the SHA256 hash of the
    // full message.
    pub async fn sign_digest(&mut self, digest: &Digest) -> Result<Signature, Error> {
        let mut inner = self.atca.inner.lock().await;

        // 1. Random value generation
        let mut data = [0u8; 32];
        self.atca.random().try_fill_bytes(&mut data).await?;
        // 2. Nonce load
        self.atca.write_message_digest_buffer(digest).await?;
        // 3. Sign
        let packet = command::Sign::new(inner.packet_builder()).external(self.key_id)?;
        let response = inner.execute(packet).await?;
        Signature::from_bytes(response.as_ref().into()).map_err(|_| ErrorKind::BadParam.into())
    }
}

impl<'a, M, PHY> Sign<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    // Takes a 32-byte message to be signed, typically the SHA256 hash of the
    // full message.
    pub fn sign_digest_blocking(&mut self, digest: &Digest) -> Result<Signature, Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        // 1. Random value generation
        let mut data = [0u8; 32];
        self.atca.random().try_fill_bytes_blocking(&mut data)?;
        // 2. Nonce load
        self.atca.write_message_digest_buffer_blocking(digest)?;
        // 3. Sign
        let packet = command::Sign::new(inner.packet_builder()).external(self.key_id)?;
        let response = inner.execute_blocking(packet)?;
        Signature::from_bytes(response.as_ref().into()).map_err(|_| ErrorKind::BadParam.into())
    }
}

pub struct Verify<'a, M: RawMutex, PHY> {
    atca: &'a AtCaClient<M, PHY>,
    key_id: Slot,
}

impl<'a, M, PHY> Verify<'a, M, PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
    M: RawMutex,
{
    // Takes a 32-byte message to be signed, typically the SHA256 hash of the
    // full message and signature.
    pub async fn verify_digest(
        &mut self,
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
}

impl<'a, M, PHY> Verify<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    // Takes a 32-byte message to be signed, typically the SHA256 hash of the
    // full message and signature.
    pub fn verify_digest_blocking(
        &mut self,
        digest: &Digest,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        let mut inner = self.atca.inner.try_lock().unwrap();

        // 1. Nonce load
        self.atca.write_message_digest_buffer_blocking(digest)?;
        // 2. Verify
        let packet =
            command::Verify::new(inner.packet_builder()).external(signature, public_key)?;
        inner.execute_blocking(packet)?;

        Ok(())
    }
}

pub struct Random<'a, M: RawMutex, PHY> {
    atca: &'a AtCaClient<M, PHY>,
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
        let mut inner = self.atca.inner.try_lock().unwrap();

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
