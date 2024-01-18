use crate::command::{Ecdh, SharedSecret};

use super::clock_divider::ClockDivider;
use super::command::{
    self, GenKey, Info, Lock, NonceCtx, PrivWrite, PublicKey, Random, Serial, Word,
};
use super::datalink::I2c;
use super::error::{Error, ErrorKind};
use super::memory::{CertificateRepr, Size, Slot, Zone};
use super::packet::{Packet, PacketBuilder, Response};
use super::tngtls::TrustAndGo;
use super::{Block, Digest, Signature};
use core::cell::RefCell;
use core::convert::TryFrom;
use core::convert::TryInto;
use embedded_hal_async::i2c;
use heapless::Vec;

pub struct Verifier<'a, PHY>(RefCell<Verify<'a, PHY>>);

impl<'a, PHY> From<Verify<'a, PHY>> for Verifier<'a, PHY> {
    fn from(verify: Verify<'a, PHY>) -> Self {
        Self(RefCell::new(verify))
    }
}

// impl<'a, PHY> async_signature::Verifier<Signature> for Verifier<'a, PHY>
// where
//     PHY: i2c::I2c,
// {
//     fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), async_signature::Error> {
//         let digest = self
//             .0
//             .borrow_mut()
//             .atca
//             .sha()
//             .digest(msg).await
//             .map_err(|_| async_signature::Error::new())?;
//         let key_id = self.0.borrow_mut().key_id.clone();
//         let public_key = self
//             .0
//             .borrow_mut()
//             .atca
//             .generate_pubkey(key_id).await
//             .map_err(|_| async_signature::Error::new())?;
//         self.0
//             .borrow_mut()
//             .verify_digest(&digest, signature, &public_key).await
//             .map_err(|_| async_signature::Error::new())
//     }
// }

pub struct Signer<'a, PHY>(RefCell<Sign<'a, PHY>>);

impl<'a, PHY> From<Sign<'a, PHY>> for Signer<'a, PHY> {
    fn from(sign: Sign<'a, PHY>) -> Self {
        Self(RefCell::new(sign))
    }
}

impl<'a, PHY> Signer<'a, PHY>
where
    PHY: i2c::I2c,
{
    pub async fn sign_async(&self, msg: &[u8]) -> Result<Signature, Error> {
        let digest = self.0.borrow_mut().atca.sha().digest(msg).await?;

        self.0.borrow_mut().sign_digest(&digest).await
    }
}

pub struct AtCaClient<PHY> {
    i2c: I2c<PHY>,
    buffer: Vec<u8, 192>,
    clock_divider: ClockDivider,
}

impl<PHY> AtCaClient<PHY> {
    pub fn new(phy: PHY) -> Self {
        let i2c = I2c::new(phy);
        let buffer = Vec::new();
        Self {
            i2c,
            buffer,
            clock_divider: ClockDivider::Zero,
        }
    }

    fn packet_builder(&mut self) -> PacketBuilder<'_> {
        let capacity = self.buffer.capacity();
        self.buffer.clear();
        self.buffer
            .resize(capacity, 0x00u8)
            .unwrap_or_else(|()| unreachable!("Input length equals to the current capacity."));
        PacketBuilder::new(&mut self.buffer)
    }

    pub fn memory(&mut self) -> Memory<'_, PHY> {
        Memory { atca: self }
    }

    pub fn aes(&mut self, key_id: Slot) -> Aes<'_, PHY> {
        Aes { atca: self, key_id }
    }

    pub fn sha(&mut self) -> Sha<'_, PHY> {
        let remaining_bytes = Vec::new();
        Sha {
            atca: self,
            remaining_bytes,
        }
    }

    pub fn sign(&mut self, key_id: Slot) -> Sign<'_, PHY> {
        Sign { atca: self, key_id }
    }

    pub fn verify(&mut self, key_id: Slot) -> Verify<'_, PHY> {
        Verify { atca: self, key_id }
    }
}

impl<PHY> AtCaClient<PHY>
where
    PHY: i2c::I2c,
{
    async fn execute(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        let exec_time = self.clock_divider.execution_time(packet.opcode());
        self.i2c.execute(&mut self.buffer, packet, exec_time).await
    }

    pub fn signer(&mut self, key_id: Slot) -> Signer<'_, PHY> {
        self.sign(key_id).into()
    }

    pub fn verifier(&mut self, key_id: Slot) -> Verifier<'_, PHY> {
        self.verify(key_id).into()
    }

    pub async fn tng(&mut self) -> Result<TrustAndGo<'_, PHY>, Error> {
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

    pub async fn sleep(&mut self) -> Result<(), Error> {
        self.i2c.sleep().await
    }

    pub async fn info(&mut self) -> Result<Word, Error> {
        let packet = Info::new(self.packet_builder()).revision()?;
        self.execute(packet).await?.as_ref().try_into()
    }

    pub async fn random(&mut self) -> Result<Block, Error> {
        let packet = Random::new(self.packet_builder()).random()?;
        self.execute(packet).await?.as_ref().try_into()
    }

    // Write to device's digest message buffer.
    pub async fn write_message_digest_buffer(&mut self, msg: &Digest) -> Result<(), Error> {
        let packet = NonceCtx::new(self.packet_builder()).message_digest_buffer(msg)?;
        self.execute(packet).await.map(drop)
    }

    // Create private key and output its public key.
    pub async fn create_private_key(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let packet = GenKey::new(self.packet_builder()).private_key(key_id)?;
        self.execute(packet).await?.as_ref().try_into()
    }

    // Write private key.
    pub async fn write_private_key(
        &mut self,
        key_id: Slot,
        private_key: &Block,
    ) -> Result<(), Error> {
        let packet =
            PrivWrite::new(self.packet_builder()).write_private_key(key_id, private_key)?;
        self.execute(packet).await.map(drop)
    }

    // Given a private key created and stored in advance, calculate its public key.
    pub async fn generate_pubkey(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let packet = GenKey::new(self.packet_builder()).public_key(key_id)?;
        self.execute(packet).await?.as_ref().try_into()
    }

    pub async fn diffie_hellman(
        &mut self,
        key_id: Slot,
        public_key: PublicKey,
    ) -> Result<SharedSecret, Error> {
        let packet = Ecdh::new(self.packet_builder()).diffie_hellman(key_id, public_key)?;
        self.execute(packet).await?.as_ref().try_into()
    }
}

// Memory zones consist of configata and OTP.
pub struct Memory<'a, PHY> {
    atca: &'a mut AtCaClient<PHY>,
}

impl<'a, PHY> Memory<'a, PHY> {
    pub(crate) const SLOT_CONFIG_INDEX: usize = 20;
    pub(crate) const CHIP_OPTIONS_INDEX: usize = 90;
    pub(crate) const KEY_CONFIG_INDEX: usize = 96;
}

impl<'a, PHY> Memory<'a, PHY>
where
    PHY: i2c::I2c,
{
    pub async fn serial_number(&mut self) -> Result<Serial, Error> {
        let packet =
            command::Read::new(self.atca.packet_builder()).read(Zone::Config, Size::Block, 0, 0)?;
        self.atca.execute(packet).await?.as_ref().try_into()
    }

    pub async fn pubkey(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut pubkey = PublicKey::default();

        let mut offset = 0;

        for (i, ranges) in CertificateRepr::new().enumerate() {
            let packet = command::Read::new(self.atca.packet_builder()).slot(key_id, i as u8)?;

            let response = self.atca.execute(packet).await?;
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
            // Initialize block sized buffer
            data.as_mut().iter_mut().for_each(|value| *value = 0);

            for range in ranges {
                let src = offset..offset + range.len();
                data.as_mut()[range.clone()].copy_from_slice(&pubkey.as_ref()[src]);
                offset += range.len();
            }

            let packet =
                command::Write::new(self.atca.packet_builder()).slot(key_id, i as u8, &data)?;

            self.atca.execute(packet).await?;
        }
        Ok(())
    }

    pub async fn write_aes_key(
        &mut self,
        key_id: Slot,
        aes_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut data = Block::default();
        data.as_mut()[..0x10].copy_from_slice(aes_key.as_ref());
        let packet =
            command::Write::new(self.atca.packet_builder()).slot(key_id, 0 as u8, &data)?;
        self.atca.execute(packet).await.map(drop)
    }

    pub async fn is_slot_locked(&mut self, slot: Slot) -> Result<bool, Error> {
        let zone = Zone::Config;
        let size = Size::Word;
        let block = 2;
        let word_offset = 6;
        let packet =
            command::Read::new(self.atca.packet_builder()).read(zone, size, block, word_offset)?;
        let response = self.atca.execute(packet).await?;
        let word = Word::try_from(response.as_ref())?;
        let slot_locked_bytes = word.as_ref()[..2]
            .try_into()
            .map(u16::from_le_bytes)
            .unwrap_or_else(|_| unreachable!());
        Ok(slot_locked_bytes & (0x01u16 << slot as u32) == 0x00)
    }

    pub async fn is_locked(&mut self, zone: Zone) -> Result<bool, Error> {
        let size = Size::Word;
        let block = 2;
        let word_offset = 5;
        let packet = command::Read::new(self.atca.packet_builder()).read(
            Zone::Config,
            size,
            block,
            word_offset,
        )?;
        let response = self.atca.execute(packet).await?;
        let word = Word::try_from(response.as_ref())?;
        match zone {
            Zone::Config => Ok(word.as_ref()[3] != 0x55),
            Zone::Data => Ok(word.as_ref()[2] != 0x55),
            Zone::Otp => Err(ErrorKind::BadParam.into()),
        }
    }

    pub async fn lock_slot(&mut self, key_id: Slot) -> Result<(), Error> {
        let packet = Lock::new(self.atca.packet_builder()).slot(key_id)?;
        self.atca.execute(packet).await.map(drop)
    }

    pub async fn lock(&mut self, zone: Zone) -> Result<(), Error> {
        let packet = Lock::new(self.atca.packet_builder()).zone(zone, None)?;
        self.atca.execute(packet).await.map(drop)
    }

    pub async fn lock_crc(&mut self, zone: Zone, crc: u16) -> Result<(), Error> {
        let packet = Lock::new(self.atca.packet_builder()).zone(zone, Some(crc))?;
        self.atca.execute(packet).await.map(drop)
    }

    pub async fn chip_options(&mut self) -> Result<u16, Error> {
        let (block, offset, pos) = Zone::locate_index(Self::CHIP_OPTIONS_INDEX);
        let range = pos as usize..pos as usize + 2;
        self.read_config(Size::Word, block, offset)
            .await
            .map(|resp| {
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
        self.read_config(Size::Word, block, offset)
            .await
            .map(|resp| {
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
        self.read_config(Size::Word, block, offset)
            .await
            .map(|resp| {
                resp.as_ref()[range]
                    .try_into()
                    .map(u16::from_le_bytes)
                    .unwrap_or_else(|_| unreachable!())
            })
    }

    // TODO: Testing purpose only.
    pub async fn read_config(
        &mut self,
        size: Size,
        block: u8,
        offset: u8,
    ) -> Result<Response<'_>, Error> {
        let packet = command::Read::new(self.atca.packet_builder()).read(
            Zone::Config,
            size,
            block,
            offset,
        )?;
        self.atca.execute(packet).await
    }

    pub async fn write_config(
        &mut self,
        size: Size,
        block: u8,
        offset: u8,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let packet = command::Write::new(self.atca.packet_builder()).write(
            Zone::Config,
            size,
            block,
            offset,
            data,
        )?;
        self.atca.execute(packet).await.map(drop)
    }
}

// Method signature is taken from cipher::block::BlockCipher.
// AES
pub struct Aes<'a, PHY> {
    atca: &'a mut AtCaClient<PHY>,
    key_id: Slot,
}

impl<'a, PHY> Aes<'a, PHY>
where
    PHY: i2c::I2c,
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
            // Input length should be exactly 16 bytes. Otherwise the device
            // couldn't recognize the command properly. If the length is not
            // enough, sufficient number of 0s are padded.
            let packet = AesCmd::new(self.atca.packet_builder()).encrypt(self.key_id, plain)?;

            // Encrypt plain bytes and write the result to cipher.
            let response = self.atca.execute(packet).await?;
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
            // Input length should be exactly 16 bytes. Otherwise the device
            // couldn't recognize the command properly. If the length is not
            // enough, sufficient number of 0s are padded.
            let packet = AesCmd::new(self.atca.packet_builder()).decrypt(self.key_id, cipher)?;

            // Decrypt cipher bytes and write the result to plain.
            let response = self.atca.execute(packet).await?;
            if response.as_ref().len() != AesCmd::DATA_SIZE {
                return Err(ErrorKind::InvalidSize.into());
            }
            plain.copy_from_slice(response.as_ref());
        }
        Ok(())
    }
}

// SHA
pub struct Sha<'a, PHY> {
    atca: &'a mut AtCaClient<PHY>,
    remaining_bytes: Vec<u8, 64>,
}

impl<'a, PHY> Sha<'a, PHY>
where
    PHY: i2c::I2c,
{
    pub async fn init(&mut self) -> Result<(), Error> {
        let packet = command::Sha::new(self.atca.packet_builder()).start()?;
        self.atca.execute(packet).await.map(drop)
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
            let packet = command::Sha::new(self.atca.packet_builder()).update(chunk)?;
            self.atca.execute(packet).await?;
        }

        Ok(())
    }

    pub async fn chain(&mut self, data: impl AsRef<[u8]>) -> Result<&mut Self, Error> {
        if self.remaining_bytes.len() != 0 {
            // TODO: Concatinate remaining bytes and input data.
        }

        self.update(data).await?;
        Ok(self)
    }

    pub async fn finalize(&mut self) -> Result<Digest, Error> {
        let packet = command::Sha::new(self.atca.packet_builder()).end(&self.remaining_bytes)?;
        self.atca.execute(packet).await?.as_ref().try_into()
    }

    pub async fn digest(&mut self, data: &[u8]) -> Result<Digest, Error> {
        self.init().await?;
        self.update(data).await?;
        self.finalize().await
    }
}

// Method signatures are taken from signature::DigestSigner.
// Sign
pub struct Sign<'a, PHY> {
    atca: &'a mut AtCaClient<PHY>,
    key_id: Slot,
}

impl<'a, PHY> Sign<'a, PHY>
where
    PHY: i2c::I2c,
{
    // Takes a 32-byte message to be signed, typically the SHA256 hash of the
    // full message.
    pub async fn sign_digest(&mut self, digest: &Digest) -> Result<Signature, Error> {
        // 1. Random value generation
        self.atca.random().await?;
        // 2. Nonce load
        self.atca.write_message_digest_buffer(digest).await?;
        // 3. Sign
        let packet = command::Sign::new(self.atca.packet_builder()).external(self.key_id)?;
        self.atca.execute(packet).await?.as_ref().try_into()
    }
}

pub struct Verify<'a, PHY> {
    atca: &'a mut AtCaClient<PHY>,
    key_id: Slot,
}

impl<'a, PHY> Verify<'a, PHY>
where
    PHY: i2c::I2c,
{
    // Takes a 32-byte message to be signed, typically the SHA256 hash of the
    // full message and signature.
    pub async fn verify_digest(
        &mut self,
        digest: &Digest,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        // 1. Nonce load
        self.atca.write_message_digest_buffer(digest).await?;
        // 2. Verify
        let packet =
            command::Verify::new(self.atca.packet_builder()).external(signature, public_key)?;
        self.atca.execute(packet).await?;

        Ok(())
    }
}
