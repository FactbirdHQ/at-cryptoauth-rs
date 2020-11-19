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
use core::convert::TryInto;
use core::convert::{identity, TryFrom};
use core::fmt::Debug;
use embedded_hal::blocking::delay::DelayUs;
use embedded_hal::blocking::i2c::{Read, Write};
use heapless::{consts, Vec};

pub struct Verifier<'a, PHY, D>(RefCell<Verify<'a, PHY, D>>);

impl<'a, PHY, D> From<Verify<'a, PHY, D>> for Verifier<'a, PHY, D> {
    fn from(verify: Verify<'a, PHY, D>) -> Self {
        Self(RefCell::new(verify))
    }
}

impl<'a, PHY, D> signature::Verifier<Signature> for Verifier<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        self.0
            .borrow_mut()
            .atca
            .sha()
            .digest(msg)
            .and_then(|digest| self.0.borrow_mut().verify_digest(&digest, signature))
            .map_err(|_| signature::Error::new())
    }
}

pub struct Signer<'a, PHY, D>(RefCell<Sign<'a, PHY, D>>);

impl<'a, PHY, D> From<Sign<'a, PHY, D>> for Signer<'a, PHY, D> {
    fn from(sign: Sign<'a, PHY, D>) -> Self {
        Self(RefCell::new(sign))
    }
}

impl<'a, PHY, D> signature::Signer<Signature> for Signer<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.0
            .borrow_mut()
            .atca
            .sha()
            .digest(msg)
            .and_then(|digest| self.0.borrow_mut().sign_digest(&digest))
            .map_err(|_| signature::Error::new())
    }
}

pub struct AtCaClient<PHY, D> {
    i2c: I2c<PHY, D>,
    buffer: Vec<u8, consts::U192>,
    clock_divider: ClockDivider,
}

impl<PHY, D> AtCaClient<PHY, D> {
    pub fn new(phy: PHY, delay: D) -> Self {
        let i2c = I2c::new(phy, delay);
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

    pub fn memory(&mut self) -> Memory<'_, PHY, D> {
        Memory { atca: self }
    }

    pub fn aes(&mut self, key_id: Slot) -> Aes<'_, PHY, D> {
        Aes { atca: self, key_id }
    }

    pub fn sha(&mut self) -> Sha<'_, PHY, D> {
        Sha { atca: self }
    }

    pub fn sign(&mut self, key_id: Slot) -> Sign<'_, PHY, D> {
        Sign { atca: self, key_id }
    }

    pub fn verify(&mut self, key_id: Slot) -> Verify<'_, PHY, D> {
        Verify { atca: self, key_id }
    }
}

impl<PHY, D> AtCaClient<PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    fn execute(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        let exec_time = self.clock_divider.execution_time(packet.opcode());
        self.i2c.execute(&mut self.buffer, packet, exec_time)
    }

    pub fn signer(&mut self, key_id: Slot) -> Signer<'_, PHY, D> {
        self.sign(key_id).into()
    }

    pub fn verifier(&mut self, key_id: Slot) -> Verifier<'_, PHY, D> {
        self.verify(key_id).into()
    }

    pub fn tng(&mut self) -> Result<TrustAndGo<'_, PHY, D>, Error> {
        self.try_into()
    }

    pub fn sleep(&mut self) -> Result<(), Error> {
        self.i2c.sleep()
    }

    pub fn info(&mut self) -> Result<Word, Error> {
        let packet = Info::new(self.packet_builder()).revision()?;
        self.execute(packet)?.as_ref().try_into()
    }

    pub fn random(&mut self) -> Result<Block, Error> {
        let packet = Random::new(self.packet_builder()).random()?;
        self.execute(packet)?.as_ref().try_into()
    }

    // Write to device's digest message buffer.
    pub fn write_message_digest_buffer(&mut self, msg: &Digest) -> Result<(), Error> {
        let packet = NonceCtx::new(self.packet_builder()).nonce(msg)?;
        self.execute(packet).map(drop)
    }

    // Create private key and output its public key.
    pub fn create_private_key(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let packet = GenKey::new(self.packet_builder()).private_key(key_id)?;
        self.execute(packet)?.as_ref().try_into()
    }

    // Write private key.
    pub fn write_private_key(&mut self, key_id: Slot, private_key: &Block) -> Result<(), Error> {
        let packet =
            PrivWrite::new(self.packet_builder()).write_private_key(key_id, private_key)?;
        self.execute(packet).map(drop)
    }

    // Given a private key created and stored in advance, calculate its public key.
    pub fn generate_pubkey(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let packet = GenKey::new(self.packet_builder()).public_key(key_id)?;
        self.execute(packet)?.as_ref().try_into()
    }
}

// Memory zones consist of config, data and OTP.
pub struct Memory<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
}

impl<'a, PHY, D> Memory<'a, PHY, D> {
    pub(crate) const SLOT_CONFIG_INDEX: usize = 20;
    pub(crate) const CHIP_OPTIONS_INDEX: usize = 90;
    pub(crate) const KEY_CONFIG_INDEX: usize = 96;
}

impl<'a, PHY, D> Memory<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    pub fn serial_number(&mut self) -> Result<Serial, Error> {
        let packet =
            command::Read::new(self.atca.packet_builder()).read(Zone::Config, Size::Block, 0, 0)?;
        self.atca.execute(packet)?.as_ref().try_into()
    }

    pub fn pubkey(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut pubkey = PublicKey::default();
        CertificateRepr::new()
            .enumerate()
            .scan(0, |offset, (i, ranges)| {
                let result = command::Read::new(self.atca.packet_builder())
                    .slot(key_id, i as u8)
                    .and_then(|packet| {
                        let response = self.atca.execute(packet)?;
                        for range in ranges {
                            let dst = *offset..*offset + range.len();
                            pubkey.as_mut()[dst].copy_from_slice(&response.as_ref()[range.clone()]);
                            *offset += range.len();
                        }
                        Ok(())
                    });
                Some(result)
            })
            .try_for_each(identity)
            .map(|()| pubkey)
    }

    pub fn write_pubkey(&mut self, key_id: Slot, pubkey: impl AsRef<[u8]>) -> Result<(), Error> {
        let mut data = Block::default();
        CertificateRepr::new()
            .enumerate()
            .scan(0, |offset, (i, ranges)| {
                // Initialize block sized buffer
                data.as_mut().iter_mut().for_each(|value| *value = 0);

                for range in ranges {
                    let src = *offset..*offset + range.len();
                    data.as_mut()[range.clone()].copy_from_slice(&pubkey.as_ref()[src]);
                    *offset += range.len();
                }

                let result = command::Write::new(self.atca.packet_builder())
                    .slot(key_id, i as u8, &data)
                    .and_then(|packet| self.atca.execute(packet).map(drop));

                Some(result)
            })
            .try_for_each(identity)
    }

    pub fn write_aes_key(&mut self, key_id: Slot, aes_key: impl AsRef<[u8]>) -> Result<(), Error> {
        let mut data = Block::default();
        data.as_mut()[..0x10].copy_from_slice(aes_key.as_ref());
        let packet =
            command::Write::new(self.atca.packet_builder()).slot(key_id, 0 as u8, &data)?;
        self.atca.execute(packet).map(drop)
    }

    pub fn is_slot_locked(&mut self, slot: Slot) -> Result<bool, Error> {
        let zone = Zone::Config;
        let size = Size::Word;
        let block = 2;
        let word_offset = 6;
        let packet =
            command::Read::new(self.atca.packet_builder()).read(zone, size, block, word_offset)?;
        let response = self.atca.execute(packet)?;
        let word = Word::try_from(response.as_ref())?;
        let slot_locked_bytes = u16::from_le_bytes([word.as_ref()[0], word.as_ref()[1]]);
        Ok(slot_locked_bytes & (0x01u16 << slot as u32) == 0x00)
    }

    pub fn is_locked(&mut self, zone: Zone) -> Result<bool, Error> {
        let size = Size::Word;
        let block = 2;
        let word_offset = 5;
        let packet = command::Read::new(self.atca.packet_builder()).read(
            Zone::Config,
            size,
            block,
            word_offset,
        )?;
        let response = self.atca.execute(packet)?;
        let word = Word::try_from(response.as_ref())?;
        match zone {
            Zone::Config => Ok(word.as_ref()[3] != 0x55),
            Zone::Data => Ok(word.as_ref()[2] != 0x55),
            Zone::Otp => Err(ErrorKind::BadParam.into()),
        }
    }

    pub fn lock_slot(&mut self, key_id: Slot) -> Result<(), Error> {
        let packet = Lock::new(self.atca.packet_builder()).slot(key_id)?;
        self.atca.execute(packet).map(drop)
    }

    pub fn lock(&mut self, zone: Zone) -> Result<(), Error> {
        let packet = Lock::new(self.atca.packet_builder()).zone(zone)?;
        self.atca.execute(packet).map(drop)
    }

    pub fn chip_options(&mut self) -> Result<u16, Error> {
        let (block, offset, pos) = Zone::locate_index(Self::CHIP_OPTIONS_INDEX);
        self.read_config(Size::Word, block, offset).map(|resp| {
            u16::from_le_bytes([resp.as_ref()[pos as usize], resp.as_ref()[pos as usize + 1]])
        })
    }

    pub fn permission(&mut self, slot: Slot) -> Result<u16, Error> {
        let index = Self::SLOT_CONFIG_INDEX + (slot as usize * 2);
        let (block, offset, pos) = Zone::locate_index(index);
        self.read_config(Size::Word, block, offset).map(|resp| {
            u16::from_le_bytes([resp.as_ref()[pos as usize], resp.as_ref()[pos as usize + 1]])
        })
    }

    pub fn key_type(&mut self, slot: Slot) -> Result<u16, Error> {
        let index = Self::KEY_CONFIG_INDEX + (slot as usize * 2);
        let (block, offset, pos) = Zone::locate_index(index);
        self.read_config(Size::Word, block, offset).map(|resp| {
            u16::from_le_bytes([resp.as_ref()[pos as usize], resp.as_ref()[pos as usize + 1]])
        })
    }

    // TODO: Testing purpose only.
    pub fn read_config(
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
        self.atca.execute(packet)
    }

    pub fn write_config(
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
        self.atca.execute(packet).map(drop)
    }
}

// Method signature is taken from cipher::block::BlockCipher.
// AES
pub struct Aes<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
    key_id: Slot,
}

impl<'a, PHY, D> Aes<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), Error> {
        let block_size = Size::Block.len();
        if plaintext.len() != ciphertext.len() {
            return Err(ErrorKind::BadParam.into());
        }

        for (plain, cipher) in plaintext
            .chunks(block_size)
            .zip(ciphertext.chunks_mut(block_size))
        {
            // Input length should be exactly 16 bytes. Otherwise the device
            // couldn't recognize the command properly. If the length is not
            // enough, sufficient number of 0s are padded.
            let packet =
                command::Aes::new(self.atca.packet_builder()).encrypt(self.key_id, plain)?;

            // Encrypt plain bytes and write the result to cipher.
            let response = self.atca.execute(packet)?;
            if response.as_ref().len() != 16 {
                return Err(ErrorKind::InvalidSize.into());
            }
            cipher.copy_from_slice(response.as_ref());
        }
        Ok(())
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), Error> {
        let block_size = Size::Block.len();
        if ciphertext.len() != plaintext.len() {
            return Err(ErrorKind::BadParam.into());
        }

        for (cipher, plain) in ciphertext
            .chunks(block_size)
            .zip(plaintext.chunks_mut(block_size))
        {
            // Input length should be exactly 16 bytes. Otherwise the device
            // couldn't recognize the command properly. If the length is not
            // enough, sufficient number of 0s are padded.
            let packet =
                command::Aes::new(self.atca.packet_builder()).decrypt(self.key_id, cipher)?;

            // Decrypt cipher bytes and write the result to plain.
            let response = self.atca.execute(packet)?;
            if response.as_ref().len() != 16 {
                return Err(ErrorKind::InvalidSize.into());
            }
            plain.copy_from_slice(response.as_ref());
        }
        Ok(())
    }
}

// Implementation design inspired by digest crate.
// Not directly applicable because the trait won't allow any member methods to be fallible.
// Moreover, `digest` requires the client stored in a global static variable.
//
// use digest::{Digest, Output};
// use heapless::consts::U32;
//
// impl Digest for Sha {
//     type OutputSize = U32;
//     fn new() -> Self { unimplemented!() }
//     fn update(&mut self, data: impl AsRef<[u8]>) { unimplemented!() }
//     fn chain(self, data: impl AsRef<[u8]>) -> Self { unimplemented!() }
//     fn finalize(self) -> Output<Self> { unimplemented!() }
//     fn finalize_reset(&mut self) -> Output<Self> { unimplemented!() }
//     fn reset(&mut self) { unimplemented!() }
//     fn output_size() -> usize { unimplemented!() }
//     fn digest(data: &[u8]) -> Output<Self> { unimplemented!() }
// }
// SHA
pub struct Sha<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
}

impl<'a, PHY, D> Sha<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    pub fn init(&mut self) -> Result<(), Error> {
        let packet = command::Sha::new(self.atca.packet_builder()).start()?;
        self.atca.execute(packet).map(drop)
    }

    // See digest::Update
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        let mut buffer = Vec::<u8, consts::U64>::new();
        let capacity = buffer.capacity();
        data.as_ref().chunks(capacity).try_for_each(|chunk| {
            buffer.clear();
            buffer
                .resize(capacity, 0x00u8)
                .unwrap_or_else(|()| unreachable!("Input length equals to the current capacity."));
            buffer[..chunk.len()].as_mut().copy_from_slice(chunk);
            let packet = command::Sha::new(self.atca.packet_builder()).update(&buffer)?;
            self.atca.execute(packet).map(drop)
        })
    }

    pub fn chain(&mut self, data: impl AsRef<[u8]>) -> Result<&mut Self, Error> {
        self.update(data)?;
        Ok(self)
    }

    pub fn finalize(&mut self) -> Result<Digest, Error> {
        let packet = command::Sha::new(self.atca.packet_builder()).end()?;
        self.atca.execute(packet)?.as_ref().try_into()
    }

    pub fn digest(&mut self, data: &[u8]) -> Result<Digest, Error> {
        self.init()?;
        self.update(data)?;
        self.finalize()
    }
}

// Method signatures are taken from signature::DigestSigner.
// Sign
pub struct Sign<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
    key_id: Slot,
}

impl<'a, PHY, D> Sign<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    // Takes a 32-byte message to be signed, typically the SHA256 hash of the
    // full message.
    pub fn sign_digest(&mut self, digest: &Digest) -> Result<Signature, Error> {
        // 1. Random value generation
        // 2. Nonce load
        self.atca.write_message_digest_buffer(digest)?;
        // 3. Sign
        let packet = command::Sign::new(self.atca.packet_builder()).sign(self.key_id)?;
        self.atca.execute(packet)?.as_ref().try_into()
    }
}

pub struct Verify<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
    key_id: Slot,
}

impl<'a, PHY, D> Verify<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    // Takes a 32-byte message to be signed, typically the SHA256 hash of the
    // full message and signature.
    pub fn verify_digest(&mut self, digest: &Digest, signature: &Signature) -> Result<(), Error> {
        // 1. Nonce load
        self.atca.write_message_digest_buffer(digest)?;
        // 2. Verify
        let packet =
            command::Verify::new(self.atca.packet_builder()).verify(self.key_id, signature)?;
        self.atca.execute(packet).map(drop)
    }
}
