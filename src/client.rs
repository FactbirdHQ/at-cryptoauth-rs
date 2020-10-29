use super::command::{self, Block, Digest, Info, Lock, Serial, Signature, Word};
use super::datalink::I2c;
use super::error::{Error, ErrorKind};
use super::memory::{Size, Slot, Zone};
use super::packet::{Packet, PacketBuilder, Response};
use super::tngtls::TrustAndGo;
use core::convert::{identity, TryFrom};
use core::fmt::Debug;
use core::slice::from_ref;
use embedded_hal::blocking::delay::DelayUs;
use embedded_hal::blocking::i2c::{Read, Write};
use heapless::{consts, Vec};

pub const PUBLIC_KEY: usize = 0x40;
const BUFFER_LEN: usize = 192;

pub struct AtCaClient<PHY, D> {
    i2c: I2c<PHY, D>,
    buffer: Vec<u8, consts::U192>,
}

impl<PHY, D> AtCaClient<PHY, D> {
    pub fn new(phy: PHY, delay: D) -> Self {
        let i2c = I2c::new(phy, delay);
        let buffer = Vec::new();
        Self { i2c, buffer }
    }

    fn packet_builder(&mut self) -> PacketBuilder<'_> {
        self.buffer.clear();
        self.buffer.resize(BUFFER_LEN, 0x00u8).unwrap_or_else(|()| {
            unreachable!("Buffer of the exact length must have been allocated.")
        });
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
}

impl<PHY, D> AtCaClient<PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    fn execute(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        self.i2c.execute(&mut self.buffer, packet, 10)
    }

    pub fn tng(&mut self) -> Result<TrustAndGo<'_, PHY, D>, Error> {
        TrustAndGo::try_from(self)
    }

    pub fn sleep(&mut self) -> Result<(), Error> {
        self.i2c.sleep()
    }

    pub fn info(&mut self) -> Result<Word, Error> {
        let packet = Info::new(self.packet_builder()).revision()?;
        let response = self.execute(packet)?;
        Word::try_from(response.as_ref())
    }
}

/// Memory zones consists of config, data and OTP.
pub struct Memory<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
}

// Only expose the highest level APIs.
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
        let response = self.atca.execute(packet)?;
        Serial::try_from(response.as_ref())
    }

    pub fn pubkey(&mut self, key_id: Slot) -> Result<[u8; PUBLIC_KEY], Error> {
        let mut pubkey = [0x00u8; PUBLIC_KEY];
        (0..=2u8)
            .scan(0, |offset, i| {
                // TODO: Elaborate creation of ranges.
                let ranges = match i {
                    0 => from_ref(&(0x04..0x20)),
                    1 => &[0x00..0x04, 0x08..0x20],
                    2 => from_ref(&(0x00..0x08)),
                    _ => unreachable!("The range i stops at 2."),
                };

                let result = command::Read::new(self.atca.packet_builder())
                    .slot(key_id, i)
                    .and_then(|packet| {
                        let response = self.atca.execute(packet)?;
                        for range in ranges {
                            let dst = *offset..*offset + range.len();
                            pubkey[dst].copy_from_slice(&response.as_ref()[range.clone()]);
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
        (0..=2u8)
            .scan(0, |offset, i| {
                // Initialize block sized buffer
                data.as_mut().iter_mut().for_each(|value| *value = 0);

                // TODO: Elaborate creation of ranges.
                let ranges = match i {
                    0 => from_ref(&(0x04..0x20)),
                    1 => &[0x00..0x04, 0x08..0x20],
                    2 => from_ref(&(0x00..0x08)),
                    _ => unreachable!("The range i stops at 2."),
                };

                for range in ranges {
                    let src = *offset..*offset + range.len();
                    data.as_mut()[range.clone()].copy_from_slice(&pubkey.as_ref()[src]);
                    *offset += range.len();
                }

                let result = command::Write::new(self.atca.packet_builder())
                    .slot(key_id, i, &data)
                    .and_then(|packet| self.atca.execute(packet).map(drop));

                Some(result)
            })
            .try_for_each(identity)
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
        let packet =
            command::Read::new(self.atca.packet_builder()).read(zone, size, block, word_offset)?;
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

    pub fn write(&mut self) -> Result<(), Error> {
        let packet = command::Write::new(self.atca.packet_builder()).write(
            Zone::Config,
            Size::Block,
            0,
            0,
            &[],
        )?;
        self.atca.execute(packet).map(drop)
    }
}

// Method signature is taken from cipher::block::BlockCipher.
/// AES
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
        let block_size = Size::Block as usize;
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
        let block_size = Size::Block as usize;
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
/// SHA
pub struct Sha<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
}

// Only expose the highest level APIs.
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
        let packet = command::Sha::new(self.atca.packet_builder()).update(data)?;
        self.atca.execute(packet).map(drop)
    }

    pub fn chain(&mut self, data: impl AsRef<[u8]>) -> Result<&mut Self, Error> {
        self.update(data)?;
        Ok(self)
    }

    pub fn finalize(&mut self) -> Result<Digest, Error> {
        let packet = command::Sha::new(self.atca.packet_builder()).end()?;
        let response = self.atca.execute(packet)?;
        Digest::try_from(response.as_ref())
    }

    pub fn digest(&mut self, data: &[u8]) -> Result<Digest, Error> {
        self.init()?;
        data.chunks(Size::Block as usize)
            .try_fold(self, |acc, chunk| acc.chain(chunk))
            .and_then(|acc| acc.finalize())
    }
}

// Method signatures are taken from signature::DigestSigner.
/// Sign
pub struct Sign<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
    key_id: Slot,
}

// Only expose the highest level APIs.
impl<'a, PHY, D> Sign<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    pub fn sign_digest(&mut self, digest: impl AsRef<[u8]>) -> Result<Signature, Error> {
        let _ = digest;
        let _ = self.atca;
        let _ = self.key_id;
        Err(ErrorKind::BadParam.into())
    }
}
