use super::command::{self, Digest, Info, Serial, Signature, Word};
use super::datalink::I2c;
use super::error::{Error, ErrorKind};
use super::memory::{Size, Slot, Zone};
use super::packet::{Packet, PacketBuilder, Response};
use core::convert::TryFrom;
use core::fmt::Debug;
use embedded_hal::blocking::delay::DelayUs;
use embedded_hal::blocking::i2c::{Read, Write};
use heapless::{consts, Vec};

pub const PUBLIC_KEY: usize = 0x20;

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

    pub fn sleep(&mut self) -> Result<(), Error> {
        self.i2c.sleep()
    }

    pub fn info(&mut self) -> Result<Word, Error> {
        let packet = Info::new(self.packet_builder()).revision()?;
        let response = self.execute(packet)?;
        Word::try_from(response.as_ref())
    }
}

/// Memory zones consists of config, OTP and data.
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
        let packet = command::Read::new(self.atca.packet_builder()).register(
            Zone::Config,
            Size::Block,
            0,
            0,
        )?;
        let response = self.atca.execute(packet)?;
        Serial::try_from(response.as_ref())
    }

    pub fn pubkey(&mut self, key_id: Slot) -> Result<[u8; PUBLIC_KEY], Error> {
        let packet = command::Read::new(self.atca.packet_builder()).slot(key_id, 0)?;
        let response = self.atca.execute(packet)?;
        let mut pubkey = [0x00u8; PUBLIC_KEY];
        pubkey.as_mut().copy_from_slice(response.as_ref());
        Ok(pubkey)
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
