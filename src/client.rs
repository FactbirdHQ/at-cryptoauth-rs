use super::clock_divider::ClockDivider;
use super::command::{self, Block, Digest, Info, Lock, Random, Serial, Signature, Word};
use super::datalink::I2c;
use super::error::{Error, ErrorKind};
use super::memory::{CertificateRepr, Size, Slot, Zone};
use super::packet::{Packet, PacketBuilder, Response};
use super::tngtls::TrustAndGo;
use core::convert::{identity, TryFrom};
use core::fmt::Debug;
use embedded_hal::blocking::delay::DelayUs;
use embedded_hal::blocking::i2c::{Read, Write};
use heapless::{consts, Vec};

pub const PUBLIC_KEY: usize = 0x40;

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

    pub fn random(&mut self) -> Result<Block, Error> {
        let packet = Random::new(self.packet_builder()).random()?;
        let response = self.execute(packet)?;
        Block::try_from(response.as_ref())
    }

    // Nonce load
    pub fn nonce(&mut self) -> Result<(), Error> {
        unimplemented!()
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
        let response = self.atca.execute(packet)?;
        Serial::try_from(response.as_ref())
    }

    pub fn pubkey(&mut self, key_id: Slot) -> Result<[u8; PUBLIC_KEY], Error> {
        let mut pubkey = [0x00u8; PUBLIC_KEY];
        CertificateRepr::new()
            .enumerate()
            .scan(0, |offset, (i, ranges)| {
                let result = command::Read::new(self.atca.packet_builder())
                    .slot(key_id, i as u8)
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

    pub fn chip_options(&mut self) -> Result<u16, Error> {
        let (block, offset, pos) = Zone::locate_index(Self::CHIP_OPTIONS_INDEX);
        self.read_config(Size::Word, block, offset).map(|resp| {
            resp.as_ref()[pos as usize] as u16 | (resp.as_ref()[pos as usize + 1] as u16) << 8
        })
    }

    pub fn permission(&mut self, slot: Slot) -> Result<u16, Error> {
        let index = Self::SLOT_CONFIG_INDEX + (slot as usize * 2);
        let (block, offset, pos) = Zone::locate_index(index);
        self.read_config(Size::Word, block, offset).map(|resp| {
            resp.as_ref()[pos as usize] as u16 | (resp.as_ref()[pos as usize + 1] as u16) << 8
        })
    }

    pub fn key_type(&mut self, slot: Slot) -> Result<u16, Error> {
        let index = Self::KEY_CONFIG_INDEX + (slot as usize * 2);
        let (block, offset, pos) = Zone::locate_index(index);
        self.read_config(Size::Word, block, offset).map(|resp| {
            resp.as_ref()[pos as usize] as u16 | (resp.as_ref()[pos as usize + 1] as u16) << 8
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
        data.chunks(Size::Block.len())
            .try_fold(self, |acc, chunk| acc.chain(chunk))
            .and_then(|acc| acc.finalize())
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
    pub fn sign_digest(&mut self, digest: impl AsRef<[u8]>) -> Result<Signature, Error> {
        let _ = digest;
        let _ = self.atca;
        let _ = self.key_id;
        Err(ErrorKind::BadParam.into())
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
    pub fn verify(&mut self, digest: impl AsRef<[u8]>) -> Result<Signature, Error> {
        let _ = digest;
        let _ = self.atca;
        let _ = self.key_id;
        Err(ErrorKind::BadParam.into())
    }
}
