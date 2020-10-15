use super::error::{Error, ErrorKind};

pub enum Zone {
    Config = 0x00,
    Otp = 0x01,
    Data = 0x02,
}

impl Zone {
    pub fn get_addr(self, slot: Option<Slot>, block: u8, offset: u8) -> Result<u16, Error> {
        if block >= 0b0010_0000u8 || offset >= 0b0000_1000u8 {
            return Err(ErrorKind::BadParam.into());
        }
        let offset = (offset & 0b0000_0111u8) as u16;
        match self {
            Self::Config | Self::Otp if slot.is_none() => Ok((block as u16) << 3 | offset),
            Self::Data => slot
                .map(|slot| (slot as u16) << 3 | offset | (block as u16) << 8)
                .ok_or(ErrorKind::BadParam.into()),
            _ => Err(ErrorKind::BadParam.into()),
        }
    }
}

pub enum Size {
    Word,
    Block,
}

pub enum Slot {
    /// PrivateKey0x contains 36 bytes, taking 2 block reads.
    PrivateKey01 = 0x01,
    PrivateKey02 = 0x02,
    PrivateKey03 = 0x03,
    PrivateKey04 = 0x04,
    PrivateKey05 = 0x05,
    PrivateKey06 = 0x06,
    PrivateKey07 = 0x07,
    /// Data08 contains 416 bytes, taking 13 block reads.
    Data08 = 0x08,
    /// Certificate0x contains 72 bytes, taking 3 block reads.
    Certificate09 = 0x09,
    Certificate0a = 0x0a,
    Certificate0b = 0x0b,
    Certificate0c = 0x0c,
    Certificate0d = 0x0d,
    Certificate0e = 0x0e,
    Certificate0f = 0x0f,
}
