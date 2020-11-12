use super::error::{Error, ErrorKind};
use core::ops::{Range, RangeInclusive};
use core::slice::from_ref;
/// Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
const ZONE_READWRITE_32: u8 = 0x80;

/// A unit of data exchange is either 4 or 32 bytes.
#[derive(Copy, Clone, Debug)]
pub enum Size {
    Word = 0x04,
    Block = 0x20,
}

impl Size {
    pub(crate) fn len(&self) -> usize {
        match self {
            Size::Word => Size::Word as usize,
            Size::Block => Size::Block as usize,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Zone {
    Config = 0x00,
    Otp = 0x01,
    Data = 0x02,
}

impl Zone {
    // A helper method to translate a global index into block and offset.
    pub(crate) fn locate_index(index: usize) -> (u8, u8) {
        let block = index / Size::Block.len();
        let offset = index % Size::Block.len() / Size::Word.len();
        (block as u8, offset as u8)
    }

    pub(crate) fn get_slot_addr(&self, slot: Slot, block: u8) -> Result<u16, Error> {
        match self {
            Self::Data if slot.is_private_key() && block == 0 => Ok((slot as u16) << 3),
            Self::Data if slot.is_certificate() && block <= 2 => {
                Ok((slot as u16) << 3 | (block as u16) << 8)
            }
            _ => Err(ErrorKind::BadParam.into()),
        }
    }

    pub(crate) fn get_addr(&self, block: u8, offset: u8) -> Result<u16, Error> {
        if block.leading_zeros() < 3 || offset.leading_zeros() < 4 {
            return Err(ErrorKind::BadParam.into());
        }
        let block = (block as u16) << 3;
        let offset = (offset & 0b0000_0111u8) as u16;
        let addr = block | offset;
        match self {
            Self::Config | Self::Otp => Ok(addr),
            // Use get_slot_addr instead.
            Self::Data => Err(ErrorKind::BadParam.into()),
        }
    }

    pub(crate) fn encode(&self, size: Size) -> u8 {
        match size {
            Size::Word => *self as u8,
            Size::Block => *self as u8 | ZONE_READWRITE_32,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    /// PrivateKey0x contains 36 bytes, taking 2 block reads.
    PrivateKey00 = 0x00,
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

impl Slot {
    /// Check if a slot can store private keys.
    pub fn is_private_key(&self) -> bool {
        *self <= Self::PrivateKey07
    }

    /// Check if a slot can store certificates.
    pub fn is_certificate(&self) -> bool {
        Self::Certificate09 <= *self
    }
}

pub(crate) struct CertificateRepr(RangeInclusive<usize>);

impl CertificateRepr {
    pub(crate) fn new() -> Self {
        Self(0..=2)
    }
}

impl Iterator for CertificateRepr {
    type Item = &'static [Range<usize>];
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().and_then(|i| match i {
            0 => from_ref(&(0x04..0x20)).into(),
            1 => [0x00..0x04, 0x08..0x20].as_ref().into(),
            2 => from_ref(&(0x00..0x08)).into(),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::identity;
    use core::iter::repeat;
    use heapless::{consts, Vec};
    use Slot::*;
    use Zone::*;

    #[test]
    fn get_slot_addr() {
        assert_eq!(0x0038, Data.get_slot_addr(PrivateKey07, 0).unwrap());
        for (&addr, block) in [0x0078, 0x0178, 0x0278].iter().zip(0..=2) {
            let result = Data.get_slot_addr(Certificate0f, block).unwrap();
            assert_eq!(addr, result);
        }
    }

    #[test]
    fn get_addr() {
        assert_eq!(0x0005, Config.get_addr(0, 5).unwrap());
        assert_eq!(0x0016, Config.get_addr(2, 6).unwrap());
        assert_eq!(0x0018, Config.get_addr(3, 0).unwrap());
    }

    #[test]
    fn certificate_representation() {
        let slot_buffer = repeat(0)
            .take(4)
            .chain(0x00..0x20)
            .chain(repeat(0).take(4))
            .chain(0x20..0x40)
            .chain(repeat(0).take(24))
            .collect::<Vec<u8, consts::U96>>();
        assert_eq!(Size::Block.len() * 3, slot_buffer.len());
        slot_buffer
            .chunks(Size::Block.len())
            .zip(CertificateRepr::new())
            .scan(0, |i, (chunk, ranges)| {
                for range in ranges {
                    for j in &chunk[range.clone()] {
                        assert_eq!(i, j);
                        *i += 1;
                    }
                }
                Some(())
            })
            .for_each(identity)
    }
}
