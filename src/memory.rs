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
            Self::Word => Self::Word as usize,
            Self::Block => Self::Block as usize,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Zone {
    Config = 0x00,
    Data = 0x01,
    Otp = 0x02,
}

impl Zone {
    // A helper method to translate a global index into block and offset.
    pub fn locate_index(index: usize) -> (u8, u8, u8) {
        let block = index / Size::Block.len();
        let offset = index % Size::Block.len() / Size::Word.len();
        let position = index % Size::Word.len();
        (block as u8, offset as u8, position as u8)
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
        let offset = (offset & 0x07) as u16;
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

    pub fn keys() -> KeysIter {
        KeysIter(0x00..=0x0f)
    }
}

pub struct KeysIter(RangeInclusive<usize>);

impl Iterator for KeysIter {
    type Item = Slot;
    fn next(&mut self) -> Option<Self::Item> {
        use Slot::*;
        self.0.next().and_then(|i| match i {
            x if x == PrivateKey00 as usize => PrivateKey00.into(),
            x if x == PrivateKey01 as usize => PrivateKey01.into(),
            x if x == PrivateKey02 as usize => PrivateKey02.into(),
            x if x == PrivateKey03 as usize => PrivateKey03.into(),
            x if x == PrivateKey04 as usize => PrivateKey04.into(),
            x if x == PrivateKey05 as usize => PrivateKey05.into(),
            x if x == PrivateKey06 as usize => PrivateKey06.into(),
            x if x == PrivateKey07 as usize => PrivateKey07.into(),
            x if x == Data08 as usize => Data08.into(),
            x if x == Certificate09 as usize => Certificate09.into(),
            x if x == Certificate0a as usize => Certificate0a.into(),
            x if x == Certificate0b as usize => Certificate0b.into(),
            x if x == Certificate0c as usize => Certificate0c.into(),
            x if x == Certificate0d as usize => Certificate0d.into(),
            x if x == Certificate0e as usize => Certificate0e.into(),
            x if x == Certificate0f as usize => Certificate0f.into(),
            _ => None,
        })
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
    use crate::client::Memory;
    use core::convert::identity;
    use core::iter::repeat;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use heapless::Vec;
    use Slot::*;
    use Zone::*;

    #[test]
    fn locate_index() {
        assert_eq!(
            (0, 5, 0),
            Zone::locate_index(Memory::<NoopRawMutex, ()>::SLOT_CONFIG_INDEX)
        );
        assert_eq!(
            (2, 6, 2),
            Zone::locate_index(Memory::<NoopRawMutex, ()>::CHIP_OPTIONS_INDEX)
        );
        assert_eq!(
            (3, 0, 0),
            Zone::locate_index(Memory::<NoopRawMutex, ()>::KEY_CONFIG_INDEX)
        );
    }

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
            .collect::<Vec<u8, 96>>();
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
