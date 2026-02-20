//! Memory and configuration operations

use crate::Block;
use crate::command::{self, Lock, PublicKey, Serial, Word};
use crate::error::{Error, ErrorKind};
use crate::memory::{CertificateRepr, CompressedCertRepr, Size, Slot, Zone};
use embassy_sync::blocking_mutex::raw::RawMutex;

use super::AtCaClient;

pub struct Memory<'a, M: RawMutex, PHY> {
    pub(crate) atca: &'a AtCaClient<M, PHY>,
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

    pub async fn write_pubkey(&mut self, key_id: Slot, pubkey: &[u8]) -> Result<(), Error> {
        let mut data = Block::default();
        let mut offset = 0;

        for (i, ranges) in CertificateRepr::new().enumerate() {
            let mut inner = self.atca.inner.lock().await;
            data.as_mut().iter_mut().for_each(|value| *value = 0);

            for range in ranges {
                let src = offset..offset + range.len();
                data.as_mut()[range.clone()].copy_from_slice(&pubkey[src]);
                offset += range.len();
            }

            let packet =
                command::Write::new(inner.packet_builder()).slot(key_id, i as u8, &data)?;
            inner.execute(packet).await?;
        }
        Ok(())
    }

    pub async fn write_aes_key(&mut self, key_id: Slot, aes_key: &[u8]) -> Result<(), Error> {
        let mut inner = self.atca.inner.lock().await;
        let mut data = Block::default();
        data.as_mut()[..0x10].copy_from_slice(aes_key);
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

    pub async unsafe fn read_config(
        &mut self,
        size: Size,
        block: u8,
        offset: u8,
    ) -> Result<heapless::Vec<u8, { Size::Block.len() }>, Error> {
        let mut inner = self.atca.inner.lock().await;
        let packet =
            command::Read::new(inner.packet_builder()).read(Zone::Config, size, block, offset)?;
        inner.execute(packet).await.and_then(|d| {
            heapless::Vec::from_slice(d.as_ref()).map_err(|_| ErrorKind::SmallBuffer.into())
        })
    }

    pub async fn write_config(
        &mut self,
        size: Size,
        block: u8,
        offset: u8,
        data: &[u8],
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

    pub async fn read_compressed_cert(
        &mut self,
        slot: Slot,
    ) -> Result<crate::cert::compressed::CompressedCertificate, Error> {
        if !slot.is_certificate() {
            return Err(ErrorKind::BadParam.into());
        }

        let mut cert_data = [0u8; crate::cert::compressed::CompressedCertificate::SIZE];
        let mut offset = 0;

        for (i, ranges) in CompressedCertRepr::new().enumerate() {
            let mut inner = self.atca.inner.lock().await;
            let packet = command::Read::new(inner.packet_builder()).slot(slot, i as u8)?;

            let response = inner.execute(packet).await?;
            for range in ranges {
                let dst = offset..offset + range.len();
                cert_data[dst].copy_from_slice(&response.as_ref()[range.clone()]);
                offset += range.len();
            }
        }

        Ok(crate::cert::compressed::CompressedCertificate::new(
            cert_data,
        ))
    }

    pub async fn write_compressed_cert(
        &mut self,
        slot: Slot,
        cert: &crate::cert::compressed::CompressedCertificate,
    ) -> Result<(), Error> {
        if !slot.is_certificate() {
            return Err(ErrorKind::BadParam.into());
        }

        let mut data = Block::default();
        let mut offset = 0;

        for (i, ranges) in CompressedCertRepr::new().enumerate() {
            let mut inner = self.atca.inner.lock().await;
            data.as_mut().iter_mut().for_each(|value| *value = 0);

            for range in ranges {
                let src = offset..offset + range.len();
                data.as_mut()[range.clone()].copy_from_slice(&cert.as_ref()[src]);
                offset += range.len();
            }

            let packet = command::Write::new(inner.packet_builder()).slot(slot, i as u8, &data)?;
            inner.execute(packet).await?;
        }
        Ok(())
    }

    pub async fn read_certificate<'b>(
        &mut self,
        def: &crate::cert::compressed::CertificateDefinition<'_>,
        output: &'b mut [u8],
    ) -> Result<usize, Error> {
        let compressed = self.read_compressed_cert(def.compressed_slot).await?;
        let public_key = self.pubkey(def.public_key_slot).await?;
        let device_serial = self.serial_number().await?;
        let mut serial_buf = [0u8; 16];
        let serial =
            def.serial_source
                .generate(&device_serial, compressed.signer_id(), &mut serial_buf)?;
        def.reconstruct(&compressed, &public_key, serial, output)
    }
}

impl<'a, M, PHY> Memory<'a, M, PHY>
where
    PHY: embedded_hal::i2c::I2c,
    M: RawMutex,
{
    pub fn serial_number_blocking(&mut self) -> Result<Serial, Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
        let packet =
            command::Read::new(inner.packet_builder()).read(Zone::Config, Size::Block, 0, 0)?;
        inner.execute_blocking(packet)?.as_ref().try_into()
    }

    pub fn pubkey_blocking(&mut self, key_id: Slot) -> Result<PublicKey, Error> {
        let mut pubkey = PublicKey::default();
        let mut offset = 0;
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

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

    pub fn write_pubkey_blocking(&mut self, key_id: Slot, pubkey: &[u8]) -> Result<(), Error> {
        let mut data = Block::default();
        let mut offset = 0;
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        for (i, ranges) in CertificateRepr::new().enumerate() {
            data.as_mut().iter_mut().for_each(|value| *value = 0);

            for range in ranges {
                let src = offset..offset + range.len();
                data.as_mut()[range.clone()].copy_from_slice(&pubkey[src]);
                offset += range.len();
            }

            let packet =
                command::Write::new(inner.packet_builder()).slot(key_id, i as u8, &data)?;
            inner.execute_blocking(packet)?;
        }
        Ok(())
    }

    pub fn write_aes_key_blocking(&mut self, key_id: Slot, aes_key: &[u8]) -> Result<(), Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
        let mut data = Block::default();
        data.as_mut()[..0x10].copy_from_slice(aes_key);
        let packet = command::Write::new(inner.packet_builder()).slot(key_id, 0 as u8, &data)?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn is_slot_locked_blocking(&mut self, slot: Slot) -> Result<bool, Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
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
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
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
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
        let packet = Lock::new(inner.packet_builder()).slot(key_id)?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn lock_blocking(&mut self, zone: Zone) -> Result<(), Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
        let packet = Lock::new(inner.packet_builder()).zone(zone, None)?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn lock_crc_blocking(&mut self, zone: Zone, crc: u16) -> Result<(), Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
        let packet = Lock::new(inner.packet_builder()).zone(zone, Some(crc))?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn chip_options_blocking(&mut self) -> Result<u16, Error> {
        let (block, offset, pos) = Zone::locate_index(Self::CHIP_OPTIONS_INDEX);
        let range = pos as usize..pos as usize + 2;
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
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
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
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
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
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
        data: &[u8],
    ) -> Result<(), Error> {
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;
        let packet = command::Write::new(inner.packet_builder()).write(
            Zone::Config,
            size,
            block,
            offset,
            data,
        )?;
        inner.execute_blocking(packet).map(drop)
    }

    pub fn read_compressed_cert_blocking(
        &mut self,
        slot: Slot,
    ) -> Result<crate::cert::compressed::CompressedCertificate, Error> {
        if !slot.is_certificate() {
            return Err(ErrorKind::BadParam.into());
        }

        let mut cert_data = [0u8; crate::cert::compressed::CompressedCertificate::SIZE];
        let mut offset = 0;
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        for (i, ranges) in CompressedCertRepr::new().enumerate() {
            let packet = command::Read::new(inner.packet_builder()).slot(slot, i as u8)?;

            let response = inner.execute_blocking(packet)?;
            for range in ranges {
                let dst = offset..offset + range.len();
                cert_data[dst].copy_from_slice(&response.as_ref()[range.clone()]);
                offset += range.len();
            }
        }

        Ok(crate::cert::compressed::CompressedCertificate::new(
            cert_data,
        ))
    }

    pub fn write_compressed_cert_blocking(
        &mut self,
        slot: Slot,
        cert: &crate::cert::compressed::CompressedCertificate,
    ) -> Result<(), Error> {
        if !slot.is_certificate() {
            return Err(ErrorKind::BadParam.into());
        }

        let mut data = Block::default();
        let mut offset = 0;
        let mut inner = self
            .atca
            .inner
            .try_lock()
            .map_err(|_| ErrorKind::MutexLocked)?;

        for (i, ranges) in CompressedCertRepr::new().enumerate() {
            data.as_mut().iter_mut().for_each(|value| *value = 0);

            for range in ranges {
                let src = offset..offset + range.len();
                data.as_mut()[range.clone()].copy_from_slice(&cert.as_ref()[src]);
                offset += range.len();
            }

            let packet = command::Write::new(inner.packet_builder()).slot(slot, i as u8, &data)?;
            inner.execute_blocking(packet)?;
        }
        Ok(())
    }

    pub fn read_certificate_blocking<'b>(
        &mut self,
        def: &crate::cert::compressed::CertificateDefinition<'_>,
        output: &'b mut [u8],
    ) -> Result<usize, Error> {
        let compressed = self.read_compressed_cert_blocking(def.compressed_slot)?;
        let public_key = self.pubkey_blocking(def.public_key_slot)?;
        let device_serial = self.serial_number_blocking()?;
        let mut serial_buf = [0u8; 16];
        let serial =
            def.serial_source
                .generate(&device_serial, compressed.signer_id(), &mut serial_buf)?;
        def.reconstruct(&compressed, &public_key, serial, output)
    }
}
