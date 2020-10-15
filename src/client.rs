use super::datalink::I2c;
use super::error::Error;
use super::memory::{Size, Zone};
use super::packet::{Packet, PacketBuilder, Response};
use core::fmt::Debug;
use embedded_hal::blocking::delay::DelayUs;
use embedded_hal::blocking::i2c::{Read, Write};
use heapless::{consts, Vec};

pub struct AtCaClient<PHY, D> {
    i2c: I2c<PHY, D>,
    buffer: Vec<u8, consts::U192>,
}

impl<PHY, D> AtCaClient<PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    pub fn execute(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        self.i2c.execute(&mut self.buffer, packet, 10)
    }
}

impl<PHY, D> AtCaClient<PHY, D> {
    pub fn new(i2c: I2c<PHY, D>) -> Self {
        let buffer = Vec::new();
        Self { i2c, buffer }
    }

    pub fn packet_builder(&mut self) -> PacketBuilder<'_> {
        self.buffer.clear();
        PacketBuilder::new(&mut self.buffer)
    }

    fn config(&mut self) -> Config<'_, PHY, D> {
        unimplemented!()
    }

    fn otp(&mut self) -> Otp {
        Otp
    }

    fn data(&mut self) -> Data {
        Data
    }
}

pub struct Config<'a, PHY, D> {
    atca: &'a mut AtCaClient<PHY, D>,
}

impl<'a, PHY, D> Config<'a, PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    fn read_block(&mut self) -> Result<Response<'_>, Error> {
        let packet = self.atca.packet_builder().build();
        self.atca.execute(packet)
    }

    fn write_block(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn serial_number(&mut self) -> Result<(), Error> {
        let block = 0x00;
        let offset = 0x00;
        let size = Size::Block;
        let response = self.read_block()?;
        Ok(())
    }
}

pub struct Otp;
impl Otp {
    fn read_block(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn write_block(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

pub struct Data;
impl Data {
    fn read_block(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn write_block(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
