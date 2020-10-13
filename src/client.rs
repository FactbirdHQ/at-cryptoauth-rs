use super::calib::packet::{Packet, Response};
use super::datalink::hal::I2c;
use core::fmt::Debug;
use embedded_hal::blocking::delay::DelayUs;
use embedded_hal::blocking::i2c::{Read, Write};
use heapless::{consts, Vec};

pub struct Error;

pub struct CaClient<PHY, D> {
    i2c: I2c<PHY, D>,
    buffer: Vec<u8, consts::U192>,
}

impl<PHY, D> CaClient<PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    pub fn execute(&mut self, packet: Packet) -> Result<Response<'_>, Error> {
        self.i2c
            .execute(&mut self.buffer, packet, 10)
            .map_err(|_| Error)
    }
}

impl<PHY, D> CaClient<PHY, D> {
    fn new(i2c: I2c<PHY, D>) -> Self {
        let buffer = Vec::new();
        Self { i2c, buffer }
    }

    fn config(&mut self) -> Config {
        Config
    }

    fn otp(&mut self) -> Otp {
        Otp
    }

    fn data(&mut self) -> Data {
        Data
    }
}

pub struct Config;
impl Config {
    fn read_block(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn write_block(&mut self) -> Result<(), Error> {
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
