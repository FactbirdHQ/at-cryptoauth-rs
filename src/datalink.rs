// for this implementation of I2C with CryptoAuth chips, txdata is assumed to
// have ATCAPacket format Devices such as ATECCx08A require a word address value
// pre-pended to the packet txdata[0] is using _reserved byte of the ATCAPacket
use super::error::{Error, ErrorKind};
use super::packet::{Packet, Response};
use core::fmt::Debug;
use core::iter::from_fn;
use core::slice::from_ref;
use embedded_hal::blocking::delay::DelayUs;
use embedded_hal::blocking::i2c::{Read, Write};
const WAKE_RESPONSE_EXPECTED: &[u8] = &[0x04, 0x11, 0x33, 0x43];
const WAKE_SELFTEST_FAILED: &[u8] = &[0x04, 0x07, 0xC4, 0x40];

/// Default I2C address of ATECC608
const ADDRESS: u8 = 0xc0 >> 1;
/// Default time in us that takes for ATECC608 device to wake up.
const DELAY_US: u32 = 1500;

// By default, wake up sequence is repeated up to 20 times until it succeeds.
// Multipy by 2, otherwise you see RxFail on wake up. It happens when you try to
// write a word to the config zone on Raspberry PI's I2C. This behaviour might
// be specific to linux HAL.
#[cfg(target_os = "none")]
const RETRY: usize = 20;
#[cfg(not(target_os = "none"))]
const RETRY: usize = 20 * 2;

/// So-called "word address".
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Transaction {
    Reset = 0x00,
    Sleep = 0x01,
    Idle = 0x02,
    Command = 0x03,
    #[allow(dead_code)]
    Reserved = 0xff,
}

pub(crate) struct I2c<PHY, D> {
    phy: PHY,
    delay: D,
}

impl<PHY, D> I2c<PHY, D> {
    pub(crate) fn new(phy: PHY, delay: D) -> Self {
        Self { phy, delay }
    }
}

impl<PHY, D> I2c<PHY, D>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    /// Wakes up device, sends the packet, waits for command completion,
    /// receives response, and puts the device into the idle state.
    pub(crate) fn execute<'a>(
        &mut self,
        buffer: &'a mut [u8],
        packet: Packet,
        exec_time: Option<u32>,
    ) -> Result<Response<'a>, Error> {
        self.wake()?;
        self.send(&packet.buffer(buffer))?;
        // Wait for the device to finish its job.
        self.delay.delay_us(exec_time.unwrap_or(1));
        let response_buffer = self.receive(buffer)?;
        self.idle()?;
        Response::new(response_buffer)
    }

    fn send<T>(&mut self, bytes: &T) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        self.phy
            .write(ADDRESS, bytes.as_ref())
            .map_err(|_| ErrorKind::TxFail.into())
    }

    /// Returns response buffer for later processing.
    fn receive<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        // Reset indicates the beginning of transaction.
        let word_address = Transaction::Reset as u8;
        from_fn(|| self.phy.write(ADDRESS, from_ref(&word_address)).into())
            .take(RETRY)
            .find_map(Result::<_, _>::ok)
            .ok_or_else(|| Error::from(ErrorKind::RxFail))?;

        let min_resp_size = 4;
        self.phy
            .read(ADDRESS, &mut buffer[0..2])
            .map_err(|_| Error::from(ErrorKind::RxFail))?;

        let length_to_read = match buffer[0] {
            // A single byte has already read.
            length if length == 1 => return Ok(buffer[0..1].as_mut()),
            // Buffer cannot contain the response to come. Abort.
            length if buffer.len() < length as usize => return Err(ErrorKind::CommFail.into()),
            // The coming response is malformed. Abort.
            length if length < min_resp_size => return Err(ErrorKind::CommFail.into()),
            length => length as usize,
        };

        self.phy
            .read(ADDRESS, buffer[2..length_to_read].as_mut())
            .map(move |()| buffer[..length_to_read].as_mut())
            .map_err(|_| ErrorKind::RxFail.into())
    }

    fn wake(&mut self) -> Result<(), Error> {
        // Send a single null byte to an absent address.
        self.phy.write(0x00, from_ref(&0x00)).unwrap_err();

        // Wait for the device to wake up.
        self.delay.delay_us(DELAY_US);

        let buffer = &mut [0x00, 0x00, 0x00, 0x00];
        from_fn(|| self.phy.read(ADDRESS, buffer.as_mut()).into())
            .take(RETRY)
            .find_map(Result::<_, _>::ok)
            .ok_or_else(|| Error::from(ErrorKind::RxFail))?;

        match buffer.as_ref() {
            WAKE_RESPONSE_EXPECTED => Ok(()),
            WAKE_SELFTEST_FAILED => Err(ErrorKind::WakeFailed.into()),
            _ => Err(ErrorKind::WakeFailed.into()),
        }
    }

    fn idle(&mut self) -> Result<(), Error> {
        let word_address = Transaction::Idle as u8;
        self.phy
            .write(ADDRESS, from_ref(&word_address))
            .map_err(|_| ErrorKind::TxFail.into())
    }

    pub(crate) fn sleep(&mut self) -> Result<(), Error> {
        let word_address = Transaction::Sleep as u8;
        self.phy
            .write(ADDRESS, from_ref(&word_address))
            .map_err(|_| ErrorKind::TxFail.into())
    }
}
