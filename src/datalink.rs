use embedded_hal::delay::DelayNs;

// for this implementation of I2C with CryptoAuth chips, txdata is assumed to
// have ATCAPacket format Devices such as ATECCx08A require a word address value
// pre-pended to the packet txdata[0] is using _reserved byte of the ATCAPacket
use super::error::{Error, ErrorKind};
use super::packet::{Packet, Response};
use core::fmt::Debug;
use core::slice::from_ref;
const WAKE_RESPONSE_EXPECTED: &[u8] = &[0x04, 0x11, 0x33, 0x43];
const WAKE_SELFTEST_FAILED: &[u8] = &[0x04, 0x07, 0xC4, 0x40];

/// Default I2C address of ATECC608
const ADDRESS: u8 = 0xc0 >> 1;
/// Default time in us that takes for ATECC608 device to wake up.
const DELAY_US: u32 = 1500;

// By default, wake up sequence is repeated up to 20 times until it succeeds.
// Multiply by 2, otherwise you see RxFail on wake up. It happens when you try
// to write a word to the config zone on Raspberry Pi's I2C. This behavior might
// be specific to linux HAL. What's worse, GenKey command from Raspberry Pi
// needs to retry 20 * 15 times until it succeeds.
#[cfg(target_os = "none")]
const RETRY: usize = 20;
#[cfg(not(target_os = "none"))]
const RETRY: usize = 20 * 15;

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

pub(crate) struct I2c<PHY> {
    phy: PHY,
}

impl<PHY> I2c<PHY> {
    pub(crate) fn new(phy: PHY) -> Self {
        Self { phy }
    }
}

impl<PHY> I2c<PHY>
where
    PHY: embedded_hal_async::i2c::I2c,
{
    /// Wakes up device, sends the packet, waits for command completion,
    /// receives response, and puts the device into the idle state.
    pub(crate) async fn execute<'a>(
        &mut self,
        buffer: &'a mut [u8],
        packet: Packet,
        exec_time: Option<u32>,
    ) -> Result<Response<'a>, Error> {
        self.wake().await?;
        self.send(&packet.buffer(buffer)).await?;
        // Wait for the device to finish its job.
        embassy_time::Timer::after(embassy_time::Duration::from_micros(
            (exec_time.unwrap_or(1) * 1000) as u64,
        ))
        .await;
        let response_buffer = self.receive(buffer).await?;
        self.idle().await?;
        Response::new(response_buffer)
    }

    async fn send<T>(&mut self, bytes: &T) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        self.phy
            .write(ADDRESS, bytes.as_ref())
            .await
            .map_err(|_| ErrorKind::TxFail.into())
    }

    /// Returns response buffer for later processing.
    async fn receive<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        // Reset indicates the beginning of transaction.
        let word_address = Transaction::Reset as u8;

        let mut count = 0;
        loop {
            let result = self.phy.write(ADDRESS, from_ref(&word_address)).await;

            if result.is_ok() {
                break;
            } else {
                if count > RETRY {
                    return Err(Error::from(ErrorKind::TxFail));
                }
                count += 1;
            }
        }

        let min_resp_size = 4;
        self.phy
            .read(ADDRESS, &mut buffer[0..2])
            .await
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
            .await
            .map(move |()| buffer[..length_to_read].as_mut())
            .map_err(|_| ErrorKind::RxFail.into())
    }

    async fn wake(&mut self) -> Result<(), Error> {
        // Send a single null byte to an absent address.
        //
        // Ignore errors as this will error if the device is not awake yet.
        self.phy.write(ADDRESS, from_ref(&0x00)).await.ok();

        // Wait for the device to wake up.
        embassy_time::Timer::after(embassy_time::Duration::from_micros(DELAY_US as u64)).await;

        let buffer = &mut [0x00, 0x00, 0x00, 0x00];

        let mut count = 0;
        loop {
            let result = self.phy.read(ADDRESS, buffer.as_mut()).await;

            if result.is_ok() {
                break;
            } else {
                if count > RETRY {
                    return Err(Error::from(ErrorKind::RxFail));
                }
                count += 1;
            }
        }

        match buffer.as_ref() {
            WAKE_RESPONSE_EXPECTED => Ok(()),
            WAKE_SELFTEST_FAILED => Err(ErrorKind::WakeFailed.into()),
            _ => Err(ErrorKind::WakeFailed.into()),
        }
    }

    async fn idle(&mut self) -> Result<(), Error> {
        let word_address = Transaction::Idle as u8;
        self.phy
            .write(ADDRESS, from_ref(&word_address))
            .await
            .map_err(|_| ErrorKind::TxFail.into())
    }

    pub(crate) async fn sleep(&mut self) -> Result<(), Error> {
        let word_address = Transaction::Sleep as u8;
        // Wait for the I2C bus to be ready.
        embassy_time::Timer::after(embassy_time::Duration::from_micros(30)).await;
        self.phy
            .write(ADDRESS, from_ref(&word_address))
            .await
            .map_err(|_| ErrorKind::TxFail.into())
    }
}

impl<PHY> I2c<PHY>
where
    PHY: embedded_hal::i2c::I2c,
{
    /// Wakes up device, sends the packet, waits for command completion,
    /// receives response, and puts the device into the idle state.
    pub(crate) fn execute_blocking<'a>(
        &mut self,
        buffer: &'a mut [u8],
        packet: Packet,
        exec_time: Option<u32>,
    ) -> Result<Response<'a>, Error> {
        self.wake_blocking()?;
        self.send_blocking(&packet.buffer(buffer))?;
        // Wait for the device to finish its job.
        embassy_time::Delay.delay_us(exec_time.unwrap_or(1) * 1000);
        let response_buffer = self.receive_blocking(buffer)?;
        self.idle_blocking()?;
        Response::new(response_buffer)
    }

    fn send_blocking<T>(&mut self, bytes: &T) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        self.phy
            .write(ADDRESS, bytes.as_ref())
            .map_err(|_| ErrorKind::TxFail.into())
    }

    /// Returns response buffer for later processing.
    fn receive_blocking<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        // Reset indicates the beginning of transaction.
        let word_address = Transaction::Reset as u8;

        let mut count = 0;
        loop {
            let result = self.phy.write(ADDRESS, from_ref(&word_address));

            if result.is_ok() {
                break;
            } else {
                if count > RETRY {
                    return Err(Error::from(ErrorKind::TxFail));
                }
                count += 1;
            }
        }

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

    fn wake_blocking(&mut self) -> Result<(), Error> {
        // Send a single null byte to an absent address.
        //
        // Ignore errors as this will error if the device is not awake yet.
        self.phy.write(ADDRESS, from_ref(&0x00)).ok();

        // Wait for the device to wake up.
        embassy_time::Delay.delay_us(DELAY_US);

        let buffer = &mut [0x00, 0x00, 0x00, 0x00];

        let mut count = 0;
        loop {
            let result = self.phy.read(ADDRESS, buffer.as_mut());

            if result.is_ok() {
                break;
            } else {
                if count > RETRY {
                    return Err(Error::from(ErrorKind::RxFail));
                }
                count += 1;
            }
        }

        match buffer.as_ref() {
            WAKE_RESPONSE_EXPECTED => Ok(()),
            WAKE_SELFTEST_FAILED => Err(ErrorKind::WakeFailed.into()),
            _ => Err(ErrorKind::WakeFailed.into()),
        }
    }

    fn idle_blocking(&mut self) -> Result<(), Error> {
        let word_address = Transaction::Idle as u8;
        self.phy
            .write(ADDRESS, from_ref(&word_address))
            .map_err(|_| ErrorKind::TxFail.into())
    }

    pub(crate) fn sleep_blocking(&mut self) -> Result<(), Error> {
        let word_address = Transaction::Sleep as u8;
        // Wait for the I2C bus to be ready.
        embassy_time::Delay.delay_us(30);

        self.phy
            .write(ADDRESS, from_ref(&word_address))
            .map_err(|_| ErrorKind::TxFail.into())
    }
}
