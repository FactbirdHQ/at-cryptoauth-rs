use super::calib::command::Packet;

type I2c<T> = Option<T>;
struct I2cConfig {
    address: u8, // 0xC0
    delay: u16,  // Herz,
    retry: usize,
}

pub struct CryptoAuthClient<T> {
    i2c: I2c<T>,
    config: I2cConfig,
}

/// /// Wakes up device, sends the packet, waits for command completion,
/// /// receives response, and puts the device into the idle state.
/// fn execute(&mut self, packet: &mut Packet) -> Result<&[u8], ()> {
///     let _ = packet.ser(&mut self.buffer)?;
///     self.i2c.send()?;
///     self.i2c.receive()?;
///     self.i2c.idle()?;
///     Err(())
/// }
///
/// fn sha<'a>(&mut self, bytes: &'a [u8]) -> Result<Sha, Error> {
///    let packet = Sha::packet(bytes)?;
///    let buf = self.execute(&packet)?;
///    Sha::parse(buf)?;
/// }
impl<T> CryptoAuthClient<T> {
    fn new(i2c: I2c<T>) -> Self {
        Self {
            i2c,
            config: I2cConfig {
                address: 0xC0,
                delay: 1500,
                retry: 20,
            },
        }
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

struct Config;
impl Config {
    fn read_block(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn write_block(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
struct Otp;
impl Otp {
    fn read_block(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn write_block(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
struct Data;
impl Data {
    fn read_block(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn write_block(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
