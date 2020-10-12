use heapless::consts::U192;
use heapless::Vec;

const WAKE_RESPONSE_EXPECTED: &[u8] = &[0x04, 0x11, 0x33, 0x43];
const WAKE_SELFTEST_FAILED: &[u8] = &[0x04, 0x07, 0xC4, 0x40];
const CMD_SIZE_MAX: usize = 4 * 36 + 7;
const RSP_SIZE_MAX: usize = 75;

pub struct I2c<T> {
    phy: T,
    buffer: Vec<u8, U192>,
}
