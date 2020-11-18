// $ CROSS_COMPILE=arm-none-linux-gnueabihf- cargo b \
//   --example tngtls --target armv7-unknown-linux-gnueabihf \
//   --features std
use cryptoauthlib_sys::hal::I2c as HalI2c;
use cryptoauthlib_sys::{
    atca_command, atca_device, atca_iface, calib_info, calib_read_serial_number,
    cfg_ateccx08a_i2c_default, initATCADevice, init_delay_wrapper, ATCA_STATUS_ATCA_SUCCESS,
};
use linux_embedded_hal::Delay;
use linux_embedded_hal::I2cdev;
use log::info;
use std::error::Error;

const I2C_PATH: &str = "/dev/i2c-1";
const ATECC608_ADDR: u16 = 0xc0 >> 1;
const PROVISION_KEYS: &[u8] = &[0x00u8, 0x01u8];
const TEST_PRIVATE_KEY: [u8; 32] = [
    /* 0x00, 0x00, 0x00, 0x00, */
    0x87, 0x8F, 0x0A, 0xB6, 0xA5, 0x26, 0xD7, 0x11, 0x1C, 0x26, 0xE6, 0x17, 0x08, 0x10, 0x79, 0x6E,
    0x7B, 0x33, 0x00, 0x7F, 0x83, 0x2B, 0x8D, 0x64, 0x46, 0x7E, 0xD6, 0xF8, 0x70, 0x53, 0x7A, 0x19,
];
const TEST_PUBLIC_KEY: [u8; 64] = [
    0x8F, 0x8D, 0x18, 0x2B, 0xD8, 0x19, 0x04, 0x85, 0x82, 0xA9, 0x92, 0x7E, 0xA0, 0xC5, 0x6D, 0xEF,
    0xB4, 0x15, 0x95, 0x48, 0xE1, 0x1C, 0xA5, 0xF7, 0xAB, 0xAC, 0x45, 0xBB, 0xCE, 0x76, 0x81, 0x5B,
    0xE5, 0xC6, 0x4F, 0xCD, 0x2F, 0xD1, 0x26, 0x98, 0x54, 0x4D, 0xE0, 0x37, 0x95, 0x17, 0x26, 0x66,
    0x60, 0x73, 0x04, 0x61, 0x19, 0xAD, 0x5E, 0x11, 0xA9, 0x0A, 0xA4, 0x97, 0x73, 0xAE, 0xAC, 0x86,
];

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut i2c = I2cdev::new(I2C_PATH)?;
    i2c.set_slave_address(ATECC608_ADDR)?;
    let mut delay = Delay;
    init_delay_wrapper(&mut delay);
    info!("Start testing ATECC608A.");

    // Boilerplate
    let mut cfg = unsafe { cfg_ateccx08a_i2c_default.clone() };
    let mut dev = atca_device::default();
    let mut iface = atca_iface::default();
    let mut command = atca_command::default();
    dev.mCommands = &mut command as *mut _;
    dev.mIface = &mut iface as *mut _;

    // Instantiate and initialize I2C HAL implementation
    let mut hal = HalI2c::new(i2c);
    assert_eq!(ATCA_STATUS_ATCA_SUCCESS, hal.register());
    assert_eq!(ATCA_STATUS_ATCA_SUCCESS, unsafe {
        initATCADevice(&mut cfg, &mut dev)
    });

    // Info
    let revision_buf = &mut [0u8, 0, 0, 0];
    assert_eq!(ATCA_STATUS_ATCA_SUCCESS, unsafe {
        calib_info(&mut dev, revision_buf.as_mut_ptr())
    });
    assert_eq!(revision_buf, &[0x00, 0x00, 0x60, 0x02]);

    // Serial
    let sn_buf = &mut [0u8, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(ATCA_STATUS_ATCA_SUCCESS, unsafe {
        calib_read_serial_number(&mut dev, sn_buf.as_mut_ptr())
    });
    assert_eq!(sn_buf[0..2], [0x01, 0x23]);
    assert_eq!(sn_buf[8], 0xee);

    info!("ATECC608A test finished.");
    Ok(())
}
