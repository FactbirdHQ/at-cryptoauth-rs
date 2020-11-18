#![no_main]
#![no_std]
extern crate cryptoauthlib_sys;
extern crate panic_semihosting;

use core::fmt::Write;
use cortex_m_rt::entry;
use cortex_m_rt::exception;
use cortex_m_rt::ExceptionFrame;
use cortex_m_semihosting::hio;
use cryptoauthlib_sys::hal::I2c as HalI2c;
use cryptoauthlib_sys::{
    atca_command, atca_device, atca_iface, calib_genkey, calib_get_pubkey, calib_info,
    calib_is_slot_locked, calib_lock_config_zone, calib_lock_data_slot, calib_lock_data_zone,
    calib_read_serial_number, calib_sha, cfg_ateccx08a_i2c_default, initATCADevice,
    init_delay_wrapper, ATCA_STATUS_ATCA_SUCCESS,
};
use hal::delay::Delay;
use hal::i2c::I2c;
use hal::prelude::*;
use hal::rcc::{MsiFreq, PllConfig, PllDivider, PllSource};
use stm32l4xx_hal as hal;

#[entry]
fn main() -> ! {
    // Semihosting. Messages will appear in openocd's log output.
    let mut hstdout = hio::hstdout().unwrap();

    // Declare peripherals
    let cp = cortex_m::Peripherals::take().unwrap();
    let dp = hal::stm32::Peripherals::take().unwrap();

    // Set up the system clock.
    let mut flash = dp.FLASH.constrain();
    let mut rcc = dp.RCC.constrain();
    let mut pwr = dp.PWR.constrain(&mut rcc.apb1r1);

    let clocks = rcc
        .cfgr
        // System Clock source = PLL (MSI)
        .pll_source(PllSource::MSI)
        // MSI Frequency(Hz) = 4000000
        .msi(MsiFreq::RANGE4M)
        // SYSCLK(Hz) = 80,000,000, PLL_M = 1, PLL_N = 40, PLL_R = 2
        .sysclk_with_pll(80.mhz(), PllConfig::new(1, 40, PllDivider::Div2))
        .freeze(&mut flash.acr, &mut pwr);

    // Set up SCL & SDA
    let mut gpiob = dp.GPIOB.split(&mut rcc.ahb2);

    let scl = gpiob
        .pb10
        .into_open_drain_output(&mut gpiob.moder, &mut gpiob.otyper);
    let scl = scl.into_af4(&mut gpiob.moder, &mut gpiob.afrh);

    let sda = gpiob
        .pb11
        .into_open_drain_output(&mut gpiob.moder, &mut gpiob.otyper);
    let sda = sda.into_af4(&mut gpiob.moder, &mut gpiob.afrh);

    // Construct delay object
    let mut delay = Delay::new(cp.SYST, clocks);
    init_delay_wrapper(&mut delay);

    // Construct I2C
    let i2c = I2c::i2c2(dp.I2C2, (scl, sda), 100.khz(), clocks, &mut rcc.apb1r1);

    writeln!(hstdout, "Start testing ATECC608A.").unwrap();

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

    // SHA
    let sha_len = 10;
    let sha_buf = &mut [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let sha_digest = &mut [0u8; 32];
    assert_eq!(ATCA_STATUS_ATCA_SUCCESS, unsafe {
        calib_sha(
            &mut dev,
            sha_len,
            sha_buf.as_mut_ptr(),
            sha_digest.as_mut_ptr(),
        )
    });
    assert_eq!(
        sha_digest,
        &[
            0x1f, 0x82, 0x5a, 0xa2, 0xf0, 0x02, 0x0e, 0xf7, 0xcf, 0x91, 0xdf, 0xa3, 0x0d, 0xa4,
            0x66, 0x8d, 0x79, 0x1c, 0x5d, 0x48, 0x24, 0xfc, 0x8e, 0x41, 0x35, 0x4b, 0x89, 0xec,
            0x05, 0x79, 0x5a, 0xb3
        ]
    );

    writeln!(hstdout, "ATECC608A test finished.").unwrap();
    loop {}
}

#[exception]
fn HardFault(ef: &ExceptionFrame) -> ! {
    panic!("{:#?}", ef);
}
