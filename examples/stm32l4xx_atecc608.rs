//! Microchip ATECC608 CryptoAuthLib Integration
//! --------------------------------------------
//!
//! An example that interacts with the crypto authentication secure elements
//! ATECC608 via the STM32L4x5 chip.
//!
//! As defined in `stm32l4xx-hal/.cargo/config`, `cargo run ..` starts semihosting
//! with OpenOCD and GDB. To run this example, provide `openocd.gdb` and
//! `openocd.cfg` files in the same directory as `Cargo.toml`.
//!
//! ``` bash
//! openocd openocd.cfg &
//! cargo run --example stm32l4xx_atecc608 \
//!     --target thumbv7em-none-eabihf \
//! ```
//!
//! ```
//! # openocd.gdb
//! target extended-remote localhost:3333
//! monitor arm semihosting enable
//! load
//! ```
//!
//! ```
//! # openocd.cfg
//! source [find interface/stlink-v2.cfg]
//! source [find target/stm32l4x.cfg]
//! ```
#![no_main]
#![no_std]

extern crate panic_semihosting;
use at_cryptoauth::AtCaClient;
use core::fmt::Write;
use cortex_m_rt::entry;
use cortex_m_rt::exception;
use cortex_m_rt::ExceptionFrame;
use cortex_m_semihosting::hio;
use hal::delay::Delay;
use hal::flash::FlashVariant;
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
    let mut flash = dp.FLASH.constrain(FlashVariant::Size1024KB);
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

    // Construct I2C
    let i2c = I2c::i2c2(dp.I2C2, (scl, sda), 100.khz(), clocks, &mut rcc.apb1r1);

    // Create delay object
    let delay = Delay::new(cp.SYST, clocks);

    writeln!(hstdout, "Start testing ATECC608A.").unwrap();

    let mut client = AtCaClient::new(i2c, delay);

    let info = client.info().unwrap();
    assert_eq!(info.as_ref(), [0x00, 0x00, 0x60, 0x02]);

    // Serial number bytes. Bytes positioned at 0..2 and 8 are fixed. Bytes at
    // 2..8 are unique to indiviual modules.
    //
    // Example: [01, 23, 14, 16, 39, cd, d1, c1, ee]
    let sn = client.memory().serial_number().unwrap();
    assert_eq!(sn.as_ref()[..2], [0x01, 0x23]);
    assert_eq!(sn.as_ref()[8], 0xee);

    let digest = client
        .sha()
        .digest(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        .unwrap();
    assert_eq!(
        digest.as_ref(),
        [
            0x17, 0xe8, 0x8d, 0xb1, 0x87, 0xaf, 0xd6, 0x2c, 0x16, 0xe5, 0xde, 0xbf, 0x3e, 0x65,
            0x27, 0xcd, 0x00, 0x6b, 0xc0, 0x12, 0xbc, 0x90, 0xb5, 0x1a, 0x81, 0x0c, 0xd8, 0x0c,
            0x2d, 0x51, 0x1f, 0x43
        ]
    );

    writeln!(hstdout, "ATECC608A test finished.").unwrap();
    loop {}
}

#[exception]
fn HardFault(ef: &ExceptionFrame) -> ! {
    panic!("{:#?}", ef);
}
