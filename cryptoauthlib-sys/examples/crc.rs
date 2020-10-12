#![no_main]
#![no_std]
extern crate cryptoauthlib_sys;
extern crate panic_semihosting;

use core::fmt::Write;
use cortex_m_rt::entry;
use cortex_m_rt::exception;
use cortex_m_rt::ExceptionFrame;
use cortex_m_semihosting::hio;
use crc::{Algorithm, Crc};
use cryptoauthlib_sys::atCRC;

// use custom algorithm
const CUSTOM_ALG: Algorithm<u16> = Algorithm {
    poly: 0x8005,
    init: 0x0000,
    refin: true,
    refout: false,
    xorout: 0x0000,
    check: 0xbcdd,
    residue: 0x0000,
};

#[entry]
fn main() -> ! {
    // Semihosting. Messages will appear in openocd's log output.
    let mut hstdout = hio::hstdout().unwrap();

    writeln!(hstdout, "Start testing CRC.").unwrap();
    let crc16 = Crc::<u16>::new(&CUSTOM_ALG);
    let mut init = b"123456789".clone();
    let mut init_a = b"123456789aaf946042".clone();
    let mut init_b = b"edcb8434325a439fbd".clone();
    let mut init_c = b"2468ace03238f64e".clone();
    let sample_1 = &mut [0x31];
    let sample_2 = &mut [0x32];
    let sample_3 = &mut [0x31, 0x32];
    let sample_4 = &mut init;
    let sample_5 = &mut init_a;
    let sample_6 = &mut init_b;
    let sample_7 = &mut init_c;
    let samples = &mut [
        sample_1.as_mut(),
        sample_2.as_mut(),
        sample_3.as_mut(),
        sample_4.as_mut(),
        sample_5.as_mut(),
        sample_6.as_mut(),
        sample_7.as_mut(),
    ];

    for sample in samples {
        let check_bytes = &mut [0u8, 0];
        unsafe {
            atCRC(
                sample.len() as u32,
                sample.as_mut_ptr(),
                check_bytes.as_mut_ptr(),
            );
        }
        assert_eq!(u16::from_le_bytes(*check_bytes), crc16.checksum(sample));
        writeln!(hstdout, "CRC: {:02x}", crc16.checksum(sample)).unwrap();
    }
    writeln!(hstdout, "CRC test finished.").unwrap();
    loop {}
}

#[exception]
fn HardFault(ef: &ExceptionFrame) -> ! {
    panic!("{:#?}", ef);
}
