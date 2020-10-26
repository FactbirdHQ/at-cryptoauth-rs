//! Exhibit CRC calculation. Examples below runs on host machine.
//! `$ cargo run --example crc`
extern crate cryptoauthlib_sys;

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

const CRC16: Crc<u16> = Crc::<u16>::new(&CUSTOM_ALG);

fn main() {
    println!("Start testing CRC.");
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
                sample.len() as u64,
                sample.as_mut_ptr(),
                check_bytes.as_mut_ptr(),
            );
        }
        assert_eq!(u16::from_le_bytes(*check_bytes), CRC16.checksum(sample));
        println!("CRC: {:02x}", CRC16.checksum(sample));
    }
    println!("CRC test finished.");
}
