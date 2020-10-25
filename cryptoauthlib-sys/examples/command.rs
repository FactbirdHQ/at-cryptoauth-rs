extern crate cryptoauthlib_sys;
use core::mem::size_of;
use core::slice::from_raw_parts_mut;
use crc::{Algorithm, Crc};
use cryptoauthlib_sys::{
    calib_aes, calib_aes_encrypt, calib_checkmac, ATCADevice, ATCAPacket, ATCA_STATUS,
    ATCA_STATUS_ATCA_COMM_FAIL,
};

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

// A single key ID throughout the tests.
const KEY_ID: u16 = 0x0a;

fn main() {
    println!("Start testing command.");
    aes();
    checkmac();
    println!("Command test finished.");
}

// AES command
fn aes() {
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let aes_in = &[0x01u8; 0x0a];
    let aes_out = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_aes(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            key_id,
            aes_in.as_ptr(),
            aes_out,
        )
    });
    check_crc(captured_packet);

    // Encrypt
    let key_id = 0x0au16;
    let key_block = 0x0bu8;
    let plaintext = &[0x00u8; 0x0a];
    let ciphertext = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_aes_encrypt(
            captured_packet.as_mut_ptr() as *mut _,
            key_id,
            key_block,
            plaintext.as_ptr(),
            ciphertext,
        )
    });
    check_crc(captured_packet);
}

//CheckMAC command
fn checkmac() {
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let challenge = &[0x00u8; 0x0a];
    let response = &[0x00u8; 0x0a];
    let other_data = &[0x00u8; 0x0a];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_checkmac(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            key_id,
            challenge.as_ptr(),
            response.as_ptr(),
            other_data.as_ptr(),
        )
    });
    check_crc(captured_packet);
}

// Mock up command execution.
#[no_mangle]
pub extern "C" fn calib_execute_command(
    packet: *const ATCAPacket,
    captured: ATCADevice,
) -> ATCA_STATUS {
    let packet_buffer = unsafe { from_raw_parts_mut(packet as *mut u8, size_of::<ATCAPacket>()) };
    let captured_buffer =
        unsafe { from_raw_parts_mut(captured as *mut u8, size_of::<ATCAPacket>()) };
    captured_buffer.copy_from_slice(packet_buffer);
    ATCA_STATUS_ATCA_COMM_FAIL
}

fn check_crc(captured: &[u8]) {
    let length = captured[1] as usize;
    let (payload, crc) = captured[1..length + 1].split_at(length - 2);
    println!("{:02x?}", payload);
    assert_eq!(crc, CRC16.checksum(payload).to_le_bytes());
}
