extern crate cryptoauthlib_sys;
use core::mem::size_of;
use core::slice::from_raw_parts_mut;
use cryptoauthlib_sys::{
    calib_aes, calib_aes_encrypt, ATCADevice, ATCAPacket, ATCA_STATUS, ATCA_STATUS_ATCA_COMM_FAIL,
};

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

fn main() {
    println!("Start testing command.");

    // AES Command
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let aes_in = &[0x01u8; 0x0a];
    let aes_out = &mut [0x00u8];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_aes(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            key_id,
            aes_in.as_ptr(),
            aes_out.as_mut_ptr(),
        )
    });
    println!("{:02x?}", captured_packet);

    // Encrypt
    let key_id = 0x0au16;
    let key_block = 0x0bu8;
    let plaintext = &[0x00u8; 0x0a];
    let ciphertext = &mut [0x00u8];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_aes_encrypt(
            captured_packet.as_mut_ptr() as *mut _,
            key_id,
            key_block,
            plaintext.as_ptr(),
            ciphertext.as_mut_ptr(),
        )
    });
    println!("{:02x?}", captured_packet);

    println!("Command test finished.");
}
