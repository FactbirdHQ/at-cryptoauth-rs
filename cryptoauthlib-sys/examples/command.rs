extern crate cryptoauthlib_sys;
use core::mem::size_of;
use core::slice::from_raw_parts_mut;
use crc::{Algorithm, Crc};
use cryptoauthlib_sys::{
    calib_aes, calib_aes_decrypt, calib_aes_encrypt, calib_checkmac, calib_counter,
    calib_counter_increment, calib_counter_read, calib_derivekey, calib_ecdh, calib_ecdh_base,
    calib_ecdh_enc, calib_ecdh_tempkey, calib_read_enc, ATCADevice, ATCAPacket, ATCA_STATUS, ATCA_STATUS_ATCA_COMM_FAIL,
};

// Use custom algorithm
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
    println!("Start testing command.");
    aes();
    checkmac();
    counter();
    derivekey();
    ecdh();
    read();
    println!("Command test finished.");
}

// AES command
fn aes() {
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let aes_in = &[0xaau8; 0xff];
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
    assert_eq!(captured_packet[0x01], 0x17);
    assert_eq!(captured_packet[0x02], 0x51);
    assert_eq!(captured_packet[0x03], mode);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
    assert_eq!(captured_packet[0x06..0x16], aes_in[0x00..0x10]);

    // Encrypt
    let key_block = 0x0bu8;
    let plaintext = &[0xaau8; 0xff];
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
    assert_eq!(captured_packet[0x01], 0x17);
    assert_eq!(captured_packet[0x02], 0x51);
    assert_eq!(captured_packet[0x03], 0xc0);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
    assert_eq!(captured_packet[0x06..0x16], plaintext[0x00..0x010]);

    // Decrypt
    let ciphertext = &[0xaau8; 0xff];
    let plaintext = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_aes_decrypt(
            captured_packet.as_mut_ptr() as *mut _,
            key_id,
            key_block,
            ciphertext.as_ptr(),
            plaintext,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x17);
    assert_eq!(captured_packet[0x02], 0x51);
    assert_eq!(captured_packet[0x03], 0xc1);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
    assert_eq!(captured_packet[0x06..0x16], ciphertext[0x00..0x010]);
}

// CheckMAC command
fn checkmac() {
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let challenge = &[0xaau8; 0xff];
    let response = &[0xbbu8; 0xff];
    let other_data = &[0xccu8; 0xff];
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
    assert_eq!(captured_packet[0x01], 0x54);
    assert_eq!(captured_packet[0x02], 0x28);
    assert_eq!(captured_packet[0x03], 0xc0);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
    assert_eq!(captured_packet[0x06..0x26], challenge[0x00..0x20]);
    assert_eq!(captured_packet[0x26..0x46], response[0x00..0x20]);
    assert_eq!(captured_packet[0x46..0x53], other_data[0x00..0x0d]);
}

// Counter command
fn counter() {
    let mode = 0xc0u8;
    let counter_id = 0x01u16;
    let counter_value = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_counter(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            counter_id,
            counter_value,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x24);
    assert_eq!(captured_packet[0x03], 0xc0);
    assert_eq!(captured_packet[0x04..0x06], counter_id.to_le_bytes());

    // Increment
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_counter_increment(
            captured_packet.as_mut_ptr() as *mut _,
            counter_id,
            counter_value,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x24);
    assert_eq!(captured_packet[0x03], 0x01);
    assert_eq!(captured_packet[0x04..0x06], counter_id.to_le_bytes());

    // Read
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_counter_read(
            captured_packet.as_mut_ptr() as *mut _,
            counter_id,
            counter_value,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x24);
    assert_eq!(captured_packet[0x03], 0x00);
    assert_eq!(captured_packet[0x04..0x06], counter_id.to_le_bytes());
}

// DeriveKey command
fn derivekey() {
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let mac = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_derivekey(captured_packet.as_mut_ptr() as *mut _, mode, key_id, mac)
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x1c);
    assert_eq!(captured_packet[0x03], 0xc0);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
}

// ECDH command functions
fn ecdh() {
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let public_key = &[0xaau8; 0xff];
    let pms = core::ptr::null_mut();
    let out_nonce = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_ecdh_base(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            key_id,
            public_key.as_ptr(),
            pms,
            out_nonce,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x47);
    assert_eq!(captured_packet[0x02], 0x43);
    assert_eq!(captured_packet[0x03], 0xc0);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
    assert_eq!(captured_packet[0x06..0x46], public_key[0x00..0x40]);

    // Compute ECDH premaster secret
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_ecdh(
            captured_packet.as_mut_ptr() as *mut _,
            key_id,
            public_key.as_ptr(),
            pms,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x47);
    assert_eq!(captured_packet[0x02], 0x43);
    assert_eq!(captured_packet[0x03], 0x00);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
    assert_eq!(captured_packet[0x06..0x46], public_key[0x00..0x40]);

    // Read ECDH
    // It is a combination of `calib_ecdh` and `calib_read_enc`.
    let pms = &mut [0x00];
    let read_key = &mut [0x00];
    let read_key_id = 0x0bu16;
    let num_in = &[0xbbu8; 0xff];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_ecdh_enc(
            captured_packet.as_mut_ptr() as *mut _,
            key_id,
            public_key.as_ptr(),
            pms.as_mut_ptr(),
            read_key.as_mut_ptr(),
            read_key_id,
            num_in.as_ptr(),
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x47);
    assert_eq!(captured_packet[0x02], 0x43);
    assert_eq!(captured_packet[0x03], 0x00);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
    assert_eq!(captured_packet[0x06..0x46], public_key[0x00..0x40]);
}

// Read command
fn read() {
    // Body of read ECDH command.
    // Combination of `calib_read_zone` and `calib_gendig`.
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let pms = &mut [0x00];
    let read_key = &mut [0x00];
    let read_key_id = 0x0bu16;
    let num_in = &[0xbbu8; 0xff];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_read_enc(
            captured_packet.as_mut_ptr() as *mut _,
            key_id,
            0,
            pms.as_mut_ptr(),
            read_key.as_mut_ptr(),
            read_key_id,
            num_in.as_ptr(),
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x02);
    assert_eq!(captured_packet[0x03], 0x80);
    assert_eq!(captured_packet[0x04..0x06], [0x00, 0x00]);
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
