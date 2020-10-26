//! Exhibit command examples. Examples below runs on host machine.
//! `$ cargo run --example command`
extern crate cryptoauthlib_sys;
use core::mem::size_of;
use core::slice::from_raw_parts_mut;
use crc::{Algorithm, Crc};
use cryptoauthlib_sys::{
    calib_aes, calib_aes_decrypt, calib_aes_encrypt, calib_challenge, calib_checkmac,
    calib_counter, calib_counter_increment, calib_counter_read, calib_derivekey, calib_ecdh,
    calib_ecdh_base, calib_ecdh_enc, calib_ecdh_tempkey, calib_gendig, calib_genkey_base,
    calib_hmac, calib_info, calib_is_locked, calib_is_slot_locked, calib_lock_config_zone,
    calib_lock_data_slot, calib_lock_data_zone, calib_nonce, calib_nonce_load, calib_read_enc,
    calib_sha_end, calib_sha_start, calib_sha_update, calib_sign_base, calib_verify, ATCADevice,
    ATCAPacket, ATCA_STATUS, ATCA_STATUS_ATCA_COMM_FAIL,
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
    gendig();
    genkey();
    hmac();
    info();
    lock();
    nonce();
    read();
    sha();
    sign();
    verify();
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

    // Tempkey
    let pms = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_ecdh_tempkey(
            captured_packet.as_mut_ptr() as *mut _,
            public_key.as_ptr(),
            pms,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x47);
    assert_eq!(captured_packet[0x02], 0x43);
    assert_eq!(captured_packet[0x03], 0x0d);
    assert_eq!(captured_packet[0x04..0x06], [0x00, 0x00]);
    assert_eq!(captured_packet[0x06..0x46], public_key[0x00..0x40]);
}

// GenDig command
fn gendig() {
    let zone = 0x08;
    let key_id = 0x0au16;
    let other_data = &[0xaau8; 0xff];
    let other_data_size = 0x04u8;
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_gendig(
            captured_packet.as_mut_ptr() as *mut _,
            zone,
            key_id,
            other_data.as_ptr(),
            other_data_size,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x15);
    assert_eq!(captured_packet[0x03], zone);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
}

// GenKey command
fn genkey() {
    let mode = 0x08;
    let key_id = 0x0au16;
    let other_data = &[0xaau8; 0xff];
    let public_key = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_genkey_base(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            key_id,
            other_data.as_ptr(),
            public_key,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x40);
    assert_eq!(captured_packet[0x03], mode);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
}

// HMAC command
fn hmac() {
    let mode = 0x08;
    let key_id = 0x0au16;
    let digest = &mut [0x00u8];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_hmac(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            key_id,
            digest.as_mut_ptr(),
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x11);
    assert_eq!(captured_packet[0x03], mode);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
}

// Info command
fn info() {
    let revision = &mut [0x00u8];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_info(
            captured_packet.as_mut_ptr() as *mut _,
            revision.as_mut_ptr(),
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x30);
    assert_eq!(captured_packet[0x03], 0x00);
    assert_eq!(captured_packet[0x04..0x06], [0x00, 0x00]);
}

// Lock command
fn lock() {
    // Config zone
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_lock_config_zone(captured_packet.as_mut_ptr() as *mut _)
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x17);
    assert_eq!(captured_packet[0x03], 0x80);

    // Data zone
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_lock_data_zone(captured_packet.as_mut_ptr() as *mut _)
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x17);
    assert_eq!(captured_packet[0x03], 0x81);

    // Data slot
    let slot = 0x09u16;
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_lock_data_slot(captured_packet.as_mut_ptr() as *mut _, slot)
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x17);
    assert_eq!(captured_packet[0x03], (slot as u8) << 2 | 0x02);
}

// Nonce command
fn nonce() {
    let num_in = &[0xaau8; 0xff];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_nonce(captured_packet.as_mut_ptr() as *mut _, num_in.as_ptr())
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x27);
    assert_eq!(captured_packet[0x02], 0x16);
    assert_eq!(captured_packet[0x03], 0x03);
    assert_eq!(captured_packet[0x04..0x06], [0x00, 0x00]);
    assert_eq!(captured_packet[0x06..0x26], num_in[0x00..0x20]);

    // Challenge
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_challenge(captured_packet.as_mut_ptr() as *mut _, num_in.as_ptr())
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x27);
    assert_eq!(captured_packet[0x02], 0x16);
    assert_eq!(captured_packet[0x03], 0x03);
    assert_eq!(captured_packet[0x04..0x06], [0x00, 0x00]);
    assert_eq!(captured_packet[0x06..0x26], num_in[0x00..0x20]);

    // Load nonce
    let nonce_target = 0x0au8;
    let msg = &[0xaau8; 0xff];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_nonce_load(
            captured_packet.as_mut_ptr() as *mut _,
            nonce_target,
            msg.as_ptr(),
            32,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x27);
    assert_eq!(captured_packet[0x02], 0x16);
    assert_eq!(captured_packet[0x03], 0x03);
    assert_eq!(captured_packet[0x04..0x06], [0x00, 0x00]);
    assert_eq!(captured_packet[0x06..0x26], msg[0x00..0x20]);
}

// Read command
fn read() {
    // Body of read ECDH command.
    // Combination of `calib_read_zone` and `calib_gendig`.
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

    // Is slot locked?
    let slot = 0x08u16;
    let is_locked = &mut true;
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_is_slot_locked(
            captured_packet.as_mut_ptr() as *mut _,
            slot,
            is_locked as *mut _,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x02);
    assert_eq!(captured_packet[0x03], 0x00);
    assert_eq!(captured_packet[0x04..0x06], [0x16, 0x00]);

    // Is locked?
    let zone = 0x08u8;
    let is_locked = &mut true;
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_is_locked(
            captured_packet.as_mut_ptr() as *mut _,
            zone,
            is_locked as *mut _,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x02);
    assert_eq!(captured_packet[0x03], 0x00);
    assert_eq!(captured_packet[0x04..0x06], [0x15, 0x00]);
}

// Sha command
// See also https://github.com/MicrochipTech/cryptoauthlib/blob/main/lib/calib/calib_sha.c#L261-L270
fn sha() {
    // Sha start
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_sha_start(captured_packet.as_mut_ptr() as *mut _)
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x47);
    assert_eq!(captured_packet[0x03], 0x00);
    assert_eq!(captured_packet[0x04..0x06], [0x00, 0x00]);

    // Sha update
    let message = &[0xaau8; 0xff];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_sha_update(captured_packet.as_mut_ptr() as *mut _, message.as_ptr())
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x47);
    assert_eq!(captured_packet[0x02], 0x47);
    assert_eq!(captured_packet[0x03], 0x01);
    assert_eq!(captured_packet[0x04..0x06], [0x40, 0x00]);
    assert_eq!(captured_packet[0x06..0x46], message[0x00..0x40]);

    // Sha end
    let digest = &mut [0x00];
    let length = 0x40u16;
    let message = &[0xaau8; 0xff];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_sha_end(
            captured_packet.as_mut_ptr() as *mut _,
            digest.as_mut_ptr(),
            length,
            message.as_ptr(),
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x47);
    assert_eq!(captured_packet[0x02], 0x47);
    assert_eq!(captured_packet[0x03], 0x02);
    assert_eq!(captured_packet[0x04..0x06], length.to_le_bytes());
}

// Sign command
fn sign() {
    let mode = 0xc0u8;
    let key_id = 0x0au16;
    let signature = &mut [0x00u8];
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_sign_base(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            key_id,
            signature.as_mut_ptr(),
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x07);
    assert_eq!(captured_packet[0x02], 0x41);
    assert_eq!(captured_packet[0x03], mode);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
}

// Verify command
fn verify() {
    let mode = 0x02u8;
    let key_id = 0x0au16;
    let signature = &[0xaau8; 0xff];
    let public_key = &[0xbbu8; 0xff];
    let other_data = &[0xccu8; 0xff];
    let mac = core::ptr::null_mut();
    let captured_packet = &mut [0x00u8; size_of::<ATCAPacket>()];
    assert_eq!(ATCA_STATUS_ATCA_COMM_FAIL, unsafe {
        calib_verify(
            captured_packet.as_mut_ptr() as *mut _,
            mode,
            key_id,
            signature.as_ptr(),
            public_key.as_ptr(),
            other_data.as_ptr(),
            mac,
        )
    });
    check_crc(captured_packet);
    assert_eq!(captured_packet[0x01], 0x87);
    assert_eq!(captured_packet[0x02], 0x45);
    assert_eq!(captured_packet[0x03], mode);
    assert_eq!(captured_packet[0x04..0x06], key_id.to_le_bytes());
    assert_eq!(captured_packet[0x06..0x46], signature[0x00..0x40]);
    assert_eq!(captured_packet[0x46..0x86], public_key[0x00..0x40]);
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
