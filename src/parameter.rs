use super::command::OpCode;
use super::packet::{Packet, PacketBuilder};

enum CommandStatus {
    /// status byte for success
    Success = 0x00,
    /// status byte after wake-up
    WakeUp = 0x11,
    /// command parse error
    ByteParse = 0x03,
    /// command ECC error
    ByteEcc = 0x05,
    /// command execution error
    ByteExec = 0x0F,
    /// communication error
    ByteComm = 0xFF,
}

fn aes<'a>(buffer: &'a mut [u8], mode: u8, key_id: u16, plain_text: &[u8; 16]) -> Packet {
    let mode = mode; // AES_MODE_ENCRYPT | (AES_MODE_KEY_BLOCK_MASK & (key_block << AES_MODE_KEY_BLOCK_POS));
    let packet = PacketBuilder::new(buffer)
        .opcode(OpCode::Aes)
        .mode(mode)
        .param2(key_id)
        .pdu_data(&plain_text)
        .build();
    packet
}
