enum Zone {
    Config = 0x00,
    Otp = 0x01,
    Data = 0x02,
}

enum Slot {
    /// PrivateKey0x contains 36 bytes, taking 2 block reads.
    PrivateKey01 = 0x01,
    PrivateKey02 = 0x02,
    PrivateKey03 = 0x03,
    PrivateKey04 = 0x04,
    PrivateKey05 = 0x05,
    PrivateKey06 = 0x06,
    PrivateKey07 = 0x07,
    /// Data08 contains bytes, taking 13 block reads.
    Data08 = 0x08,
    /// Certificate0x contains 72 bytes, taking 3 block reads.
    Certificate09 = 0x09,
    Certificate0a = 0x0a,
    Certificate0b = 0x0b,
    Certificate0c = 0x0c,
    Certificate0d = 0x0d,
    Certificate0e = 0x0e,
    Certificate0f = 0x0f,
}

fn get_config_address(zone: u8, block: usize, offset: usize) -> u16 {
    unimplemented!()
}
fn get_otp_address(zone: u8, block: usize, offset: usize) -> u16 {
    unimplemented!()
}
fn get_data_address(zone: u8, slot: Slot, block: usize, offset: usize) -> u16 {
    unimplemented!()
}
