use core::convert::TryFrom;
struct UnknownVariantError;

enum OpCode {
    /// CheckMac command op-code
    CheckMac = 0x28,
    /// DeriveKey command op-code
    DeriveKey = 0x1C,
    /// Info command op-code
    Info = 0x30,
    /// GenDig command op-code
    GenDig = 0x15,
    /// GenKey command op-code
    GenKey = 0x40,
    /// HMAC command op-code
    HMac = 0x11,
    /// Lock command op-code
    Lock = 0x17,
    /// MAC command op-code
    Mac = 0x08,
    /// Nonce command op-code
    Nonce = 0x16,
    /// Pause command op-code
    Pause = 0x01,
    /// PrivWrite command op-code
    PrivWrite = 0x46,
    /// Random command op-code
    Random = 0x1B,
    /// Read command op-code
    Read = 0x02,
    /// Sign command op-code
    Sign = 0x41,
    /// UpdateExtra command op-code
    UpdateExtra = 0x20,
    /// GenKey command op-code
    Verify = 0x45,
    /// Write command op-code
    Write = 0x12,
    /// ECDH command op-code
    Ecdh = 0x43,
    /// Counter command op-code
    Counter = 0x24,
    /// SHA command op-code
    Sha = 0x47,
    /// AES command op-code
    Aes = 0x51,
    /// KDF command op-code
    Kdf = 0x56,
    /// Secure Boot command op-code
    SecureBoot = 0x80,
    /// Self test command op-code
    SelfTest = 0x77,
}
/*
    { ATCA_AES,          27},      { ATCA_AES,          27},    { ATCA_AES,          27},
    { ATCA_CHECKMAC,     40},      { ATCA_CHECKMAC,     40},    { ATCA_CHECKMAC,     40},
    { ATCA_COUNTER,      25},      { ATCA_COUNTER,      25},    { ATCA_COUNTER,      25},
    { ATCA_DERIVE_KEY,   50},      { ATCA_DERIVE_KEY,   50},    { ATCA_DERIVE_KEY,   50},
    { ATCA_ECDH,         172},     { ATCA_ECDH,         75},    { ATCA_ECDH,         531}
    { ATCA_GENDIG,       35},      { ATCA_GENDIG,       25},    { ATCA_GENDIG,       35},
    { ATCA_GENKEY,       215},     { ATCA_GENKEY,       115}    { ATCA_GENKEY,       653},
    { ATCA_INFO,         5},       { ATCA_INFO,         5},     { ATCA_INFO,         5},
    { ATCA_KDF,          165},     { ATCA_KDF,          165}    { ATCA_KDF,          165},
    { ATCA_LOCK,         35},      { ATCA_LOCK,         35},    { ATCA_LOCK,         35},
    { ATCA_MAC,          55},      { ATCA_MAC,          55},    { ATCA_MAC,          55},
    { ATCA_NONCE,        20},      { ATCA_NONCE,        20},    { ATCA_NONCE,        20},
    { ATCA_PRIVWRITE,    50},      { ATCA_PRIVWRITE,    50},    { ATCA_PRIVWRITE,    50},
    { ATCA_RANDOM,       23},      { ATCA_RANDOM,       23},    { ATCA_RANDOM,       23},
    { ATCA_READ,         5},       { ATCA_READ,         5},     { ATCA_READ,         5},
    { ATCA_SECUREBOOT,   160},     { ATCA_SECUREBOOT,   80},    { ATCA_SECUREBOOT,   480}
    { ATCA_SELFTEST,     625},     { ATCA_SELFTEST,     250}    { ATCA_SELFTEST,     2324,
    { ATCA_SHA,          36},      { ATCA_SHA,          42},    { ATCA_SHA,          75},
    { ATCA_SIGN,         115}      { ATCA_SIGN,         220}    { ATCA_SIGN,         665},
    { ATCA_UPDATE_EXTRA, 10},      { ATCA_UPDATE_EXTRA, 10},    { ATCA_UPDATE_EXTRA, 10},
    { ATCA_VERIFY,       105}      { ATCA_VERIFY,       295}    { ATCA_VERIFY,       1085,
    { ATCA_WRITE,        45}       { ATCA_WRITE,        45}     { ATCA_WRITE,        45}
*/

impl OpCode {
    fn execution_time(&self) -> u32 {
        unimplemented!();
    }
}

pub struct Packet {
    txsize: u8,
    opcode: u8,
    mode: u8,
    lenght: u16,
    data: [u8; 192usize],
    exec_time: u8,
}

///
/// [<len == 0x04>, <error_code>, <CRC_low>, <CRC_high>]
pub struct ErrorPacket {
    raw: [u8; 4],
    error: u8,
}

struct CheckMac;
struct Counter;
struct DeriveKey;
struct Ecdh;
/// Generate Digest
struct GenDig;
struct GenKey;
struct HMac;
struct Info;
struct Lock;
struct Mac;
struct Nonce;
struct Pause;
struct PrivWrite;
struct Random;
struct Read;
struct Sign;
struct UpdateExtra;
struct Verify;
struct Write;
struct Ecdh;
struct Counter;
struct Sha;
struct Aes;
struct Kdf;
struct SecureBoot;
struct SelfTest;
