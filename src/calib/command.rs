use super::packet::{Packet, PacketBuilder};
use core::convert::TryFrom;
use signature::Signer;
pub struct Error;
struct UnknownVariantError;

#[derive(Clone, Copy, Debug)]
pub enum OpCode {
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

/// ChipMode clock divider {M0, M1, M2}
pub enum ClockDivider {
    Zero = 0,
    One = 1,
    Two = 2,
}

const EXEC_TIME_AES: [u32; 3] = [27, 27, 27];
const EXEC_TIME_CHECKMAC: [u32; 3] = [40, 40, 40];
const EXEC_TIME_COUNTER: [u32; 3] = [25, 25, 25];
const EXEC_TIME_DERIVE_KEY: [u32; 3] = [50, 50, 50];
const EXEC_TIME_ECDH: [u32; 3] = [172, 75, 531];
const EXEC_TIME_GENDIG: [u32; 3] = [35, 25, 35];
const EXEC_TIME_GENKEY: [u32; 3] = [215, 115, 653];
const EXEC_TIME_INFO: [u32; 3] = [5, 5, 5];
const EXEC_TIME_KDF: [u32; 3] = [165, 165, 165];
const EXEC_TIME_LOCK: [u32; 3] = [35, 35, 35];
const EXEC_TIME_MAC: [u32; 3] = [55, 55, 55];
const EXEC_TIME_NONCE: [u32; 3] = [20, 20, 20];
const EXEC_TIME_PRIVWRITE: [u32; 3] = [50, 50, 50];
const EXEC_TIME_RANDOM: [u32; 3] = [23, 23, 23];
const EXEC_TIME_READ: [u32; 3] = [5, 5, 5];
const EXEC_TIME_SECUREBOOT: [u32; 3] = [160, 80, 480];
const EXEC_TIME_SELFTEST: [u32; 3] = [625, 250, 2324];
const EXEC_TIME_SHA: [u32; 3] = [36, 42, 75];
const EXEC_TIME_SIGN: [u32; 3] = [115, 220, 665];
const EXEC_TIME_UPDATE_EXTRA: [u32; 3] = [10, 10, 10];
const EXEC_TIME_VERIFY: [u32; 3] = [105, 295, 1085];
const EXEC_TIME_WRITE: [u32; 3] = [45, 45, 45];

impl OpCode {
    pub fn execution_time(&self, div: ClockDivider) -> Option<u32> {
        use OpCode::*;
        match self {
            CheckMac => EXEC_TIME_CHECKMAC[div as usize].into(),
            Counter => EXEC_TIME_COUNTER[div as usize].into(),
            DeriveKey => EXEC_TIME_DERIVE_KEY[div as usize].into(),
            Ecdh => EXEC_TIME_ECDH[div as usize].into(),
            GenDig => EXEC_TIME_GENDIG[div as usize].into(),
            GenKey => EXEC_TIME_GENKEY[div as usize].into(),
            Info => EXEC_TIME_INFO[div as usize].into(),
            Lock => EXEC_TIME_LOCK[div as usize].into(),
            Mac => EXEC_TIME_MAC[div as usize].into(),
            Nonce => EXEC_TIME_NONCE[div as usize].into(),
            PrivWrite => EXEC_TIME_PRIVWRITE[div as usize].into(),
            Random => EXEC_TIME_RANDOM[div as usize].into(),
            Read => EXEC_TIME_READ[div as usize].into(),
            Sign => EXEC_TIME_SIGN[div as usize].into(),
            UpdateExtra => EXEC_TIME_UPDATE_EXTRA[div as usize].into(),
            Verify => EXEC_TIME_VERIFY[div as usize].into(),
            Write => EXEC_TIME_WRITE[div as usize].into(),
            Sha => EXEC_TIME_SHA[div as usize].into(),
            Aes => EXEC_TIME_AES[div as usize].into(),
            Kdf => EXEC_TIME_KDF[div as usize].into(),
            SecureBoot => EXEC_TIME_SECUREBOOT[div as usize].into(),
            SelfTest => EXEC_TIME_SELFTEST[div as usize].into(),
            _ => None,
        }
    }
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
struct Sha;
struct Aes;
struct Kdf;
struct SecureBoot;
struct SelfTest;

// Implementation design inspired by digest crate.
// Not directly applicable because the trait won't allow any member methods to be fallible.
// Moreover, `digest` requires the client stored in a global static variable.
//
// use digest::{Digest, Output};
// use heapless::consts::U32;
//
// impl Digest for Sha {
//     type OutputSize = U32;
//     fn new() -> Self { unimplemented!() }
//     fn update(&mut self, data: impl AsRef<[u8]>) { unimplemented!() }
//     fn chain(self, data: impl AsRef<[u8]>) -> Self { unimplemented!() }
//     fn finalize(self) -> Output<Self> { unimplemented!() }
//     fn finalize_reset(&mut self) -> Output<Self> { unimplemented!() }
//     fn reset(&mut self) { unimplemented!() }
//     fn output_size() -> usize { unimplemented!() }
//     fn digest(data: &[u8]) -> Output<Self> { unimplemented!() }
// }

impl Sha {
    fn start<'a>(buffer: &'a mut [u8]) -> Result<Packet, Error> {
        let mode = 0x00;
        let packet = PacketBuilder::new(buffer)
            .opcode(OpCode::Sha)
            .mode(0)
            .param2(0)
            .build();
        Ok(packet)
    }

    fn update<'a>(buffer: &'a mut [u8], data: impl AsRef<[u8]>) -> Result<Packet, Error> {
        let packet = PacketBuilder::new(buffer)
            .opcode(OpCode::Sha)
            .pdu_data(data)
            .build();
        Ok(packet)
    }
}
