use super::command::OpCode;

const EXEC_TIME_AES: [u32; 3] = [27, 27, 27];
const EXEC_TIME_CHECKMAC: [u32; 3] = [40, 40, 40];
const EXEC_TIME_COUNTER: [u32; 3] = [25, 25, 25];
const EXEC_TIME_DERIVE_KEY: [u32; 3] = [50, 50, 50];
const EXEC_TIME_ECDH: [u32; 3] = [75, 172, 531];
const EXEC_TIME_GENDIG: [u32; 3] = [25, 35, 35];
const EXEC_TIME_GENKEY: [u32; 3] = [115, 215, 653];
const EXEC_TIME_INFO: [u32; 3] = [5, 5, 5];
const EXEC_TIME_KDF: [u32; 3] = [165, 165, 165];
const EXEC_TIME_LOCK: [u32; 3] = [35, 35, 35];
const EXEC_TIME_MAC: [u32; 3] = [55, 55, 55];
const EXEC_TIME_NONCE: [u32; 3] = [20, 20, 20];
const EXEC_TIME_PRIVWRITE: [u32; 3] = [50, 50, 50];
const EXEC_TIME_RANDOM: [u32; 3] = [23, 23, 23];
const EXEC_TIME_READ: [u32; 3] = [5, 5, 5];
const EXEC_TIME_SECUREBOOT: [u32; 3] = [80, 160, 480];
const EXEC_TIME_SELFTEST: [u32; 3] = [250, 625, 2324];
const EXEC_TIME_SHA: [u32; 3] = [36, 42, 75];
const EXEC_TIME_SIGN: [u32; 3] = [115, 220, 665];
const EXEC_TIME_UPDATE_EXTRA: [u32; 3] = [10, 10, 10];
const EXEC_TIME_VERIFY: [u32; 3] = [105, 295, 1085];
const EXEC_TIME_WRITE: [u32; 3] = [45, 45, 45];

/// ChipMode clock divider {M0, M1, M2}
#[derive(Clone, Copy, Debug)]
pub(crate) enum ClockDivider {
    Zero = 0,
    #[allow(dead_code)]
    One = 1,
    #[allow(dead_code)]
    Two = 2,
}

impl ClockDivider {
    /// Get the typical execution time for the given command.
    pub(crate) fn execution_time(&self, opcode: &OpCode) -> Option<u32> {
        use OpCode::*;
        let index = *self as usize;
        match opcode {
            Aes => EXEC_TIME_AES[index].into(),
            CheckMac => EXEC_TIME_CHECKMAC[index].into(),
            Counter => EXEC_TIME_COUNTER[index].into(),
            DeriveKey => EXEC_TIME_DERIVE_KEY[index].into(),
            Ecdh => EXEC_TIME_ECDH[index].into(),
            GenDig => EXEC_TIME_GENDIG[index].into(),
            GenKey => EXEC_TIME_GENKEY[index].into(),
            Info => EXEC_TIME_INFO[index].into(),
            Kdf => EXEC_TIME_KDF[index].into(),
            Lock => EXEC_TIME_LOCK[index].into(),
            Mac => EXEC_TIME_MAC[index].into(),
            Nonce => EXEC_TIME_NONCE[index].into(),
            PrivWrite => EXEC_TIME_PRIVWRITE[index].into(),
            Random => EXEC_TIME_RANDOM[index].into(),
            Read => EXEC_TIME_READ[index].into(),
            SecureBoot => EXEC_TIME_SECUREBOOT[index].into(),
            SelfTest => EXEC_TIME_SELFTEST[index].into(),
            Sha => EXEC_TIME_SHA[index].into(),
            Sign => EXEC_TIME_SIGN[index].into(),
            UpdateExtra => EXEC_TIME_UPDATE_EXTRA[index].into(),
            Verify => EXEC_TIME_VERIFY[index].into(),
            Write => EXEC_TIME_WRITE[index].into(),
            HMac | Pause => None,
        }
    }
}
