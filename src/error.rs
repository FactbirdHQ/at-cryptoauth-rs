use core::fmt;

/// An error type representing ATECC608's erroneous conditions.
#[derive(Copy, Clone, Debug)]
pub struct Error {
    repr: Repr,
}

#[derive(Copy, Clone, Debug)]
enum Repr {
    Device(Status),
    Simple(ErrorKind),
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            repr: Repr::Simple(kind),
        }
    }
}

impl From<Status> for Error {
    fn from(status: Status) -> Error {
        Error {
            repr: Repr::Device(status),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            Repr::Device(status) => write!(fmt, "{}", status.as_str()),
            Repr::Simple(kind) => write!(fmt, "{}", kind.as_str()),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Status {
    /// response status byte indicates CheckMac failure (status byte = 0x01)
    CheckmacVerifyFailed = 0x01,
    /// chip was in a state where it could not execute the command, response
    /// status byte indicates command execution error (status byte = 0x0F)
    Execution = 0x0F,
    /// response status byte indicates parsing error (status byte = 0x03)
    Parse = 0x03,
    /// response status byte indicates Device did not receive data properly
    /// (status byte = 0xFF)
    Crc = 0xFF,
    /// response status byte is unknown
    Unknown = 0xD5,
    /// response status byte is Ecc fault (status byte = 0x05)
    Ecc = 0x05,
    /// response status byte is Self Test Error, chip in failure mode (status
    /// byte = 0x07)
    SelfTest = 0x07,
    /// random number generator health test error
    HealthTest = 0x08,
}

impl Status {
    pub fn from_u8(status: u8) -> Option<Self> {
        use Status::*;
        match status {
            0x00 => None,
            x if x == CheckmacVerifyFailed as u8 => CheckmacVerifyFailed.into(),
            x if x == Execution as u8 => Execution.into(),
            x if x == Parse as u8 => Parse.into(),
            x if x == Crc as u8 => Crc.into(),
            x if x == Ecc as u8 => Ecc.into(),
            x if x == SelfTest as u8 => SelfTest.into(),
            x if x == HealthTest as u8 => HealthTest.into(),
            _ => Unknown.into(),
        }
    }

    fn as_str(&self) -> &'static str {
        use Status::*;
        match self {
            CheckmacVerifyFailed => "checkmac or verify failed",
            Crc => "bad crc found (command not properly received by device) or other comm error",
            Ecc => "computation error during ECC processing causing invalid results",
            Execution => "chip can't execute the command",
            HealthTest => "random number generator health test error",
            Parse => "command received byte length, opcode or parameter was illegal",
            SelfTest => "chip is in self test failure mode",
            Unknown => "response contains unknown non-zero status byte",
        }
    }
}

/// A list of specific error causes. Each kind is converted into `Error` type.
#[derive(Copy, Clone, Debug)]
pub enum ErrorKind {
    /// Code failed run-time consistency check
    AssertFailure = 0xF6,
    /// opcode is not supported by the device
    BadOpcode = 0xF2,
    /// bad argument (out of range, null pointer, etc.)
    BadParam = 0xE2,
    /// Communication with device failed. Same as in hardware dependent modules.
    CommFail = 0xF0,
    ConfigZoneLocked = 0x01,
    DataZoneLocked = 0x04,
    /// Function could not execute due to incorrect condition / state.
    FuncFail = 0xE0,
    /// invalid device id, id not set
    InvalidId = 0xE3,
    /// Count value is out of range or greater than buffer size.
    InvalidSize = 0xE4,
    /// required zone was not locked
    NotLocked = 0xF8,
    /// Re-synchronization succeeded, but only after generating a Wake-up
    ResyncWithWakeup = 0xE8,
    /// Crc error in data received from device
    RxCrcError = 0xE5,
    /// Timed out while waiting for response. Number of bytes received is > 0.
    RxFail = 0xE6,
    /// Supplied buffer is too small for data required
    SmallBuffer = 0xED,
    /// Timed out while waiting for response. Number of bytes received is 0.
    Timeout = 0xF1,
    /// Device did not respond too many times during a transmission. Could
    /// indicate no device present.
    TooManyCommRetries = 0xEC,
    /// Failed to write
    TxFail = 0xF7,
    /// Function or some element of it hasn't been implemented yet
    Unimplemented = 0xF5,
    /// Use flags on the device indicates its consumed fully
    UseFlagsConsumed = 0xFC,
    /// Device did not respond to wake call as expected
    WakeFailed = 0xD0,
}

impl ErrorKind {
    fn as_str(&self) -> &'static str {
        use ErrorKind::*;
        match self {
            AssertFailure => "failed run-time consistency check",
            BadOpcode => "opcode is not supported by the device",
            BadParam => "bad argument (out of range, null pointer, etc.)",
            CommFail => "communication with device failed",
            ConfigZoneLocked => "config zone is locked",
            DataZoneLocked => "data zone is locked",
            FuncFail => "function could not execute due to incorrect condition / state",
            InvalidId => "invalid device id, id not set",
            InvalidSize => "count value is out of range or greater than buffer size",
            NotLocked => "required zone was not locked",
            ResyncWithWakeup => "re-synchronization succeeded, but only after generating a Wake-up",
            RxCrcError => "crc error in data received from device",
            RxFail => "timed out while waiting for response. Number of bytes received is > 0",
            SmallBuffer => "supplied buffer is too small for data required",
            Timeout => "timed out while waiting for response",
            TooManyCommRetries => {
                "device did not respond too many times, indicating no device present"
            }
            TxFail => "failed to write",
            Unimplemented => "function or some element of it hasn't been implemented yet",
            UseFlagsConsumed => "use flags on the device indicates its consumed fully",
            WakeFailed => "device did not respond to wake call as expected",
        }
    }
}
