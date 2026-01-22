use core::convert::TryFrom;

/// An error type representing ATECC608's erroneous conditions.
#[derive(Copy, Clone, Debug)]
pub struct Error {
    repr: Repr,
}

impl Error {
    pub fn code(&self) -> u32 {
        match self.repr {
            Repr::Device(i) => i as u32,
            Repr::Simple(i) => i as u32,
        }
    }
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

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.repr {
            Repr::Device(status) => write!(fmt, "{}", status),
            Repr::Simple(kind) => write!(fmt, "{}", kind),
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

impl TryFrom<u8> for Status {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Err(()),
            0x01 => Ok(Self::CheckmacVerifyFailed),
            0x0F => Ok(Self::Execution),
            0x03 => Ok(Self::Parse),
            0xFF => Ok(Self::Crc),
            0x05 => Ok(Self::Ecc),
            0x07 => Ok(Self::SelfTest),
            0x08 => Ok(Self::HealthTest),
            _ => Ok(Self::Unknown),
        }
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CheckmacVerifyFailed => write!(fmt, "checkmac or verify failed"),
            Self::Crc => write!(
                fmt,
                "bad crc found (command not properly received by device) or other comm error"
            ),
            Self::Ecc => write!(
                fmt,
                "computation error during ECC processing causing invalid results"
            ),
            Self::Execution => write!(fmt, "chip can't execute the command"),
            Self::HealthTest => write!(fmt, "random number generator health test error"),
            Self::Parse => write!(
                fmt,
                "command received byte length, opcode or parameter was illegal"
            ),
            Self::SelfTest => write!(fmt, "chip is in self test failure mode"),
            Self::Unknown => write!(fmt, "response contains unknown non-zero status byte"),
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

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AssertFailure => write!(fmt, "failed run-time consistency check"),
            Self::BadOpcode => write!(fmt, "opcode is not supported by the device"),
            Self::BadParam => write!(fmt, "bad argument (out of range, null pointer, etc.)"),
            Self::CommFail => write!(fmt, "communication with device failed"),
            Self::ConfigZoneLocked => write!(fmt, "config zone is locked"),
            Self::DataZoneLocked => write!(fmt, "data zone is locked"),
            Self::FuncFail => write!(
                fmt,
                "function could not execute due to incorrect condition / state"
            ),
            Self::InvalidId => write!(fmt, "invalid device id, id not set"),
            Self::InvalidSize => write!(
                fmt,
                "count value is out of range or greater than buffer size"
            ),
            Self::NotLocked => write!(fmt, "required zone was not locked"),
            Self::ResyncWithWakeup => write!(
                fmt,
                "re-synchronization succeeded, but only after generating a Wake-up"
            ),
            Self::RxCrcError => write!(fmt, "crc error in data received from device"),
            Self::RxFail => write!(
                fmt,
                "timed out while waiting for response. Number of bytes received is > 0"
            ),
            Self::SmallBuffer => write!(fmt, "supplied buffer is too small for data required"),
            Self::Timeout => write!(fmt, "timed out while waiting for response"),
            Self::TooManyCommRetries => {
                write!(
                    fmt,
                    "device did not respond too many times, indicating no device present"
                )
            }
            Self::TxFail => write!(fmt, "failed to write"),
            Self::Unimplemented => write!(
                fmt,
                "function or some element of it hasn't been implemented yet"
            ),
            Self::UseFlagsConsumed => {
                write!(fmt, "use flags on the device indicates its consumed fully")
            }
            Self::WakeFailed => write!(fmt, "device did not respond to wake call as expected"),
        }
    }
}
