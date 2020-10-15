use core::fmt;

/// An error type representing ATECC608's erroneous conditions.
#[derive(Clone, Debug)]
pub struct Error {
    repr: Repr,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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
    Selftest = 0x07,
    /// random number generator health test error
    HealthTest = 0xFA,
    /// received proper wake token
    WakeSuccess = 0xF3,
}

impl Status {
    pub fn from_u8(status: u8) -> Self {
        Self::Ecc
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
            Selftest => "chip is in self test failure mode",
            Unknown => "response contains unknown non-zero status byte",
            WakeSuccess => "chip was successfully woken up",
        }
    }
}

/// A list of specific error causes. Each kind is converted into `Error` type.
/// TODO: Don't need that much. Erase irrelevant ones.
#[derive(Clone, Debug)]
pub enum ErrorKind {
    ConfigZoneLocked = 0x01,
    DataZoneLocked = 0x04,
    /// Device did not respond to wake call as expected
    WakeFailed = 0xD0,
    /// Function could not execute due to incorrect condition / state.
    FuncFail = 0xE0,
    /// bad argument (out of range, null pointer, etc.)
    BadParam = 0xE2,
    /// invalid device id, id not set
    InvalidId = 0xE3,
    /// Count value is out of range or greater than buffer size.
    InvalidSize = 0xE4,
    /// Crc error in data received from device
    RxCrcError = 0xE5,
    /// Timed out while waiting for response. Number of bytes received is > 0.
    RxFail = 0xE6,
    /// Not an error while the Command layer is polling for a command response.
    RxNoResponse = 0xE7,
    /// Re-synchronization succeeded, but only after generating a Wake-up
    ResyncWithWakeup = 0xE8,
    /// for protocols needing parity
    ParityError = 0xE9,
    /// for Microchip Phy protocol, timeout on transmission waiting for master
    TxTimeout = 0xEa,
    /// for Microchip Phy protocol, timeout on receipt waiting for master
    RxTimeout = 0xEb,
    /// Device did not respond too many times during a transmission. Could
    /// indicate no device present.
    TooManyCommRetries = 0xEc,
    /// Supplied buffer is too small for data required
    SmallBuffer = 0xEd,
    /// Communication with device failed. Same as in hardware dependent modules.
    CommFail = 0xF0,
    /// Timed out while waiting for response. Number of bytes received is 0.
    Timeout = 0xF1,
    /// opcode is not supported by the device
    BadOpcode = 0xF2,
    /// Function or some element of it hasn't been implemented yet
    Unimplemented = 0xF5,
    /// Code failed run-time consistency check
    AssertFailure = 0xF6,
    /// Failed to write
    TxFail = 0xF7,
    /// required zone was not locked
    NotLocked = 0xF8,
    /// For protocols that support device discovery (kit protocol), no devices
    /// were found
    NoDevices = 0xF9,
    /// Use flags on the device indicates its consumed fully
    UseFlagsConsumed = 0xFc,
}

impl ErrorKind {
    fn as_str(&self) -> &'static str {
        use ErrorKind::*;
        match self {
            ConfigZoneLocked => "config zone is locked",
            DataZoneLocked => "data zone is locked",
            WakeFailed => "device did not respond to wake call as expected",
            FuncFail => "function could not execute due to incorrect condition / state",
            BadParam => "bad argument (out of range, null pointer, etc.)",
            InvalidId => "invalid device id, id not set",
            InvalidSize => "count value is out of range or greater than buffer size",
            RxCrcError => "crc error in data received from device",
            RxFail => "timed out while waiting for response. Number of bytes received is > 0",
            RxNoResponse => {
                "not an error while the Command layer is polling for a command response"
            }
            ResyncWithWakeup => "re-synchronization succeeded, but only after generating a Wake-up",
            /*
                        /// for protocols needing parity
                        ParityError => 0xE9,
                        /// for Microchip Phy protocol, timeout on transmission waiting for master
                        TxTimeout => 0xEa,
                        /// for Microchip Phy protocol, timeout on receipt waiting for master
                        RxTimeout => 0xEb,
                        /// Device did not respond too many times during a transmission. Could
                        /// indicate no device present.
                        TooManyCommRetries => 0xEc,
                        /// Supplied buffer is too small for data required
                        SmallBuffer => 0xEd,
                        /// Communication with device failed. Same as in hardware dependent modules.
                        CommFail => 0xF0,
                        /// Timed out while waiting for response. Number of bytes received is 0.
                        Timeout => 0xF1,
                        /// opcode is not supported by the device
                        BadOpcode => 0xF2,
                        /// received proper wake token
                        WakeSuccess => 0xF3,
                        /// chip was in a state where it could not execute the command, response
                        /// status byte indicates command execution error (status byte => 0x0F)
                        ExecutionError => 0xF4,
                        /// Function or some element of it hasn't been implemented yet
                        Unimplemented => 0xF5,
                        /// Code failed run-time consistency check
                        AssertFailure => 0xF6,
                        /// Failed to write
                        TxFail => 0xF7,
                        /// required zone was not locked
                        NotLocked => 0xF8,
                        /// For protocols that support device discovery (kit protocol), no devices
                        /// were found
                        NoDevices => 0xF9,
                        /// random number generator health test error
                        HealthTestError => 0xFa,
                        /// Use flags on the device indicates its consumed fully
                        UseFlagsConsumed => 0xFc,
            */
            _ => "unknown error",
        }
    }
}
