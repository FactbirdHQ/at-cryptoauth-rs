pub enum ErrorKind {
    ConfigZoneLocked = 0x01,
    DataZoneLocked = 0x04,
    /// Device did not respond to wake call as expected
    WakeFailed = 0xD0,
    /// response status byte indicates CheckMac failure (status byte = 0x01)
    CheckmacVerifyFailed = 0xD1,
    /// response status byte indicates parsing error (status byte = 0x03)
    ParseError = 0xD2,
    /// response status byte indicates Device did not receive data properly
    /// (status byte = 0xFf)
    StatusCrc = 0xD4,
    /// response status byte is unknown
    StatusUnknown = 0xD5,
    /// response status byte is Ecc fault (status byte = 0x05)
    StatusEcc = 0xD6,
    /// response status byte is Self Test Error, chip in failure mode (status
    /// byte = 0x07)
    StatusSelftestError = 0xD7,
    /// Function could not execute due to incorrect condition / state.
    FuncFail = 0xE0,
    /// unspecified error
    GenFail = 0xE1,
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
    /// received proper wake token
    WakeSuccess = 0xF3,
    /// chip was in a state where it could not execute the command, response
    /// status byte indicates command execution error (status byte = 0x0F)
    ExecutionError = 0xF4,
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
    /// random number generator health test error
    HealthTestError = 0xFa,
    /// Use flags on the device indicates its consumed fully
    UseFlagsConsumed = 0xFc,
}
