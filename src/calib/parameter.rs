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
