// Command definitions
// Overall structure is modeled after https://github.com/tokio-rs/mini-redis/blob/master/src/cmd/mod.rs
use super::error::{Error, ErrorKind};
use super::memory::{Size, Slot, Zone};
use super::packet::{Packet, PacketBuilder};
use core::convert::TryFrom;
use signature::digest::generic_array::typenum::{U32, U4, U64, U9};
use signature::digest::generic_array::GenericArray;

// Encapsulates raw 4 bytes. When it is a return value of `info`, it contains
// the device's revision number.
#[derive(Clone, Copy, Debug, Default)]
pub struct Word {
    value: GenericArray<u8, U4>,
}

impl TryFrom<&[u8]> for Word {
    type Error = Error;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() != Size::Word.len() {
            return Err(ErrorKind::BadParam.into());
        }

        let mut value = Self::default();
        value.as_mut().copy_from_slice(buffer);
        Ok(value)
    }
}

impl AsRef<[u8]> for Word {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl AsMut<[u8]> for Word {
    fn as_mut(&mut self) -> &mut [u8] {
        self.value.as_mut()
    }
}

// Encapsulates raw 32 bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Block {
    value: GenericArray<u8, U32>,
}

impl TryFrom<&[u8]> for Block {
    type Error = Error;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() != Size::Block.len() {
            return Err(ErrorKind::BadParam.into());
        }

        let mut value = Self::default();
        value.as_mut().copy_from_slice(buffer);
        Ok(value)
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl AsMut<[u8]> for Block {
    fn as_mut(&mut self) -> &mut [u8] {
        self.value.as_mut()
    }
}

// Represents a serial number consisting of 9 bytes. Its uniqueness is
// guaranteed. A return type of API `read_serial`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Serial {
    value: GenericArray<u8, U9>,
}

impl TryFrom<&[u8]> for Serial {
    type Error = Error;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() != Size::Block.len() {
            return Err(ErrorKind::BadParam.into());
        }

        let mut value = [0x00; 9];
        value[0..4].as_mut().copy_from_slice(&buffer[0..4]);
        value[4..9].as_mut().copy_from_slice(&buffer[8..13]);
        Ok(Self {
            value: value.into(),
        })
    }
}

impl AsRef<[u8]> for Serial {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl AsMut<[u8]> for Serial {
    fn as_mut(&mut self) -> &mut [u8] {
        self.value.as_mut()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PublicKey {
    pub(crate) value: GenericArray<u8, U64>,
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl AsMut<[u8]> for PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.value.as_mut()
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() != 0x40 {
            return Err(ErrorKind::BadParam.into());
        }

        let mut value = Self::default();
        value.as_mut().copy_from_slice(buffer);
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SharedSecret {
    value: GenericArray<u8, U32>,
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl AsMut<[u8]> for SharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        self.value.as_mut()
    }
}

impl TryFrom<&[u8]> for SharedSecret {
    type Error = Error;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() != 32 {
            return Err(ErrorKind::BadParam.into());
        }

        let mut value = Self::default();
        value.as_mut().copy_from_slice(buffer);
        Ok(value)
    }
}

// A digest yielded from cryptographic hash functions. Merely a wrapper around
// `GenericArray<u8, 32>` of `digest` crate.
#[derive(Clone, Copy, Debug, Default)]
pub struct Digest {
    pub(crate) value: GenericArray<u8, U32>,
}

impl TryFrom<&[u8]> for Digest {
    type Error = Error;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() != 32 {
            return Err(ErrorKind::BadParam.into());
        }

        let mut value = Self::default();
        value.as_mut().copy_from_slice(buffer);
        Ok(value)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl AsMut<[u8]> for Digest {
    fn as_mut(&mut self) -> &mut [u8] {
        self.value.as_mut()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpCode {
    /// CheckMac command op-code
    #[allow(dead_code)]
    CheckMac = 0x28,
    /// DeriveKey command op-code
    #[allow(dead_code)]
    DeriveKey = 0x1C,
    /// Info command op-code
    Info = 0x30,
    /// GenDig command op-code
    GenDig = 0x15,
    /// GenKey command op-code
    GenKey = 0x40,
    /// HMAC command op-code
    #[allow(dead_code)]
    HMac = 0x11,
    /// Lock command op-code
    Lock = 0x17,
    /// MAC command op-code
    #[allow(dead_code)]
    Mac = 0x08,
    /// Nonce command op-code
    Nonce = 0x16,
    /// Pause command op-code
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    UpdateExtra = 0x20,
    /// Verify command op-code
    Verify = 0x45,
    /// Write command op-code
    Write = 0x12,
    /// ECDH command op-code
    #[allow(dead_code)]
    Ecdh = 0x43,
    /// Counter command op-code
    #[allow(dead_code)]
    Counter = 0x24,
    /// SHA command op-code
    Sha = 0x47,
    /// AES command op-code
    Aes = 0x51,
    /// KDF command op-code
    #[allow(dead_code)]
    Kdf = 0x56,
    /// Secure Boot command op-code
    #[allow(dead_code)]
    SecureBoot = 0x80,
    /// Self test command op-code
    #[allow(dead_code)]
    SelfTest = 0x77,
}

#[allow(dead_code)]
pub(crate) struct CheckMac<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct Counter<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct DeriveKey<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct Ecdh<'a>(PacketBuilder<'a>);
pub(crate) struct GenDig<'a>(PacketBuilder<'a>);
pub(crate) struct GenKey<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct HMac<'a>(PacketBuilder<'a>);
pub(crate) struct Info<'a>(PacketBuilder<'a>);
pub(crate) struct Lock<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct Mac<'a>(PacketBuilder<'a>);
pub(crate) struct NonceCtx<'a> {
    builder: PacketBuilder<'a>,
    #[allow(dead_code)]
    counter: u32,
}
#[allow(dead_code)]
pub(crate) struct Pause<'a>(PacketBuilder<'a>);

// For best security, it is recommended that the `PrivWrite` command not be
// used, and that private keys be internally generated from the RNG using the
// `GenKey` command.
pub(crate) struct PrivWrite<'a>(PacketBuilder<'a>);
pub(crate) struct Random<'a>(PacketBuilder<'a>);
pub(crate) struct Read<'a>(PacketBuilder<'a>);
pub(crate) struct Sign<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct UpdateExtra<'a>(PacketBuilder<'a>);
pub(crate) struct Verify<'a>(PacketBuilder<'a>);
pub(crate) struct Write<'a>(PacketBuilder<'a>);
pub(crate) struct Sha<'a>(PacketBuilder<'a>);
pub(crate) struct Aes<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct Kdf<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct SecureBoot<'a>(PacketBuilder<'a>);
#[allow(dead_code)]
pub(crate) struct SelfTest<'a>(PacketBuilder<'a>);

#[allow(dead_code)]
impl<'a> Ecdh<'a> {
    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn diffie_hellman(
        &mut self,
        private_key_id: Slot,
        public_key: PublicKey,
    ) -> Result<Packet, Error> {
        let packet = self
            .0
            .opcode(OpCode::Ecdh)
            .mode(0x00)
            .param2(private_key_id as u16)
            .pdu_data(public_key)
            .build()?;
        Ok(packet)
    }
}

// Used when signing an internally stored digest. The GenDig command uses
// SHA-256 to combine a stored value with the contents of TempKey, which must
// have been valid prior to the execution of this command.
#[allow(dead_code)]
impl<'a> GenDig<'a> {
    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn gendig(&mut self, key_id: Slot) -> Result<Packet, Error> {
        let packet = self
            .0
            .opcode(OpCode::GenDig)
            .param2(key_id as u16)
            .build()?;
        Ok(packet)
    }
}

/// GenKey
impl<'a> GenKey<'a> {
    // Config zone should be locked, otherwise GenKey always fails regardless of
    // a mode parameter.
    const MODE_PRIVATE: u8 = 0x04; // Private key generation
    const MODE_PUBLIC: u8 = 0x00; // Public key calculation
    #[allow(dead_code)]
    const MODE_DIGEST: u8 = 0x08; // PubKey digest will be created after the public key is calculated
    #[allow(dead_code)]
    const MODE_PUBKEY_DIGEST: u8 = 0x10; // Calculate a digest on the public key

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn private_key(&mut self, key_id: Slot) -> Result<Packet, Error> {
        let packet = self
            .0
            .opcode(OpCode::GenKey)
            .mode(Self::MODE_PRIVATE)
            .param2(key_id as u16)
            .build()?;
        Ok(packet)
    }

    pub(crate) fn public_key(&mut self, key_id: Slot) -> Result<Packet, Error> {
        let packet = self
            .0
            .opcode(OpCode::GenKey)
            .mode(Self::MODE_PUBLIC)
            .param2(key_id as u16)
            .build()?;
        Ok(packet)
    }
}

impl<'a> Info<'a> {
    // Info mode Revision
    const MODE_REVISION: u8 = 0x00;

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    /// Command execution will return a word containing the revision.
    pub(crate) fn revision(&mut self) -> Result<Packet, Error> {
        let packet = self
            .0
            .opcode(OpCode::Info)
            .mode(Self::MODE_REVISION)
            .build()?;
        Ok(packet)
    }
}

impl<'a> Lock<'a> {
    const LOCK_ZONE_NO_CRC: u8 = 0x80;

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn zone(&mut self, zone: Zone, crc: Option<u16>) -> Result<Packet, Error> {
        if matches!(zone, Zone::Otp) {
            return Err(ErrorKind::BadParam.into());
        }

        let packet = match crc {
            None => self
                .0
                .opcode(OpCode::Lock)
                .mode(Self::LOCK_ZONE_NO_CRC | zone as u8)
                .build()?,
            Some(crc) => self
                .0
                .opcode(OpCode::Lock)
                .mode(zone as u8)
                .param2(crc)
                .build()?,
        };

        Ok(packet)
    }

    pub(crate) fn slot(&mut self, key_id: Slot) -> Result<Packet, Error> {
        let mode = (key_id as u8) << 2 | 0x02 | Self::LOCK_ZONE_NO_CRC;
        let packet = self.0.opcode(OpCode::Lock).mode(mode).build()?;
        Ok(packet)
    }
}

/// Nonce
impl<'a> NonceCtx<'a> {
    #[allow(dead_code)]
    const MODE_MASK: u8 = 0x03; // Nonce mode bits 2 to 7 are 0.
    #[allow(dead_code)]
    const MODE_SEED_UPDATE: u8 = 0x00; // Nonce mode: update seed
    #[allow(dead_code)]
    const MODE_NO_SEED_UPDATE: u8 = 0x01; // Nonce mode: do not update seed
    #[allow(dead_code)]
    const MODE_INVALID: u8 = 0x02; // Nonce mode 2 is invalid.
    const MODE_PASSTHROUGH: u8 = 0x03; // Nonce mode: pass-through
    #[allow(dead_code)]
    const MODE_INPUT_LEN_MASK: u8 = 0x20; // Nonce mode: input size mask
    #[allow(dead_code)]
    const MODE_INPUT_LEN_32: u8 = 0x00; // Nonce mode: input size is 32 bytes
    #[allow(dead_code)]
    const MODE_INPUT_LEN_64: u8 = 0x20; // Nonce mode: input size is 64 bytes
    const MODE_TARGET_MASK: u8 = 0xc0; // Nonce mode: target mask
    #[allow(dead_code)]
    const MODE_TARGET_TEMPKEY: u8 = 0x00; // Nonce mode: target is TempKey
    const MODE_TARGET_MSGDIGBUF: u8 = 0x40; // Nonce mode: target is Message Digest Buffer
    #[allow(dead_code)]
    const MODE_TARGET_ALTKEYBUF: u8 = 0x80; // Nonce mode: target is Alternate Key Buffer

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        let counter = 0x4432;
        Self { builder, counter }
    }

    // TODO: Usage of Nonce, especially its correct timing is not clear. In
    // `test/api_atcab/atca_tests_aes.c`, AES encryption/decryption assumes
    // nonce value is loaded to TempKey in advance.
    pub(crate) fn message_digest_buffer(&mut self, msg: &Digest) -> Result<Packet, Error> {
        let mode = Self::MODE_PASSTHROUGH | (Self::MODE_TARGET_MSGDIGBUF & Self::MODE_TARGET_MASK);
        let packet = self
            .builder
            .opcode(OpCode::Nonce)
            .mode(mode)
            .pdu_data(msg)
            .build()?;
        Ok(packet)
    }

    #[allow(dead_code)]
    fn load(&mut self) -> Self {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn rand(&mut self) -> Self {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn challenge(&mut self) -> Self {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn challenge_seed_update(&mut self) -> Self {
        unimplemented!()
    }
}

/// PrivWrite
impl<'a> PrivWrite<'a> {
    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn write_private_key(
        &mut self,
        key_id: Slot,
        private_key: &Block,
    ) -> Result<Packet, Error> {
        // Input is an ECC private key consisting of padding 4 bytes of all 0s
        // and 32 byte integer.
        let private_key_range = 4..Size::Block.len() + 4;
        let private_key_length = private_key_range.end;
        let mac_range = private_key_length..private_key_length + Size::Block.len();
        let mac_length = mac_range.end;
        // Write the padding and private key to the PDU buffer directly.
        self.0.pdu_buffer()[private_key_range]
            .as_mut()
            .copy_from_slice(private_key.as_ref());
        let packet = self
            .0
            .pdu_length(mac_length)
            .opcode(OpCode::PrivWrite)
            .param2(key_id as u16)
            .build()?;
        Ok(packet)
    }
}

impl<'a> Sha<'a> {
    /// Initialization, does not accept a message
    const MODE_SHA256_START: u8 = 0x00;
    /// Add 64 bytes in the meesage to the SHA context
    const MODE_SHA256_UPDATE: u8 = 0x01;
    /// Complete the calculation and return the digest
    const MODE_SHA256_END: u8 = 0x02;
    /// Add 64 byte ECC public key in the slot to the SHA context
    #[allow(dead_code)]
    const MODE_SHA256_PUBLIC: u8 = 0x03;

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn start(&mut self) -> Result<Packet, Error> {
        let packet = self
            .0
            .opcode(OpCode::Sha)
            .mode(Self::MODE_SHA256_START)
            .build()?;
        Ok(packet)
    }

    /// Data length should be exactly 64 bytes.
    pub(crate) fn update(&mut self, data: impl AsRef<[u8]>) -> Result<Packet, Error> {
        let length = data.as_ref().len();
        if length != 64 {
            return Err(ErrorKind::BadParam.into());
        }

        let packet = self
            .0
            .opcode(OpCode::Sha)
            .mode(Self::MODE_SHA256_UPDATE)
            .param2(length as u16)
            .pdu_data(data)
            .build()?;
        Ok(packet)
    }

    /// Command execution will return a digest of Block size.
    pub(crate) fn end(&mut self, data: impl AsRef<[u8]>) -> Result<Packet, Error> {
        let length = data.as_ref().len();
        if length > 64 {
            return Err(ErrorKind::BadParam.into());
        }

        let packet = self
            .0
            .opcode(OpCode::Sha)
            .mode(Self::MODE_SHA256_END)
            .param2(length as u16)
            .pdu_data(data)
            .build()?;
        Ok(packet)
    }
}

/// AES
impl<'a> Aes<'a> {
    pub(crate) const DATA_SIZE: usize = 0x10;
    /// AES mode: Encrypt
    const MODE_ENCRYPT: u8 = 0x00;
    /// AES mode: Decrypt
    const MODE_DECRYPT: u8 = 0x01;

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    /// Plain text has length of 16 bytes.
    pub(crate) fn encrypt(&mut self, slot: Slot, plaintext: &[u8]) -> Result<Packet, Error> {
        if !slot.is_private_key() {
            return Err(ErrorKind::BadParam.into());
        }

        // Input length should be exactly 16 bytes. Otherwise the device
        // couldn't recognize the command properly.
        if plaintext.len() != Self::DATA_SIZE {
            return Err(ErrorKind::InvalidSize.into());
        }

        let packet = self
            .0
            .opcode(OpCode::Aes)
            .mode(Self::MODE_ENCRYPT)
            .param2(slot as u16)
            .pdu_data(plaintext)
            .build()?;
        Ok(packet)
    }

    /// Cipher text has length of 16 bytes.
    pub(crate) fn decrypt(&mut self, slot: Slot, ciphertext: &[u8]) -> Result<Packet, Error> {
        if !slot.is_private_key() {
            return Err(ErrorKind::BadParam.into());
        }

        // Input length should be exactly 16 bytes. Otherwise the device
        // couldn't recognize the command properly.
        if ciphertext.len() != Self::DATA_SIZE {
            return Err(ErrorKind::InvalidSize.into());
        }

        let packet = self
            .0
            .opcode(OpCode::Aes)
            .mode(Self::MODE_DECRYPT)
            .param2(slot as u16)
            .pdu_data(ciphertext)
            .build()?;
        Ok(packet)
    }
}

/// Random
impl<'a> Random<'a> {
    const MODE_SEED_UPDATE: u8 = 0x00;

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn random(&mut self) -> Result<Packet, Error> {
        let packet = self
            .0
            .opcode(OpCode::Random)
            .mode(Self::MODE_SEED_UPDATE)
            .build()?;
        Ok(packet)
    }
}

/// Read
impl<'a> Read<'a> {
    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn slot(&mut self, slot: Slot, block: u8) -> Result<Packet, Error> {
        let addr = Zone::Data.get_slot_addr(slot, block)?;
        let mode = Zone::Data.encode(Size::Block);
        let packet = self
            .0
            .opcode(OpCode::Read)
            .mode(mode)
            .param2(addr)
            .build()?;
        Ok(packet)
    }

    pub(crate) fn read(
        &mut self,
        zone: Zone,
        size: Size,
        block: u8,
        offset: u8,
    ) -> Result<Packet, Error> {
        let addr = zone.get_addr(block, offset)?;
        let mode = zone.encode(size);
        let packet = self
            .0
            .opcode(OpCode::Read)
            .mode(mode)
            .param2(addr)
            .build()?;
        Ok(packet)
    }
}

/// Sign
impl<'a> Sign<'a> {
    /// Sign mode bit 0: internal
    #[allow(dead_code)]
    const MODE_INTERNAL: u8 = 0x00;
    /// Sign mode bit 1: Signature will be used for Verify(Invalidate)
    #[allow(dead_code)]
    const MODE_INVALIDATE: u8 = 0x01;
    /// Sign mode bit 6: include serial number
    #[allow(dead_code)]
    const MODE_INCLUDE_SN: u8 = 0x40;
    /// Sign mode bit 7: external
    const MODE_EXTERNAL: u8 = 0x80;

    /// Sign mode message source is TempKey
    #[allow(dead_code)]
    const MODE_SOURCE_TEMPKEY: u8 = 0x00;
    /// Sign mode message source is the Message Digest Buffer
    const MODE_SOURCE_MSGDIGBUF: u8 = 0x20;

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    // Sign a 32-byte external message using the private key in the specified
    // slot.
    pub(crate) fn external(&mut self, key_id: Slot) -> Result<Packet, Error> {
        let mode = Self::MODE_EXTERNAL | Self::MODE_SOURCE_MSGDIGBUF;
        let packet = self
            .0
            .opcode(OpCode::Sign)
            .mode(mode)
            .param2(key_id as u16)
            .build()?;
        Ok(packet)
    }
}

/// Verify
impl<'a> Verify<'a> {
    const MODE_SOURCE_MSGDIGBUF: u8 = 0x20;
    const MODE_EXTERNAL: u8 = 0x02;
    const KEY_P256: u16 = 0x0004;

    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    // Verify a 32-byte external message using the provided private key.
    pub(crate) fn external(
        &mut self,
        signature: &p256::ecdsa::Signature,
        public_key: &PublicKey,
    ) -> Result<Packet, Error> {
        let mode = Self::MODE_EXTERNAL | Self::MODE_SOURCE_MSGDIGBUF;

        // Load PDU data
        let sig_bytes = signature.to_bytes();
        let sig_length = sig_bytes.len();
        let (sig_buf, pdu_buffer) = self.0.pdu_buffer().split_at_mut(sig_length);
        sig_buf.copy_from_slice(sig_bytes.as_slice());
        let pubkey_length = public_key.as_ref().len();
        let (pubkey_buffer, _) = pdu_buffer.split_at_mut(pubkey_length);
        pubkey_buffer.copy_from_slice(public_key.as_ref());

        let packet = self
            .0
            .opcode(OpCode::Verify)
            .mode(mode)
            .param2(Self::KEY_P256)
            .pdu_length(sig_length + pubkey_length)
            .build()?;
        Ok(packet)
    }
}

/// Write
impl<'a> Write<'a> {
    pub(crate) fn new(builder: PacketBuilder<'a>) -> Self {
        Self(builder)
    }

    pub(crate) fn slot(&mut self, slot: Slot, block: u8, data: &Block) -> Result<Packet, Error> {
        let addr = Zone::Data.get_slot_addr(slot, block)?;
        let mode = Zone::Data.encode(Size::Block);
        let packet = self
            .0
            .opcode(OpCode::Write)
            .mode(mode)
            .param2(addr)
            .pdu_data(data)
            .build()?;
        Ok(packet)
    }

    pub(crate) fn write(
        &mut self,
        zone: Zone,
        size: Size,
        block: u8,
        offset: u8,
        data: impl AsRef<[u8]>,
    ) -> Result<Packet, Error> {
        if size.len() != data.as_ref().len() {
            return Err(ErrorKind::BadParam.into());
        }

        let addr = zone.get_addr(block, offset)?;
        let mode = zone.encode(size);
        let packet = self
            .0
            .opcode(OpCode::Write)
            .mode(mode)
            .param2(addr)
            .pdu_data(data)
            .build()?;
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha() {
        let buf = &mut [0x00u8; 0xff];
        let packet = Sha::new(PacketBuilder::new(buf.as_mut()))
            .start()
            .unwrap()
            .buffer(buf.as_ref());
        assert_eq!(packet[0x01], 0x07);
        assert_eq!(packet[0x02], OpCode::Sha as u8);
        assert_eq!(packet[0x03], Sha::MODE_SHA256_START);
        assert_eq!(packet[0x04..0x06], [0x00, 0x00]);
    }

    #[test]
    fn lock() {
        let buf = &mut [0x00u8; 0xff];
        let packet = Lock::new(PacketBuilder::new(buf.as_mut()))
            .zone(Zone::Config, None)
            .unwrap()
            .buffer(buf.as_ref());
        assert_eq!(packet[0x01], 0x07);
        assert_eq!(packet[0x02], OpCode::Lock as u8);
        assert_eq!(packet[0x03], 0x80);
        assert_eq!(packet[0x04..0x06], [0x00, 0x00]);
    }

    #[test]
    fn lock_crc() {
        let buf = &mut [0x00u8; 0xff];
        let crc = 0xDEAD;
        let packet = Lock::new(PacketBuilder::new(buf.as_mut()))
            .zone(Zone::Config, Some(crc))
            .unwrap()
            .buffer(buf.as_ref());
        assert_eq!(packet[0x01], 0x07);
        assert_eq!(packet[0x02], OpCode::Lock as u8);
        assert_eq!(packet[0x03], 0x00);
        assert_eq!(packet[0x04..0x06], crc.to_le_bytes());
    }

    #[test]
    fn genkey() {
        let buf = &mut [0x00u8; 0xff];
        let packet = GenKey::new(PacketBuilder::new(buf.as_mut()))
            .private_key(Slot::PrivateKey01)
            .unwrap()
            .buffer(buf.as_ref());
        assert_eq!(packet[0x01], 0x07);
        assert_eq!(packet[0x02], OpCode::GenKey as u8);
        assert_eq!(packet[0x03], 0x04);
        assert_eq!(packet[0x04..0x06], [0x01, 0x00]);
    }

    #[test]
    fn privwrite() {
        let buf = &mut [0x00u8; 0xff];
        let mut data = Block::default();
        data.as_mut()
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = i as u8);
        let packet = PrivWrite::new(PacketBuilder::new(buf.as_mut()))
            .write_private_key(Slot::PrivateKey01, &data)
            .unwrap()
            .buffer(buf.as_ref());
        assert_eq!(packet[0x01], 0x4b);
        assert_eq!(packet[0x02], OpCode::PrivWrite as u8);
        assert_eq!(packet[0x03], 0x00);
        assert_eq!(packet[0x04..0x06], [0x01, 0x00]);
        assert_eq!(packet[0x06..0x0a], [0x00; 0x04]);
        assert_eq!(packet[0x0a..0x2a].as_ref(), data.as_ref());
    }

    // #[test]
    // fn verify() {
    //     let buf = &mut [0x00u8; 0xff];
    //     let mut signature = p256::ecdsa::Signature::default();
    //     let mut public_key = PublicKey::default();

    //     let (r, s) = signature.as_mut().split_at_mut(32);
    //     r.iter_mut().for_each(|v| *v = 'r' as u8);
    //     s.iter_mut().for_each(|v| *v = 's' as u8);
    //     let (x, y) = public_key.as_mut().split_at_mut(32);
    //     x.iter_mut().for_each(|v| *v = 'x' as u8);
    //     y.iter_mut().for_each(|v| *v = 'y' as u8);

    //     let packet = Verify::new(PacketBuilder::new(buf.as_mut()))
    //         .external(&signature, &public_key)
    //         .unwrap()
    //         .buffer(buf.as_ref());
    //     assert_eq!(packet[0x01], 0x87);
    //     assert_eq!(packet[0x02], OpCode::Verify as u8);
    //     assert_eq!(packet[0x03], 0x22);
    //     assert_eq!(packet[0x04..0x06], [0x04, 0x00]);
    //     assert_eq!(packet[0x06..0x46].as_ref(), signature.as_ref());
    //     assert_eq!(packet[0x46..0x86].as_ref(), public_key.as_ref());
    // }
}
