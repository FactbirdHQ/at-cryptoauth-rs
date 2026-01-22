//! Compressed certificate format for ATECC608 devices
//!
//! This module implements the ATECC-specific 72-byte compressed certificate format
//! as defined in Microchip's Application Note (Atmel-8974).
//!
//! The compressed format stores only the dynamic parts of a certificate:
//! - Signature (64 bytes: R + S)
//! - Encoded date (3 bytes)
//! - Signer ID (2 bytes)
//! - Template ID (1 byte)
//! - Chain ID (1 byte)
//! - Serial number source (1 byte)

use der::{asn1::GeneralizedTime, DateTime};
use p256::ecdsa::DerSignature;

use crate::{
    command::Serial,
    error::{Error, ErrorKind},
    memory::Slot,
    PublicKey,
};

use super::time::{Time, Validity};

/// 3-byte date encoding per Microchip format
///
/// Layout (24 bits total, little-endian):
/// - Bits 0-4: Year (years since 2000, valid 0-31 = 2000-2031)
/// - Bits 5-8: Month (1-12)
/// - Bits 9-13: Day (1-31)
/// - Bits 14-18: Hour (0-23)
/// - Bits 19-23: Expire years (0-31 years validity)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedDate(u32);

impl CompressedDate {
    // Bit field masks and offsets
    const YEAR_MASK: u32 = 0x1F;        // 5 bits
    const YEAR_OFFSET: u32 = 0;
    const MONTH_MASK: u32 = 0x0F;       // 4 bits
    const MONTH_OFFSET: u32 = 5;
    const DAY_MASK: u32 = 0x1F;         // 5 bits
    const DAY_OFFSET: u32 = 9;
    const HOUR_MASK: u32 = 0x1F;        // 5 bits
    const HOUR_OFFSET: u32 = 14;
    const EXPIRE_MASK: u32 = 0x1F;      // 5 bits
    const EXPIRE_OFFSET: u32 = 19;

    /// Create a new CompressedDate with all fields set to 0
    pub const fn new() -> Self {
        Self(0)
    }

    /// Get the year offset from 2000 (0-31)
    pub const fn year(&self) -> u8 {
        ((self.0 >> Self::YEAR_OFFSET) & Self::YEAR_MASK) as u8
    }

    /// Set the year offset and return self (builder pattern)
    pub const fn with_year(self, year: u8) -> Self {
        let cleared = self.0 & !(Self::YEAR_MASK << Self::YEAR_OFFSET);
        Self(cleared | (((year as u32) & Self::YEAR_MASK) << Self::YEAR_OFFSET))
    }

    /// Get the month (1-12)
    pub const fn month(&self) -> u8 {
        ((self.0 >> Self::MONTH_OFFSET) & Self::MONTH_MASK) as u8
    }

    /// Set the month and return self (builder pattern)
    pub const fn with_month(self, month: u8) -> Self {
        let cleared = self.0 & !(Self::MONTH_MASK << Self::MONTH_OFFSET);
        Self(cleared | (((month as u32) & Self::MONTH_MASK) << Self::MONTH_OFFSET))
    }

    /// Get the day of month (1-31)
    pub const fn day(&self) -> u8 {
        ((self.0 >> Self::DAY_OFFSET) & Self::DAY_MASK) as u8
    }

    /// Set the day and return self (builder pattern)
    pub const fn with_day(self, day: u8) -> Self {
        let cleared = self.0 & !(Self::DAY_MASK << Self::DAY_OFFSET);
        Self(cleared | (((day as u32) & Self::DAY_MASK) << Self::DAY_OFFSET))
    }

    /// Get the hour (0-23)
    pub const fn hour(&self) -> u8 {
        ((self.0 >> Self::HOUR_OFFSET) & Self::HOUR_MASK) as u8
    }

    /// Set the hour and return self (builder pattern)
    pub const fn with_hour(self, hour: u8) -> Self {
        let cleared = self.0 & !(Self::HOUR_MASK << Self::HOUR_OFFSET);
        Self(cleared | (((hour as u32) & Self::HOUR_MASK) << Self::HOUR_OFFSET))
    }

    /// Get the certificate validity in years (0-31)
    pub const fn expire_years(&self) -> u8 {
        ((self.0 >> Self::EXPIRE_OFFSET) & Self::EXPIRE_MASK) as u8
    }

    /// Set the expire years and return self (builder pattern)
    pub const fn with_expire_years(self, years: u8) -> Self {
        let cleared = self.0 & !(Self::EXPIRE_MASK << Self::EXPIRE_OFFSET);
        Self(cleared | (((years as u32) & Self::EXPIRE_MASK) << Self::EXPIRE_OFFSET))
    }
}

impl CompressedDate {
    /// Base year for compressed date encoding
    pub const BASE_YEAR: u16 = 2000;

    /// Maximum year offset (5 bits)
    pub const MAX_YEAR_OFFSET: u8 = 31;

    /// Maximum expire years (5 bits)
    pub const MAX_EXPIRE_YEARS: u8 = 31;

    /// Convert from X.509 Validity to compressed date format
    pub fn from_validity(validity: &Validity) -> Result<Self, Error> {
        let issue_date = validity.not_before.to_date_time();
        let expire_date = validity.not_after.to_date_time();

        // Calculate year offset from 2000
        let year_offset = issue_date
            .year()
            .checked_sub(Self::BASE_YEAR)
            .ok_or(ErrorKind::BadParam)?;

        if year_offset > Self::MAX_YEAR_OFFSET as u16 {
            return Err(ErrorKind::BadParam.into());
        }

        // Calculate validity period in years
        let expire_years = expire_date
            .year()
            .checked_sub(issue_date.year())
            .ok_or(ErrorKind::BadParam)?;

        if expire_years > Self::MAX_EXPIRE_YEARS as u16 {
            return Err(ErrorKind::BadParam.into());
        }

        Ok(Self::new()
            .with_year(year_offset as u8)
            .with_month(issue_date.month())
            .with_day(issue_date.day())
            .with_hour(issue_date.hour())
            .with_expire_years(expire_years as u8))
    }

    /// Convert compressed date to X.509 Validity
    pub fn to_validity(&self) -> Result<Validity, Error> {
        let issue_year = Self::BASE_YEAR + self.year() as u16;
        let expire_year = issue_year + self.expire_years() as u16;

        // Create issue date (second and nanosecond are 0)
        let issue_datetime = DateTime::new(issue_year, self.month(), self.day(), self.hour(), 0, 0)
            .map_err(|_| ErrorKind::BadParam)?;

        // Create expire date (same month/day/hour, different year)
        let expire_datetime =
            DateTime::new(expire_year, self.month(), self.day(), self.hour(), 0, 0)
                .map_err(|_| ErrorKind::BadParam)?;

        // Convert to Time (use GeneralizedTime for years >= 2050, UTCTime otherwise)
        let not_before = if issue_year >= 2050 {
            Time::GeneralTime(
                GeneralizedTime::from_date_time(issue_datetime)
            )
        } else {
            Time::UtcTime(
                der::asn1::UtcTime::from_date_time(issue_datetime)
                    .map_err(|_| ErrorKind::BadParam)?,
            )
        };

        let not_after = if expire_year >= 2050 {
            Time::GeneralTime(
                GeneralizedTime::from_date_time(expire_datetime)
            )
        } else {
            Time::UtcTime(
                der::asn1::UtcTime::from_date_time(expire_datetime)
                    .map_err(|_| ErrorKind::BadParam)?,
            )
        };

        Ok(Validity {
            not_before,
            not_after,
        })
    }

    /// Convert to 3-byte array for storage
    pub fn to_bytes(&self) -> [u8; 3] {
        let raw = self.0.to_le_bytes();
        [raw[0], raw[1], raw[2]]
    }

    /// Create from 3-byte array
    pub fn from_bytes(bytes: [u8; 3]) -> Self {
        let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
        Self(raw)
    }
}

/// Source of certificate serial number
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SerialSource {
    /// Serial is stored in a slot on the device
    Stored = 0x00,
    /// Serial is 0x40 | device_sn[0..9] (device certificates only)
    DeviceSerial = 0x01,
    /// Serial is 0x40 | signer_id[0..2] (signer certificates only)
    SignerId = 0x02,
    /// Serial is SHA256(subject public key + encoded dates) with upper 2 bits = 01
    PubKeyHash = 0x03,
    /// Serial is SHA256(device SN + encoded dates) with upper 2 bits = 01
    DeviceSerialHash = 0x04,
}

impl SerialSource {
    /// Generate serial number into provided buffer
    ///
    /// Returns the slice of the buffer containing the serial number.
    /// The serial number format depends on the source type.
    pub fn generate<'a>(
        &self,
        device_serial: &Serial,
        signer_id: u16,
        output: &'a mut [u8; 16],
    ) -> Result<&'a [u8], Error> {
        match self {
            SerialSource::Stored => {
                // Stored serial is handled externally
                Err(ErrorKind::BadParam.into())
            }
            SerialSource::DeviceSerial => {
                // 0x40 | device_sn[0..9] = 10 bytes total
                output[0] = 0x40;
                output[1..10].copy_from_slice(device_serial.as_ref());
                Ok(&output[..10])
            }
            SerialSource::SignerId => {
                // 0x40 | signer_id[0..2] = 3 bytes total
                output[0] = 0x40;
                output[1..3].copy_from_slice(&signer_id.to_be_bytes());
                Ok(&output[..3])
            }
            SerialSource::PubKeyHash | SerialSource::DeviceSerialHash => {
                // Hash-based serials require SHA256 computation on device
                // This is a placeholder - actual implementation needs device SHA
                Err(ErrorKind::Unimplemented.into())
            }
        }
    }
}

/// 72-byte compressed certificate stored on device
///
/// Layout:
/// - Bytes 0-31: Signature R component
/// - Bytes 32-63: Signature S component
/// - Bytes 64-66: Compressed date (3 bytes)
/// - Bytes 67-68: Signer ID (2 bytes, big-endian)
/// - Byte 69: Template ID
/// - Byte 70: Chain ID
/// - Byte 71: Serial number source
#[derive(Clone, Debug)]
pub struct CompressedCertificate {
    data: [u8; Self::SIZE],
}

impl CompressedCertificate {
    /// Total size of compressed certificate in bytes
    pub const SIZE: usize = 72;

    /// Offset of signature R component
    const SIG_R_OFFSET: usize = 0;
    /// Offset of signature S component
    const SIG_S_OFFSET: usize = 32;
    /// Offset of compressed date
    const DATE_OFFSET: usize = 64;
    /// Offset of signer ID
    const SIGNER_ID_OFFSET: usize = 67;
    /// Offset of template ID
    const TEMPLATE_ID_OFFSET: usize = 69;
    /// Offset of chain ID
    const CHAIN_ID_OFFSET: usize = 70;
    /// Offset of serial source
    const SERIAL_SOURCE_OFFSET: usize = 71;

    /// Create a new compressed certificate from raw data
    pub fn new(data: [u8; Self::SIZE]) -> Self {
        Self { data }
    }

    /// Create a zeroed compressed certificate
    pub fn zeroed() -> Self {
        Self {
            data: [0u8; Self::SIZE],
        }
    }

    /// Get the signature R component (32 bytes)
    pub fn signature_r(&self) -> &[u8; 32] {
        self.data[Self::SIG_R_OFFSET..Self::SIG_S_OFFSET]
            .try_into()
            .unwrap()
    }

    /// Get the signature S component (32 bytes)
    pub fn signature_s(&self) -> &[u8; 32] {
        self.data[Self::SIG_S_OFFSET..Self::DATE_OFFSET]
            .try_into()
            .unwrap()
    }

    /// Set the signature from R and S components
    pub fn set_signature(&mut self, r: &[u8; 32], s: &[u8; 32]) {
        self.data[Self::SIG_R_OFFSET..Self::SIG_S_OFFSET].copy_from_slice(r);
        self.data[Self::SIG_S_OFFSET..Self::DATE_OFFSET].copy_from_slice(s);
    }

    /// Convert the stored signature to a DER-encoded signature
    pub fn to_der_signature(&self) -> Result<DerSignature, Error> {
        // Combine R and S into a fixed-size signature
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(self.signature_r());
        sig_bytes[32..].copy_from_slice(self.signature_s());

        // Convert to p256 Signature first, then to DER
        let signature = p256::ecdsa::Signature::from_slice(&sig_bytes)
            .map_err(|_| ErrorKind::BadParam)?;

        Ok(signature.to_der())
    }

    /// Set the signature from a DER-encoded signature
    pub fn set_signature_from_der(&mut self, sig: &DerSignature) -> Result<(), Error> {
        // Convert DER to fixed-size format
        let signature = p256::ecdsa::Signature::from_der(sig.as_bytes())
            .map_err(|_| ErrorKind::BadParam)?;

        let bytes = signature.to_bytes();
        self.data[Self::SIG_R_OFFSET..Self::SIG_S_OFFSET].copy_from_slice(&bytes[..32]);
        self.data[Self::SIG_S_OFFSET..Self::DATE_OFFSET].copy_from_slice(&bytes[32..]);

        Ok(())
    }

    /// Get the encoded date
    pub fn encoded_date(&self) -> CompressedDate {
        let bytes: [u8; 3] = self.data[Self::DATE_OFFSET..Self::SIGNER_ID_OFFSET]
            .try_into()
            .unwrap();
        CompressedDate::from_bytes(bytes)
    }

    /// Set the encoded date
    pub fn set_encoded_date(&mut self, date: CompressedDate) {
        let bytes = date.to_bytes();
        self.data[Self::DATE_OFFSET..Self::SIGNER_ID_OFFSET].copy_from_slice(&bytes);
    }

    /// Get the signer ID (big-endian)
    pub fn signer_id(&self) -> u16 {
        u16::from_be_bytes(
            self.data[Self::SIGNER_ID_OFFSET..Self::TEMPLATE_ID_OFFSET]
                .try_into()
                .unwrap(),
        )
    }

    /// Set the signer ID
    pub fn set_signer_id(&mut self, id: u16) {
        self.data[Self::SIGNER_ID_OFFSET..Self::TEMPLATE_ID_OFFSET]
            .copy_from_slice(&id.to_be_bytes());
    }

    /// Get the template ID
    pub fn template_id(&self) -> u8 {
        self.data[Self::TEMPLATE_ID_OFFSET]
    }

    /// Set the template ID
    pub fn set_template_id(&mut self, id: u8) {
        self.data[Self::TEMPLATE_ID_OFFSET] = id;
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> u8 {
        self.data[Self::CHAIN_ID_OFFSET]
    }

    /// Set the chain ID
    pub fn set_chain_id(&mut self, id: u8) {
        self.data[Self::CHAIN_ID_OFFSET] = id;
    }

    /// Get the serial number source
    pub fn serial_source(&self) -> u8 {
        self.data[Self::SERIAL_SOURCE_OFFSET]
    }

    /// Set the serial number source
    pub fn set_serial_source(&mut self, source: SerialSource) {
        self.data[Self::SERIAL_SOURCE_OFFSET] = source as u8;
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.data
    }

    /// Get mutable access to the raw bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8; Self::SIZE] {
        &mut self.data
    }
}

impl Default for CompressedCertificate {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl AsRef<[u8]> for CompressedCertificate {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for CompressedCertificate {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl TryFrom<&[u8]> for CompressedCertificate {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != Self::SIZE {
            return Err(ErrorKind::InvalidSize.into());
        }
        let mut data = [0u8; Self::SIZE];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }
}

/// Location of a dynamic element in the DER template
#[derive(Clone, Copy, Debug, Default)]
pub struct CertElement {
    /// Offset from start of template
    pub offset: u16,
    /// Number of bytes to copy
    pub count: u8,
}

impl CertElement {
    /// Create a new certificate element location
    pub const fn new(offset: u16, count: u8) -> Self {
        Self { offset, count }
    }
}

/// Template-based certificate definition
///
/// This structure defines how to reconstruct a full X.509 certificate
/// from a compressed certificate and a DER template.
pub struct CertificateDefinition<'a> {
    /// DER template with static content
    pub template: &'a [u8],
    /// Where to insert signature
    pub signature: CertElement,
    /// Where to insert public key X coordinate
    pub public_key_x: CertElement,
    /// Where to insert public key Y coordinate
    pub public_key_y: CertElement,
    /// Where to insert issue date
    pub issue_date: CertElement,
    /// Where to insert expire date
    pub expire_date: CertElement,
    /// Where to insert serial number
    pub serial_number: CertElement,
    /// How to generate serial number
    pub serial_source: SerialSource,
    /// Slot where compressed certificate is stored
    pub compressed_slot: Slot,
    /// Slot where public key is stored (or generated from)
    pub public_key_slot: Slot,
}

impl<'a> CertificateDefinition<'a> {
    /// Reconstruct full DER certificate from compressed cert + template
    ///
    /// # Arguments
    /// * `compressed` - The compressed certificate data
    /// * `public_key` - The subject's public key
    /// * `serial` - Pre-generated serial number bytes
    /// * `output` - Buffer to write the reconstructed DER certificate
    ///
    /// # Returns
    /// The number of bytes written to output, or an error
    pub fn reconstruct(
        &self,
        compressed: &CompressedCertificate,
        public_key: &PublicKey,
        serial: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        // Verify output buffer is large enough
        if output.len() < self.template.len() {
            return Err(ErrorKind::SmallBuffer.into());
        }

        // Copy template to output
        let len = self.template.len();
        output[..len].copy_from_slice(self.template);

        // Insert public key X coordinate
        if self.public_key_x.count > 0 {
            let offset = self.public_key_x.offset as usize;
            let count = self.public_key_x.count as usize;
            if offset + count > len || count > 32 {
                return Err(ErrorKind::BadParam.into());
            }
            output[offset..offset + count].copy_from_slice(&public_key.as_ref()[..count]);
        }

        // Insert public key Y coordinate
        if self.public_key_y.count > 0 {
            let offset = self.public_key_y.offset as usize;
            let count = self.public_key_y.count as usize;
            if offset + count > len || count > 32 {
                return Err(ErrorKind::BadParam.into());
            }
            output[offset..offset + count].copy_from_slice(&public_key.as_ref()[32..32 + count]);
        }

        // Insert serial number
        if self.serial_number.count > 0 {
            let offset = self.serial_number.offset as usize;
            let count = self.serial_number.count as usize;
            if offset + count > len || count > serial.len() {
                return Err(ErrorKind::BadParam.into());
            }
            output[offset..offset + count].copy_from_slice(&serial[..count]);
        }

        // Get validity from compressed date and encode it
        let validity = compressed.encoded_date().to_validity()?;

        // Insert issue date (as ASN.1 UTCTime or GeneralizedTime)
        if self.issue_date.count > 0 {
            let offset = self.issue_date.offset as usize;
            let count = self.issue_date.count as usize;
            if offset + count > len {
                return Err(ErrorKind::BadParam.into());
            }
            let date_bytes = encode_time(&validity.not_before)?;
            if count <= date_bytes.len() {
                output[offset..offset + count].copy_from_slice(&date_bytes[..count]);
            }
        }

        // Insert expire date
        if self.expire_date.count > 0 {
            let offset = self.expire_date.offset as usize;
            let count = self.expire_date.count as usize;
            if offset + count > len {
                return Err(ErrorKind::BadParam.into());
            }
            let date_bytes = encode_time(&validity.not_after)?;
            if count <= date_bytes.len() {
                output[offset..offset + count].copy_from_slice(&date_bytes[..count]);
            }
        }

        // Insert signature (DER format: SEQUENCE { INTEGER r, INTEGER s })
        if self.signature.count > 0 {
            let offset = self.signature.offset as usize;
            let count = self.signature.count as usize;
            if offset + count > len {
                return Err(ErrorKind::BadParam.into());
            }
            let der_sig = compressed.to_der_signature()?;
            let sig_bytes = der_sig.as_bytes();
            if count <= sig_bytes.len() {
                output[offset..offset + count].copy_from_slice(&sig_bytes[..count]);
            }
        }

        Ok(len)
    }
}

/// Encode a Time value to bytes (simplified - just the date portion)
fn encode_time(time: &Time) -> Result<[u8; 15], Error> {
    let dt = time.to_date_time();
    let mut buf = [0u8; 15];

    // Format as YYMMDDHHmmssZ (UTCTime) or YYYYMMDDHHmmssZ (GeneralizedTime)
    match time {
        Time::UtcTime(_) => {
            // YYMMDDHHmmssZ (13 bytes)
            let year = dt.year() % 100;
            buf[0] = b'0' + (year / 10) as u8;
            buf[1] = b'0' + (year % 10) as u8;
            buf[2] = b'0' + (dt.month() / 10);
            buf[3] = b'0' + (dt.month() % 10);
            buf[4] = b'0' + (dt.day() / 10);
            buf[5] = b'0' + (dt.day() % 10);
            buf[6] = b'0' + (dt.hour() / 10);
            buf[7] = b'0' + (dt.hour() % 10);
            buf[8] = b'0' + (dt.minutes() / 10);
            buf[9] = b'0' + (dt.minutes() % 10);
            buf[10] = b'0' + (dt.seconds() / 10);
            buf[11] = b'0' + (dt.seconds() % 10);
            buf[12] = b'Z';
        }
        Time::GeneralTime(_) => {
            // YYYYMMDDHHmmssZ (15 bytes)
            let year = dt.year();
            buf[0] = b'0' + (year / 1000) as u8;
            buf[1] = b'0' + ((year / 100) % 10) as u8;
            buf[2] = b'0' + ((year / 10) % 10) as u8;
            buf[3] = b'0' + (year % 10) as u8;
            buf[4] = b'0' + (dt.month() / 10);
            buf[5] = b'0' + (dt.month() % 10);
            buf[6] = b'0' + (dt.day() / 10);
            buf[7] = b'0' + (dt.day() % 10);
            buf[8] = b'0' + (dt.hour() / 10);
            buf[9] = b'0' + (dt.hour() % 10);
            buf[10] = b'0' + (dt.minutes() / 10);
            buf[11] = b'0' + (dt.minutes() % 10);
            buf[12] = b'0' + (dt.seconds() / 10);
            buf[13] = b'0' + (dt.seconds() % 10);
            buf[14] = b'Z';
        }
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::UtcTime;

    #[test]
    fn test_compressed_date_roundtrip() {
        // Create a validity period: 2023-06-15 10:00 to 2028-06-15 10:00
        let not_before = Time::UtcTime(
            UtcTime::from_date_time(DateTime::new(2023, 6, 15, 10, 0, 0).unwrap()).unwrap(),
        );
        let not_after = Time::UtcTime(
            UtcTime::from_date_time(DateTime::new(2028, 6, 15, 10, 0, 0).unwrap()).unwrap(),
        );
        let validity = Validity {
            not_before,
            not_after,
        };

        // Convert to compressed date
        let compressed = CompressedDate::from_validity(&validity).unwrap();

        // Verify fields
        assert_eq!(compressed.year(), 23); // 2023 - 2000
        assert_eq!(compressed.month(), 6);
        assert_eq!(compressed.day(), 15);
        assert_eq!(compressed.hour(), 10);
        assert_eq!(compressed.expire_years(), 5);

        // Convert back to validity
        let decoded = compressed.to_validity().unwrap();
        let decoded_issue = decoded.not_before.to_date_time();
        let decoded_expire = decoded.not_after.to_date_time();

        assert_eq!(decoded_issue.year(), 2023);
        assert_eq!(decoded_issue.month(), 6);
        assert_eq!(decoded_issue.day(), 15);
        assert_eq!(decoded_issue.hour(), 10);
        assert_eq!(decoded_expire.year(), 2028);
    }

    #[test]
    fn test_compressed_date_bytes() {
        let date = CompressedDate::new()
            .with_year(23)
            .with_month(6)
            .with_day(15)
            .with_hour(10)
            .with_expire_years(5);

        let bytes = date.to_bytes();
        let decoded = CompressedDate::from_bytes(bytes);

        assert_eq!(date, decoded);
    }

    #[test]
    fn test_compressed_certificate_signature() {
        let mut cert = CompressedCertificate::zeroed();

        let r = [1u8; 32];
        let s = [2u8; 32];
        cert.set_signature(&r, &s);

        assert_eq!(cert.signature_r(), &r);
        assert_eq!(cert.signature_s(), &s);
    }

    #[test]
    fn test_compressed_certificate_fields() {
        let mut cert = CompressedCertificate::zeroed();

        cert.set_signer_id(0x1234);
        assert_eq!(cert.signer_id(), 0x1234);

        cert.set_template_id(5);
        assert_eq!(cert.template_id(), 5);

        cert.set_chain_id(3);
        assert_eq!(cert.chain_id(), 3);

        cert.set_serial_source(SerialSource::DeviceSerial);
        assert_eq!(cert.serial_source(), SerialSource::DeviceSerial as u8);
    }

    #[test]
    fn test_serial_source_device_serial() {
        // Create a mock serial with known values
        let serial_bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x12];
        let device_serial = Serial::new_for_test(&serial_bytes);

        let mut output = [0u8; 16];
        let result = SerialSource::DeviceSerial
            .generate(&device_serial, 0, &mut output)
            .unwrap();

        assert_eq!(result.len(), 10);
        assert_eq!(result[0], 0x40);
        assert_eq!(&result[1..], &serial_bytes);
    }

    #[test]
    fn test_serial_source_signer_id() {
        // Create a dummy serial (not used for SignerId)
        let serial_bytes = [0u8; 9];
        let device_serial = Serial::new_for_test(&serial_bytes);

        let mut output = [0u8; 16];
        let result = SerialSource::SignerId
            .generate(&device_serial, 0xABCD, &mut output)
            .unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0], 0x40);
        assert_eq!(result[1], 0xAB);
        assert_eq!(result[2], 0xCD);
    }
}
