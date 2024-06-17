//! X.509 serial number

use core::fmt::Display;

use der::{
    asn1::{self, IntRef},
    DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader, Result, Tag, ValueOrd,
    Writer,
};

/// [RFC 5280 Section 4.1.2.2.]  Serial Number
///
///   The serial number MUST be a positive integer assigned by the CA to
///   each certificate.  It MUST be unique for each certificate issued by a
///   given CA (i.e., the issuer name and serial number identify a unique
///   certificate).  CAs MUST force the serialNumber to be a non-negative
///   integer.
///
///   Given the uniqueness requirements above, serial numbers can be
///   expected to contain long integers.  Certificate users MUST be able to
///   handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
///   use serialNumber values longer than 20 octets.
///
///   Note: Non-conforming CAs may issue certificates with serial numbers
///   that are negative or zero.  Certificate users SHOULD be prepared to
///   gracefully handle such certificates.
#[derive(Clone, Debug, Eq, PartialEq, ValueOrd, PartialOrd, Ord)]
pub struct SerialNumber<'a> {
    pub(crate) inner: IntRef<'a>,
}

impl<'a> SerialNumber<'a> {
    /// Maximum length in bytes for a [`SerialNumber`]
    pub const MAX_LEN: Length = Length::new(20);

    /// See notes in `SerialNumber::new` and `SerialNumber::decode_value`.
    #[allow(dead_code)]
    pub(crate) const MAX_DECODE_LEN: Length = Length::new(21);

    /// Create a new [`SerialNumber`] from a byte slice.
    ///
    /// The byte slice **must** represent a positive integer.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        let inner = asn1::UintRef::new(bytes)?;

        // The user might give us a 20 byte unsigned integer with a high MSB,
        // which we'd then encode with 21 octets to preserve the sign bit.
        // RFC 5280 is ambiguous about whether this is valid, so we limit
        // `SerialNumber` *encodings* to 20 bytes or fewer while permitting
        // `SerialNumber` *decodings* to have up to 21 bytes below.
        if inner.value_len()? > Self::MAX_LEN {
            return Err(ErrorKind::Overlength.into());
        }

        Ok(Self {
            inner: IntRef::new(inner.as_bytes())?,
        })
    }

    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading zeros stripped.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

// impl<'a> SerialNumber<'a> {
//     /// Generates a random serial number from RNG.
//     ///
//     /// This follows the recommendation the CAB forum [ballot 164] and uses a minimum of 64 bits
//     /// of output from the CSPRNG. This currently defaults to a 17-bytes long serial number.
//     ///
//     /// [ballot 164]: https://cabforum.org/2016/03/31/ballot-164/
//     pub fn generate(rng: &mut impl CryptoRngCore) -> Result<Self> {
//         Self::generate_with_prefix(&[], 17, rng)
//     }

//     /// Generates a random serial number from RNG. Include a prefix value.
//     ///
//     /// This follows the recommendation the CAB forum [ballot 164] and uses a minimum of 64 bits
//     /// of output from the CSPRNG.
//     ///
//     /// The specified length does not include the length of the prefix, the maximum length must be
//     /// equal or below 19 (to account for leading sign disambiguation, and the maximum length of 20).
//     ///
//     /// [ballot 164]: https://cabforum.org/2016/03/31/ballot-164/
//     pub fn generate_with_prefix(
//         prefix: &[u8],
//         rand_len: usize,
//         rng: &mut impl CryptoRngCore,
//     ) -> Result<Self> {
//         // CABF requires a minimum of 64 bits of random
//         if rand_len < 8 {
//             return Err(ErrorKind::Failed.into());
//         }

//         if rand_len + prefix.len() > 19 {
//             return Err(ErrorKind::Failed.into());
//         }

//         let mut buf = vec![0; prefix.len() + rand_len];
//         buf[..prefix.len()].copy_from_slice(prefix);

//         let rand_buf = &mut buf[prefix.len()..];

//         // Make sure the first byte isn't 0, [`Int`] will otherwise optimize out the leading zeros,
//         // shorten the value of the serial and trigger false positives in linters.
//         while rand_buf[0] == 0 {
//             rng.fill_bytes(rand_buf);
//         }

//         Self::new(&buf)
//     }
// }

impl<'a> EncodeValue for SerialNumber<'a> {
    fn value_len(&self) -> Result<Length> {
        self.inner.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        self.inner.encode_value(writer)
    }
}

impl<'a> DecodeValue<'a> for SerialNumber<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let inner = IntRef::decode_value(reader, header)?;
        let serial = Self { inner };

        // P::check_serial_number(&serial)?;

        Ok(serial)
    }
}

impl FixedTag for SerialNumber<'_> {
    const TAG: Tag = <IntRef as FixedTag>::TAG;
}

impl Display for SerialNumber<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut iter = self.as_bytes().iter().peekable();

        while let Some(byte) = iter.next() {
            match iter.peek() {
                Some(_) => write!(f, "{:02X}:", byte)?,
                None => write!(f, "{:02X}", byte)?,
            }
        }

        Ok(())
    }
}

// macro_rules! impl_from {
//     ($source:ty) => {
//         impl From<$source> for SerialNumber<'_> {
//             fn from(inner: $source) -> Self {
//                 let serial_number = &inner.to_be_bytes()[..];
//                 let serial_number = asn1::UintRef::new(serial_number).unwrap();

//                 // This could only fail if the big endian representation was to be more than 20
//                 // bytes long. Because it's only implemented for up to u64 / usize (8 bytes).
//                 SerialNumber::new(serial_number.as_bytes()).unwrap()
//             }
//         }
//     };
// }

// impl_from!(u8);
// impl_from!(u16);
// impl_from!(u32);
// impl_from!(u64);
// impl_from!(usize);
