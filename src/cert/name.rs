//! Name-related definitions as defined in X.501 (and updated by RFC 5280).

use crate::impl_newtype;

use super::attr::AttributeTypeAndValue;
use der::asn1::{SequenceOf, SetOf};

const MAX_RDN_SEQ: usize = 1;
const MAX_RDN_ATTRS: usize = 1;

/// X.501 Name as defined in [RFC 5280 Section 4.1.2.4]. X.501 Name is used to represent distinguished names.
///
/// ```text
/// Name ::= CHOICE { rdnSequence  RDNSequence }
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type Name<'a> = RdnSequence<'a>;

/// X.501 RDNSequence as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RdnSequence<'a>(pub SequenceOf<RelativeDistinguishedName<'a>, MAX_RDN_SEQ>);

impl RdnSequence<'_> {
    /// Is this [`RdnSequence`] empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// /// Parse an [`RdnSequence`] string.
// ///
// /// Follows the rules in [RFC 4514].
// ///
// /// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
// impl FromStr for RdnSequence<'_> {
//     type Err = der::Error;

//     fn from_str(s: &str) -> der::Result<Self> {
//         let mut parts_vec = split(s, b',')
//             .map(RelativeDistinguishedName::from_str)
//             .collect::<der::Result<heapless::Vec<_, MAX_RDN_SEQ>>>()?;
//         parts_vec.reverse();

//         let mut parts = SequenceOf::new();
//         for p in parts_vec {
//             parts.add(p);
//         }

//         Ok(Self(parts))
//     }
// }

// /// Serializes the structure according to the rules in [RFC 4514].
// ///
// /// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
// impl fmt::Display for RdnSequence<'_> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         // As per RFC 4514 Section 2.1, the elements are reversed
//         for (i, atv) in self.0.iter().rev().enumerate() {
//             match i {
//                 0 => write!(f, "{}", atv)?,
//                 _ => write!(f, ",{}", atv)?,
//             }
//         }

//         Ok(())
//     }
// }

impl_newtype!(
    RdnSequence<'a>,
    SequenceOf<RelativeDistinguishedName<'a>, MAX_RDN_SEQ>
);

// /// Find the indices of all non-escaped separators.
// fn find(s: &str, b: u8) -> impl '_ + Iterator<Item = usize> {
//     (0..s.len())
//         .filter(move |i| s.as_bytes()[*i] == b)
//         .filter(|i| {
//             let x = i
//                 .checked_sub(2)
//                 .map(|i| s.as_bytes()[i])
//                 .unwrap_or_default();

//             let y = i
//                 .checked_sub(1)
//                 .map(|i| s.as_bytes()[i])
//                 .unwrap_or_default();

//             y != b'\\' || x == b'\\'
//         })
// }

// /// Split a string at all non-escaped separators.
// fn split(s: &str, b: u8) -> impl '_ + Iterator<Item = &'_ str> {
//     let mut prev = 0;
//     find(s, b).chain([s.len()]).map(move |i| {
//         let x = &s[prev..i];
//         prev = i + 1;
//         x
//     })
// }

/// X.501 DistinguishedName as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// DistinguishedName ::=   RDNSequence
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type DistinguishedName<'a> = RdnSequence<'a>;

/// RelativeDistinguishedName as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
///
/// Note that we follow the more common definition above. This technically
/// differs from the definition in X.501, which is:
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndDistinguishedValue
///
/// AttributeTypeAndDistinguishedValue ::= SEQUENCE {
///     type ATTRIBUTE.&id ({SupportedAttributes}),
///     value ATTRIBUTE.&Type({SupportedAttributes}{@type}),
///     primaryDistinguished BOOLEAN DEFAULT TRUE,
///     valuesWithContext SET SIZE (1..MAX) OF SEQUENCE {
///         distingAttrValue [0] ATTRIBUTE.&Type ({SupportedAttributes}{@type}) OPTIONAL,
///         contextList SET SIZE (1..MAX) OF Context
///     } OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelativeDistinguishedName<'a>(pub SetOf<AttributeTypeAndValue<'a>, MAX_RDN_ATTRS>);

// /// Parse a [`RelativeDistinguishedName`] string.
// ///
// /// This function follows the rules in [RFC 4514].
// ///
// /// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
// impl FromStr for RelativeDistinguishedName<'_> {
//     type Err = der::Error;

//     fn from_str(s: &str) -> der::Result<Self> {
//         let parts_vec = split(s, b'+')
//             .map(AttributeTypeAndValue::from_str)
//             .collect::<der::Result<heapless::Vec<_, MAX_RDN_ATTRS>>>()?;

//         parts_vec
//             .into_array()
//             .map_err(|_| der::Error::new(der::ErrorKind::Overflow, Length::new(0)))?
//             .try_into()
//             .map(Self)
//     }
// }

// impl<'a> TryFrom<SequenceOf<AttributeTypeAndValue<'a>, MAX_RDN_ATTRS>>
//     for RelativeDistinguishedName<'a>
// {
//     type Error = der::Error;

//     fn try_from(
//         vec: SequenceOf<AttributeTypeAndValue, MAX_RDN_ATTRS>,
//     ) -> der::Result<RelativeDistinguishedName<'a>> {
//         Ok(RelativeDistinguishedName(SetOf::try_from(vec)?))
//     }
// }

// /// Serializes the structure according to the rules in [RFC 4514].
// ///
// /// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
// impl fmt::Display for RelativeDistinguishedName<'_> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         for (i, atv) in self.0.iter().enumerate() {
//             match i {
//                 0 => write!(f, "{}", atv)?,
//                 _ => write!(f, "+{}", atv)?,
//             }
//         }

//         Ok(())
//     }
// }

impl_newtype!(
    RelativeDistinguishedName<'a>,
    SetOf<AttributeTypeAndValue<'a>, MAX_RDN_ATTRS>
);
