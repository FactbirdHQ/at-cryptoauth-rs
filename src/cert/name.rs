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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RdnSequence<'a>(pub SequenceOf<RelativeDistinguishedName<'a>, MAX_RDN_SEQ>);

impl RdnSequence<'_> {
    /// Is this [`RdnSequence`] empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl_newtype!(
    RdnSequence<'a>,
    SequenceOf<RelativeDistinguishedName<'a>, MAX_RDN_SEQ>
);

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelativeDistinguishedName<'a>(pub SetOf<AttributeTypeAndValue<'a>, MAX_RDN_ATTRS>);

impl_newtype!(
    RelativeDistinguishedName<'a>,
    SetOf<AttributeTypeAndValue<'a>, MAX_RDN_ATTRS>
);
