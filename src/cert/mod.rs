//! X.509 certificate handling for ATECC608 compressed format.
//!
//! This module provides types and functions for working with X.509 certificates
//! in both standard DER/PEM format and ATECC608's compressed 72-byte format.
//!
//! ## Modules
//!
//! - [`builder`]: Certificate builder for creating new certificates
//! - [`certificate`]: X.509 certificate parsing and generation
//! - [`compressed`]: ATECC608 compressed certificate format (72 bytes)
//! - [`request`]: Certificate Signing Request (CSR) support
//! - [`time`]: Validity period and timestamp handling
//! - [`name`]: X.500 Distinguished Name support
//! - [`attr`]: X.509 attribute types
//! - [`ext`]: X.509 extensions
//! - [`serial_number`]: Certificate serial number handling
//! - [`pem`]: PEM encoding/decoding utilities

pub mod attr;
pub mod builder;
pub mod certificate;
pub mod compressed;
pub mod ext;
mod macros;
pub mod name;
pub mod pem;
pub mod request;
pub mod serial_number;
pub mod time;
