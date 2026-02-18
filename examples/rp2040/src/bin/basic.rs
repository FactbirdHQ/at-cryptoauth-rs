//! Basic ATECC608 usage example for RP2040
//!
//! This example demonstrates:
//! - Reading the device serial number
//! - Generating SHA256 digests
//! - Generating random numbers
//! - Creating a CSR (Certificate Signing Request)

#![no_std]
#![no_main]

use at_cryptoauth::{
    AtCaClient, cert::attr::AttributeTypeAndValue, memory::Slot, signature::digest::const_oid,
};
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    I2C0_IRQ => embassy_rp::i2c::InterruptHandler<embassy_rp::peripherals::I2C0>;
});

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    defmt::info!("ATECC608 Basic Usage Example");

    let p = embassy_rp::init(Default::default());

    // Initialize I2C - adjust pins as needed for your hardware
    let i2c = embassy_rp::i2c::I2c::new_async(p.I2C0, p.PIN_29, p.PIN_28, Irqs, Default::default());

    let mut client: AtCaClient<CriticalSectionRawMutex, _> = AtCaClient::new(i2c);

    // Read device info
    let info = client.info().await.unwrap();
    defmt::info!("Device info: {:#04x}", info.as_ref());

    // Read serial number
    // Serial number format: bytes [0..2] and [8] are fixed, [2..8] are unique
    let sn = client.memory().serial_number().await.unwrap();
    defmt::info!("Serial number: {:#04x}", sn.as_ref());

    // Compute SHA256 hash
    let message = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let digest = client.sha().digest(&message).await.unwrap();
    defmt::info!("SHA256 digest: {:#04x}", digest.as_ref());

    // Expected digest for the test message
    let expected_digest = [
        0x17, 0xe8, 0x8d, 0xb1, 0x87, 0xaf, 0xd6, 0x2c, 0x16, 0xe5, 0xde, 0xbf, 0x3e, 0x65, 0x27,
        0xcd, 0x00, 0x6b, 0xc0, 0x12, 0xbc, 0x90, 0xb5, 0x1a, 0x81, 0x0c, 0xd8, 0x0c, 0x2d, 0x51,
        0x1f, 0x43,
    ];
    assert_eq!(digest.as_ref(), &expected_digest);
    defmt::info!("SHA256 digest verified!");

    // Generate random bytes
    let mut random = client.random();
    let mut random_bytes = [0u8; 32];
    random.try_fill_bytes_blocking(&mut random_bytes);
    defmt::info!("Random bytes: {:#04x}", random_bytes);

    // Create a Certificate Signing Request (CSR)
    defmt::info!("Creating CSR...");

    // Build subject name: CN=example-device
    let mut cn = at_cryptoauth::der::asn1::SetOf::new();
    cn.insert(AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value: at_cryptoauth::der::AnyRef::new(
            at_cryptoauth::der::Tag::Utf8String,
            b"example-device",
        )
        .unwrap(),
    })
    .unwrap();

    let mut rdn_seq = at_cryptoauth::der::asn1::SequenceOf::new();
    rdn_seq
        .add(at_cryptoauth::cert::name::RelativeDistinguishedName(cn))
        .unwrap();
    let subject = at_cryptoauth::cert::name::RdnSequence(rdn_seq);

    // Create signer using key in slot 2
    let signer = client.signer(Slot::PrivateKey02);

    // Build CSR
    let builder =
        at_cryptoauth::cert::builder::RequestBuilder::new(subject).expect("Create CSR builder");

    let mut buf = [0u8; 256];
    let cert_req =
        at_cryptoauth::cert::builder::Builder::build::<_>(builder, &mut buf, &signer).unwrap();

    defmt::info!("CSR created successfully");

    // Convert to PEM format
    let mut pem_buf = [0u8; 512];
    let pem_len = cert_req
        .to_pem_slice(&mut pem_buf, at_cryptoauth::pem_rfc7468::LineEnding::LF)
        .expect("Generate PEM");

    // Print CSR as ASCII
    defmt::info!("CSR (PEM):");
    defmt::info!("{=[u8]:a}", &pem_buf[..pem_len]);

    defmt::info!("Basic example completed successfully!");
}
