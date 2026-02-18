//! Compressed Certificate example for RP2040
//!
//! This example demonstrates:
//! - Reading compressed certificates from device slots
//! - Writing compressed certificates to device slots
//! - Working with compressed date encoding
//! - Certificate definition and reconstruction concepts
//!
//! Note: This example shows the API usage. Actual certificate reconstruction
//! requires a valid certificate template which is device/application specific.

#![no_std]
#![no_main]

use at_cryptoauth::{
    AtCaClient,
    cert::compressed::{
        CertElement, CertificateDefinition, CompressedCertificate, CompressedDate, SerialSource,
    },
    memory::Slot,
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
    defmt::info!("ATECC608 Certificate Example");

    let p = embassy_rp::init(Default::default());

    // Initialize I2C - adjust pins as needed for your hardware
    let i2c = embassy_rp::i2c::I2c::new_async(p.I2C0, p.PIN_29, p.PIN_28, Irqs, Default::default());

    let mut client: AtCaClient<CriticalSectionRawMutex, _> = AtCaClient::new(i2c);

    // Read device serial number (used for certificate serial generation)
    let sn = client.memory().serial_number().await.unwrap();
    defmt::info!("Device serial: {:#04x}", sn.as_ref());

    // =========================================================================
    // Part 1: Working with CompressedDate
    // =========================================================================
    defmt::info!("--- Compressed Date Demo ---");

    // Create a compressed date representing:
    // Issue: 2024-06-15 10:00
    // Validity: 5 years
    let date = CompressedDate::new()
        .with_year(24) // Year offset from 2000 (2024 = 24)
        .with_month(6) // June
        .with_day(15) // 15th
        .with_hour(10) // 10:00
        .with_expire_years(5); // Valid for 5 years

    defmt::info!(
        "Compressed date: year={}, month={}, day={}, hour={}, expire_years={}",
        date.year(),
        date.month(),
        date.day(),
        date.hour(),
        date.expire_years()
    );

    // Convert to 3-byte representation
    let date_bytes = date.to_bytes();
    defmt::info!("Date as bytes: {:#04x}", date_bytes);

    // Roundtrip test
    let date_decoded = CompressedDate::from_bytes(date_bytes);
    assert_eq!(date.year(), date_decoded.year());
    assert_eq!(date.month(), date_decoded.month());
    defmt::info!("Date roundtrip verified!");

    // =========================================================================
    // Part 2: Working with CompressedCertificate
    // =========================================================================
    defmt::info!("--- Compressed Certificate Demo ---");

    // Create a new compressed certificate
    let mut cert = CompressedCertificate::zeroed();

    // Set signature (R and S components, 32 bytes each)
    let sig_r = [0x11u8; 32];
    let sig_s = [0x22u8; 32];
    cert.set_signature(&sig_r, &sig_s);

    // Set encoded date
    cert.set_encoded_date(date);

    // Set signer ID (identifies the CA that signed this certificate)
    cert.set_signer_id(0xABCD);

    // Set template and chain IDs (application-specific)
    cert.set_template_id(1);
    cert.set_chain_id(0);

    // Set serial number source
    cert.set_serial_source(SerialSource::DeviceSerial);

    defmt::info!("Certificate fields:");
    defmt::info!("  Signature R: {:#04x}", cert.signature_r()[..8]);
    defmt::info!("  Signature S: {:#04x}", cert.signature_s()[..8]);
    defmt::info!("  Signer ID: {:#06x}", cert.signer_id());
    defmt::info!("  Template ID: {}", cert.template_id());
    defmt::info!("  Chain ID: {}", cert.chain_id());
    defmt::info!("  Serial source: {}", cert.serial_source());

    // =========================================================================
    // Part 3: Reading/Writing Compressed Certificates from Device
    // =========================================================================
    defmt::info!("--- Device Certificate I/O Demo ---");

    // Note: Writing to certificate slots may require the data zone to be locked
    // and appropriate slot configuration. This example shows the API usage.

    // Try to read a compressed certificate from slot 9
    defmt::info!("Reading compressed certificate from slot 9...");
    match client
        .memory()
        .read_compressed_cert(Slot::Certificate09)
        .await
    {
        Ok(stored_cert) => {
            defmt::info!("Read certificate successfully!");
            defmt::info!("  Signer ID: {:#06x}", stored_cert.signer_id());
            defmt::info!("  Template ID: {}", stored_cert.template_id());

            let stored_date = stored_cert.encoded_date();
            defmt::info!(
                "  Date: {}-{:02}-{:02} {:02}:00, valid {} years",
                2000 + stored_date.year() as u16,
                stored_date.month(),
                stored_date.day(),
                stored_date.hour(),
                stored_date.expire_years()
            );
        }
        Err(e) => {
            defmt::warn!("Could not read certificate: {:?}", defmt::Debug2Format(&e));
            defmt::info!("(This is expected if the slot is empty or locked)");
        }
    }

    // =========================================================================
    // Part 4: Certificate Definition Example
    // =========================================================================
    defmt::info!("--- Certificate Definition Demo ---");

    // A CertificateDefinition describes how to reconstruct a full X.509 certificate
    // from a compressed certificate. In practice, you would:
    //
    // 1. Generate a certificate template (DER-encoded X.509 with placeholder values)
    // 2. Identify the byte offsets of dynamic elements (pubkey, dates, serial, signature)
    // 3. Create the CertificateDefinition with those offsets
    // 4. Use read_certificate() to reconstruct certificates at runtime

    // This is a minimal example template (NOT a valid certificate)
    static EXAMPLE_TEMPLATE: &[u8] = &[
        // SEQUENCE header (certificate wrapper)
        0x30, 0x82, 0x01,
        0x00,
        // ... in a real template, this would contain the full DER structure
        // with placeholder bytes for dynamic elements
    ];

    let _cert_def = CertificateDefinition {
        template: EXAMPLE_TEMPLATE,
        // Offsets where to insert dynamic data (these are examples only)
        signature: CertElement::new(100, 72), // DER signature location
        public_key_x: CertElement::new(50, 32), // X coordinate of public key
        public_key_y: CertElement::new(82, 32), // Y coordinate of public key
        issue_date: CertElement::new(120, 13), // UTCTime is 13 bytes
        expire_date: CertElement::new(135, 13),
        serial_number: CertElement::new(10, 10), // Serial number location
        serial_source: SerialSource::DeviceSerial, // How to generate serial
        compressed_slot: Slot::Certificate09,    // Where compressed cert is stored
        public_key_slot: Slot::Certificate0a,    // Where public key is stored
    };

    defmt::info!("Certificate definition created (example only)");
    defmt::info!("In production, use a real DER template with correct offsets");

    // To reconstruct a certificate, you would call:
    // let mut output = [0u8; 512];
    // let len = client.memory().read_certificate(&cert_def, &mut output).await?;
    // The output[..len] would contain the full DER-encoded X.509 certificate

    // =========================================================================
    // Part 5: Serial Number Generation
    // =========================================================================
    defmt::info!("--- Serial Number Generation Demo ---");

    // Generate serial number using device serial
    let mut serial_buf = [0u8; 16];
    match SerialSource::DeviceSerial.generate(&sn, 0, &mut serial_buf) {
        Ok(serial) => {
            defmt::info!("Generated serial (DeviceSerial): {:#04x}", serial);
            // Format: 0x40 | device_sn[0..9]
            assert_eq!(serial[0], 0x40);
            assert_eq!(&serial[1..], sn.as_ref());
        }
        Err(e) => {
            defmt::error!("Failed to generate serial: {:?}", defmt::Debug2Format(&e));
        }
    }

    // Generate serial number using signer ID
    let signer_id = 0x1234u16;
    match SerialSource::SignerId.generate(&sn, signer_id, &mut serial_buf) {
        Ok(serial) => {
            defmt::info!("Generated serial (SignerId): {:#04x}", serial);
            // Format: 0x40 | signer_id[0..2]
            assert_eq!(serial[0], 0x40);
            assert_eq!(serial[1], 0x12);
            assert_eq!(serial[2], 0x34);
        }
        Err(e) => {
            defmt::error!("Failed to generate serial: {:?}", defmt::Debug2Format(&e));
        }
    }

    defmt::info!("Certificate example completed successfully!");
}
