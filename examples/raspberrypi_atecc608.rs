// $ CROSS_COMPILE=arm-none-linux-gnueabihf- cargo b \
//   --example raspberrypi_atecc608 --features std \
//   --target armv7-unknown-linux-gnueabihf
//
// $ scp target/armv7-unknown-linux-gnueabihf/debug/examples/raspberrypi_atecc608 \
//   pi@${PI_IP_ADDR}:/home/pi/
//
// $ ssh pi@${PI_IP_ADDR} "RUST_LOG=info ./raspberrypi_atecc608"
use at_cryptoauth::client::AtCaClient;
use at_cryptoauth::command::Block;
use at_cryptoauth::memory::{Size, Slot, Zone};
use at_cryptoauth::tngtls::{TrustAndGo, AES_KEY, AUTH_PRIVATE_KEY, SIGN_PRIVATE_KEY};
use core::fmt::Debug;
use embedded_hal::blocking::delay::DelayUs;
use embedded_hal::blocking::i2c::{Read, Write};
use linux_embedded_hal::Delay;
use linux_embedded_hal::I2cdev;
use log::info;
use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use std::error::Error;
use std::str;

const I2C_PATH: &str = "/dev/i2c-1";
const ATECC608_ADDR: u16 = 0xc0 >> 1;

// Taken from atca_test.c
const AES_KEY_CONTENT: [u8; 0x40] = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63,
    0x70, 0x58, 0x71, 0x0B, 0x58, 0xE1, 0xE6, 0x65, 0xD3, 0xD2, 0xF5, 0xB4, 0x65, 0x17, 0x64, 0x03,
    0x11, 0x44, 0x43, 0xFA, 0x8E, 0x96, 0x14, 0x84, 0x5E, 0xC7, 0x29, 0x6C, 0xD1, 0x3B, 0xC9, 0xDC,
];

const PROVISION_KEYS: &[Slot] = &[AUTH_PRIVATE_KEY, SIGN_PRIVATE_KEY];

const TEST_PRIVATE_KEY: [u8; 32] = [
    /* 0x00, 0x00, 0x00, 0x00, */
    0x87, 0x8F, 0x0A, 0xB6, 0xA5, 0x26, 0xD7, 0x11, 0x1C, 0x26, 0xE6, 0x17, 0x08, 0x10, 0x79, 0x6E,
    0x7B, 0x33, 0x00, 0x7F, 0x83, 0x2B, 0x8D, 0x64, 0x46, 0x7E, 0xD6, 0xF8, 0x70, 0x53, 0x7A, 0x19,
];

const TEST_PUBLIC_KEY: [u8; 64] = [
    0x8F, 0x8D, 0x18, 0x2B, 0xD8, 0x19, 0x04, 0x85, 0x82, 0xA9, 0x92, 0x7E, 0xA0, 0xC5, 0x6D, 0xEF,
    0xB4, 0x15, 0x95, 0x48, 0xE1, 0x1C, 0xA5, 0xF7, 0xAB, 0xAC, 0x45, 0xBB, 0xCE, 0x76, 0x81, 0x5B,
    0xE5, 0xC6, 0x4F, 0xCD, 0x2F, 0xD1, 0x26, 0x98, 0x54, 0x4D, 0xE0, 0x37, 0x95, 0x17, 0x26, 0x66,
    0x60, 0x73, 0x04, 0x61, 0x19, 0xAD, 0x5E, 0x11, 0xA9, 0x0A, 0xA4, 0x97, 0x73, 0xAE, 0xAC, 0x86,
];

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Ensure OpenSSL understands ECC key pair from CryptoAuthLib.
    check_openssl_key_format()?;

    let mut i2c = I2cdev::new(I2C_PATH)?;
    i2c.set_slave_address(ATECC608_ADDR)?;
    let mut atca = AtCaClient::new(i2c, Delay);

    // Imitate flash-time procedure.
    let revision = atca.info().map_err(|e| format!("{}", e))?;
    info!("Revision {:02x?}", revision.as_ref());
    let sn = atca
        .memory()
        .serial_number()
        .map_err(|e| format!("{}", e))?;
    info!("Serial number {:02x?}", sn.as_ref());

    let digest = atca
        .sha()
        .digest(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        .map_err(|e| format!("{}", e))?;
    info!("SHA digest {:02x?}", &digest.as_ref()[0..3]);

    // Lock bytes
    atca.memory()
        .read_config(Size::Word, 2, 5)
        .map(|response| info!("Lock bytes {:02x?}", response.as_ref()))
        .map_err(|e| format!("{}", e))?;
    atca.memory()
        .is_locked(Zone::Config)
        .map(|response| info!("Config zone is locked: {}", response))
        .map_err(|e| format!("{}", e))?;
    atca.memory()
        .is_locked(Zone::Data)
        .map(|response| info!("Data zone is locked: {}", response))
        .map_err(|e| format!("{}", e))?;
    for key_id in Slot::keys() {
        atca.memory()
            .is_slot_locked(key_id)
            .map(|response| {
                if response {
                    info!("{:?} is locked: {}", key_id, response)
                }
            })
            .map_err(|e| format!("{}", e))?;
    }

    // Chip options
    let chip_options = atca.memory().chip_options().map_err(|e| format!("{}", e))?;
    info!("Chip options 0x{:04x}", chip_options);

    // Key configurations
    for key_id in Slot::keys() {
        let permission = atca
            .memory()
            .permission(key_id)
            .map_err(|e| format!("{}", e))?;
        let key_type = atca
            .memory()
            .key_type(key_id)
            .map_err(|e| format!("{}", e))?;
        info!(
            "{:?}, key type 0x{:04x}, permission 0x{:04x}",
            key_id, key_type, permission
        );
    }

    // Which key slot can you read? According to the doc, read/write to slot
    // requires the Data zone to be locked.
    for key_id in Slot::keys() {
        if key_id.is_certificate() {
            match atca.memory().pubkey(key_id) {
                Ok(cert) => info!("{:?}, {:?}", key_id, &cert.as_ref()[..0x10]),
                Err(e) => info!("{:?}, {}", key_id, e),
            }
        }
    }

    // Lock config zone
    if !atca
        .memory()
        .is_locked(Zone::Config)
        .map_err(|e| format!("{}", e))?
    {
        let mut tng = TrustAndGo::new(&mut atca);
        tng.configure_chip_options().map_err(|e| format!("{}", e))?;
        tng.configure_permissions().map_err(|e| format!("{}", e))?;
        tng.configure_key_types().map_err(|e| format!("{}", e))?;
        atca.memory()
            .lock(Zone::Config)
            .map(|response| info!("Config zone is locked"))
            .map_err(|e| format!("{}", e))?;
    }

    // Nonce is required
    atca.nonce()
        .map(|response| info!("Nonce is calculated"))
        .map_err(|e| format!("{}", e))?;

    // Leave data zone unloced.
    // Write AES key to AES_KEY slot
    atca.memory()
        .write_aes_key(AES_KEY, &AES_KEY_CONTENT[..0x10])
        .map(|()| info!("Wrote AES KEY"))
        .map_err(|e| format!("{}", e))?;

    // Create a private key
    for key_id in Slot::keys() {
        if key_id.is_private_key() && PROVISION_KEYS.iter().all(|&p| p != key_id) {
            // check_openssl_public_key_format(&mut atca, key_id)?;
        }
    }

    for key_id in PROVISION_KEYS {
        // check_openssl_private_key_format(&mut atca, *key_id)?;
        check_privwrite_key_format(&mut atca, *key_id)?;
    }

    Ok(())
}

fn check_openssl_key_format() -> Result<(), Box<dyn Error>> {
    let p256 = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| format!("{}", e))?;
    let x = BigNum::from_slice(&TEST_PUBLIC_KEY[..32]).map_err(|e| format!("{}", e))?;
    let y = BigNum::from_slice(&TEST_PUBLIC_KEY[32..]).map_err(|e| format!("{}", e))?;
    let openssl_public_key =
        EcKey::from_public_key_affine_coordinates(&p256, &x, &y).map_err(|e| format!("{}", e))?;
    let private_number = BigNum::from_slice(&TEST_PRIVATE_KEY).map_err(|e| format!("{}", e))?;
    let openssl_private_key =
        EcKey::from_private_components(&p256, &private_number, openssl_public_key.public_key())
            .map_err(|e| format!("{}", e))?;
    assert!(openssl_public_key.check_key().is_ok());
    assert!(openssl_private_key.check_key().is_ok());
    Ok(())
}

fn check_privwrite_key_format<PHY, D>(
    atca: &mut AtCaClient<PHY, D>,
    key_id: Slot,
) -> Result<(), Box<dyn Error>>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    let mut test_private_key = Block::default();
    test_private_key.as_mut().copy_from_slice(&TEST_PRIVATE_KEY);
    atca.write_private_key(key_id, &test_private_key)
        .map_err(|e| format!("{}", e))?;
    let pub_key = atca.generate_pubkey(key_id).map_err(|e| format!("{}", e))?;
    info!(
        "{:?}, PRIVWRITE_FORMAT {:?}",
        key_id,
        TEST_PUBLIC_KEY.as_ref() == pub_key.as_ref()
    );
    info!("{:02x?}", TEST_PUBLIC_KEY);
    info!("{:02x?}", pub_key.as_ref());
    Ok(())
}

fn check_openssl_public_key_format<PHY, D>(
    atca: &mut AtCaClient<PHY, D>,
    key_id: Slot,
) -> Result<(), Box<dyn Error>>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    let result = atca
        .create_private_key(key_id)
        .map_err(|e| info!("{:?}, {}", key_id, e));

    if let Ok(pub_key) = result {
        // OpenSSL
        let p256 = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| format!("{}", e))?;
        let x = BigNum::from_slice(&pub_key.as_ref()[..32]).map_err(|e| format!("{}", e))?;
        let y = BigNum::from_slice(&pub_key.as_ref()[32..]).map_err(|e| format!("{}", e))?;
        let openssl_pubkey = EcKey::from_public_key_affine_coordinates(&p256, &x, &y)
            .map_err(|e| format!("{}", e))?;

        info!("{:?}, {:?}", key_id, openssl_pubkey.check_key());
    }
    Ok(())
}

fn check_openssl_private_key_format<PHY, D>(
    atca: &mut AtCaClient<PHY, D>,
    key_id: Slot,
) -> Result<(), Box<dyn Error>>
where
    PHY: Read + Write,
    <PHY as Read>::Error: Debug,
    <PHY as Write>::Error: Debug,
    D: DelayUs<u32>,
{
    // Let OpenSSL create a key pair.
    let p256 = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| format!("{}", e))?;
    let openssl_keypair = EcKey::generate(&p256).map_err(|e| format!("{}", e))?;
    let mut openssl_private_key = Block::default();
    openssl_private_key
        .as_mut()
        .copy_from_slice(openssl_keypair.private_key().to_vec().as_ref());
    assert_eq!(32, openssl_keypair.private_key().to_vec().len());

    atca.write_private_key(key_id, &openssl_private_key)
        .map_err(|e| format!("{}", e))?;

    let pub_key = atca.generate_pubkey(key_id).map_err(|e| format!("{}", e))?;
    info!(
        "Generated public key for {:?}, {:?}",
        key_id,
        &pub_key.as_ref()[..0x10]
    );

    let p256 = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| format!("{}", e))?;
    let x = BigNum::from_slice(&pub_key.as_ref()[..32]).map_err(|e| format!("{}", e))?;
    let y = BigNum::from_slice(&pub_key.as_ref()[32..]).map_err(|e| format!("{}", e))?;
    let openssl_public_key =
        EcKey::from_public_key_affine_coordinates(&p256, &x, &y).map_err(|e| format!("{}", e))?;

    let mut ctx = BigNumContext::new().map_err(|e| format!("{}", e))?;
    let mut x_to_compare = BigNum::new().map_err(|e| format!("{}", e))?;
    let mut y_to_compare = BigNum::new().map_err(|e| format!("{}", e))?;
    openssl_keypair
        .public_key()
        .affine_coordinates_gfp(&p256, &mut x_to_compare, &mut y_to_compare, &mut ctx)
        .map_err(|e| format!("{}", e))?;
    info!(
        "{:?}, {:?}, X, {:?}, Y, {:?}",
        key_id,
        openssl_public_key.check_key(),
        x.to_vec() == x_to_compare.to_vec(),
        y.to_vec() == y_to_compare.to_vec()
    );
    Ok(())
}
