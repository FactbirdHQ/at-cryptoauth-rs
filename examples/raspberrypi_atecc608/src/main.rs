// $ cargo b --target armv7-unknown-linux-gnueabihf
// $ scp target/armv7-unknown-linux-gnueabihf/debug/raspberrypi_atecc608 pi@<IP addr>:/home/pi/raspberrypi_atecc608
// $ ssh pi@<IP addr> "RUST_LOG=info ./raspberrypi_atecc608"
use at_cryptoauth::client::AtCaClient;
use at_cryptoauth::memory::{Size, Slot, Zone};
use at_cryptoauth::tngtls::{AES_KEY, AUTH_PRIVATE_KEY, SIGN_PRIVATE_KEY, USER_PRIVATE_KEY1};
use linux_embedded_hal::Delay;
use linux_embedded_hal::I2cdev;
use log::info;
use std::error::Error;

const I2C_PATH: &str = "/dev/i2c-1";
const ATECC608_ADDR: u16 = 0xc0 >> 1;
const PROVISION_PIVATE_KEY: Slot = USER_PRIVATE_KEY1;

// Taken from atca_test.c
const AES_KEY_CONTENT: [u8; 0x40] = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63,
    0x70, 0x58, 0x71, 0x0B, 0x58, 0xE1, 0xE6, 0x65, 0xD3, 0xD2, 0xF5, 0xB4, 0x65, 0x17, 0x64, 0x03,
    0x11, 0x44, 0x43, 0xFA, 0x8E, 0x96, 0x14, 0x84, 0x5E, 0xC7, 0x29, 0x6C, 0xD1, 0x3B, 0xC9, 0xDC,
];

const MSG_TO_SIGN: &[u8] = b"";
const RAW_SECRET_TO_ENCRYPT: &[u8] = b"";

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

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
            let result = atca.memory().pubkey(key_id);
            info!("{:?}, {:?}", key_id, result);
        }
    }

    // Lock config zone
    if !atca
        .memory()
        .is_locked(Zone::Config)
        .map_err(|e| format!("{}", e))?
    {
        atca.memory()
            .lock(Zone::Config)
            .map(|response| info!("Config zone is locked"))
            .map_err(|e| format!("{}", e))?;
    }

    // Write AES key to AES_KEY slot
    atca.memory()
        .write_aes_key(AES_KEY, &AES_KEY_CONTENT[..0x10])
        .map(|()| info!("Wrote AES KEY"))
        .map_err(|e| format!("{}", e))?;

    // Lock data zone
    /*
    if !atca
        .memory()
        .is_locked(Zone::Data)
        .map_err(|e| format!("{}", e))?
    {
        atca.memory()
            .lock(Zone::Data)
            .map(|response| info!("Data zone is locked"))
            .map_err(|e| format!("{}", e))?;
    }
    */

    // Nonce is required
    /*
        atca.nonce()
            .map(|response| info!("Nonce is calculated"))
            .map_err(|e| format!("{}", e))?;
    */
    // Create a private key
    for key_id in Slot::keys() {
        if key_id.is_private_key()
        /*&& key_id != AUTH_PRIVATE_KEY && key_id != SIGN_PRIVATE_KEY*/
        {
            match atca.create_private_key(key_id) {
                Ok(pub_key) => info!("{:?}, {:?}", key_id, &pub_key.as_ref()[..0x10]),
                Err(e) => info!("{:?}, {}", key_id, e),
            }
        }
    }
    /*
        let mut tng = TrustAndGo::new(&mut atca);
        tng.configure_chip_options().map_err(|e| format!("{}", e))?;
        tng.configure_permissions().map_err(|e| format!("{}", e))?;
        tng.configure_key_types().map_err(|e| format!("{}", e))?;
    */
    Ok(())
}
