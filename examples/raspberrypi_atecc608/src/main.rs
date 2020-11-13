// $ cargo b --target armv7-unknown-linux-gnueabihf
// $ scp target/armv7-unknown-linux-gnueabihf/debug/raspberrypi_atecc608 pi@<IP addr>:/home/pi/raspberrypi_atecc608
// $ ssh pi@<IP addr> "RUST_LOG=info ./raspberrypi_atecc608"
use at_cryptoauth::client::AtCaClient;
use at_cryptoauth::memory::{Size, Slot, Zone};
use at_cryptoauth::tngtls::TrustAndGo;
use linux_embedded_hal::Delay;
use linux_embedded_hal::I2cdev;
use log::info;
use std::error::Error;

const I2C_PATH: &str = "/dev/i2c-1";
const ATECC608_ADDR: u16 = 0xc0 >> 1;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut i2c = I2cdev::new(I2C_PATH)?;
    i2c.set_slave_address(ATECC608_ADDR)?;
    let mut atca = AtCaClient::new(i2c, Delay);

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

    // Which key slot can you read?
    for key_id in Slot::keys() {
        if key_id.is_certificate() {
            let result = atca.memory().pubkey(key_id);
            info!("{:?}, {:?}", key_id, result);
        }
    }

    // let mut tng = TrustAndGo::new(&mut atca);
    // tng.configure_chip_options().map_err(|e| format!("{}", e))?;
    // tng.configure_permissions().map_err(|e| format!("{}", e))?;
    // tng.configure_key_types().map_err(|e| format!("{}", e))?;
    Ok(())
}
