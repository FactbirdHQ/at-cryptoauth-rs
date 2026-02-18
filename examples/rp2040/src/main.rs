#![no_std]
#![no_main]

use at_cryptoauth::AtCaClient;
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    I2C0_IRQ => embassy_rp::i2c::InterruptHandler<embassy_rp::peripherals::I2C0>;
});

const SLOT_CONFIG_READ_KEY_MASK: u16 = 0b1111;
const SLOT_CONFIG_EXT_SIGN_ENABLED: u16 = 0x01 << 0;
const SLOT_CONFIG_INT_SIGN_ENABLED: u16 = 0x01 << 1;
const SLOT_CONFIG_ECDH_PERMITTED: u16 = 0x01 << 2;
const SLOT_CONFIG_ECDH_MASTER_SECRET_MODE: u16 = 0x01 << 3;
const SLOT_CONFIG_NO_MAC: u16 = 0x01 << 4;
const SLOT_CONFIG_LIMITED_USE: u16 = 0x01 << 5;
const SLOT_CONFIG_ENCRYPT_READ: u16 = 0x01 << 6;
const SLOT_CONFIG_IS_SECRET: u16 = 0x01 << 7;

const SLOT_CONFIG_WRITE_KEY_OFFSET: u16 = 8;
const SLOT_CONFIG_WRITE_KEY_MASK: u16 = 0b1111 << SLOT_CONFIG_WRITE_KEY_OFFSET;

const SLOT_CONFIG_WRITE_CONFIG_OFFSET: u16 = 12;
const SLOT_CONFIG_WRITE_CONFIG_MASK: u16 = 0b1111 << SLOT_CONFIG_WRITE_CONFIG_OFFSET;

#[allow(dead_code)]
fn dump_slot_config(value: u16) {
    defmt::info!("Decoding SlotConfig value = 0x{:04X}", value);

    defmt::info!(
        "Read key (except ECC private keys): {}",
        value & SLOT_CONFIG_READ_KEY_MASK
    );
    defmt::info!(" If slot contains ECC private keys:");
    defmt::info!(
        "  External signatures of arbitrary messages are enabled: {} ",
        (value & SLOT_CONFIG_EXT_SIGN_ENABLED) != 0
    );
    defmt::info!(
        "  Internal signatures are enabled: {} ",
        (value & SLOT_CONFIG_INT_SIGN_ENABLED) != 0
    );
    defmt::info!(
        "  ECDH operation is permitted for this key: {} ",
        (value & SLOT_CONFIG_ECDH_PERMITTED) != 0
    );
    defmt::info!(
        "   ECDH master secret output mode: {} ",
        (value & SLOT_CONFIG_ECDH_MASTER_SECRET_MODE) != 0
    );

    defmt::info!("NoMac bit: {} ", (value & SLOT_CONFIG_NO_MAC) != 0);
    defmt::info!(
        "LimitedUse bit: {} ",
        (value & SLOT_CONFIG_LIMITED_USE) != 0
    );
    defmt::info!(
        "EncryptRead bit: {} ",
        (value & SLOT_CONFIG_ENCRYPT_READ) != 0
    );
    defmt::info!("IsSecret bit: {} ", (value & SLOT_CONFIG_IS_SECRET) != 0);
    defmt::info!(
        "Write key: {}",
        (value & SLOT_CONFIG_WRITE_KEY_MASK) >> SLOT_CONFIG_WRITE_KEY_OFFSET
    );

    let write_config = (value & SLOT_CONFIG_WRITE_CONFIG_MASK) >> SLOT_CONFIG_WRITE_CONFIG_OFFSET;

    defmt::info!(
        "Write config: 0x{:X} (hex) = {:b}  (bin)",
        write_config,
        write_config,
    );

    // 'Write' configuration bits
    defmt::info!("  Write cmd: ");
    if write_config == 0b0000 {
        defmt::info!("Always");
    } else if write_config == 0b0001 {
        defmt::info!("PubInvalid");
    } else if (write_config & 0b1110) == 0b0010 {
        defmt::info!("Never");
    } else if (write_config & 0b1100) == 0b1000 {
        defmt::info!("Never");
    } else if (write_config & 0b0100) == 0b0100 {
        defmt::info!("Encrypt");
    } else {
        defmt::info!("Unknown");
    }
    defmt::info!("");

    // 'DeriveKey' configuration bits
    defmt::info!("  DeriveKey cmd: ");
    if (write_config & 0b1011) == 0b0010 {
        defmt::info!("Roll without MAC");
    } else if (write_config & 0b1011) == 0b1010 {
        defmt::info!("Roll with MAC");
    } else if (write_config & 0b1011) == 0b0011 {
        defmt::info!("Create without MAC");
    } else if (write_config & 0b1011) == 0b1011 {
        defmt::info!("Create with MAC");
    } else if (write_config & 0b0010) == 0b0000 {
        defmt::info!("Can't be used");
    } else {
        defmt::info!("Unknown");
    }
    defmt::info!("");

    // 'GenKey' configuration bits
    defmt::info!(
        "  GenKey cmd: {:?} ",
        if write_config & (0x01 << 1) == (0x01 << 1) {
            "may be used"
        } else {
            "may NOT be used"
        }
    );
    // 'PrivWrite' configuration bits
    defmt::info!(
        "  PrivWrite cmd: {:?} ",
        if write_config & (0x01 << 2) == (0x01 << 2) {
            "Encrypt"
        } else {
            "Forbidden"
        }
    );
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    defmt::info!("Hello World!");

    let p = embassy_rp::init(Default::default());

    let i2c = embassy_rp::i2c::I2c::new_async(p.I2C0, p.PIN_29, p.PIN_28, Irqs, Default::default());

    defmt::info!("Start testing ATECC608A.");

    let client: AtCaClient<NoopRawMutex, _> = AtCaClient::new(i2c);

    let info = client.info().await.unwrap();
    assert_eq!(info.as_ref(), [0x00, 0x00, 0x60, 0x02]);

    // Serial number bytes. Bytes positioned at 0..2 and 8 are fixed. Bytes at
    // 2..8 are unique to individual modules.
    //
    // Example: [01, 23, 14, 16, 39, cd, d1, c1, ee]
    let sn = client.memory().serial_number().await.unwrap();
    assert_eq!(sn.as_ref()[..2], [0x01, 0x23]);
    assert_eq!(sn.as_ref()[8], 0xee);

    let digest = client
        .sha()
        .digest(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        .await
        .unwrap();

    assert_eq!(
        digest.as_ref(),
        [
            0x17, 0xe8, 0x8d, 0xb1, 0x87, 0xaf, 0xd6, 0x2c, 0x16, 0xe5, 0xde, 0xbf, 0x3e, 0x65,
            0x27, 0xcd, 0x00, 0x6b, 0xc0, 0x12, 0xbc, 0x90, 0xb5, 0x1a, 0x81, 0x0c, 0xd8, 0x0c,
            0x2d, 0x51, 0x1f, 0x43
        ]
    );

    let mut random = client.random();
    let mut dest = [0u8; 32];
    random.try_fill_bytes(&mut dest).await.unwrap();
    defmt::info!("Random bytes: {:#02x}", dest);

    defmt::info!("ATECC608A test finished.");
}
