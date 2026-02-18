# at-cryptoauth

A `no_std` Rust driver for the Microchip ATECC608A secure element over I2C.

Provides both async and blocking APIs for hardware-backed ECDSA (P-256) signing/verification, SHA-256 hashing, AES-128 encryption, ECDH key exchange, hardware RNG, and X.509 certificate management including ATECC compressed certificate format. Built on `embedded-hal` 1.0 and embassy.

## Usage

```rust
use at_cryptoauth::AtCaClient;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

// Create a client with default I2C settings (address 0x60)
let atca = AtCaClient::<NoopRawMutex, _>::new(i2c);

// Or with custom I2C configuration
use at_cryptoauth::I2cConfig;
let atca = AtCaClient::<NoopRawMutex, _>::with_config(i2c, I2cConfig {
    address: 0x60,
    wake_delay_us: 1500,
    max_retries: 20,
});

// Device info and serial number
let revision = atca.info().await?;
let serial = atca.memory().serial_number().await?;

// SHA-256
let digest = atca.sha().digest(b"message").await?;

// ECDSA signing
let signer = atca.signer(at_cryptoauth::tngtls::SIGN_PRIVATE_KEY);
let signature = signer.sign(b"message").await?;

// Hardware RNG
let mut buf = [0u8; 32];
atca.random().try_fill_bytes(&mut buf).await?;
```

All async methods have `_blocking` counterparts (e.g. `info_blocking()`, `digest_blocking()`).

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `embedded-tls` | yes | `CryptoProvider` impl for [embedded-tls](https://github.com/drogue-iot/embedded-tls) (AES-128-GCM-SHA256) |
| `pem` | yes | PEM encoding/decoding for certificates |
| `log` | no | Logging via the `log` crate |
| `defmt` | no | Structured logging via `defmt` |

## Device model

The driver follows the TNG-TLS (Trust & Go) configuration model, which assigns fixed roles to the ATECC608A's key slots:

| Slot | Role | Type |
|------|------|------|
| 0 | Authentication private key | P-256 private |
| 1 | Signing private key | P-256 private |
| 2-4 | User private keys | P-256 private |
| 6 | I/O protection key | P-256 private |
| 9 | AES key | Data |
| 10 | Device certificate | Certificate |
| 11 | Signer public key | Certificate |
| 12 | Signer certificate | Certificate |

This fixed layout trades flexibility for a well-defined provisioning path. Call `atca.tng()` to enforce the TNG-TLS configuration and lock the config zone.

## Architecture

The client is generic over a mutex type (`M: RawMutex`) and an I2C peripheral (`PHY`). Interior mutability via embassy-sync's `Mutex` allows sharing the client across async tasks.

Sub-APIs are accessed through borrowing methods on the client:

- `atca.memory()` — slot/zone reads, writes, locking, configuration
- `atca.sha()` — SHA-256 (streaming or one-shot)
- `atca.aes(slot)` — AES-128 encrypt/decrypt
- `atca.signer(slot)` — ECDSA signing (implements `signature::Signer`)
- `atca.verifier(slot)` — ECDSA verification (implements `signature::Verifier`)
- `atca.random()` — hardware RNG (implements `rand_core::CryptoRng`)
- `atca.tng()` — TNG-TLS provisioning

The `cert` module provides X.509 certificate types including the ATECC 72-byte compressed certificate format (`cert::compressed`), DER/PEM encoding, and certificate building.

## Limitations

- Only the ATECC608A is supported. Other devices in the CryptoAuth family (ATECC508A, ATECC108A) are not tested.
- I2C is the only supported transport (no SWI/single-wire).
- The blocking API is not thread-safe — it returns `ErrorKind::MutexLocked` if the client is already in use.
- The `embedded-tls` provider does not perform certificate verification; the caller is responsible for trust anchor validation.

## References

- [ATECC608A Datasheet](https://atecc608a.github.io/ATECC608A.pdf)
- [ATECC608A-TNGTLS Datasheet](http://ww1.microchip.com/downloads/en/DeviceDoc/ATECC608A-TNGTLS-CryptoAuthentication-Data-Sheet-DS40002112B.pdf)
- [Compressed Certificate Application Note](http://ww1.microchip.com/downloads/en/AppNotes/Atmel-8974-CryptoAuth-ATECC-Compressed-Certificate-Definition-ApplicationNote.pdf)

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT license](http://opensource.org/licenses/MIT) at your option.
