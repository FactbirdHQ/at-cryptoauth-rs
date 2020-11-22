# ATECCx08 CryptoAuth

- [Datasheet](https://atecc608a.github.io/ATECC608A.pdf)
- [Datasheet (TNG-TLS)](http://ww1.microchip.com/downloads/en/DeviceDoc/ATECC608A-TNGTLS-CryptoAuthentication-Data-Sheet-DS40002112B.pdf)
- [X.509 Certificate](http://ww1.microchip.com/downloads/en/AppNotes/Atmel-8974-CryptoAuth-ATECC-Compressed-Certificate-Definition-ApplicationNote.pdf)

## Existing works

The chip vendor open-sources CryptoAuthLib, the official driver library. It is
firmly coupled with the Harmony framework and well suited for SAM families.

Rusty_CryptoAuthLib is an implementation in Rust that maintains API
compatibility with the CryptoAuthlib.

## Limitations

This driver only supports ATECC608 over an I2C bus and on its host side,
STM32-L4 family or RaspberryPi. As a matter of fact, tests have been running
only on these combinations.

By design, the driver does not conform to the vendor’s authentic library
implementation. Instead, it provides with just a tiny subset of APIs, which is
necessary and sufficient for implementing traits proposed by Rust Crypto.

Prior to finalize the device, a user has to plan how to deploy or generate keys
and which API operates on them. The driver imposes a fixed usage model called
TNG-TLS. At the cost of the users’ degree of freedom, the limited scope helps
them provision the device.
