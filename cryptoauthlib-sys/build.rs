//! Build script for CryptoAuthLib
//!
//! Top level CMake task creats `atca_config.h`.
use bindgen::RustTarget;
use cmake::Config;
use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    match env::var("TARGET")?.as_str() {
        "thumbv7em-none-eabihf" => {}
        target => panic!("Target triple {} not supported", target),
    }

    // Retrieve SYSROOT path
    let cmd_output = Command::new("arm-none-eabi-gcc")
        .arg("-print-sysroot")
        .output()?;
    let mut sysroot = String::from_utf8(cmd_output.stdout)?;
    assert_eq!(sysroot.pop(), Some('\n'));

    let out_path = PathBuf::from(env::var("OUT_DIR")?);

    // Compile a static link library
    let dst = Config::new("cryptoauthlib")
        .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY")
        .define("CMAKE_SYSTEM_NAME", "Generic")
        .define("CMAKE_SYSTEM_PROCESSOR", "arm")
        .define("CMAKE_CROSSCOMPILING", "TRUE")
        .define("ATCA_HAL_I2C", "TRUE")
        .define("ATCA_TNGTLS_SUPPORT", "TRUE")
        .define("ATCA_ATSHA204A_SUPPORT", "FALSE")
        .define("ATCA_ATSHA206A_SUPPORT", "FALSE")
        .define("ATCA_ATECC108A_SUPPORT", "FALSE")
        .define("ATCA_ATECC508A_SUPPORT", "FALSE")
        .define("ATCA_ATECC608_SUPPORT", "TRUE")
        .define("ATCA_ATECC608A_SUPPORT", "TRUE")
        .define("ATCA_BUILD_SHARED_LIBS", "FALSE")
        .define("ATCA_NO_HEAP", "TRUE")
        .define("ATCA_PRINTF", "FALSE")
        .build_target("cryptoauth")
        .build();

    // Bind CryptoAuthLib library
    let bindings = bindgen::Builder::default()
        .use_core()
        .ctypes_prefix("c_types")
        .derive_default(true)
        .rust_target(RustTarget::Nightly)
        .clang_arg(format!("--sysroot={}", sysroot))
        .clang_arg("-Icryptoauthlib/lib")
        .clang_arg(format!("-I{}", out_path.join("build/lib").display()))
        .header("cryptoauthlib/lib/cryptoauthlib.h")
        .whitelist_function("atgetifacecfg")
        .whitelist_function("atgetifacehaldat")
        .whitelist_function("calib_.*")
        .whitelist_function("hal_iface_register_hal")
        .whitelist_function("initATCADevice")
        .whitelist_type("atca_command")
        .whitelist_type("atca_device")
        .whitelist_type("atca_iface")
        .whitelist_type("ATCAHAL_t")
        .whitelist_var("cfg_ateccx08a_i2c_default")
        .generate()
        .expect("Unable to generate bindings.");

    bindings.write_to_file(out_path.join("bindings.rs"))?;

    println!("cargo:rustc-link-search=native={}/build/lib", dst.display());
    println!("cargo:rustc-link-lib=static=cryptoauth");
    Ok(())
}
