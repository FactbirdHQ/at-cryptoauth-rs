//! Build script for CryptoAuthLib
//!
//! Top level CMake task creates `atca_config.h`.
use bindgen::RustTarget;
use cmake::Config;
use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

struct CmakeToolchainInner {
    c_compiler: String,
    cpp_compiler: String,
    sysroot: String,
}

struct CmakeToolchain(Option<CmakeToolchainInner>);
impl CmakeToolchain {
    // Retrieve SYSROOT path of a given gcc toolchain
    fn get_sysroot(compiler: &str) -> Result<String, Box<dyn Error>> {
        let cmd_output = Command::new(compiler).arg("-print-sysroot").output()?;
        let mut sysroot = String::from_utf8(cmd_output.stdout)?;
        assert_eq!(sysroot.pop(), Some('\n'));
        Ok(sysroot)
    }

    fn new() -> Result<Self, Box<dyn Error>> {
        let target = env::var("TARGET")?;
        let c_compiler = match target.as_str() {
            // Bare-metal
            "thumbv7em-none-eabihf" => "arm-none-eabi-gcc".to_string(),
            // Raspberry Pi
            "armv7-unknown-linux-gnueabihf" => "arm-none-linux-gnueabihf-gcc".to_string(),
            // Target triple does not require cross-compiling
            _ => return Ok(Self(None)),
        };
        let cpp_compiler = format!("{}++", &c_compiler[..c_compiler.len() - 2]);
        let sysroot = Self::get_sysroot(&c_compiler)?;
        Ok(Self(
            CmakeToolchainInner {
                c_compiler,
                cpp_compiler,
                sysroot,
            }
            .into(),
        ))
    }

    fn cross_compile(&self) -> Option<&CmakeToolchainInner> {
        self.0.as_ref()
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let toolchain = CmakeToolchain::new()?;
    let out_path = PathBuf::from(env::var("OUT_DIR")?);

    // Compile a static link library
    let mut config = Config::new("cryptoauthlib");
    let dst = toolchain
        .cross_compile()
        .iter()
        .fold(&mut config, |acc, cross| {
            acc.define("CMAKE_SYSTEM_PROCESSOR", "arm")
                .define("CMAKE_CROSSCOMPILING", "TRUE")
                .define("CMAKE_C_COMPILER", &cross.c_compiler)
                .define("CMAKE_CXX_COMPILER", &cross.cpp_compiler)
        })
        .define("CMAKE_SYSTEM_NAME", "Generic")
        .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY")
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
    let bindings = toolchain
        .cross_compile()
        .iter()
        .fold(bindgen::Builder::default(), |acc, cross| {
            acc.clang_arg(format!("--sysroot={}", &cross.sysroot))
        })
        .use_core()
        .ctypes_prefix("c_types")
        .derive_default(true)
        .rust_target(RustTarget::Nightly)
        .clang_arg("-Icryptoauthlib/lib")
        .clang_arg(format!("-I{}", out_path.join("build/lib").display()))
        .header("cryptoauthlib/lib/cryptoauthlib.h")
        .whitelist_function("atCRC")
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
