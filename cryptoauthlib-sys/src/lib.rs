#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![no_std]
mod facade;
pub mod hal;

use stm32l4xx_hal::delay::Delay;
pub static mut DELAY_WRAPPER: Option<Delay> = None;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod c_types {
    pub type c_uint = u32;
    pub type c_uchar = u8;
    pub type c_ushort = u16;
    pub type c_short = i16;
    pub type c_int = i32;
    pub type c_void = core::ffi::c_void;
    pub type c_char = u8;
    pub type c_long = i64;
    pub type c_ulong = u64;
    pub type c_ulonglong = i64;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
