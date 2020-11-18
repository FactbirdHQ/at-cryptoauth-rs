#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![no_std]
mod facade;
pub mod hal;

use core::mem::transmute;
use embedded_hal::blocking::delay::{DelayMs, DelayUs};

pub static mut DELAY_WRAPPER: Option<&mut dyn DelayWrapper> = None;

pub trait DelayWrapper: DelayUs<u32> + DelayMs<u32> {}
impl<T> DelayWrapper for T where T: DelayUs<u32> + DelayMs<u32> {}

pub fn init_delay_wrapper<T: DelayWrapper>(delay: &mut T) {
    let delay_ref = unsafe {
        transmute::<&mut dyn DelayWrapper, &'static mut dyn DelayWrapper>(
            delay as &mut dyn DelayWrapper,
        )
    };
    unsafe {
        DELAY_WRAPPER.replace(delay_ref);
    }
}

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
