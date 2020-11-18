use super::c_types;
use super::DELAY_WRAPPER;
use super::{ATCAIface, ATCAIfaceCfg, ATCA_STATUS, ATCA_STATUS_ATCA_COMM_FAIL};
use core::ffi::c_void;

#[no_mangle]
pub extern "C" fn hal_i2c_init(_hal: *mut c_void, _cfg: *mut ATCAIfaceCfg) -> ATCA_STATUS {
    unimplemented!()
}
#[no_mangle]
pub extern "C" fn hal_i2c_post_init(_iface: ATCAIface) -> ATCA_STATUS {
    unimplemented!()
}
#[no_mangle]
pub extern "C" fn hal_i2c_send(
    _iface: ATCAIface,
    _word_address: u8,
    _txdata: *mut u8,
    _txlength: c_types::c_int,
) -> ATCA_STATUS {
    unimplemented!()
}
#[no_mangle]
pub extern "C" fn hal_i2c_receive(
    _iface: ATCAIface,
    _word_address: u8,
    _rxdata: *mut u8,
    _rxlength: *mut u16,
) -> ATCA_STATUS {
    unimplemented!()
}
#[no_mangle]
pub extern "C" fn hal_i2c_wake(_iface: ATCAIface) -> ATCA_STATUS {
    // Make `execute_command` return earlier.
    ATCA_STATUS_ATCA_COMM_FAIL
}
#[no_mangle]
pub extern "C" fn hal_i2c_idle(_iface: ATCAIface) -> ATCA_STATUS {
    unimplemented!()
}
#[no_mangle]
pub extern "C" fn hal_i2c_sleep(_iface: ATCAIface) -> ATCA_STATUS {
    unimplemented!()
}
#[no_mangle]
pub extern "C" fn hal_i2c_release(_hal_data: *mut c_void) -> ATCA_STATUS {
    unimplemented!()
}
#[no_mangle]
pub extern "C" fn hal_i2c_discover_buses(
    _i2c_buses: *mut c_types::c_int,
    _max_buses: c_types::c_int,
) -> ATCA_STATUS {
    unimplemented!()
}
#[no_mangle]
pub extern "C" fn hal_i2c_discover_devices(
    _bus_num: c_types::c_int,
    _cfg: *mut ATCAIfaceCfg,
    _found: *mut c_types::c_int,
) -> ATCA_STATUS {
    unimplemented!()
}

/// Delay MS
#[no_mangle]
#[export_name = "hal_delay_ms"]
pub extern "C" fn delay_ms(ms: u32) {
    unsafe {
        DELAY_WRAPPER
            .as_mut()
            .map(|delay| delay.delay_ms(ms))
            .expect("DELAY not initialized.")
    }
}

/// Delay US
#[no_mangle]
#[export_name = "hal_delay_us"]
pub extern "C" fn delay_us(us: u32) {
    unsafe {
        DELAY_WRAPPER
            .as_mut()
            .map(|delay| delay.delay_us(us))
            .expect("DELAY not initialized.")
    }
}
