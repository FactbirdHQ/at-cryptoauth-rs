use super::c_types;
use super::facade::delay_us;
use super::{
    atgetifacehaldat, cfg_ateccx08a_i2c_default, hal_iface_register_hal, ATCAHAL_t, ATCAIface,
    ATCAIfaceCfg, ATCAIfaceType_ATCA_I2C_IFACE, ATCA_STATUS, ATCA_STATUS_ATCA_BAD_PARAM,
    ATCA_STATUS_ATCA_COMM_FAIL, ATCA_STATUS_ATCA_STATUS_SELFTEST_ERROR, ATCA_STATUS_ATCA_SUCCESS,
    ATCA_STATUS_ATCA_WAKE_FAILED,
};
use core::convert::{identity, TryFrom};
use core::ffi::c_void;
use core::fmt::Debug;
use core::mem::transmute;
use core::slice::from_raw_parts_mut;
use embedded_hal::blocking::i2c::{Read, Write};

pub struct I2c<T>(T, ATCAHAL_t, ATCAIfaceCfg);
impl<T> I2c<T>
where
    T: Read + Write,
    <T as Read>::Error: Debug,
    <T as Write>::Error: Debug,
{
    pub fn new(i2c: T) -> Self {
        let hal = ATCAHAL_t {
            halinit: Some(Self::init),
            halpostinit: Some(Self::post_init),
            halsend: Some(Self::send),
            halreceive: Some(Self::receive),
            halwake: Some(Self::wake),
            halidle: Some(Self::idle),
            halsleep: Some(Self::sleep),
            halrelease: Some(Self::release),
            hal_data: core::ptr::null_mut(),
        };
        let iface_cfg = unsafe { cfg_ateccx08a_i2c_default.clone() };
        let mut hal_i2c = Self(i2c, hal, iface_cfg);
        hal_i2c.1.hal_data = &mut hal_i2c.0 as *mut _ as *mut c_void;
        hal_i2c
    }

    pub fn register(&mut self) -> ATCA_STATUS {
        unsafe {
            hal_iface_register_hal(
                ATCAIfaceType_ATCA_I2C_IFACE,
                &mut self.1,
                core::ptr::null_mut(),
            )
        }
    }

    extern "C" fn init(_hal: *mut c_void, _cfg: *mut ATCAIfaceCfg) -> ATCA_STATUS {
        ATCA_STATUS_ATCA_SUCCESS
    }

    extern "C" fn post_init(_iface: ATCAIface) -> ATCA_STATUS {
        ATCA_STATUS_ATCA_SUCCESS
    }

    extern "C" fn send(
        iface: ATCAIface,
        word_address: u8,
        txdata: *mut u8,
        txlength: c_types::c_int,
    ) -> ATCA_STATUS {
        let bytes = if word_address != 0xff {
            let bytes = unsafe { from_raw_parts_mut(txdata, txlength as usize + 1) };
            // insert the Word Address Value, Command token
            bytes[0] = word_address;
            bytes
        } else {
            unsafe { from_raw_parts_mut(txdata, txlength as usize) }
        };
        unsafe { atgetifacehaldat(iface).as_mut() }
            .ok_or(ATCA_STATUS_ATCA_BAD_PARAM)
            .and_then(I2cRef::<T>::try_from)
            .and_then(|i2c_ref| {
                i2c_ref
                    .0
                    .write(0xC0 >> 1, bytes)
                    .map_err(|_| ATCA_STATUS_ATCA_COMM_FAIL)
            })
            .map(|()| ATCA_STATUS_ATCA_SUCCESS)
            .unwrap_or_else(identity)
    }

    extern "C" fn receive(
        iface: ATCAIface,
        word_address: u8,
        rxdata: *mut u8,
        rxlength: *mut u16,
    ) -> ATCA_STATUS {
        let work_buffer = &mut [0u8, 0];
        let rxdata_max_size = unsafe { *rxlength.as_ref().unwrap() };
        let min_resp_size = 4;

        unsafe { atgetifacehaldat(iface).as_mut() }
            .ok_or(ATCA_STATUS_ATCA_BAD_PARAM)
            .and_then(I2cRef::<T>::try_from)
            .and_then(|i2c_ref| {
                core::iter::from_fn(|| {
                    match Self::send(iface, word_address, &mut word_address.clone(), 0) {
                        ATCA_STATUS_ATCA_SUCCESS => Ok(()).into(),
                        e => Err(e).into(),
                    }
                })
                .take(20)
                .find_map(Result::<_, _>::ok)
                .ok_or_else(|| ATCA_STATUS_ATCA_COMM_FAIL)?;
                i2c_ref
                    .0
                    .read(0xC0 >> 1, work_buffer)
                    .map_err(|_| ATCA_STATUS_ATCA_COMM_FAIL)?;
                let length_to_read = match work_buffer[0] {
                    length if u16::from(length) > rxdata_max_size => panic!("too big"),
                    length if length < min_resp_size => panic!("too small"),
                    length => length,
                };

                let buffer = unsafe { from_raw_parts_mut(rxdata, length_to_read.into()) };
                buffer[0] = work_buffer[0];
                buffer[1] = work_buffer[1];
                i2c_ref
                    .0
                    .read(0xC0 >> 1, &mut buffer[2..])
                    .map(|()| {
                        let _ = core::mem::replace(
                            unsafe { rxlength.as_mut() }.unwrap(),
                            length_to_read.into(),
                        );
                    })
                    .map_err(|_| ATCA_STATUS_ATCA_COMM_FAIL)
            })
            .map(|()| ATCA_STATUS_ATCA_SUCCESS)
            .unwrap_or_else(identity)
    }

    extern "C" fn wake(iface: ATCAIface) -> ATCA_STATUS {
        let buffer = &mut [0x00, 0x00, 0x00, 0x00];
        unsafe { atgetifacehaldat(iface).as_mut() }
            .ok_or(ATCA_STATUS_ATCA_BAD_PARAM)
            .and_then(I2cRef::<T>::try_from)
            .and_then(|i2c_ref| {
                i2c_ref.0.write(0x00, &buffer[0..1]).unwrap_err();
                delay_us(1500);
                core::iter::from_fn(|| i2c_ref.0.read(0xC0 >> 1, buffer.as_mut()).into())
                    .take(20)
                    .find_map(Result::<_, _>::ok)
                    .ok_or_else(|| ATCA_STATUS_ATCA_COMM_FAIL)
            })
            .and_then(|()| match buffer.as_ref() {
                &[0x04, 0x11, 0x33, 0x43] => Ok(()),
                &[0x04, 0x07, 0xC4, 0x40] => Err(ATCA_STATUS_ATCA_STATUS_SELFTEST_ERROR),
                _ => Err(ATCA_STATUS_ATCA_WAKE_FAILED),
            })
            .map(|()| ATCA_STATUS_ATCA_SUCCESS)
            .unwrap_or_else(identity)
    }

    extern "C" fn idle(iface: ATCAIface) -> ATCA_STATUS {
        // idle word address value
        let data = &mut [0x02];
        unsafe { atgetifacehaldat(iface).as_mut() }
            .ok_or(ATCA_STATUS_ATCA_BAD_PARAM)
            .and_then(I2cRef::<T>::try_from)
            .and_then(|i2c_ref| {
                i2c_ref
                    .0
                    .write(0xC0 >> 1, data)
                    .map_err(|_| ATCA_STATUS_ATCA_COMM_FAIL)
            })
            .map(|()| ATCA_STATUS_ATCA_SUCCESS)
            .unwrap_or_else(identity)
    }

    extern "C" fn sleep(iface: ATCAIface) -> ATCA_STATUS {
        // sleep word address value
        let data = &mut [0x01];
        unsafe { atgetifacehaldat(iface).as_mut() }
            .ok_or(ATCA_STATUS_ATCA_BAD_PARAM)
            .and_then(I2cRef::<T>::try_from)
            .and_then(|i2c_ref| {
                i2c_ref
                    .0
                    .write(0xC0 >> 1, data)
                    .map_err(|_| ATCA_STATUS_ATCA_COMM_FAIL)
            })
            .map(|()| ATCA_STATUS_ATCA_SUCCESS)
            .unwrap_or_else(identity)
    }

    extern "C" fn release(_hal_data: *mut c_void) -> ATCA_STATUS {
        ATCA_STATUS_ATCA_SUCCESS
    }
}

#[derive(Debug)]
pub struct I2cRef<'a, T>(&'a mut T);

impl<'a, T> TryFrom<&mut c_void> for I2cRef<'a, T> {
    type Error = ATCA_STATUS;
    fn try_from(hal: &mut c_void) -> Result<Self, Self::Error> {
        Ok(Self(unsafe { transmute::<&mut c_void, &mut T>(hal) }))
    }
}
