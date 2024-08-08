// Generated automatically from dpms.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::dpms::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_dpms_id
    }
}

pub const MAJOR_VERSION: u32 = 0;
pub const MINOR_VERSION: u32 = 0;

pub type DpmsMode = u32;
pub const DPMS_MODE_ON     : DpmsMode = 0x00;
pub const DPMS_MODE_STANDBY: DpmsMode = 0x01;
pub const DPMS_MODE_SUSPEND: DpmsMode = 0x02;
pub const DPMS_MODE_OFF    : DpmsMode = 0x03;



pub const GET_VERSION: u8 = 0;

pub type GetVersionCookie<'a> = base::Cookie<'a, xcb_dpms_get_version_cookie_t>;

impl<'a> GetVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<GetVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetVersionReply {
                    ptr: xcb_dpms_get_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetVersionReply {
                    ptr: xcb_dpms_get_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetVersionReply = base::Reply<xcb_dpms_get_version_reply_t>;

impl GetVersionReply {
    pub fn server_major_version(&self) -> u16 {
        unsafe {
            (*self.ptr).server_major_version
        }
    }
    pub fn server_minor_version(&self) -> u16 {
        unsafe {
            (*self.ptr).server_minor_version
        }
    }
}

pub fn get_version<'a>(c                   : &'a base::Connection,
                       client_major_version: u16,
                       client_minor_version: u16)
        -> GetVersionCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_get_version(c.get_raw_conn(),
                                          client_major_version as u16,  // 0
                                          client_minor_version as u16);  // 1
        GetVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_version_unchecked<'a>(c                   : &'a base::Connection,
                                 client_major_version: u16,
                                 client_minor_version: u16)
        -> GetVersionCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_get_version_unchecked(c.get_raw_conn(),
                                                    client_major_version as u16,  // 0
                                                    client_minor_version as u16);  // 1
        GetVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CAPABLE: u8 = 1;

pub type CapableCookie<'a> = base::Cookie<'a, xcb_dpms_capable_cookie_t>;

impl<'a> CapableCookie<'a> {
    pub fn get_reply(&self) -> Result<CapableReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CapableReply {
                    ptr: xcb_dpms_capable_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CapableReply {
                    ptr: xcb_dpms_capable_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CapableReply = base::Reply<xcb_dpms_capable_reply_t>;

impl CapableReply {
    pub fn capable(&self) -> bool {
        unsafe {
            (*self.ptr).capable != 0
        }
    }
}

pub fn capable<'a>(c: &'a base::Connection)
        -> CapableCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_capable(c.get_raw_conn());
        CapableCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn capable_unchecked<'a>(c: &'a base::Connection)
        -> CapableCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_capable_unchecked(c.get_raw_conn());
        CapableCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TIMEOUTS: u8 = 2;

pub type GetTimeoutsCookie<'a> = base::Cookie<'a, xcb_dpms_get_timeouts_cookie_t>;

impl<'a> GetTimeoutsCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTimeoutsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTimeoutsReply {
                    ptr: xcb_dpms_get_timeouts_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTimeoutsReply {
                    ptr: xcb_dpms_get_timeouts_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTimeoutsReply = base::Reply<xcb_dpms_get_timeouts_reply_t>;

impl GetTimeoutsReply {
    pub fn standby_timeout(&self) -> u16 {
        unsafe {
            (*self.ptr).standby_timeout
        }
    }
    pub fn suspend_timeout(&self) -> u16 {
        unsafe {
            (*self.ptr).suspend_timeout
        }
    }
    pub fn off_timeout(&self) -> u16 {
        unsafe {
            (*self.ptr).off_timeout
        }
    }
}

pub fn get_timeouts<'a>(c: &'a base::Connection)
        -> GetTimeoutsCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_get_timeouts(c.get_raw_conn());
        GetTimeoutsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_timeouts_unchecked<'a>(c: &'a base::Connection)
        -> GetTimeoutsCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_get_timeouts_unchecked(c.get_raw_conn());
        GetTimeoutsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_TIMEOUTS: u8 = 3;

pub fn set_timeouts<'a>(c              : &'a base::Connection,
                        standby_timeout: u16,
                        suspend_timeout: u16,
                        off_timeout    : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_set_timeouts(c.get_raw_conn(),
                                           standby_timeout as u16,  // 0
                                           suspend_timeout as u16,  // 1
                                           off_timeout as u16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_timeouts_checked<'a>(c              : &'a base::Connection,
                                standby_timeout: u16,
                                suspend_timeout: u16,
                                off_timeout    : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_set_timeouts_checked(c.get_raw_conn(),
                                                   standby_timeout as u16,  // 0
                                                   suspend_timeout as u16,  // 1
                                                   off_timeout as u16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ENABLE: u8 = 4;

pub fn enable<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_enable(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn enable_checked<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_enable_checked(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DISABLE: u8 = 5;

pub fn disable<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_disable(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn disable_checked<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_disable_checked(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FORCE_LEVEL: u8 = 6;

pub fn force_level<'a>(c          : &'a base::Connection,
                       power_level: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_force_level(c.get_raw_conn(),
                                          power_level as u16);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn force_level_checked<'a>(c          : &'a base::Connection,
                               power_level: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_force_level_checked(c.get_raw_conn(),
                                                  power_level as u16);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const INFO: u8 = 7;

pub type InfoCookie<'a> = base::Cookie<'a, xcb_dpms_info_cookie_t>;

impl<'a> InfoCookie<'a> {
    pub fn get_reply(&self) -> Result<InfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = InfoReply {
                    ptr: xcb_dpms_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( InfoReply {
                    ptr: xcb_dpms_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type InfoReply = base::Reply<xcb_dpms_info_reply_t>;

impl InfoReply {
    pub fn power_level(&self) -> u16 {
        unsafe {
            (*self.ptr).power_level
        }
    }
    pub fn state(&self) -> bool {
        unsafe {
            (*self.ptr).state != 0
        }
    }
}

pub fn info<'a>(c: &'a base::Connection)
        -> InfoCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_info(c.get_raw_conn());
        InfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn info_unchecked<'a>(c: &'a base::Connection)
        -> InfoCookie<'a> {
    unsafe {
        let cookie = xcb_dpms_info_unchecked(c.get_raw_conn());
        InfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
