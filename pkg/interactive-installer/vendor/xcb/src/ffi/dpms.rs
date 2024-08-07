// Generated automatically from dpms.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_DPMS_MAJOR_VERSION: u32 = 0;
pub const XCB_DPMS_MINOR_VERSION: u32 = 0;

pub const XCB_DPMS_GET_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_dpms_get_version_request_t {
    pub major_opcode:         u8,
    pub minor_opcode:         u8,
    pub length:               u16,
    pub client_major_version: u16,
    pub client_minor_version: u16,
}

impl Copy for xcb_dpms_get_version_request_t {}
impl Clone for xcb_dpms_get_version_request_t {
    fn clone(&self) -> xcb_dpms_get_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_dpms_get_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_dpms_get_version_reply_t {
    pub response_type:        u8,
    pub pad0:                 u8,
    pub sequence:             u16,
    pub length:               u32,
    pub server_major_version: u16,
    pub server_minor_version: u16,
}

impl Copy for xcb_dpms_get_version_reply_t {}
impl Clone for xcb_dpms_get_version_reply_t {
    fn clone(&self) -> xcb_dpms_get_version_reply_t { *self }
}

pub const XCB_DPMS_CAPABLE: u8 = 1;

#[repr(C)]
pub struct xcb_dpms_capable_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_dpms_capable_request_t {}
impl Clone for xcb_dpms_capable_request_t {
    fn clone(&self) -> xcb_dpms_capable_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_dpms_capable_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_dpms_capable_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub capable:       u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_dpms_capable_reply_t {}
impl Clone for xcb_dpms_capable_reply_t {
    fn clone(&self) -> xcb_dpms_capable_reply_t { *self }
}

pub const XCB_DPMS_GET_TIMEOUTS: u8 = 2;

#[repr(C)]
pub struct xcb_dpms_get_timeouts_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_dpms_get_timeouts_request_t {}
impl Clone for xcb_dpms_get_timeouts_request_t {
    fn clone(&self) -> xcb_dpms_get_timeouts_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_dpms_get_timeouts_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_dpms_get_timeouts_reply_t {
    pub response_type:   u8,
    pub pad0:            u8,
    pub sequence:        u16,
    pub length:          u32,
    pub standby_timeout: u16,
    pub suspend_timeout: u16,
    pub off_timeout:     u16,
    pub pad1:            [u8; 18],
}

impl Copy for xcb_dpms_get_timeouts_reply_t {}
impl Clone for xcb_dpms_get_timeouts_reply_t {
    fn clone(&self) -> xcb_dpms_get_timeouts_reply_t { *self }
}

pub const XCB_DPMS_SET_TIMEOUTS: u8 = 3;

#[repr(C)]
pub struct xcb_dpms_set_timeouts_request_t {
    pub major_opcode:    u8,
    pub minor_opcode:    u8,
    pub length:          u16,
    pub standby_timeout: u16,
    pub suspend_timeout: u16,
    pub off_timeout:     u16,
}

impl Copy for xcb_dpms_set_timeouts_request_t {}
impl Clone for xcb_dpms_set_timeouts_request_t {
    fn clone(&self) -> xcb_dpms_set_timeouts_request_t { *self }
}

pub const XCB_DPMS_ENABLE: u8 = 4;

#[repr(C)]
pub struct xcb_dpms_enable_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_dpms_enable_request_t {}
impl Clone for xcb_dpms_enable_request_t {
    fn clone(&self) -> xcb_dpms_enable_request_t { *self }
}

pub const XCB_DPMS_DISABLE: u8 = 5;

#[repr(C)]
pub struct xcb_dpms_disable_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_dpms_disable_request_t {}
impl Clone for xcb_dpms_disable_request_t {
    fn clone(&self) -> xcb_dpms_disable_request_t { *self }
}

pub type xcb_dpms_dpms_mode_t = u32;
pub const XCB_DPMS_DPMS_MODE_ON     : xcb_dpms_dpms_mode_t = 0x00;
pub const XCB_DPMS_DPMS_MODE_STANDBY: xcb_dpms_dpms_mode_t = 0x01;
pub const XCB_DPMS_DPMS_MODE_SUSPEND: xcb_dpms_dpms_mode_t = 0x02;
pub const XCB_DPMS_DPMS_MODE_OFF    : xcb_dpms_dpms_mode_t = 0x03;

pub const XCB_DPMS_FORCE_LEVEL: u8 = 6;

#[repr(C)]
pub struct xcb_dpms_force_level_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub power_level:  u16,
}

impl Copy for xcb_dpms_force_level_request_t {}
impl Clone for xcb_dpms_force_level_request_t {
    fn clone(&self) -> xcb_dpms_force_level_request_t { *self }
}

pub const XCB_DPMS_INFO: u8 = 7;

#[repr(C)]
pub struct xcb_dpms_info_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_dpms_info_request_t {}
impl Clone for xcb_dpms_info_request_t {
    fn clone(&self) -> xcb_dpms_info_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_dpms_info_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_dpms_info_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub power_level:   u16,
    pub state:         u8,
    pub pad1:          [u8; 21],
}

impl Copy for xcb_dpms_info_reply_t {}
impl Clone for xcb_dpms_info_reply_t {
    fn clone(&self) -> xcb_dpms_info_reply_t { *self }
}


#[link(name="xcb-dpms")]
extern {

    pub static mut xcb_dpms_id: xcb_extension_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dpms_get_version_reply (c:      *mut xcb_connection_t,
                                       cookie: xcb_dpms_get_version_cookie_t,
                                       error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_dpms_get_version_reply_t;

    pub fn xcb_dpms_get_version (c:                    *mut xcb_connection_t,
                                 client_major_version: u16,
                                 client_minor_version: u16)
            -> xcb_dpms_get_version_cookie_t;

    pub fn xcb_dpms_get_version_unchecked (c:                    *mut xcb_connection_t,
                                           client_major_version: u16,
                                           client_minor_version: u16)
            -> xcb_dpms_get_version_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dpms_capable_reply (c:      *mut xcb_connection_t,
                                   cookie: xcb_dpms_capable_cookie_t,
                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_dpms_capable_reply_t;

    pub fn xcb_dpms_capable (c: *mut xcb_connection_t)
            -> xcb_dpms_capable_cookie_t;

    pub fn xcb_dpms_capable_unchecked (c: *mut xcb_connection_t)
            -> xcb_dpms_capable_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dpms_get_timeouts_reply (c:      *mut xcb_connection_t,
                                        cookie: xcb_dpms_get_timeouts_cookie_t,
                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_dpms_get_timeouts_reply_t;

    pub fn xcb_dpms_get_timeouts (c: *mut xcb_connection_t)
            -> xcb_dpms_get_timeouts_cookie_t;

    pub fn xcb_dpms_get_timeouts_unchecked (c: *mut xcb_connection_t)
            -> xcb_dpms_get_timeouts_cookie_t;

    pub fn xcb_dpms_set_timeouts (c:               *mut xcb_connection_t,
                                  standby_timeout: u16,
                                  suspend_timeout: u16,
                                  off_timeout:     u16)
            -> xcb_void_cookie_t;

    pub fn xcb_dpms_set_timeouts_checked (c:               *mut xcb_connection_t,
                                          standby_timeout: u16,
                                          suspend_timeout: u16,
                                          off_timeout:     u16)
            -> xcb_void_cookie_t;

    pub fn xcb_dpms_enable (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_dpms_enable_checked (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_dpms_disable (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_dpms_disable_checked (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_dpms_force_level (c:           *mut xcb_connection_t,
                                 power_level: u16)
            -> xcb_void_cookie_t;

    pub fn xcb_dpms_force_level_checked (c:           *mut xcb_connection_t,
                                         power_level: u16)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dpms_info_reply (c:      *mut xcb_connection_t,
                                cookie: xcb_dpms_info_cookie_t,
                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_dpms_info_reply_t;

    pub fn xcb_dpms_info (c: *mut xcb_connection_t)
            -> xcb_dpms_info_cookie_t;

    pub fn xcb_dpms_info_unchecked (c: *mut xcb_connection_t)
            -> xcb_dpms_info_cookie_t;

} // extern
