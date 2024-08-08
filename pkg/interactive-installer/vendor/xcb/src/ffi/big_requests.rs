// Generated automatically from bigreq.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_BIG_REQUESTS_MAJOR_VERSION: u32 = 0;
pub const XCB_BIG_REQUESTS_MINOR_VERSION: u32 = 0;

pub const XCB_BIG_REQUESTS_ENABLE: u8 = 0;

#[repr(C)]
pub struct xcb_big_requests_enable_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_big_requests_enable_request_t {}
impl Clone for xcb_big_requests_enable_request_t {
    fn clone(&self) -> xcb_big_requests_enable_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_big_requests_enable_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_big_requests_enable_reply_t {
    pub response_type:          u8,
    pub pad0:                   u8,
    pub sequence:               u16,
    pub length:                 u32,
    pub maximum_request_length: u32,
}

impl Copy for xcb_big_requests_enable_reply_t {}
impl Clone for xcb_big_requests_enable_reply_t {
    fn clone(&self) -> xcb_big_requests_enable_reply_t { *self }
}


#[link(name="xcb")]
extern {

    pub static mut xcb_big_requests_id: xcb_extension_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_big_requests_enable_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_big_requests_enable_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_big_requests_enable_reply_t;

    pub fn xcb_big_requests_enable (c: *mut xcb_connection_t)
            -> xcb_big_requests_enable_cookie_t;

    pub fn xcb_big_requests_enable_unchecked (c: *mut xcb_connection_t)
            -> xcb_big_requests_enable_cookie_t;

} // extern
