// Generated automatically from xtest.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_TEST_MAJOR_VERSION: u32 = 2;
pub const XCB_TEST_MINOR_VERSION: u32 = 2;

pub const XCB_TEST_GET_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_test_get_version_request_t {
    pub major_opcode:  u8,
    pub minor_opcode:  u8,
    pub length:        u16,
    pub major_version: u8,
    pub pad0:          u8,
    pub minor_version: u16,
}

impl Copy for xcb_test_get_version_request_t {}
impl Clone for xcb_test_get_version_request_t {
    fn clone(&self) -> xcb_test_get_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_test_get_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_test_get_version_reply_t {
    pub response_type: u8,
    pub major_version: u8,
    pub sequence:      u16,
    pub length:        u32,
    pub minor_version: u16,
}

impl Copy for xcb_test_get_version_reply_t {}
impl Clone for xcb_test_get_version_reply_t {
    fn clone(&self) -> xcb_test_get_version_reply_t { *self }
}

pub type xcb_test_cursor_t = u32;
pub const XCB_TEST_CURSOR_NONE   : xcb_test_cursor_t = 0x00;
pub const XCB_TEST_CURSOR_CURRENT: xcb_test_cursor_t = 0x01;

pub const XCB_TEST_COMPARE_CURSOR: u8 = 1;

#[repr(C)]
pub struct xcb_test_compare_cursor_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub cursor:       xcb_cursor_t,
}

impl Copy for xcb_test_compare_cursor_request_t {}
impl Clone for xcb_test_compare_cursor_request_t {
    fn clone(&self) -> xcb_test_compare_cursor_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_test_compare_cursor_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_test_compare_cursor_reply_t {
    pub response_type: u8,
    pub same:          u8,
    pub sequence:      u16,
    pub length:        u32,
}

impl Copy for xcb_test_compare_cursor_reply_t {}
impl Clone for xcb_test_compare_cursor_reply_t {
    fn clone(&self) -> xcb_test_compare_cursor_reply_t { *self }
}

pub const XCB_TEST_FAKE_INPUT: u8 = 2;

#[repr(C)]
pub struct xcb_test_fake_input_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub type_:        u8,
    pub detail:       u8,
    pub pad0:         [u8; 2],
    pub time:         u32,
    pub root:         xcb_window_t,
    pub pad1:         [u8; 8],
    pub rootX:        i16,
    pub rootY:        i16,
    pub pad2:         [u8; 7],
    pub deviceid:     u8,
}

impl Copy for xcb_test_fake_input_request_t {}
impl Clone for xcb_test_fake_input_request_t {
    fn clone(&self) -> xcb_test_fake_input_request_t { *self }
}

pub const XCB_TEST_GRAB_CONTROL: u8 = 3;

#[repr(C)]
pub struct xcb_test_grab_control_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub impervious:   u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_test_grab_control_request_t {}
impl Clone for xcb_test_grab_control_request_t {
    fn clone(&self) -> xcb_test_grab_control_request_t { *self }
}


#[link(name="xcb-xtest")]
extern {

    pub static mut xcb_test_id: xcb_extension_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_test_get_version_reply (c:      *mut xcb_connection_t,
                                       cookie: xcb_test_get_version_cookie_t,
                                       error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_test_get_version_reply_t;

    pub fn xcb_test_get_version (c:             *mut xcb_connection_t,
                                 major_version: u8,
                                 minor_version: u16)
            -> xcb_test_get_version_cookie_t;

    pub fn xcb_test_get_version_unchecked (c:             *mut xcb_connection_t,
                                           major_version: u8,
                                           minor_version: u16)
            -> xcb_test_get_version_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_test_compare_cursor_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_test_compare_cursor_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_test_compare_cursor_reply_t;

    pub fn xcb_test_compare_cursor (c:      *mut xcb_connection_t,
                                    window: xcb_window_t,
                                    cursor: xcb_cursor_t)
            -> xcb_test_compare_cursor_cookie_t;

    pub fn xcb_test_compare_cursor_unchecked (c:      *mut xcb_connection_t,
                                              window: xcb_window_t,
                                              cursor: xcb_cursor_t)
            -> xcb_test_compare_cursor_cookie_t;

    pub fn xcb_test_fake_input (c:        *mut xcb_connection_t,
                                type_:    u8,
                                detail:   u8,
                                time:     u32,
                                root:     xcb_window_t,
                                rootX:    i16,
                                rootY:    i16,
                                deviceid: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_test_fake_input_checked (c:        *mut xcb_connection_t,
                                        type_:    u8,
                                        detail:   u8,
                                        time:     u32,
                                        root:     xcb_window_t,
                                        rootX:    i16,
                                        rootY:    i16,
                                        deviceid: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_test_grab_control (c:          *mut xcb_connection_t,
                                  impervious: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_test_grab_control_checked (c:          *mut xcb_connection_t,
                                          impervious: u8)
            -> xcb_void_cookie_t;

} // extern
