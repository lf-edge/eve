// Generated automatically from xinerama.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_XINERAMA_MAJOR_VERSION: u32 = 1;
pub const XCB_XINERAMA_MINOR_VERSION: u32 = 1;

#[repr(C)]
pub struct xcb_xinerama_screen_info_t {
    pub x_org:  i16,
    pub y_org:  i16,
    pub width:  u16,
    pub height: u16,
}

impl Copy for xcb_xinerama_screen_info_t {}
impl Clone for xcb_xinerama_screen_info_t {
    fn clone(&self) -> xcb_xinerama_screen_info_t { *self }
}

#[repr(C)]
pub struct xcb_xinerama_screen_info_iterator_t {
    pub data:  *mut xcb_xinerama_screen_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_XINERAMA_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_xinerama_query_version_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub major:        u8,
    pub minor:        u8,
}

impl Copy for xcb_xinerama_query_version_request_t {}
impl Clone for xcb_xinerama_query_version_request_t {
    fn clone(&self) -> xcb_xinerama_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xinerama_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xinerama_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub major:         u16,
    pub minor:         u16,
}

impl Copy for xcb_xinerama_query_version_reply_t {}
impl Clone for xcb_xinerama_query_version_reply_t {
    fn clone(&self) -> xcb_xinerama_query_version_reply_t { *self }
}

pub const XCB_XINERAMA_GET_STATE: u8 = 1;

#[repr(C)]
pub struct xcb_xinerama_get_state_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_xinerama_get_state_request_t {}
impl Clone for xcb_xinerama_get_state_request_t {
    fn clone(&self) -> xcb_xinerama_get_state_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xinerama_get_state_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xinerama_get_state_reply_t {
    pub response_type: u8,
    pub state:         u8,
    pub sequence:      u16,
    pub length:        u32,
    pub window:        xcb_window_t,
}

impl Copy for xcb_xinerama_get_state_reply_t {}
impl Clone for xcb_xinerama_get_state_reply_t {
    fn clone(&self) -> xcb_xinerama_get_state_reply_t { *self }
}

pub const XCB_XINERAMA_GET_SCREEN_COUNT: u8 = 2;

#[repr(C)]
pub struct xcb_xinerama_get_screen_count_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_xinerama_get_screen_count_request_t {}
impl Clone for xcb_xinerama_get_screen_count_request_t {
    fn clone(&self) -> xcb_xinerama_get_screen_count_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xinerama_get_screen_count_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xinerama_get_screen_count_reply_t {
    pub response_type: u8,
    pub screen_count:  u8,
    pub sequence:      u16,
    pub length:        u32,
    pub window:        xcb_window_t,
}

impl Copy for xcb_xinerama_get_screen_count_reply_t {}
impl Clone for xcb_xinerama_get_screen_count_reply_t {
    fn clone(&self) -> xcb_xinerama_get_screen_count_reply_t { *self }
}

pub const XCB_XINERAMA_GET_SCREEN_SIZE: u8 = 3;

#[repr(C)]
pub struct xcb_xinerama_get_screen_size_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub screen:       u32,
}

impl Copy for xcb_xinerama_get_screen_size_request_t {}
impl Clone for xcb_xinerama_get_screen_size_request_t {
    fn clone(&self) -> xcb_xinerama_get_screen_size_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xinerama_get_screen_size_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xinerama_get_screen_size_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub width:         u32,
    pub height:        u32,
    pub window:        xcb_window_t,
    pub screen:        u32,
}

impl Copy for xcb_xinerama_get_screen_size_reply_t {}
impl Clone for xcb_xinerama_get_screen_size_reply_t {
    fn clone(&self) -> xcb_xinerama_get_screen_size_reply_t { *self }
}

pub const XCB_XINERAMA_IS_ACTIVE: u8 = 4;

#[repr(C)]
pub struct xcb_xinerama_is_active_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_xinerama_is_active_request_t {}
impl Clone for xcb_xinerama_is_active_request_t {
    fn clone(&self) -> xcb_xinerama_is_active_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xinerama_is_active_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xinerama_is_active_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub state:         u32,
}

impl Copy for xcb_xinerama_is_active_reply_t {}
impl Clone for xcb_xinerama_is_active_reply_t {
    fn clone(&self) -> xcb_xinerama_is_active_reply_t { *self }
}

pub const XCB_XINERAMA_QUERY_SCREENS: u8 = 5;

#[repr(C)]
pub struct xcb_xinerama_query_screens_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_xinerama_query_screens_request_t {}
impl Clone for xcb_xinerama_query_screens_request_t {
    fn clone(&self) -> xcb_xinerama_query_screens_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xinerama_query_screens_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xinerama_query_screens_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub number:        u32,
    pub pad1:          [u8; 20],
}


#[link(name="xcb-xinerama")]
extern {

    pub static mut xcb_xinerama_id: xcb_extension_t;

    pub fn xcb_xinerama_screen_info_next (i: *mut xcb_xinerama_screen_info_iterator_t);

    pub fn xcb_xinerama_screen_info_end (i: *mut xcb_xinerama_screen_info_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xinerama_query_version_reply (c:      *mut xcb_connection_t,
                                             cookie: xcb_xinerama_query_version_cookie_t,
                                             error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xinerama_query_version_reply_t;

    pub fn xcb_xinerama_query_version (c:     *mut xcb_connection_t,
                                       major: u8,
                                       minor: u8)
            -> xcb_xinerama_query_version_cookie_t;

    pub fn xcb_xinerama_query_version_unchecked (c:     *mut xcb_connection_t,
                                                 major: u8,
                                                 minor: u8)
            -> xcb_xinerama_query_version_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xinerama_get_state_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_xinerama_get_state_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xinerama_get_state_reply_t;

    pub fn xcb_xinerama_get_state (c:      *mut xcb_connection_t,
                                   window: xcb_window_t)
            -> xcb_xinerama_get_state_cookie_t;

    pub fn xcb_xinerama_get_state_unchecked (c:      *mut xcb_connection_t,
                                             window: xcb_window_t)
            -> xcb_xinerama_get_state_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xinerama_get_screen_count_reply (c:      *mut xcb_connection_t,
                                                cookie: xcb_xinerama_get_screen_count_cookie_t,
                                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xinerama_get_screen_count_reply_t;

    pub fn xcb_xinerama_get_screen_count (c:      *mut xcb_connection_t,
                                          window: xcb_window_t)
            -> xcb_xinerama_get_screen_count_cookie_t;

    pub fn xcb_xinerama_get_screen_count_unchecked (c:      *mut xcb_connection_t,
                                                    window: xcb_window_t)
            -> xcb_xinerama_get_screen_count_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xinerama_get_screen_size_reply (c:      *mut xcb_connection_t,
                                               cookie: xcb_xinerama_get_screen_size_cookie_t,
                                               error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xinerama_get_screen_size_reply_t;

    pub fn xcb_xinerama_get_screen_size (c:      *mut xcb_connection_t,
                                         window: xcb_window_t,
                                         screen: u32)
            -> xcb_xinerama_get_screen_size_cookie_t;

    pub fn xcb_xinerama_get_screen_size_unchecked (c:      *mut xcb_connection_t,
                                                   window: xcb_window_t,
                                                   screen: u32)
            -> xcb_xinerama_get_screen_size_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xinerama_is_active_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_xinerama_is_active_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xinerama_is_active_reply_t;

    pub fn xcb_xinerama_is_active (c: *mut xcb_connection_t)
            -> xcb_xinerama_is_active_cookie_t;

    pub fn xcb_xinerama_is_active_unchecked (c: *mut xcb_connection_t)
            -> xcb_xinerama_is_active_cookie_t;

    pub fn xcb_xinerama_query_screens_screen_info (R: *const xcb_xinerama_query_screens_reply_t)
            -> *mut xcb_xinerama_screen_info_t;

    pub fn xcb_xinerama_query_screens_screen_info_length (R: *const xcb_xinerama_query_screens_reply_t)
            -> c_int;

    pub fn xcb_xinerama_query_screens_screen_info_iterator (R: *const xcb_xinerama_query_screens_reply_t)
            -> xcb_xinerama_screen_info_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xinerama_query_screens_reply (c:      *mut xcb_connection_t,
                                             cookie: xcb_xinerama_query_screens_cookie_t,
                                             error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xinerama_query_screens_reply_t;

    pub fn xcb_xinerama_query_screens (c: *mut xcb_connection_t)
            -> xcb_xinerama_query_screens_cookie_t;

    pub fn xcb_xinerama_query_screens_unchecked (c: *mut xcb_connection_t)
            -> xcb_xinerama_query_screens_cookie_t;

} // extern
