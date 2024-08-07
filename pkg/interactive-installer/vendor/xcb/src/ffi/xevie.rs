// Generated automatically from xevie.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_XEVIE_MAJOR_VERSION: u32 = 1;
pub const XCB_XEVIE_MINOR_VERSION: u32 = 0;

pub const XCB_XEVIE_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_xevie_query_version_request_t {
    pub major_opcode:         u8,
    pub minor_opcode:         u8,
    pub length:               u16,
    pub client_major_version: u16,
    pub client_minor_version: u16,
}

impl Copy for xcb_xevie_query_version_request_t {}
impl Clone for xcb_xevie_query_version_request_t {
    fn clone(&self) -> xcb_xevie_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xevie_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xevie_query_version_reply_t {
    pub response_type:        u8,
    pub pad0:                 u8,
    pub sequence:             u16,
    pub length:               u32,
    pub server_major_version: u16,
    pub server_minor_version: u16,
    pub pad1:                 [u8; 20],
}

impl Copy for xcb_xevie_query_version_reply_t {}
impl Clone for xcb_xevie_query_version_reply_t {
    fn clone(&self) -> xcb_xevie_query_version_reply_t { *self }
}

pub const XCB_XEVIE_START: u8 = 1;

#[repr(C)]
pub struct xcb_xevie_start_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u32,
}

impl Copy for xcb_xevie_start_request_t {}
impl Clone for xcb_xevie_start_request_t {
    fn clone(&self) -> xcb_xevie_start_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xevie_start_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xevie_start_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad1:          [u8; 24],
}

impl Copy for xcb_xevie_start_reply_t {}
impl Clone for xcb_xevie_start_reply_t {
    fn clone(&self) -> xcb_xevie_start_reply_t { *self }
}

pub const XCB_XEVIE_END: u8 = 2;

#[repr(C)]
pub struct xcb_xevie_end_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub cmap:         u32,
}

impl Copy for xcb_xevie_end_request_t {}
impl Clone for xcb_xevie_end_request_t {
    fn clone(&self) -> xcb_xevie_end_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xevie_end_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xevie_end_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad1:          [u8; 24],
}

impl Copy for xcb_xevie_end_reply_t {}
impl Clone for xcb_xevie_end_reply_t {
    fn clone(&self) -> xcb_xevie_end_reply_t { *self }
}

pub type xcb_xevie_datatype_t = u32;
pub const XCB_XEVIE_DATATYPE_UNMODIFIED: xcb_xevie_datatype_t = 0x00;
pub const XCB_XEVIE_DATATYPE_MODIFIED  : xcb_xevie_datatype_t = 0x01;

#[repr(C)]
pub struct xcb_xevie_event_t {
    pub pad0: [u8; 32],
}

impl Copy for xcb_xevie_event_t {}
impl Clone for xcb_xevie_event_t {
    fn clone(&self) -> xcb_xevie_event_t { *self }
}

#[repr(C)]
pub struct xcb_xevie_event_iterator_t {
    pub data:  *mut xcb_xevie_event_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_XEVIE_SEND: u8 = 3;

#[repr(C)]
pub struct xcb_xevie_send_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub event:        xcb_xevie_event_t,
    pub data_type:    u32,
    pub pad0:         [u8; 64],
}

impl Copy for xcb_xevie_send_request_t {}
impl Clone for xcb_xevie_send_request_t {
    fn clone(&self) -> xcb_xevie_send_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xevie_send_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xevie_send_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad1:          [u8; 24],
}

impl Copy for xcb_xevie_send_reply_t {}
impl Clone for xcb_xevie_send_reply_t {
    fn clone(&self) -> xcb_xevie_send_reply_t { *self }
}

pub const XCB_XEVIE_SELECT_INPUT: u8 = 4;

#[repr(C)]
pub struct xcb_xevie_select_input_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub event_mask:   u32,
}

impl Copy for xcb_xevie_select_input_request_t {}
impl Clone for xcb_xevie_select_input_request_t {
    fn clone(&self) -> xcb_xevie_select_input_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xevie_select_input_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xevie_select_input_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad1:          [u8; 24],
}

impl Copy for xcb_xevie_select_input_reply_t {}
impl Clone for xcb_xevie_select_input_reply_t {
    fn clone(&self) -> xcb_xevie_select_input_reply_t { *self }
}


#[link(name="xcb-xevie")]
extern {

    pub static mut xcb_xevie_id: xcb_extension_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xevie_query_version_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_xevie_query_version_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xevie_query_version_reply_t;

    pub fn xcb_xevie_query_version (c:                    *mut xcb_connection_t,
                                    client_major_version: u16,
                                    client_minor_version: u16)
            -> xcb_xevie_query_version_cookie_t;

    pub fn xcb_xevie_query_version_unchecked (c:                    *mut xcb_connection_t,
                                              client_major_version: u16,
                                              client_minor_version: u16)
            -> xcb_xevie_query_version_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xevie_start_reply (c:      *mut xcb_connection_t,
                                  cookie: xcb_xevie_start_cookie_t,
                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xevie_start_reply_t;

    pub fn xcb_xevie_start (c:      *mut xcb_connection_t,
                            screen: u32)
            -> xcb_xevie_start_cookie_t;

    pub fn xcb_xevie_start_unchecked (c:      *mut xcb_connection_t,
                                      screen: u32)
            -> xcb_xevie_start_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xevie_end_reply (c:      *mut xcb_connection_t,
                                cookie: xcb_xevie_end_cookie_t,
                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xevie_end_reply_t;

    pub fn xcb_xevie_end (c:    *mut xcb_connection_t,
                          cmap: u32)
            -> xcb_xevie_end_cookie_t;

    pub fn xcb_xevie_end_unchecked (c:    *mut xcb_connection_t,
                                    cmap: u32)
            -> xcb_xevie_end_cookie_t;

    pub fn xcb_xevie_event_next (i: *mut xcb_xevie_event_iterator_t);

    pub fn xcb_xevie_event_end (i: *mut xcb_xevie_event_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xevie_send_reply (c:      *mut xcb_connection_t,
                                 cookie: xcb_xevie_send_cookie_t,
                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xevie_send_reply_t;

    pub fn xcb_xevie_send (c:         *mut xcb_connection_t,
                           event:     xcb_xevie_event_t,
                           data_type: u32)
            -> xcb_xevie_send_cookie_t;

    pub fn xcb_xevie_send_unchecked (c:         *mut xcb_connection_t,
                                     event:     xcb_xevie_event_t,
                                     data_type: u32)
            -> xcb_xevie_send_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xevie_select_input_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_xevie_select_input_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xevie_select_input_reply_t;

    pub fn xcb_xevie_select_input (c:          *mut xcb_connection_t,
                                   event_mask: u32)
            -> xcb_xevie_select_input_cookie_t;

    pub fn xcb_xevie_select_input_unchecked (c:          *mut xcb_connection_t,
                                             event_mask: u32)
            -> xcb_xevie_select_input_cookie_t;

} // extern
