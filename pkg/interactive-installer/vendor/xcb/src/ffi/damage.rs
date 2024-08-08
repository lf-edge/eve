// Generated automatically from damage.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;
use ffi::render::*;
use ffi::shape::*;
use ffi::xfixes::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_DAMAGE_MAJOR_VERSION: u32 = 1;
pub const XCB_DAMAGE_MINOR_VERSION: u32 = 1;

pub type xcb_damage_damage_t = u32;

#[repr(C)]
pub struct xcb_damage_damage_iterator_t {
    pub data:  *mut xcb_damage_damage_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_damage_report_level_t = u32;
pub const XCB_DAMAGE_REPORT_LEVEL_RAW_RECTANGLES  : xcb_damage_report_level_t = 0x00;
pub const XCB_DAMAGE_REPORT_LEVEL_DELTA_RECTANGLES: xcb_damage_report_level_t = 0x01;
pub const XCB_DAMAGE_REPORT_LEVEL_BOUNDING_BOX    : xcb_damage_report_level_t = 0x02;
pub const XCB_DAMAGE_REPORT_LEVEL_NON_EMPTY       : xcb_damage_report_level_t = 0x03;

pub const XCB_DAMAGE_BAD_DAMAGE: u8 = 0;

#[repr(C)]
pub struct xcb_damage_bad_damage_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_damage_bad_damage_error_t {}
impl Clone for xcb_damage_bad_damage_error_t {
    fn clone(&self) -> xcb_damage_bad_damage_error_t { *self }
}

pub const XCB_DAMAGE_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_damage_query_version_request_t {
    pub major_opcode:         u8,
    pub minor_opcode:         u8,
    pub length:               u16,
    pub client_major_version: u32,
    pub client_minor_version: u32,
}

impl Copy for xcb_damage_query_version_request_t {}
impl Clone for xcb_damage_query_version_request_t {
    fn clone(&self) -> xcb_damage_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_damage_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_damage_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub pad1:          [u8; 16],
}

impl Copy for xcb_damage_query_version_reply_t {}
impl Clone for xcb_damage_query_version_reply_t {
    fn clone(&self) -> xcb_damage_query_version_reply_t { *self }
}

pub const XCB_DAMAGE_CREATE: u8 = 1;

#[repr(C)]
pub struct xcb_damage_create_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub damage:       xcb_damage_damage_t,
    pub drawable:     xcb_drawable_t,
    pub level:        u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_damage_create_request_t {}
impl Clone for xcb_damage_create_request_t {
    fn clone(&self) -> xcb_damage_create_request_t { *self }
}

pub const XCB_DAMAGE_DESTROY: u8 = 2;

#[repr(C)]
pub struct xcb_damage_destroy_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub damage:       xcb_damage_damage_t,
}

impl Copy for xcb_damage_destroy_request_t {}
impl Clone for xcb_damage_destroy_request_t {
    fn clone(&self) -> xcb_damage_destroy_request_t { *self }
}

pub const XCB_DAMAGE_SUBTRACT: u8 = 3;

#[repr(C)]
pub struct xcb_damage_subtract_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub damage:       xcb_damage_damage_t,
    pub repair:       xcb_xfixes_region_t,
    pub parts:        xcb_xfixes_region_t,
}

impl Copy for xcb_damage_subtract_request_t {}
impl Clone for xcb_damage_subtract_request_t {
    fn clone(&self) -> xcb_damage_subtract_request_t { *self }
}

pub const XCB_DAMAGE_ADD: u8 = 4;

#[repr(C)]
pub struct xcb_damage_add_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub region:       xcb_xfixes_region_t,
}

impl Copy for xcb_damage_add_request_t {}
impl Clone for xcb_damage_add_request_t {
    fn clone(&self) -> xcb_damage_add_request_t { *self }
}

pub const XCB_DAMAGE_NOTIFY: u8 = 0;

#[repr(C)]
pub struct xcb_damage_notify_event_t {
    pub response_type: u8,
    pub level:         u8,
    pub sequence:      u16,
    pub drawable:      xcb_drawable_t,
    pub damage:        xcb_damage_damage_t,
    pub timestamp:     xcb_timestamp_t,
    pub area:          xcb_rectangle_t,
    pub geometry:      xcb_rectangle_t,
}

impl Copy for xcb_damage_notify_event_t {}
impl Clone for xcb_damage_notify_event_t {
    fn clone(&self) -> xcb_damage_notify_event_t { *self }
}


#[link(name="xcb-damage")]
extern {

    pub static mut xcb_damage_id: xcb_extension_t;

    pub fn xcb_damage_damage_next (i: *mut xcb_damage_damage_iterator_t);

    pub fn xcb_damage_damage_end (i: *mut xcb_damage_damage_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_damage_query_version_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_damage_query_version_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_damage_query_version_reply_t;

    pub fn xcb_damage_query_version (c:                    *mut xcb_connection_t,
                                     client_major_version: u32,
                                     client_minor_version: u32)
            -> xcb_damage_query_version_cookie_t;

    pub fn xcb_damage_query_version_unchecked (c:                    *mut xcb_connection_t,
                                               client_major_version: u32,
                                               client_minor_version: u32)
            -> xcb_damage_query_version_cookie_t;

    pub fn xcb_damage_create (c:        *mut xcb_connection_t,
                              damage:   xcb_damage_damage_t,
                              drawable: xcb_drawable_t,
                              level:    u8)
            -> xcb_void_cookie_t;

    pub fn xcb_damage_create_checked (c:        *mut xcb_connection_t,
                                      damage:   xcb_damage_damage_t,
                                      drawable: xcb_drawable_t,
                                      level:    u8)
            -> xcb_void_cookie_t;

    pub fn xcb_damage_destroy (c:      *mut xcb_connection_t,
                               damage: xcb_damage_damage_t)
            -> xcb_void_cookie_t;

    pub fn xcb_damage_destroy_checked (c:      *mut xcb_connection_t,
                                       damage: xcb_damage_damage_t)
            -> xcb_void_cookie_t;

    pub fn xcb_damage_subtract (c:      *mut xcb_connection_t,
                                damage: xcb_damage_damage_t,
                                repair: xcb_xfixes_region_t,
                                parts:  xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_damage_subtract_checked (c:      *mut xcb_connection_t,
                                        damage: xcb_damage_damage_t,
                                        repair: xcb_xfixes_region_t,
                                        parts:  xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_damage_add (c:        *mut xcb_connection_t,
                           drawable: xcb_drawable_t,
                           region:   xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_damage_add_checked (c:        *mut xcb_connection_t,
                                   drawable: xcb_drawable_t,
                                   region:   xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

} // extern
