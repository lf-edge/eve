// Generated automatically from dri3.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_DRI3_MAJOR_VERSION: u32 = 1;
pub const XCB_DRI3_MINOR_VERSION: u32 = 0;

pub const XCB_DRI3_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_dri3_query_version_request_t {
    pub major_opcode:  u8,
    pub minor_opcode:  u8,
    pub length:        u16,
    pub major_version: u32,
    pub minor_version: u32,
}

impl Copy for xcb_dri3_query_version_request_t {}
impl Clone for xcb_dri3_query_version_request_t {
    fn clone(&self) -> xcb_dri3_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_dri3_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_dri3_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub major_version: u32,
    pub minor_version: u32,
}

impl Copy for xcb_dri3_query_version_reply_t {}
impl Clone for xcb_dri3_query_version_reply_t {
    fn clone(&self) -> xcb_dri3_query_version_reply_t { *self }
}

pub const XCB_DRI3_OPEN: u8 = 1;

#[repr(C)]
pub struct xcb_dri3_open_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub provider:     u32,
}

impl Copy for xcb_dri3_open_request_t {}
impl Clone for xcb_dri3_open_request_t {
    fn clone(&self) -> xcb_dri3_open_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_dri3_open_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_dri3_open_reply_t {
    pub response_type: u8,
    pub nfd:           u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad0:          [u8; 24],
}

impl Copy for xcb_dri3_open_reply_t {}
impl Clone for xcb_dri3_open_reply_t {
    fn clone(&self) -> xcb_dri3_open_reply_t { *self }
}

pub const XCB_DRI3_PIXMAP_FROM_BUFFER: u8 = 2;

#[repr(C)]
pub struct xcb_dri3_pixmap_from_buffer_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub pixmap:       xcb_pixmap_t,
    pub drawable:     xcb_drawable_t,
    pub size:         u32,
    pub width:        u16,
    pub height:       u16,
    pub stride:       u16,
    pub depth:        u8,
    pub bpp:          u8,
}

impl Copy for xcb_dri3_pixmap_from_buffer_request_t {}
impl Clone for xcb_dri3_pixmap_from_buffer_request_t {
    fn clone(&self) -> xcb_dri3_pixmap_from_buffer_request_t { *self }
}

pub const XCB_DRI3_BUFFER_FROM_PIXMAP: u8 = 3;

#[repr(C)]
pub struct xcb_dri3_buffer_from_pixmap_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub pixmap:       xcb_pixmap_t,
}

impl Copy for xcb_dri3_buffer_from_pixmap_request_t {}
impl Clone for xcb_dri3_buffer_from_pixmap_request_t {
    fn clone(&self) -> xcb_dri3_buffer_from_pixmap_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_dri3_buffer_from_pixmap_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_dri3_buffer_from_pixmap_reply_t {
    pub response_type: u8,
    pub nfd:           u8,
    pub sequence:      u16,
    pub length:        u32,
    pub size:          u32,
    pub width:         u16,
    pub height:        u16,
    pub stride:        u16,
    pub depth:         u8,
    pub bpp:           u8,
    pub pad0:          [u8; 12],
}

impl Copy for xcb_dri3_buffer_from_pixmap_reply_t {}
impl Clone for xcb_dri3_buffer_from_pixmap_reply_t {
    fn clone(&self) -> xcb_dri3_buffer_from_pixmap_reply_t { *self }
}

pub const XCB_DRI3_FENCE_FROM_FD: u8 = 4;

#[repr(C)]
pub struct xcb_dri3_fence_from_fd_request_t {
    pub major_opcode:        u8,
    pub minor_opcode:        u8,
    pub length:              u16,
    pub drawable:            xcb_drawable_t,
    pub fence:               u32,
    pub initially_triggered: u8,
    pub pad0:                [u8; 3],
}

impl Copy for xcb_dri3_fence_from_fd_request_t {}
impl Clone for xcb_dri3_fence_from_fd_request_t {
    fn clone(&self) -> xcb_dri3_fence_from_fd_request_t { *self }
}

pub const XCB_DRI3_FD_FROM_FENCE: u8 = 5;

#[repr(C)]
pub struct xcb_dri3_fd_from_fence_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub fence:        u32,
}

impl Copy for xcb_dri3_fd_from_fence_request_t {}
impl Clone for xcb_dri3_fd_from_fence_request_t {
    fn clone(&self) -> xcb_dri3_fd_from_fence_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_dri3_fd_from_fence_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_dri3_fd_from_fence_reply_t {
    pub response_type: u8,
    pub nfd:           u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad0:          [u8; 24],
}

impl Copy for xcb_dri3_fd_from_fence_reply_t {}
impl Clone for xcb_dri3_fd_from_fence_reply_t {
    fn clone(&self) -> xcb_dri3_fd_from_fence_reply_t { *self }
}


#[link(name="xcb-dri3")]
extern {

    pub static mut xcb_dri3_id: xcb_extension_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dri3_query_version_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_dri3_query_version_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_dri3_query_version_reply_t;

    pub fn xcb_dri3_query_version (c:             *mut xcb_connection_t,
                                   major_version: u32,
                                   minor_version: u32)
            -> xcb_dri3_query_version_cookie_t;

    pub fn xcb_dri3_query_version_unchecked (c:             *mut xcb_connection_t,
                                             major_version: u32,
                                             minor_version: u32)
            -> xcb_dri3_query_version_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dri3_open_reply (c:      *mut xcb_connection_t,
                                cookie: xcb_dri3_open_cookie_t,
                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_dri3_open_reply_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dri3_open_reply_fds (c:     *mut xcb_connection_t,
                                    reply: *mut xcb_dri3_open_reply_t)
            -> *mut c_int;

    pub fn xcb_dri3_open (c:        *mut xcb_connection_t,
                          drawable: xcb_drawable_t,
                          provider: u32)
            -> xcb_dri3_open_cookie_t;

    pub fn xcb_dri3_open_unchecked (c:        *mut xcb_connection_t,
                                    drawable: xcb_drawable_t,
                                    provider: u32)
            -> xcb_dri3_open_cookie_t;

    pub fn xcb_dri3_pixmap_from_buffer (c:         *mut xcb_connection_t,
                                        pixmap:    xcb_pixmap_t,
                                        drawable:  xcb_drawable_t,
                                        size:      u32,
                                        width:     u16,
                                        height:    u16,
                                        stride:    u16,
                                        depth:     u8,
                                        bpp:       u8,
                                        pixmap_fd: i32)
            -> xcb_void_cookie_t;

    pub fn xcb_dri3_pixmap_from_buffer_checked (c:         *mut xcb_connection_t,
                                                pixmap:    xcb_pixmap_t,
                                                drawable:  xcb_drawable_t,
                                                size:      u32,
                                                width:     u16,
                                                height:    u16,
                                                stride:    u16,
                                                depth:     u8,
                                                bpp:       u8,
                                                pixmap_fd: i32)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dri3_buffer_from_pixmap_reply (c:      *mut xcb_connection_t,
                                              cookie: xcb_dri3_buffer_from_pixmap_cookie_t,
                                              error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_dri3_buffer_from_pixmap_reply_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dri3_buffer_from_pixmap_reply_fds (c:     *mut xcb_connection_t,
                                                  reply: *mut xcb_dri3_buffer_from_pixmap_reply_t)
            -> *mut c_int;

    pub fn xcb_dri3_buffer_from_pixmap (c:      *mut xcb_connection_t,
                                        pixmap: xcb_pixmap_t)
            -> xcb_dri3_buffer_from_pixmap_cookie_t;

    pub fn xcb_dri3_buffer_from_pixmap_unchecked (c:      *mut xcb_connection_t,
                                                  pixmap: xcb_pixmap_t)
            -> xcb_dri3_buffer_from_pixmap_cookie_t;

    pub fn xcb_dri3_fence_from_fd (c:                   *mut xcb_connection_t,
                                   drawable:            xcb_drawable_t,
                                   fence:               u32,
                                   initially_triggered: u8,
                                   fence_fd:            i32)
            -> xcb_void_cookie_t;

    pub fn xcb_dri3_fence_from_fd_checked (c:                   *mut xcb_connection_t,
                                           drawable:            xcb_drawable_t,
                                           fence:               u32,
                                           initially_triggered: u8,
                                           fence_fd:            i32)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dri3_fd_from_fence_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_dri3_fd_from_fence_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_dri3_fd_from_fence_reply_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_dri3_fd_from_fence_reply_fds (c:     *mut xcb_connection_t,
                                             reply: *mut xcb_dri3_fd_from_fence_reply_t)
            -> *mut c_int;

    pub fn xcb_dri3_fd_from_fence (c:        *mut xcb_connection_t,
                                   drawable: xcb_drawable_t,
                                   fence:    u32)
            -> xcb_dri3_fd_from_fence_cookie_t;

    pub fn xcb_dri3_fd_from_fence_unchecked (c:        *mut xcb_connection_t,
                                             drawable: xcb_drawable_t,
                                             fence:    u32)
            -> xcb_dri3_fd_from_fence_cookie_t;

} // extern
