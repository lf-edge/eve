// Generated automatically from xvmc.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;
use ffi::shm::*;
use ffi::xv::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_XVMC_MAJOR_VERSION: u32 = 1;
pub const XCB_XVMC_MINOR_VERSION: u32 = 1;

pub type xcb_xvmc_context_t = u32;

#[repr(C)]
pub struct xcb_xvmc_context_iterator_t {
    pub data:  *mut xcb_xvmc_context_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_xvmc_surface_t = u32;

#[repr(C)]
pub struct xcb_xvmc_surface_iterator_t {
    pub data:  *mut xcb_xvmc_surface_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_xvmc_subpicture_t = u32;

#[repr(C)]
pub struct xcb_xvmc_subpicture_iterator_t {
    pub data:  *mut xcb_xvmc_subpicture_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_xvmc_surface_info_t {
    pub id:                    xcb_xvmc_surface_t,
    pub chroma_format:         u16,
    pub pad0:                  u16,
    pub max_width:             u16,
    pub max_height:            u16,
    pub subpicture_max_width:  u16,
    pub subpicture_max_height: u16,
    pub mc_type:               u32,
    pub flags:                 u32,
}

impl Copy for xcb_xvmc_surface_info_t {}
impl Clone for xcb_xvmc_surface_info_t {
    fn clone(&self) -> xcb_xvmc_surface_info_t { *self }
}

#[repr(C)]
pub struct xcb_xvmc_surface_info_iterator_t {
    pub data:  *mut xcb_xvmc_surface_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_XVMC_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_xvmc_query_version_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_xvmc_query_version_request_t {}
impl Clone for xcb_xvmc_query_version_request_t {
    fn clone(&self) -> xcb_xvmc_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xvmc_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xvmc_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub major:         u32,
    pub minor:         u32,
}

impl Copy for xcb_xvmc_query_version_reply_t {}
impl Clone for xcb_xvmc_query_version_reply_t {
    fn clone(&self) -> xcb_xvmc_query_version_reply_t { *self }
}

pub const XCB_XVMC_LIST_SURFACE_TYPES: u8 = 1;

#[repr(C)]
pub struct xcb_xvmc_list_surface_types_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub port_id:      xcb_xv_port_t,
}

impl Copy for xcb_xvmc_list_surface_types_request_t {}
impl Clone for xcb_xvmc_list_surface_types_request_t {
    fn clone(&self) -> xcb_xvmc_list_surface_types_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xvmc_list_surface_types_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xvmc_list_surface_types_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num:           u32,
    pub pad1:          [u8; 20],
}

pub const XCB_XVMC_CREATE_CONTEXT: u8 = 2;

#[repr(C)]
pub struct xcb_xvmc_create_context_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context_id:   xcb_xvmc_context_t,
    pub port_id:      xcb_xv_port_t,
    pub surface_id:   xcb_xvmc_surface_t,
    pub width:        u16,
    pub height:       u16,
    pub flags:        u32,
}

impl Copy for xcb_xvmc_create_context_request_t {}
impl Clone for xcb_xvmc_create_context_request_t {
    fn clone(&self) -> xcb_xvmc_create_context_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xvmc_create_context_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xvmc_create_context_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub width_actual:  u16,
    pub height_actual: u16,
    pub flags_return:  u32,
    pub pad1:          [u8; 20],
}

pub const XCB_XVMC_DESTROY_CONTEXT: u8 = 3;

#[repr(C)]
pub struct xcb_xvmc_destroy_context_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context_id:   xcb_xvmc_context_t,
}

impl Copy for xcb_xvmc_destroy_context_request_t {}
impl Clone for xcb_xvmc_destroy_context_request_t {
    fn clone(&self) -> xcb_xvmc_destroy_context_request_t { *self }
}

pub const XCB_XVMC_CREATE_SURFACE: u8 = 4;

#[repr(C)]
pub struct xcb_xvmc_create_surface_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub surface_id:   xcb_xvmc_surface_t,
    pub context_id:   xcb_xvmc_context_t,
}

impl Copy for xcb_xvmc_create_surface_request_t {}
impl Clone for xcb_xvmc_create_surface_request_t {
    fn clone(&self) -> xcb_xvmc_create_surface_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xvmc_create_surface_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xvmc_create_surface_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad1:          [u8; 24],
}

pub const XCB_XVMC_DESTROY_SURFACE: u8 = 5;

#[repr(C)]
pub struct xcb_xvmc_destroy_surface_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub surface_id:   xcb_xvmc_surface_t,
}

impl Copy for xcb_xvmc_destroy_surface_request_t {}
impl Clone for xcb_xvmc_destroy_surface_request_t {
    fn clone(&self) -> xcb_xvmc_destroy_surface_request_t { *self }
}

pub const XCB_XVMC_CREATE_SUBPICTURE: u8 = 6;

#[repr(C)]
pub struct xcb_xvmc_create_subpicture_request_t {
    pub major_opcode:  u8,
    pub minor_opcode:  u8,
    pub length:        u16,
    pub subpicture_id: xcb_xvmc_subpicture_t,
    pub context:       xcb_xvmc_context_t,
    pub xvimage_id:    u32,
    pub width:         u16,
    pub height:        u16,
}

impl Copy for xcb_xvmc_create_subpicture_request_t {}
impl Clone for xcb_xvmc_create_subpicture_request_t {
    fn clone(&self) -> xcb_xvmc_create_subpicture_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xvmc_create_subpicture_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xvmc_create_subpicture_reply_t {
    pub response_type:       u8,
    pub pad0:                u8,
    pub sequence:            u16,
    pub length:              u32,
    pub width_actual:        u16,
    pub height_actual:       u16,
    pub num_palette_entries: u16,
    pub entry_bytes:         u16,
    pub component_order:     [u8; 4],
    pub pad1:                [u8; 12],
}

pub const XCB_XVMC_DESTROY_SUBPICTURE: u8 = 7;

#[repr(C)]
pub struct xcb_xvmc_destroy_subpicture_request_t {
    pub major_opcode:  u8,
    pub minor_opcode:  u8,
    pub length:        u16,
    pub subpicture_id: xcb_xvmc_subpicture_t,
}

impl Copy for xcb_xvmc_destroy_subpicture_request_t {}
impl Clone for xcb_xvmc_destroy_subpicture_request_t {
    fn clone(&self) -> xcb_xvmc_destroy_subpicture_request_t { *self }
}

pub const XCB_XVMC_LIST_SUBPICTURE_TYPES: u8 = 8;

#[repr(C)]
pub struct xcb_xvmc_list_subpicture_types_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub port_id:      xcb_xv_port_t,
    pub surface_id:   xcb_xvmc_surface_t,
}

impl Copy for xcb_xvmc_list_subpicture_types_request_t {}
impl Clone for xcb_xvmc_list_subpicture_types_request_t {
    fn clone(&self) -> xcb_xvmc_list_subpicture_types_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xvmc_list_subpicture_types_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xvmc_list_subpicture_types_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num:           u32,
    pub pad1:          [u8; 20],
}


#[link(name="xcb-xvmc")]
extern {

    pub static mut xcb_xvmc_id: xcb_extension_t;

    pub fn xcb_xvmc_context_next (i: *mut xcb_xvmc_context_iterator_t);

    pub fn xcb_xvmc_context_end (i: *mut xcb_xvmc_context_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xvmc_surface_next (i: *mut xcb_xvmc_surface_iterator_t);

    pub fn xcb_xvmc_surface_end (i: *mut xcb_xvmc_surface_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xvmc_subpicture_next (i: *mut xcb_xvmc_subpicture_iterator_t);

    pub fn xcb_xvmc_subpicture_end (i: *mut xcb_xvmc_subpicture_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xvmc_surface_info_next (i: *mut xcb_xvmc_surface_info_iterator_t);

    pub fn xcb_xvmc_surface_info_end (i: *mut xcb_xvmc_surface_info_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xvmc_query_version_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_xvmc_query_version_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xvmc_query_version_reply_t;

    pub fn xcb_xvmc_query_version (c: *mut xcb_connection_t)
            -> xcb_xvmc_query_version_cookie_t;

    pub fn xcb_xvmc_query_version_unchecked (c: *mut xcb_connection_t)
            -> xcb_xvmc_query_version_cookie_t;

    pub fn xcb_xvmc_list_surface_types_surfaces (R: *const xcb_xvmc_list_surface_types_reply_t)
            -> *mut xcb_xvmc_surface_info_t;

    pub fn xcb_xvmc_list_surface_types_surfaces_length (R: *const xcb_xvmc_list_surface_types_reply_t)
            -> c_int;

    pub fn xcb_xvmc_list_surface_types_surfaces_iterator (R: *const xcb_xvmc_list_surface_types_reply_t)
            -> xcb_xvmc_surface_info_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xvmc_list_surface_types_reply (c:      *mut xcb_connection_t,
                                              cookie: xcb_xvmc_list_surface_types_cookie_t,
                                              error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xvmc_list_surface_types_reply_t;

    pub fn xcb_xvmc_list_surface_types (c:       *mut xcb_connection_t,
                                        port_id: xcb_xv_port_t)
            -> xcb_xvmc_list_surface_types_cookie_t;

    pub fn xcb_xvmc_list_surface_types_unchecked (c:       *mut xcb_connection_t,
                                                  port_id: xcb_xv_port_t)
            -> xcb_xvmc_list_surface_types_cookie_t;

    pub fn xcb_xvmc_create_context_priv_data (R: *const xcb_xvmc_create_context_reply_t)
            -> *mut u32;

    pub fn xcb_xvmc_create_context_priv_data_length (R: *const xcb_xvmc_create_context_reply_t)
            -> c_int;

    pub fn xcb_xvmc_create_context_priv_data_end (R: *const xcb_xvmc_create_context_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xvmc_create_context_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_xvmc_create_context_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xvmc_create_context_reply_t;

    pub fn xcb_xvmc_create_context (c:          *mut xcb_connection_t,
                                    context_id: xcb_xvmc_context_t,
                                    port_id:    xcb_xv_port_t,
                                    surface_id: xcb_xvmc_surface_t,
                                    width:      u16,
                                    height:     u16,
                                    flags:      u32)
            -> xcb_xvmc_create_context_cookie_t;

    pub fn xcb_xvmc_create_context_unchecked (c:          *mut xcb_connection_t,
                                              context_id: xcb_xvmc_context_t,
                                              port_id:    xcb_xv_port_t,
                                              surface_id: xcb_xvmc_surface_t,
                                              width:      u16,
                                              height:     u16,
                                              flags:      u32)
            -> xcb_xvmc_create_context_cookie_t;

    pub fn xcb_xvmc_destroy_context (c:          *mut xcb_connection_t,
                                     context_id: xcb_xvmc_context_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xvmc_destroy_context_checked (c:          *mut xcb_connection_t,
                                             context_id: xcb_xvmc_context_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xvmc_create_surface_priv_data (R: *const xcb_xvmc_create_surface_reply_t)
            -> *mut u32;

    pub fn xcb_xvmc_create_surface_priv_data_length (R: *const xcb_xvmc_create_surface_reply_t)
            -> c_int;

    pub fn xcb_xvmc_create_surface_priv_data_end (R: *const xcb_xvmc_create_surface_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xvmc_create_surface_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_xvmc_create_surface_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xvmc_create_surface_reply_t;

    pub fn xcb_xvmc_create_surface (c:          *mut xcb_connection_t,
                                    surface_id: xcb_xvmc_surface_t,
                                    context_id: xcb_xvmc_context_t)
            -> xcb_xvmc_create_surface_cookie_t;

    pub fn xcb_xvmc_create_surface_unchecked (c:          *mut xcb_connection_t,
                                              surface_id: xcb_xvmc_surface_t,
                                              context_id: xcb_xvmc_context_t)
            -> xcb_xvmc_create_surface_cookie_t;

    pub fn xcb_xvmc_destroy_surface (c:          *mut xcb_connection_t,
                                     surface_id: xcb_xvmc_surface_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xvmc_destroy_surface_checked (c:          *mut xcb_connection_t,
                                             surface_id: xcb_xvmc_surface_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xvmc_create_subpicture_priv_data (R: *const xcb_xvmc_create_subpicture_reply_t)
            -> *mut u32;

    pub fn xcb_xvmc_create_subpicture_priv_data_length (R: *const xcb_xvmc_create_subpicture_reply_t)
            -> c_int;

    pub fn xcb_xvmc_create_subpicture_priv_data_end (R: *const xcb_xvmc_create_subpicture_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xvmc_create_subpicture_reply (c:      *mut xcb_connection_t,
                                             cookie: xcb_xvmc_create_subpicture_cookie_t,
                                             error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xvmc_create_subpicture_reply_t;

    pub fn xcb_xvmc_create_subpicture (c:             *mut xcb_connection_t,
                                       subpicture_id: xcb_xvmc_subpicture_t,
                                       context:       xcb_xvmc_context_t,
                                       xvimage_id:    u32,
                                       width:         u16,
                                       height:        u16)
            -> xcb_xvmc_create_subpicture_cookie_t;

    pub fn xcb_xvmc_create_subpicture_unchecked (c:             *mut xcb_connection_t,
                                                 subpicture_id: xcb_xvmc_subpicture_t,
                                                 context:       xcb_xvmc_context_t,
                                                 xvimage_id:    u32,
                                                 width:         u16,
                                                 height:        u16)
            -> xcb_xvmc_create_subpicture_cookie_t;

    pub fn xcb_xvmc_destroy_subpicture (c:             *mut xcb_connection_t,
                                        subpicture_id: xcb_xvmc_subpicture_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xvmc_destroy_subpicture_checked (c:             *mut xcb_connection_t,
                                                subpicture_id: xcb_xvmc_subpicture_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xvmc_list_subpicture_types_types (R: *const xcb_xvmc_list_subpicture_types_reply_t)
            -> *mut xcb_xv_image_format_info_t;

    pub fn xcb_xvmc_list_subpicture_types_types_length (R: *const xcb_xvmc_list_subpicture_types_reply_t)
            -> c_int;

    pub fn xcb_xvmc_list_subpicture_types_types_iterator<'a> (R: *const xcb_xvmc_list_subpicture_types_reply_t)
            -> xcb_xv_image_format_info_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xvmc_list_subpicture_types_reply (c:      *mut xcb_connection_t,
                                                 cookie: xcb_xvmc_list_subpicture_types_cookie_t,
                                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xvmc_list_subpicture_types_reply_t;

    pub fn xcb_xvmc_list_subpicture_types (c:          *mut xcb_connection_t,
                                           port_id:    xcb_xv_port_t,
                                           surface_id: xcb_xvmc_surface_t)
            -> xcb_xvmc_list_subpicture_types_cookie_t;

    pub fn xcb_xvmc_list_subpicture_types_unchecked (c:          *mut xcb_connection_t,
                                                     port_id:    xcb_xv_port_t,
                                                     surface_id: xcb_xvmc_surface_t)
            -> xcb_xvmc_list_subpicture_types_cookie_t;

} // extern
