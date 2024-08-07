// Generated automatically from res.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_RES_MAJOR_VERSION: u32 = 1;
pub const XCB_RES_MINOR_VERSION: u32 = 2;

#[repr(C)]
pub struct xcb_res_client_t {
    pub resource_base: u32,
    pub resource_mask: u32,
}

impl Copy for xcb_res_client_t {}
impl Clone for xcb_res_client_t {
    fn clone(&self) -> xcb_res_client_t { *self }
}

#[repr(C)]
pub struct xcb_res_client_iterator_t {
    pub data:  *mut xcb_res_client_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_res_type_t {
    pub resource_type: xcb_atom_t,
    pub count:         u32,
}

impl Copy for xcb_res_type_t {}
impl Clone for xcb_res_type_t {
    fn clone(&self) -> xcb_res_type_t { *self }
}

#[repr(C)]
pub struct xcb_res_type_iterator_t {
    pub data:  *mut xcb_res_type_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_res_client_id_mask_t = u32;
pub const XCB_RES_CLIENT_ID_MASK_CLIENT_XID      : xcb_res_client_id_mask_t = 0x01;
pub const XCB_RES_CLIENT_ID_MASK_LOCAL_CLIENT_PID: xcb_res_client_id_mask_t = 0x02;

#[repr(C)]
pub struct xcb_res_client_id_spec_t {
    pub client: u32,
    pub mask:   u32,
}

impl Copy for xcb_res_client_id_spec_t {}
impl Clone for xcb_res_client_id_spec_t {
    fn clone(&self) -> xcb_res_client_id_spec_t { *self }
}

#[repr(C)]
pub struct xcb_res_client_id_spec_iterator_t {
    pub data:  *mut xcb_res_client_id_spec_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_res_client_id_value_t {
    pub spec:   xcb_res_client_id_spec_t,
    pub length: u32,
}

#[repr(C)]
pub struct xcb_res_client_id_value_iterator_t<'a> {
    pub data:  *mut xcb_res_client_id_value_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_res_client_id_value_t>,
}

#[repr(C)]
pub struct xcb_res_resource_id_spec_t {
    pub resource: u32,
    pub type_:    u32,
}

impl Copy for xcb_res_resource_id_spec_t {}
impl Clone for xcb_res_resource_id_spec_t {
    fn clone(&self) -> xcb_res_resource_id_spec_t { *self }
}

#[repr(C)]
pub struct xcb_res_resource_id_spec_iterator_t {
    pub data:  *mut xcb_res_resource_id_spec_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_res_resource_size_spec_t {
    pub spec:      xcb_res_resource_id_spec_t,
    pub bytes:     u32,
    pub ref_count: u32,
    pub use_count: u32,
}

impl Copy for xcb_res_resource_size_spec_t {}
impl Clone for xcb_res_resource_size_spec_t {
    fn clone(&self) -> xcb_res_resource_size_spec_t { *self }
}

#[repr(C)]
pub struct xcb_res_resource_size_spec_iterator_t {
    pub data:  *mut xcb_res_resource_size_spec_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_res_resource_size_value_t {
    pub size:                 xcb_res_resource_size_spec_t,
    pub num_cross_references: u32,
}

#[repr(C)]
pub struct xcb_res_resource_size_value_iterator_t<'a> {
    pub data:  *mut xcb_res_resource_size_value_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_res_resource_size_value_t>,
}

pub const XCB_RES_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_res_query_version_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub client_major: u8,
    pub client_minor: u8,
}

impl Copy for xcb_res_query_version_request_t {}
impl Clone for xcb_res_query_version_request_t {
    fn clone(&self) -> xcb_res_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_res_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_res_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub server_major:  u16,
    pub server_minor:  u16,
}

impl Copy for xcb_res_query_version_reply_t {}
impl Clone for xcb_res_query_version_reply_t {
    fn clone(&self) -> xcb_res_query_version_reply_t { *self }
}

pub const XCB_RES_QUERY_CLIENTS: u8 = 1;

#[repr(C)]
pub struct xcb_res_query_clients_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_res_query_clients_request_t {}
impl Clone for xcb_res_query_clients_request_t {
    fn clone(&self) -> xcb_res_query_clients_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_res_query_clients_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_res_query_clients_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_clients:   u32,
    pub pad1:          [u8; 20],
}

pub const XCB_RES_QUERY_CLIENT_RESOURCES: u8 = 2;

#[repr(C)]
pub struct xcb_res_query_client_resources_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub xid:          u32,
}

impl Copy for xcb_res_query_client_resources_request_t {}
impl Clone for xcb_res_query_client_resources_request_t {
    fn clone(&self) -> xcb_res_query_client_resources_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_res_query_client_resources_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_res_query_client_resources_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_types:     u32,
    pub pad1:          [u8; 20],
}

pub const XCB_RES_QUERY_CLIENT_PIXMAP_BYTES: u8 = 3;

#[repr(C)]
pub struct xcb_res_query_client_pixmap_bytes_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub xid:          u32,
}

impl Copy for xcb_res_query_client_pixmap_bytes_request_t {}
impl Clone for xcb_res_query_client_pixmap_bytes_request_t {
    fn clone(&self) -> xcb_res_query_client_pixmap_bytes_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_res_query_client_pixmap_bytes_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_res_query_client_pixmap_bytes_reply_t {
    pub response_type:  u8,
    pub pad0:           u8,
    pub sequence:       u16,
    pub length:         u32,
    pub bytes:          u32,
    pub bytes_overflow: u32,
}

impl Copy for xcb_res_query_client_pixmap_bytes_reply_t {}
impl Clone for xcb_res_query_client_pixmap_bytes_reply_t {
    fn clone(&self) -> xcb_res_query_client_pixmap_bytes_reply_t { *self }
}

pub const XCB_RES_QUERY_CLIENT_IDS: u8 = 4;

#[repr(C)]
pub struct xcb_res_query_client_ids_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub num_specs:    u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_res_query_client_ids_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_res_query_client_ids_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_ids:       u32,
    pub pad1:          [u8; 20],
}

pub const XCB_RES_QUERY_RESOURCE_BYTES: u8 = 5;

#[repr(C)]
pub struct xcb_res_query_resource_bytes_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub client:       u32,
    pub num_specs:    u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_res_query_resource_bytes_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_res_query_resource_bytes_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_sizes:     u32,
    pub pad1:          [u8; 20],
}


#[link(name="xcb-res")]
extern {

    pub static mut xcb_res_id: xcb_extension_t;

    pub fn xcb_res_client_next (i: *mut xcb_res_client_iterator_t);

    pub fn xcb_res_client_end (i: *mut xcb_res_client_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_res_type_next (i: *mut xcb_res_type_iterator_t);

    pub fn xcb_res_type_end (i: *mut xcb_res_type_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_res_client_id_spec_next (i: *mut xcb_res_client_id_spec_iterator_t);

    pub fn xcb_res_client_id_spec_end (i: *mut xcb_res_client_id_spec_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_res_client_id_value_value (R: *const xcb_res_client_id_value_t)
            -> *mut u32;

    pub fn xcb_res_client_id_value_value_length (R: *const xcb_res_client_id_value_t)
            -> c_int;

    pub fn xcb_res_client_id_value_value_end (R: *const xcb_res_client_id_value_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_res_client_id_value_next (i: *mut xcb_res_client_id_value_iterator_t);

    pub fn xcb_res_client_id_value_end (i: *mut xcb_res_client_id_value_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_res_resource_id_spec_next (i: *mut xcb_res_resource_id_spec_iterator_t);

    pub fn xcb_res_resource_id_spec_end (i: *mut xcb_res_resource_id_spec_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_res_resource_size_spec_next (i: *mut xcb_res_resource_size_spec_iterator_t);

    pub fn xcb_res_resource_size_spec_end (i: *mut xcb_res_resource_size_spec_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_res_resource_size_value_cross_references (R: *const xcb_res_resource_size_value_t)
            -> *mut xcb_res_resource_size_spec_t;

    pub fn xcb_res_resource_size_value_cross_references_length (R: *const xcb_res_resource_size_value_t)
            -> c_int;

    pub fn xcb_res_resource_size_value_cross_references_iterator (R: *const xcb_res_resource_size_value_t)
            -> xcb_res_resource_size_spec_iterator_t;

    pub fn xcb_res_resource_size_value_next (i: *mut xcb_res_resource_size_value_iterator_t);

    pub fn xcb_res_resource_size_value_end (i: *mut xcb_res_resource_size_value_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_res_query_version_reply (c:      *mut xcb_connection_t,
                                        cookie: xcb_res_query_version_cookie_t,
                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_res_query_version_reply_t;

    pub fn xcb_res_query_version (c:            *mut xcb_connection_t,
                                  client_major: u8,
                                  client_minor: u8)
            -> xcb_res_query_version_cookie_t;

    pub fn xcb_res_query_version_unchecked (c:            *mut xcb_connection_t,
                                            client_major: u8,
                                            client_minor: u8)
            -> xcb_res_query_version_cookie_t;

    pub fn xcb_res_query_clients_clients (R: *const xcb_res_query_clients_reply_t)
            -> *mut xcb_res_client_t;

    pub fn xcb_res_query_clients_clients_length (R: *const xcb_res_query_clients_reply_t)
            -> c_int;

    pub fn xcb_res_query_clients_clients_iterator (R: *const xcb_res_query_clients_reply_t)
            -> xcb_res_client_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_res_query_clients_reply (c:      *mut xcb_connection_t,
                                        cookie: xcb_res_query_clients_cookie_t,
                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_res_query_clients_reply_t;

    pub fn xcb_res_query_clients (c: *mut xcb_connection_t)
            -> xcb_res_query_clients_cookie_t;

    pub fn xcb_res_query_clients_unchecked (c: *mut xcb_connection_t)
            -> xcb_res_query_clients_cookie_t;

    pub fn xcb_res_query_client_resources_types (R: *const xcb_res_query_client_resources_reply_t)
            -> *mut xcb_res_type_t;

    pub fn xcb_res_query_client_resources_types_length (R: *const xcb_res_query_client_resources_reply_t)
            -> c_int;

    pub fn xcb_res_query_client_resources_types_iterator (R: *const xcb_res_query_client_resources_reply_t)
            -> xcb_res_type_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_res_query_client_resources_reply (c:      *mut xcb_connection_t,
                                                 cookie: xcb_res_query_client_resources_cookie_t,
                                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_res_query_client_resources_reply_t;

    pub fn xcb_res_query_client_resources (c:   *mut xcb_connection_t,
                                           xid: u32)
            -> xcb_res_query_client_resources_cookie_t;

    pub fn xcb_res_query_client_resources_unchecked (c:   *mut xcb_connection_t,
                                                     xid: u32)
            -> xcb_res_query_client_resources_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_res_query_client_pixmap_bytes_reply (c:      *mut xcb_connection_t,
                                                    cookie: xcb_res_query_client_pixmap_bytes_cookie_t,
                                                    error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_res_query_client_pixmap_bytes_reply_t;

    pub fn xcb_res_query_client_pixmap_bytes (c:   *mut xcb_connection_t,
                                              xid: u32)
            -> xcb_res_query_client_pixmap_bytes_cookie_t;

    pub fn xcb_res_query_client_pixmap_bytes_unchecked (c:   *mut xcb_connection_t,
                                                        xid: u32)
            -> xcb_res_query_client_pixmap_bytes_cookie_t;

    pub fn xcb_res_query_client_ids_ids_length (R: *const xcb_res_query_client_ids_reply_t)
            -> c_int;

    pub fn xcb_res_query_client_ids_ids_iterator<'a> (R: *const xcb_res_query_client_ids_reply_t)
            -> xcb_res_client_id_value_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_res_query_client_ids_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_res_query_client_ids_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_res_query_client_ids_reply_t;

    pub fn xcb_res_query_client_ids (c:         *mut xcb_connection_t,
                                     num_specs: u32,
                                     specs:     *const xcb_res_client_id_spec_t)
            -> xcb_res_query_client_ids_cookie_t;

    pub fn xcb_res_query_client_ids_unchecked (c:         *mut xcb_connection_t,
                                               num_specs: u32,
                                               specs:     *const xcb_res_client_id_spec_t)
            -> xcb_res_query_client_ids_cookie_t;

    pub fn xcb_res_query_resource_bytes_sizes_length (R: *const xcb_res_query_resource_bytes_reply_t)
            -> c_int;

    pub fn xcb_res_query_resource_bytes_sizes_iterator<'a> (R: *const xcb_res_query_resource_bytes_reply_t)
            -> xcb_res_resource_size_value_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_res_query_resource_bytes_reply (c:      *mut xcb_connection_t,
                                               cookie: xcb_res_query_resource_bytes_cookie_t,
                                               error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_res_query_resource_bytes_reply_t;

    pub fn xcb_res_query_resource_bytes (c:         *mut xcb_connection_t,
                                         client:    u32,
                                         num_specs: u32,
                                         specs:     *const xcb_res_resource_id_spec_t)
            -> xcb_res_query_resource_bytes_cookie_t;

    pub fn xcb_res_query_resource_bytes_unchecked (c:         *mut xcb_connection_t,
                                                   client:    u32,
                                                   num_specs: u32,
                                                   specs:     *const xcb_res_resource_id_spec_t)
            -> xcb_res_query_resource_bytes_cookie_t;

} // extern
