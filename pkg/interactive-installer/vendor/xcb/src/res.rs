// Generated automatically from res.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::res::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_res_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 2;

pub type ClientIdMask = u32;
pub const CLIENT_ID_MASK_CLIENT_XID      : ClientIdMask = 0x01;
pub const CLIENT_ID_MASK_LOCAL_CLIENT_PID: ClientIdMask = 0x02;



#[derive(Copy, Clone)]
pub struct Client {
    pub base: xcb_res_client_t,
}

impl Client {
    #[allow(unused_unsafe)]
    pub fn new(resource_base: u32,
               resource_mask: u32)
            -> Client {
        unsafe {
            Client {
                base: xcb_res_client_t {
                    resource_base: resource_base,
                    resource_mask: resource_mask,
                }
            }
        }
    }
    pub fn resource_base(&self) -> u32 {
        unsafe {
            self.base.resource_base
        }
    }
    pub fn resource_mask(&self) -> u32 {
        unsafe {
            self.base.resource_mask
        }
    }
}

pub type ClientIterator = xcb_res_client_iterator_t;

impl Iterator for ClientIterator {
    type Item = Client;
    fn next(&mut self) -> std::option::Option<Client> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_res_client_iterator_t;
                let data = (*iter).data;
                xcb_res_client_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Type {
    pub base: xcb_res_type_t,
}

impl Type {
    #[allow(unused_unsafe)]
    pub fn new(resource_type: xproto::Atom,
               count:         u32)
            -> Type {
        unsafe {
            Type {
                base: xcb_res_type_t {
                    resource_type: resource_type,
                    count:         count,
                }
            }
        }
    }
    pub fn resource_type(&self) -> xproto::Atom {
        unsafe {
            self.base.resource_type
        }
    }
    pub fn count(&self) -> u32 {
        unsafe {
            self.base.count
        }
    }
}

pub type TypeIterator = xcb_res_type_iterator_t;

impl Iterator for TypeIterator {
    type Item = Type;
    fn next(&mut self) -> std::option::Option<Type> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_res_type_iterator_t;
                let data = (*iter).data;
                xcb_res_type_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ClientIdSpec {
    pub base: xcb_res_client_id_spec_t,
}

impl ClientIdSpec {
    #[allow(unused_unsafe)]
    pub fn new(client: u32,
               mask:   u32)
            -> ClientIdSpec {
        unsafe {
            ClientIdSpec {
                base: xcb_res_client_id_spec_t {
                    client: client,
                    mask:   mask,
                }
            }
        }
    }
    pub fn client(&self) -> u32 {
        unsafe {
            self.base.client
        }
    }
    pub fn mask(&self) -> u32 {
        unsafe {
            self.base.mask
        }
    }
}

pub type ClientIdSpecIterator = xcb_res_client_id_spec_iterator_t;

impl Iterator for ClientIdSpecIterator {
    type Item = ClientIdSpec;
    fn next(&mut self) -> std::option::Option<ClientIdSpec> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_res_client_id_spec_iterator_t;
                let data = (*iter).data;
                xcb_res_client_id_spec_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type ClientIdValue<'a> = base::StructPtr<'a, xcb_res_client_id_value_t>;

impl<'a> ClientIdValue<'a> {
    pub fn spec(&self) -> ClientIdSpec {
        unsafe {
            std::mem::transmute((*self.ptr).spec)
        }
    }
    pub fn length(&self) -> u32 {
        unsafe {
            (*self.ptr).length
        }
    }
    pub fn value(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_res_client_id_value_value_length(field) as usize;
            let data = xcb_res_client_id_value_value(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type ClientIdValueIterator<'a> = xcb_res_client_id_value_iterator_t<'a>;

impl<'a> Iterator for ClientIdValueIterator<'a> {
    type Item = ClientIdValue<'a>;
    fn next(&mut self) -> std::option::Option<ClientIdValue<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_res_client_id_value_iterator_t;
                let data = (*iter).data;
                xcb_res_client_id_value_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ResourceIdSpec {
    pub base: xcb_res_resource_id_spec_t,
}

impl ResourceIdSpec {
    #[allow(unused_unsafe)]
    pub fn new(resource: u32,
               type_:    u32)
            -> ResourceIdSpec {
        unsafe {
            ResourceIdSpec {
                base: xcb_res_resource_id_spec_t {
                    resource: resource,
                    type_:    type_,
                }
            }
        }
    }
    pub fn resource(&self) -> u32 {
        unsafe {
            self.base.resource
        }
    }
    pub fn type_(&self) -> u32 {
        unsafe {
            self.base.type_
        }
    }
}

pub type ResourceIdSpecIterator = xcb_res_resource_id_spec_iterator_t;

impl Iterator for ResourceIdSpecIterator {
    type Item = ResourceIdSpec;
    fn next(&mut self) -> std::option::Option<ResourceIdSpec> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_res_resource_id_spec_iterator_t;
                let data = (*iter).data;
                xcb_res_resource_id_spec_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ResourceSizeSpec {
    pub base: xcb_res_resource_size_spec_t,
}

impl ResourceSizeSpec {
    #[allow(unused_unsafe)]
    pub fn new(spec:      ResourceIdSpec,
               bytes:     u32,
               ref_count: u32,
               use_count: u32)
            -> ResourceSizeSpec {
        unsafe {
            ResourceSizeSpec {
                base: xcb_res_resource_size_spec_t {
                    spec:      std::mem::transmute(spec),
                    bytes:     bytes,
                    ref_count: ref_count,
                    use_count: use_count,
                }
            }
        }
    }
    pub fn spec(&self) -> ResourceIdSpec {
        unsafe {
            std::mem::transmute(self.base.spec)
        }
    }
    pub fn bytes(&self) -> u32 {
        unsafe {
            self.base.bytes
        }
    }
    pub fn ref_count(&self) -> u32 {
        unsafe {
            self.base.ref_count
        }
    }
    pub fn use_count(&self) -> u32 {
        unsafe {
            self.base.use_count
        }
    }
}

pub type ResourceSizeSpecIterator = xcb_res_resource_size_spec_iterator_t;

impl Iterator for ResourceSizeSpecIterator {
    type Item = ResourceSizeSpec;
    fn next(&mut self) -> std::option::Option<ResourceSizeSpec> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_res_resource_size_spec_iterator_t;
                let data = (*iter).data;
                xcb_res_resource_size_spec_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type ResourceSizeValue<'a> = base::StructPtr<'a, xcb_res_resource_size_value_t>;

impl<'a> ResourceSizeValue<'a> {
    pub fn size(&self) -> ResourceSizeSpec {
        unsafe {
            std::mem::transmute((*self.ptr).size)
        }
    }
    pub fn num_cross_references(&self) -> u32 {
        unsafe {
            (*self.ptr).num_cross_references
        }
    }
    pub fn cross_references(&self) -> ResourceSizeSpecIterator {
        unsafe {
            xcb_res_resource_size_value_cross_references_iterator(self.ptr)
        }
    }
}

pub type ResourceSizeValueIterator<'a> = xcb_res_resource_size_value_iterator_t<'a>;

impl<'a> Iterator for ResourceSizeValueIterator<'a> {
    type Item = ResourceSizeValue<'a>;
    fn next(&mut self) -> std::option::Option<ResourceSizeValue<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_res_resource_size_value_iterator_t;
                let data = (*iter).data;
                xcb_res_resource_size_value_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_res_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_res_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_res_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_res_query_version_reply_t>;

impl QueryVersionReply {
    pub fn server_major(&self) -> u16 {
        unsafe {
            (*self.ptr).server_major
        }
    }
    pub fn server_minor(&self) -> u16 {
        unsafe {
            (*self.ptr).server_minor
        }
    }
}

pub fn query_version<'a>(c           : &'a base::Connection,
                         client_major: u8,
                         client_minor: u8)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_res_query_version(c.get_raw_conn(),
                                           client_major as u8,  // 0
                                           client_minor as u8);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c           : &'a base::Connection,
                                   client_major: u8,
                                   client_minor: u8)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_res_query_version_unchecked(c.get_raw_conn(),
                                                     client_major as u8,  // 0
                                                     client_minor as u8);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_CLIENTS: u8 = 1;

pub type QueryClientsCookie<'a> = base::Cookie<'a, xcb_res_query_clients_cookie_t>;

impl<'a> QueryClientsCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryClientsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryClientsReply {
                    ptr: xcb_res_query_clients_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryClientsReply {
                    ptr: xcb_res_query_clients_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryClientsReply = base::Reply<xcb_res_query_clients_reply_t>;

impl QueryClientsReply {
    pub fn num_clients(&self) -> u32 {
        unsafe {
            (*self.ptr).num_clients
        }
    }
    pub fn clients(&self) -> ClientIterator {
        unsafe {
            xcb_res_query_clients_clients_iterator(self.ptr)
        }
    }
}

pub fn query_clients<'a>(c: &'a base::Connection)
        -> QueryClientsCookie<'a> {
    unsafe {
        let cookie = xcb_res_query_clients(c.get_raw_conn());
        QueryClientsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_clients_unchecked<'a>(c: &'a base::Connection)
        -> QueryClientsCookie<'a> {
    unsafe {
        let cookie = xcb_res_query_clients_unchecked(c.get_raw_conn());
        QueryClientsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_CLIENT_RESOURCES: u8 = 2;

pub type QueryClientResourcesCookie<'a> = base::Cookie<'a, xcb_res_query_client_resources_cookie_t>;

impl<'a> QueryClientResourcesCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryClientResourcesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryClientResourcesReply {
                    ptr: xcb_res_query_client_resources_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryClientResourcesReply {
                    ptr: xcb_res_query_client_resources_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryClientResourcesReply = base::Reply<xcb_res_query_client_resources_reply_t>;

impl QueryClientResourcesReply {
    pub fn num_types(&self) -> u32 {
        unsafe {
            (*self.ptr).num_types
        }
    }
    pub fn types(&self) -> TypeIterator {
        unsafe {
            xcb_res_query_client_resources_types_iterator(self.ptr)
        }
    }
}

pub fn query_client_resources<'a>(c  : &'a base::Connection,
                                  xid: u32)
        -> QueryClientResourcesCookie<'a> {
    unsafe {
        let cookie = xcb_res_query_client_resources(c.get_raw_conn(),
                                                    xid as u32);  // 0
        QueryClientResourcesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_client_resources_unchecked<'a>(c  : &'a base::Connection,
                                            xid: u32)
        -> QueryClientResourcesCookie<'a> {
    unsafe {
        let cookie = xcb_res_query_client_resources_unchecked(c.get_raw_conn(),
                                                              xid as u32);  // 0
        QueryClientResourcesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_CLIENT_PIXMAP_BYTES: u8 = 3;

pub type QueryClientPixmapBytesCookie<'a> = base::Cookie<'a, xcb_res_query_client_pixmap_bytes_cookie_t>;

impl<'a> QueryClientPixmapBytesCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryClientPixmapBytesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryClientPixmapBytesReply {
                    ptr: xcb_res_query_client_pixmap_bytes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryClientPixmapBytesReply {
                    ptr: xcb_res_query_client_pixmap_bytes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryClientPixmapBytesReply = base::Reply<xcb_res_query_client_pixmap_bytes_reply_t>;

impl QueryClientPixmapBytesReply {
    pub fn bytes(&self) -> u32 {
        unsafe {
            (*self.ptr).bytes
        }
    }
    pub fn bytes_overflow(&self) -> u32 {
        unsafe {
            (*self.ptr).bytes_overflow
        }
    }
}

pub fn query_client_pixmap_bytes<'a>(c  : &'a base::Connection,
                                     xid: u32)
        -> QueryClientPixmapBytesCookie<'a> {
    unsafe {
        let cookie = xcb_res_query_client_pixmap_bytes(c.get_raw_conn(),
                                                       xid as u32);  // 0
        QueryClientPixmapBytesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_client_pixmap_bytes_unchecked<'a>(c  : &'a base::Connection,
                                               xid: u32)
        -> QueryClientPixmapBytesCookie<'a> {
    unsafe {
        let cookie = xcb_res_query_client_pixmap_bytes_unchecked(c.get_raw_conn(),
                                                                 xid as u32);  // 0
        QueryClientPixmapBytesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_CLIENT_IDS: u8 = 4;

pub type QueryClientIdsCookie<'a> = base::Cookie<'a, xcb_res_query_client_ids_cookie_t>;

impl<'a> QueryClientIdsCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryClientIdsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryClientIdsReply {
                    ptr: xcb_res_query_client_ids_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryClientIdsReply {
                    ptr: xcb_res_query_client_ids_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryClientIdsReply = base::Reply<xcb_res_query_client_ids_reply_t>;

impl QueryClientIdsReply {
    pub fn num_ids(&self) -> u32 {
        unsafe {
            (*self.ptr).num_ids
        }
    }
    pub fn ids(&self) -> ClientIdValueIterator {
        unsafe {
            xcb_res_query_client_ids_ids_iterator(self.ptr)
        }
    }
}

pub fn query_client_ids<'a>(c    : &'a base::Connection,
                            specs: &[ClientIdSpec])
        -> QueryClientIdsCookie<'a> {
    unsafe {
        let specs_len = specs.len();
        let specs_ptr = specs.as_ptr();
        let cookie = xcb_res_query_client_ids(c.get_raw_conn(),
                                              specs_len as u32,  // 0
                                              specs_ptr as *const xcb_res_client_id_spec_t);  // 1
        QueryClientIdsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_client_ids_unchecked<'a>(c    : &'a base::Connection,
                                      specs: &[ClientIdSpec])
        -> QueryClientIdsCookie<'a> {
    unsafe {
        let specs_len = specs.len();
        let specs_ptr = specs.as_ptr();
        let cookie = xcb_res_query_client_ids_unchecked(c.get_raw_conn(),
                                                        specs_len as u32,  // 0
                                                        specs_ptr as *const xcb_res_client_id_spec_t);  // 1
        QueryClientIdsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_RESOURCE_BYTES: u8 = 5;

pub type QueryResourceBytesCookie<'a> = base::Cookie<'a, xcb_res_query_resource_bytes_cookie_t>;

impl<'a> QueryResourceBytesCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryResourceBytesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryResourceBytesReply {
                    ptr: xcb_res_query_resource_bytes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryResourceBytesReply {
                    ptr: xcb_res_query_resource_bytes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryResourceBytesReply = base::Reply<xcb_res_query_resource_bytes_reply_t>;

impl QueryResourceBytesReply {
    pub fn num_sizes(&self) -> u32 {
        unsafe {
            (*self.ptr).num_sizes
        }
    }
    pub fn sizes(&self) -> ResourceSizeValueIterator {
        unsafe {
            xcb_res_query_resource_bytes_sizes_iterator(self.ptr)
        }
    }
}

pub fn query_resource_bytes<'a>(c     : &'a base::Connection,
                                client: u32,
                                specs : &[ResourceIdSpec])
        -> QueryResourceBytesCookie<'a> {
    unsafe {
        let specs_len = specs.len();
        let specs_ptr = specs.as_ptr();
        let cookie = xcb_res_query_resource_bytes(c.get_raw_conn(),
                                                  client as u32,  // 0
                                                  specs_len as u32,  // 1
                                                  specs_ptr as *const xcb_res_resource_id_spec_t);  // 2
        QueryResourceBytesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_resource_bytes_unchecked<'a>(c     : &'a base::Connection,
                                          client: u32,
                                          specs : &[ResourceIdSpec])
        -> QueryResourceBytesCookie<'a> {
    unsafe {
        let specs_len = specs.len();
        let specs_ptr = specs.as_ptr();
        let cookie = xcb_res_query_resource_bytes_unchecked(c.get_raw_conn(),
                                                            client as u32,  // 0
                                                            specs_len as u32,  // 1
                                                            specs_ptr as *const xcb_res_resource_id_spec_t);  // 2
        QueryResourceBytesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
