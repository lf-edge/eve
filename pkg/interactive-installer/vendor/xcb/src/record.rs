// Generated automatically from record.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::record::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_record_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 13;

pub type Context = xcb_record_context_t;

pub type ElementHeader = xcb_record_element_header_t;

pub type HType = u32;
pub const H_TYPE_FROM_SERVER_TIME    : HType = 0x01;
pub const H_TYPE_FROM_CLIENT_TIME    : HType = 0x02;
pub const H_TYPE_FROM_CLIENT_SEQUENCE: HType = 0x04;

pub type ClientSpec = xcb_record_client_spec_t;

pub type Cs = u32;
pub const CS_CURRENT_CLIENTS: Cs = 0x01;
pub const CS_FUTURE_CLIENTS : Cs = 0x02;
pub const CS_ALL_CLIENTS    : Cs = 0x03;

pub struct BadContextError {
    pub base: base::Error<xcb_record_bad_context_error_t>
}



#[derive(Copy, Clone)]
pub struct Range8 {
    pub base: xcb_record_range_8_t,
}

impl Range8 {
    #[allow(unused_unsafe)]
    pub fn new(first: u8,
               last:  u8)
            -> Range8 {
        unsafe {
            Range8 {
                base: xcb_record_range_8_t {
                    first: first,
                    last:  last,
                }
            }
        }
    }
    pub fn first(&self) -> u8 {
        unsafe {
            self.base.first
        }
    }
    pub fn last(&self) -> u8 {
        unsafe {
            self.base.last
        }
    }
}

pub type Range8Iterator = xcb_record_range_8_iterator_t;

impl Iterator for Range8Iterator {
    type Item = Range8;
    fn next(&mut self) -> std::option::Option<Range8> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_record_range_8_iterator_t;
                let data = (*iter).data;
                xcb_record_range_8_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Range16 {
    pub base: xcb_record_range_16_t,
}

impl Range16 {
    #[allow(unused_unsafe)]
    pub fn new(first: u16,
               last:  u16)
            -> Range16 {
        unsafe {
            Range16 {
                base: xcb_record_range_16_t {
                    first: first,
                    last:  last,
                }
            }
        }
    }
    pub fn first(&self) -> u16 {
        unsafe {
            self.base.first
        }
    }
    pub fn last(&self) -> u16 {
        unsafe {
            self.base.last
        }
    }
}

pub type Range16Iterator = xcb_record_range_16_iterator_t;

impl Iterator for Range16Iterator {
    type Item = Range16;
    fn next(&mut self) -> std::option::Option<Range16> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_record_range_16_iterator_t;
                let data = (*iter).data;
                xcb_record_range_16_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ExtRange {
    pub base: xcb_record_ext_range_t,
}

impl ExtRange {
    #[allow(unused_unsafe)]
    pub fn new(major: Range8,
               minor: Range16)
            -> ExtRange {
        unsafe {
            ExtRange {
                base: xcb_record_ext_range_t {
                    major: std::mem::transmute(major),
                    minor: std::mem::transmute(minor),
                }
            }
        }
    }
    pub fn major(&self) -> Range8 {
        unsafe {
            std::mem::transmute(self.base.major)
        }
    }
    pub fn minor(&self) -> Range16 {
        unsafe {
            std::mem::transmute(self.base.minor)
        }
    }
}

pub type ExtRangeIterator = xcb_record_ext_range_iterator_t;

impl Iterator for ExtRangeIterator {
    type Item = ExtRange;
    fn next(&mut self) -> std::option::Option<ExtRange> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_record_ext_range_iterator_t;
                let data = (*iter).data;
                xcb_record_ext_range_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Range {
    pub base: xcb_record_range_t,
}

impl Range {
    #[allow(unused_unsafe)]
    pub fn new(core_requests:    Range8,
               core_replies:     Range8,
               ext_requests:     ExtRange,
               ext_replies:      ExtRange,
               delivered_events: Range8,
               device_events:    Range8,
               errors:           Range8,
               client_started:   bool,
               client_died:      bool)
            -> Range {
        unsafe {
            Range {
                base: xcb_record_range_t {
                    core_requests:    std::mem::transmute(core_requests),
                    core_replies:     std::mem::transmute(core_replies),
                    ext_requests:     std::mem::transmute(ext_requests),
                    ext_replies:      std::mem::transmute(ext_replies),
                    delivered_events: std::mem::transmute(delivered_events),
                    device_events:    std::mem::transmute(device_events),
                    errors:           std::mem::transmute(errors),
                    client_started:   if client_started { 1 } else { 0 },
                    client_died:      if client_died { 1 } else { 0 },
                }
            }
        }
    }
    pub fn core_requests(&self) -> Range8 {
        unsafe {
            std::mem::transmute(self.base.core_requests)
        }
    }
    pub fn core_replies(&self) -> Range8 {
        unsafe {
            std::mem::transmute(self.base.core_replies)
        }
    }
    pub fn ext_requests(&self) -> ExtRange {
        unsafe {
            std::mem::transmute(self.base.ext_requests)
        }
    }
    pub fn ext_replies(&self) -> ExtRange {
        unsafe {
            std::mem::transmute(self.base.ext_replies)
        }
    }
    pub fn delivered_events(&self) -> Range8 {
        unsafe {
            std::mem::transmute(self.base.delivered_events)
        }
    }
    pub fn device_events(&self) -> Range8 {
        unsafe {
            std::mem::transmute(self.base.device_events)
        }
    }
    pub fn errors(&self) -> Range8 {
        unsafe {
            std::mem::transmute(self.base.errors)
        }
    }
    pub fn client_started(&self) -> bool {
        unsafe {
            self.base.client_started != 0
        }
    }
    pub fn client_died(&self) -> bool {
        unsafe {
            self.base.client_died != 0
        }
    }
}

pub type RangeIterator = xcb_record_range_iterator_t;

impl Iterator for RangeIterator {
    type Item = Range;
    fn next(&mut self) -> std::option::Option<Range> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_record_range_iterator_t;
                let data = (*iter).data;
                xcb_record_range_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type ClientInfo<'a> = base::StructPtr<'a, xcb_record_client_info_t>;

impl<'a> ClientInfo<'a> {
    pub fn client_resource(&self) -> ClientSpec {
        unsafe {
            (*self.ptr).client_resource
        }
    }
    pub fn num_ranges(&self) -> u32 {
        unsafe {
            (*self.ptr).num_ranges
        }
    }
    pub fn ranges(&self) -> RangeIterator {
        unsafe {
            xcb_record_client_info_ranges_iterator(self.ptr)
        }
    }
}

pub type ClientInfoIterator<'a> = xcb_record_client_info_iterator_t<'a>;

impl<'a> Iterator for ClientInfoIterator<'a> {
    type Item = ClientInfo<'a>;
    fn next(&mut self) -> std::option::Option<ClientInfo<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_record_client_info_iterator_t;
                let data = (*iter).data;
                xcb_record_client_info_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const BAD_CONTEXT: u8 = 0;

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_record_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_record_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_record_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_record_query_version_reply_t>;

impl QueryVersionReply {
    pub fn major_version(&self) -> u16 {
        unsafe {
            (*self.ptr).major_version
        }
    }
    pub fn minor_version(&self) -> u16 {
        unsafe {
            (*self.ptr).minor_version
        }
    }
}

pub fn query_version<'a>(c            : &'a base::Connection,
                         major_version: u16,
                         minor_version: u16)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_record_query_version(c.get_raw_conn(),
                                              major_version as u16,  // 0
                                              minor_version as u16);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c            : &'a base::Connection,
                                   major_version: u16,
                                   minor_version: u16)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_record_query_version_unchecked(c.get_raw_conn(),
                                                        major_version as u16,  // 0
                                                        minor_version as u16);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_CONTEXT: u8 = 1;

pub fn create_context<'a>(c             : &'a base::Connection,
                          context       : Context,
                          element_header: ElementHeader,
                          client_specs  : &[ClientSpec],
                          ranges        : &[Range])
        -> base::VoidCookie<'a> {
    unsafe {
        let client_specs_len = client_specs.len();
        let client_specs_ptr = client_specs.as_ptr();
        let ranges_len = ranges.len();
        let ranges_ptr = ranges.as_ptr();
        let cookie = xcb_record_create_context(c.get_raw_conn(),
                                               context as xcb_record_context_t,  // 0
                                               element_header as xcb_record_element_header_t,  // 1
                                               client_specs_len as u32,  // 2
                                               ranges_len as u32,  // 3
                                               client_specs_ptr as *const xcb_record_client_spec_t,  // 4
                                               ranges_ptr as *const xcb_record_range_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_context_checked<'a>(c             : &'a base::Connection,
                                  context       : Context,
                                  element_header: ElementHeader,
                                  client_specs  : &[ClientSpec],
                                  ranges        : &[Range])
        -> base::VoidCookie<'a> {
    unsafe {
        let client_specs_len = client_specs.len();
        let client_specs_ptr = client_specs.as_ptr();
        let ranges_len = ranges.len();
        let ranges_ptr = ranges.as_ptr();
        let cookie = xcb_record_create_context_checked(c.get_raw_conn(),
                                                       context as xcb_record_context_t,  // 0
                                                       element_header as xcb_record_element_header_t,  // 1
                                                       client_specs_len as u32,  // 2
                                                       ranges_len as u32,  // 3
                                                       client_specs_ptr as *const xcb_record_client_spec_t,  // 4
                                                       ranges_ptr as *const xcb_record_range_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const REGISTER_CLIENTS: u8 = 2;

pub fn register_clients<'a>(c             : &'a base::Connection,
                            context       : Context,
                            element_header: ElementHeader,
                            client_specs  : &[ClientSpec],
                            ranges        : &[Range])
        -> base::VoidCookie<'a> {
    unsafe {
        let client_specs_len = client_specs.len();
        let client_specs_ptr = client_specs.as_ptr();
        let ranges_len = ranges.len();
        let ranges_ptr = ranges.as_ptr();
        let cookie = xcb_record_register_clients(c.get_raw_conn(),
                                                 context as xcb_record_context_t,  // 0
                                                 element_header as xcb_record_element_header_t,  // 1
                                                 client_specs_len as u32,  // 2
                                                 ranges_len as u32,  // 3
                                                 client_specs_ptr as *const xcb_record_client_spec_t,  // 4
                                                 ranges_ptr as *const xcb_record_range_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn register_clients_checked<'a>(c             : &'a base::Connection,
                                    context       : Context,
                                    element_header: ElementHeader,
                                    client_specs  : &[ClientSpec],
                                    ranges        : &[Range])
        -> base::VoidCookie<'a> {
    unsafe {
        let client_specs_len = client_specs.len();
        let client_specs_ptr = client_specs.as_ptr();
        let ranges_len = ranges.len();
        let ranges_ptr = ranges.as_ptr();
        let cookie = xcb_record_register_clients_checked(c.get_raw_conn(),
                                                         context as xcb_record_context_t,  // 0
                                                         element_header as xcb_record_element_header_t,  // 1
                                                         client_specs_len as u32,  // 2
                                                         ranges_len as u32,  // 3
                                                         client_specs_ptr as *const xcb_record_client_spec_t,  // 4
                                                         ranges_ptr as *const xcb_record_range_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNREGISTER_CLIENTS: u8 = 3;

pub fn unregister_clients<'a>(c           : &'a base::Connection,
                              context     : Context,
                              client_specs: &[ClientSpec])
        -> base::VoidCookie<'a> {
    unsafe {
        let client_specs_len = client_specs.len();
        let client_specs_ptr = client_specs.as_ptr();
        let cookie = xcb_record_unregister_clients(c.get_raw_conn(),
                                                   context as xcb_record_context_t,  // 0
                                                   client_specs_len as u32,  // 1
                                                   client_specs_ptr as *const xcb_record_client_spec_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn unregister_clients_checked<'a>(c           : &'a base::Connection,
                                      context     : Context,
                                      client_specs: &[ClientSpec])
        -> base::VoidCookie<'a> {
    unsafe {
        let client_specs_len = client_specs.len();
        let client_specs_ptr = client_specs.as_ptr();
        let cookie = xcb_record_unregister_clients_checked(c.get_raw_conn(),
                                                           context as xcb_record_context_t,  // 0
                                                           client_specs_len as u32,  // 1
                                                           client_specs_ptr as *const xcb_record_client_spec_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_CONTEXT: u8 = 4;

pub type GetContextCookie<'a> = base::Cookie<'a, xcb_record_get_context_cookie_t>;

impl<'a> GetContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetContextReply {
                    ptr: xcb_record_get_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetContextReply {
                    ptr: xcb_record_get_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetContextReply = base::Reply<xcb_record_get_context_reply_t>;

impl GetContextReply {
    pub fn enabled(&self) -> bool {
        unsafe {
            (*self.ptr).enabled != 0
        }
    }
    pub fn element_header(&self) -> ElementHeader {
        unsafe {
            (*self.ptr).element_header
        }
    }
    pub fn num_intercepted_clients(&self) -> u32 {
        unsafe {
            (*self.ptr).num_intercepted_clients
        }
    }
    pub fn intercepted_clients(&self) -> ClientInfoIterator {
        unsafe {
            xcb_record_get_context_intercepted_clients_iterator(self.ptr)
        }
    }
}

pub fn get_context<'a>(c      : &'a base::Connection,
                       context: Context)
        -> GetContextCookie<'a> {
    unsafe {
        let cookie = xcb_record_get_context(c.get_raw_conn(),
                                            context as xcb_record_context_t);  // 0
        GetContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_context_unchecked<'a>(c      : &'a base::Connection,
                                 context: Context)
        -> GetContextCookie<'a> {
    unsafe {
        let cookie = xcb_record_get_context_unchecked(c.get_raw_conn(),
                                                      context as xcb_record_context_t);  // 0
        GetContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const ENABLE_CONTEXT: u8 = 5;

pub type EnableContextCookie<'a> = base::Cookie<'a, xcb_record_enable_context_cookie_t>;

impl<'a> EnableContextCookie<'a> {
    pub fn get_reply(&self) -> Result<EnableContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = EnableContextReply {
                    ptr: xcb_record_enable_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( EnableContextReply {
                    ptr: xcb_record_enable_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type EnableContextReply = base::Reply<xcb_record_enable_context_reply_t>;

impl EnableContextReply {
    pub fn category(&self) -> u8 {
        unsafe {
            (*self.ptr).category
        }
    }
    pub fn element_header(&self) -> ElementHeader {
        unsafe {
            (*self.ptr).element_header
        }
    }
    pub fn client_swapped(&self) -> bool {
        unsafe {
            (*self.ptr).client_swapped != 0
        }
    }
    pub fn xid_base(&self) -> u32 {
        unsafe {
            (*self.ptr).xid_base
        }
    }
    pub fn server_time(&self) -> u32 {
        unsafe {
            (*self.ptr).server_time
        }
    }
    pub fn rec_sequence_num(&self) -> u32 {
        unsafe {
            (*self.ptr).rec_sequence_num
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_record_enable_context_data_length(field) as usize;
            let data = xcb_record_enable_context_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn enable_context<'a>(c      : &'a base::Connection,
                          context: Context)
        -> EnableContextCookie<'a> {
    unsafe {
        let cookie = xcb_record_enable_context(c.get_raw_conn(),
                                               context as xcb_record_context_t);  // 0
        EnableContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn enable_context_unchecked<'a>(c      : &'a base::Connection,
                                    context: Context)
        -> EnableContextCookie<'a> {
    unsafe {
        let cookie = xcb_record_enable_context_unchecked(c.get_raw_conn(),
                                                         context as xcb_record_context_t);  // 0
        EnableContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DISABLE_CONTEXT: u8 = 6;

pub fn disable_context<'a>(c      : &'a base::Connection,
                           context: Context)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_record_disable_context(c.get_raw_conn(),
                                                context as xcb_record_context_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn disable_context_checked<'a>(c      : &'a base::Connection,
                                   context: Context)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_record_disable_context_checked(c.get_raw_conn(),
                                                        context as xcb_record_context_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FREE_CONTEXT: u8 = 7;

pub fn free_context<'a>(c      : &'a base::Connection,
                        context: Context)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_record_free_context(c.get_raw_conn(),
                                             context as xcb_record_context_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn free_context_checked<'a>(c      : &'a base::Connection,
                                context: Context)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_record_free_context_checked(c.get_raw_conn(),
                                                     context as xcb_record_context_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}
