// Generated automatically from ge.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::genericevent::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_genericevent_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 0;



pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_genericevent_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_genericevent_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_genericevent_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_genericevent_query_version_reply_t>;

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

pub fn query_version<'a>(c                   : &'a base::Connection,
                         client_major_version: u16,
                         client_minor_version: u16)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_genericevent_query_version(c.get_raw_conn(),
                                                    client_major_version as u16,  // 0
                                                    client_minor_version as u16);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c                   : &'a base::Connection,
                                   client_major_version: u16,
                                   client_minor_version: u16)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_genericevent_query_version_unchecked(c.get_raw_conn(),
                                                              client_major_version as u16,  // 0
                                                              client_minor_version as u16);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
