// Generated automatically from bigreq.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::big_requests::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_big_requests_id
    }
}

pub const MAJOR_VERSION: u32 = 0;
pub const MINOR_VERSION: u32 = 0;



pub const ENABLE: u8 = 0;

pub type EnableCookie<'a> = base::Cookie<'a, xcb_big_requests_enable_cookie_t>;

impl<'a> EnableCookie<'a> {
    pub fn get_reply(&self) -> Result<EnableReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = EnableReply {
                    ptr: xcb_big_requests_enable_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( EnableReply {
                    ptr: xcb_big_requests_enable_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type EnableReply = base::Reply<xcb_big_requests_enable_reply_t>;

impl EnableReply {
    pub fn maximum_request_length(&self) -> u32 {
        unsafe {
            (*self.ptr).maximum_request_length
        }
    }
}

pub fn enable<'a>(c: &'a base::Connection)
        -> EnableCookie<'a> {
    unsafe {
        let cookie = xcb_big_requests_enable(c.get_raw_conn());
        EnableCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn enable_unchecked<'a>(c: &'a base::Connection)
        -> EnableCookie<'a> {
    unsafe {
        let cookie = xcb_big_requests_enable_unchecked(c.get_raw_conn());
        EnableCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
