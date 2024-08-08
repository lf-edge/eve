// Generated automatically from xc_misc.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::xc_misc::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_xc_misc_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 1;



pub const GET_VERSION: u8 = 0;

pub type GetVersionCookie<'a> = base::Cookie<'a, xcb_xc_misc_get_version_cookie_t>;

impl<'a> GetVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<GetVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetVersionReply {
                    ptr: xcb_xc_misc_get_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetVersionReply {
                    ptr: xcb_xc_misc_get_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetVersionReply = base::Reply<xcb_xc_misc_get_version_reply_t>;

impl GetVersionReply {
    pub fn server_major_version(&self) -> u16 {
        unsafe {
            (*self.ptr).server_major_version
        }
    }
    pub fn server_minor_version(&self) -> u16 {
        unsafe {
            (*self.ptr).server_minor_version
        }
    }
}

pub fn get_version<'a>(c                   : &'a base::Connection,
                       client_major_version: u16,
                       client_minor_version: u16)
        -> GetVersionCookie<'a> {
    unsafe {
        let cookie = xcb_xc_misc_get_version(c.get_raw_conn(),
                                             client_major_version as u16,  // 0
                                             client_minor_version as u16);  // 1
        GetVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_version_unchecked<'a>(c                   : &'a base::Connection,
                                 client_major_version: u16,
                                 client_minor_version: u16)
        -> GetVersionCookie<'a> {
    unsafe {
        let cookie = xcb_xc_misc_get_version_unchecked(c.get_raw_conn(),
                                                       client_major_version as u16,  // 0
                                                       client_minor_version as u16);  // 1
        GetVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_XID_RANGE: u8 = 1;

pub type GetXidRangeCookie<'a> = base::Cookie<'a, xcb_xc_misc_get_xid_range_cookie_t>;

impl<'a> GetXidRangeCookie<'a> {
    pub fn get_reply(&self) -> Result<GetXidRangeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetXidRangeReply {
                    ptr: xcb_xc_misc_get_xid_range_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetXidRangeReply {
                    ptr: xcb_xc_misc_get_xid_range_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetXidRangeReply = base::Reply<xcb_xc_misc_get_xid_range_reply_t>;

impl GetXidRangeReply {
    pub fn start_id(&self) -> u32 {
        unsafe {
            (*self.ptr).start_id
        }
    }
    pub fn count(&self) -> u32 {
        unsafe {
            (*self.ptr).count
        }
    }
}

pub fn get_xid_range<'a>(c: &'a base::Connection)
        -> GetXidRangeCookie<'a> {
    unsafe {
        let cookie = xcb_xc_misc_get_xid_range(c.get_raw_conn());
        GetXidRangeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_xid_range_unchecked<'a>(c: &'a base::Connection)
        -> GetXidRangeCookie<'a> {
    unsafe {
        let cookie = xcb_xc_misc_get_xid_range_unchecked(c.get_raw_conn());
        GetXidRangeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_XID_LIST: u8 = 2;

pub type GetXidListCookie<'a> = base::Cookie<'a, xcb_xc_misc_get_xid_list_cookie_t>;

impl<'a> GetXidListCookie<'a> {
    pub fn get_reply(&self) -> Result<GetXidListReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetXidListReply {
                    ptr: xcb_xc_misc_get_xid_list_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetXidListReply {
                    ptr: xcb_xc_misc_get_xid_list_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetXidListReply = base::Reply<xcb_xc_misc_get_xid_list_reply_t>;

impl GetXidListReply {
    pub fn ids_len(&self) -> u32 {
        unsafe {
            (*self.ptr).ids_len
        }
    }
    pub fn ids(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xc_misc_get_xid_list_ids_length(field) as usize;
            let data = xcb_xc_misc_get_xid_list_ids(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_xid_list<'a>(c    : &'a base::Connection,
                        count: u32)
        -> GetXidListCookie<'a> {
    unsafe {
        let cookie = xcb_xc_misc_get_xid_list(c.get_raw_conn(),
                                              count as u32);  // 0
        GetXidListCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_xid_list_unchecked<'a>(c    : &'a base::Connection,
                                  count: u32)
        -> GetXidListCookie<'a> {
    unsafe {
        let cookie = xcb_xc_misc_get_xid_list_unchecked(c.get_raw_conn(),
                                                        count as u32);  // 0
        GetXidListCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
