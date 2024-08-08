// Generated automatically from xevie.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::xevie::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_xevie_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 0;

pub type Datatype = u32;
pub const DATATYPE_UNMODIFIED: Datatype = 0x00;
pub const DATATYPE_MODIFIED  : Datatype = 0x01;



pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_xevie_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_xevie_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_xevie_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_xevie_query_version_reply_t>;

impl QueryVersionReply {
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

pub fn query_version<'a>(c                   : &'a base::Connection,
                         client_major_version: u16,
                         client_minor_version: u16)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_query_version(c.get_raw_conn(),
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
        let cookie = xcb_xevie_query_version_unchecked(c.get_raw_conn(),
                                                       client_major_version as u16,  // 0
                                                       client_minor_version as u16);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const START: u8 = 1;

pub type StartCookie<'a> = base::Cookie<'a, xcb_xevie_start_cookie_t>;

impl<'a> StartCookie<'a> {
    pub fn get_reply(&self) -> Result<StartReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = StartReply {
                    ptr: xcb_xevie_start_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( StartReply {
                    ptr: xcb_xevie_start_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type StartReply = base::Reply<xcb_xevie_start_reply_t>;

impl StartReply {
}

pub fn start<'a>(c     : &'a base::Connection,
                 screen: u32)
        -> StartCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_start(c.get_raw_conn(),
                                     screen as u32);  // 0
        StartCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn start_unchecked<'a>(c     : &'a base::Connection,
                           screen: u32)
        -> StartCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_start_unchecked(c.get_raw_conn(),
                                               screen as u32);  // 0
        StartCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const END: u8 = 2;

pub type EndCookie<'a> = base::Cookie<'a, xcb_xevie_end_cookie_t>;

impl<'a> EndCookie<'a> {
    pub fn get_reply(&self) -> Result<EndReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = EndReply {
                    ptr: xcb_xevie_end_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( EndReply {
                    ptr: xcb_xevie_end_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type EndReply = base::Reply<xcb_xevie_end_reply_t>;

impl EndReply {
}

pub fn end<'a>(c   : &'a base::Connection,
               cmap: u32)
        -> EndCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_end(c.get_raw_conn(),
                                   cmap as u32);  // 0
        EndCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn end_unchecked<'a>(c   : &'a base::Connection,
                         cmap: u32)
        -> EndCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_end_unchecked(c.get_raw_conn(),
                                             cmap as u32);  // 0
        EndCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

#[derive(Copy, Clone)]
pub struct Event {
    pub base: xcb_xevie_event_t,
}

impl Event {
    #[allow(unused_unsafe)]
    pub fn new() -> Event {
        unsafe {
            Event {
                base: xcb_xevie_event_t {
                    pad0: [0; 32],
                }
            }
        }
    }
}

pub type EventIterator = xcb_xevie_event_iterator_t;

impl Iterator for EventIterator {
    type Item = Event;
    fn next(&mut self) -> std::option::Option<Event> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xevie_event_iterator_t;
                let data = (*iter).data;
                xcb_xevie_event_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const SEND: u8 = 3;

pub type SendCookie<'a> = base::Cookie<'a, xcb_xevie_send_cookie_t>;

impl<'a> SendCookie<'a> {
    pub fn get_reply(&self) -> Result<SendReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SendReply {
                    ptr: xcb_xevie_send_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SendReply {
                    ptr: xcb_xevie_send_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SendReply = base::Reply<xcb_xevie_send_reply_t>;

impl SendReply {
}

pub fn send<'a>(c        : &'a base::Connection,
                event    : Event,
                data_type: u32)
        -> SendCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_send(c.get_raw_conn(),
                                    event.base,  // 0
                                    data_type as u32);  // 1
        SendCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn send_unchecked<'a>(c        : &'a base::Connection,
                          event    : Event,
                          data_type: u32)
        -> SendCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_send_unchecked(c.get_raw_conn(),
                                              event.base,  // 0
                                              data_type as u32);  // 1
        SendCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SELECT_INPUT: u8 = 4;

pub type SelectInputCookie<'a> = base::Cookie<'a, xcb_xevie_select_input_cookie_t>;

impl<'a> SelectInputCookie<'a> {
    pub fn get_reply(&self) -> Result<SelectInputReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SelectInputReply {
                    ptr: xcb_xevie_select_input_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SelectInputReply {
                    ptr: xcb_xevie_select_input_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SelectInputReply = base::Reply<xcb_xevie_select_input_reply_t>;

impl SelectInputReply {
}

pub fn select_input<'a>(c         : &'a base::Connection,
                        event_mask: u32)
        -> SelectInputCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_select_input(c.get_raw_conn(),
                                            event_mask as u32);  // 0
        SelectInputCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn select_input_unchecked<'a>(c         : &'a base::Connection,
                                  event_mask: u32)
        -> SelectInputCookie<'a> {
    unsafe {
        let cookie = xcb_xevie_select_input_unchecked(c.get_raw_conn(),
                                                      event_mask as u32);  // 0
        SelectInputCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
