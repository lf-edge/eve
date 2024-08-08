// Generated automatically from screensaver.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::screensaver::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_screensaver_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 1;

pub type Kind = u32;
pub const KIND_BLANKED : Kind = 0x00;
pub const KIND_INTERNAL: Kind = 0x01;
pub const KIND_EXTERNAL: Kind = 0x02;

pub type Event = u32;
pub const EVENT_NOTIFY_MASK: Event = 0x01;
pub const EVENT_CYCLE_MASK : Event = 0x02;

pub type State = u32;
pub const STATE_OFF     : State = 0x00;
pub const STATE_ON      : State = 0x01;
pub const STATE_CYCLE   : State = 0x02;
pub const STATE_DISABLED: State = 0x03;



pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_screensaver_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_screensaver_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_screensaver_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_screensaver_query_version_reply_t>;

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
                         client_major_version: u8,
                         client_minor_version: u8)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_query_version(c.get_raw_conn(),
                                                   client_major_version as u8,  // 0
                                                   client_minor_version as u8);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c                   : &'a base::Connection,
                                   client_major_version: u8,
                                   client_minor_version: u8)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_query_version_unchecked(c.get_raw_conn(),
                                                             client_major_version as u8,  // 0
                                                             client_minor_version as u8);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_INFO: u8 = 1;

pub type QueryInfoCookie<'a> = base::Cookie<'a, xcb_screensaver_query_info_cookie_t>;

impl<'a> QueryInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryInfoReply {
                    ptr: xcb_screensaver_query_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryInfoReply {
                    ptr: xcb_screensaver_query_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryInfoReply = base::Reply<xcb_screensaver_query_info_reply_t>;

impl QueryInfoReply {
    pub fn state(&self) -> u8 {
        unsafe {
            (*self.ptr).state
        }
    }
    pub fn saver_window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).saver_window
        }
    }
    pub fn ms_until_server(&self) -> u32 {
        unsafe {
            (*self.ptr).ms_until_server
        }
    }
    pub fn ms_since_user_input(&self) -> u32 {
        unsafe {
            (*self.ptr).ms_since_user_input
        }
    }
    pub fn event_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).event_mask
        }
    }
    pub fn kind(&self) -> u8 {
        unsafe {
            (*self.ptr).kind
        }
    }
}

pub fn query_info<'a>(c       : &'a base::Connection,
                      drawable: xproto::Drawable)
        -> QueryInfoCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_query_info(c.get_raw_conn(),
                                                drawable as xcb_drawable_t);  // 0
        QueryInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_info_unchecked<'a>(c       : &'a base::Connection,
                                drawable: xproto::Drawable)
        -> QueryInfoCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_query_info_unchecked(c.get_raw_conn(),
                                                          drawable as xcb_drawable_t);  // 0
        QueryInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SELECT_INPUT: u8 = 2;

pub fn select_input<'a>(c         : &'a base::Connection,
                        drawable  : xproto::Drawable,
                        event_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_select_input(c.get_raw_conn(),
                                                  drawable as xcb_drawable_t,  // 0
                                                  event_mask as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_input_checked<'a>(c         : &'a base::Connection,
                                drawable  : xproto::Drawable,
                                event_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_select_input_checked(c.get_raw_conn(),
                                                          drawable as xcb_drawable_t,  // 0
                                                          event_mask as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_ATTRIBUTES: u8 = 3;

pub fn set_attributes<'a>(c           : &'a base::Connection,
                          drawable    : xproto::Drawable,
                          x           : i16,
                          y           : i16,
                          width       : u16,
                          height      : u16,
                          border_width: u16,
                          class       : u8,
                          depth       : u8,
                          visual      : xproto::Visualid,
                          value_list  : &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_screensaver_set_attributes(c.get_raw_conn(),
                                                    drawable as xcb_drawable_t,  // 0
                                                    x as i16,  // 1
                                                    y as i16,  // 2
                                                    width as u16,  // 3
                                                    height as u16,  // 4
                                                    border_width as u16,  // 5
                                                    class as u8,  // 6
                                                    depth as u8,  // 7
                                                    visual as xcb_visualid_t,  // 8
                                                    value_list_mask as u32,  // 9
                                                    value_list_ptr as *const u32);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_attributes_checked<'a>(c           : &'a base::Connection,
                                  drawable    : xproto::Drawable,
                                  x           : i16,
                                  y           : i16,
                                  width       : u16,
                                  height      : u16,
                                  border_width: u16,
                                  class       : u8,
                                  depth       : u8,
                                  visual      : xproto::Visualid,
                                  value_list  : &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_screensaver_set_attributes_checked(c.get_raw_conn(),
                                                            drawable as xcb_drawable_t,  // 0
                                                            x as i16,  // 1
                                                            y as i16,  // 2
                                                            width as u16,  // 3
                                                            height as u16,  // 4
                                                            border_width as u16,  // 5
                                                            class as u8,  // 6
                                                            depth as u8,  // 7
                                                            visual as xcb_visualid_t,  // 8
                                                            value_list_mask as u32,  // 9
                                                            value_list_ptr as *const u32);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNSET_ATTRIBUTES: u8 = 4;

pub fn unset_attributes<'a>(c       : &'a base::Connection,
                            drawable: xproto::Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_unset_attributes(c.get_raw_conn(),
                                                      drawable as xcb_drawable_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn unset_attributes_checked<'a>(c       : &'a base::Connection,
                                    drawable: xproto::Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_unset_attributes_checked(c.get_raw_conn(),
                                                              drawable as xcb_drawable_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SUSPEND: u8 = 5;

pub fn suspend<'a>(c      : &'a base::Connection,
                   suspend: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_suspend(c.get_raw_conn(),
                                             suspend as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn suspend_checked<'a>(c      : &'a base::Connection,
                           suspend: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_screensaver_suspend_checked(c.get_raw_conn(),
                                                     suspend as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const NOTIFY: u8 = 0;

pub type NotifyEvent = base::Event<xcb_screensaver_notify_event_t>;

impl NotifyEvent {
    pub fn state(&self) -> u8 {
        unsafe {
            (*self.ptr).state
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn kind(&self) -> u8 {
        unsafe {
            (*self.ptr).kind
        }
    }
    pub fn forced(&self) -> bool {
        unsafe {
            (*self.ptr).forced != 0
        }
    }
    /// Constructs a new NotifyEvent
    /// `response_type` will be set automatically to NOTIFY
    pub fn new(state: u8,
               time: xproto::Timestamp,
               root: xproto::Window,
               window: xproto::Window,
               kind: u8,
               forced: bool)
            -> NotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_screensaver_notify_event_t;
            (*raw).response_type = NOTIFY;
            (*raw).state = state;
            (*raw).time = time;
            (*raw).root = root;
            (*raw).window = window;
            (*raw).kind = kind;
            (*raw).forced = if forced { 1 } else { 0 };
            NotifyEvent {
                ptr: raw
            }
        }
    }
}
