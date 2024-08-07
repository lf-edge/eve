// Generated automatically from damage.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use render;
use shape;
use xfixes;
use ffi::base::*;
use ffi::damage::*;
use ffi::xproto::*;
use ffi::render::*;
use ffi::shape::*;
use ffi::xfixes::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_damage_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 1;

pub type Damage = xcb_damage_damage_t;

pub type ReportLevel = u32;
pub const REPORT_LEVEL_RAW_RECTANGLES  : ReportLevel = 0x00;
pub const REPORT_LEVEL_DELTA_RECTANGLES: ReportLevel = 0x01;
pub const REPORT_LEVEL_BOUNDING_BOX    : ReportLevel = 0x02;
pub const REPORT_LEVEL_NON_EMPTY       : ReportLevel = 0x03;

pub struct BadDamageError {
    pub base: base::Error<xcb_damage_bad_damage_error_t>
}



pub const BAD_DAMAGE: u8 = 0;

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_damage_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_damage_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_damage_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_damage_query_version_reply_t>;

impl QueryVersionReply {
    pub fn major_version(&self) -> u32 {
        unsafe {
            (*self.ptr).major_version
        }
    }
    pub fn minor_version(&self) -> u32 {
        unsafe {
            (*self.ptr).minor_version
        }
    }
}

pub fn query_version<'a>(c                   : &'a base::Connection,
                         client_major_version: u32,
                         client_minor_version: u32)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_damage_query_version(c.get_raw_conn(),
                                              client_major_version as u32,  // 0
                                              client_minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c                   : &'a base::Connection,
                                   client_major_version: u32,
                                   client_minor_version: u32)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_damage_query_version_unchecked(c.get_raw_conn(),
                                                        client_major_version as u32,  // 0
                                                        client_minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE: u8 = 1;

pub fn create<'a>(c       : &'a base::Connection,
                  damage  : Damage,
                  drawable: xproto::Drawable,
                  level   : u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_damage_create(c.get_raw_conn(),
                                       damage as xcb_damage_damage_t,  // 0
                                       drawable as xcb_drawable_t,  // 1
                                       level as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_checked<'a>(c       : &'a base::Connection,
                          damage  : Damage,
                          drawable: xproto::Drawable,
                          level   : u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_damage_create_checked(c.get_raw_conn(),
                                               damage as xcb_damage_damage_t,  // 0
                                               drawable as xcb_drawable_t,  // 1
                                               level as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY: u8 = 2;

pub fn destroy<'a>(c     : &'a base::Connection,
                   damage: Damage)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_damage_destroy(c.get_raw_conn(),
                                        damage as xcb_damage_damage_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_checked<'a>(c     : &'a base::Connection,
                           damage: Damage)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_damage_destroy_checked(c.get_raw_conn(),
                                                damage as xcb_damage_damage_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SUBTRACT: u8 = 3;

pub fn subtract<'a>(c     : &'a base::Connection,
                    damage: Damage,
                    repair: xfixes::Region,
                    parts : xfixes::Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_damage_subtract(c.get_raw_conn(),
                                         damage as xcb_damage_damage_t,  // 0
                                         repair as xcb_xfixes_region_t,  // 1
                                         parts as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn subtract_checked<'a>(c     : &'a base::Connection,
                            damage: Damage,
                            repair: xfixes::Region,
                            parts : xfixes::Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_damage_subtract_checked(c.get_raw_conn(),
                                                 damage as xcb_damage_damage_t,  // 0
                                                 repair as xcb_xfixes_region_t,  // 1
                                                 parts as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ADD: u8 = 4;

pub fn add<'a>(c       : &'a base::Connection,
               drawable: xproto::Drawable,
               region  : xfixes::Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_damage_add(c.get_raw_conn(),
                                    drawable as xcb_drawable_t,  // 0
                                    region as xcb_xfixes_region_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn add_checked<'a>(c       : &'a base::Connection,
                       drawable: xproto::Drawable,
                       region  : xfixes::Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_damage_add_checked(c.get_raw_conn(),
                                            drawable as xcb_drawable_t,  // 0
                                            region as xcb_xfixes_region_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const NOTIFY: u8 = 0;

pub type NotifyEvent = base::Event<xcb_damage_notify_event_t>;

impl NotifyEvent {
    pub fn level(&self) -> u8 {
        unsafe {
            (*self.ptr).level
        }
    }
    pub fn drawable(&self) -> xproto::Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    pub fn damage(&self) -> Damage {
        unsafe {
            (*self.ptr).damage
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn area(&self) -> xproto::Rectangle {
        unsafe {
            std::mem::transmute((*self.ptr).area)
        }
    }
    pub fn geometry(&self) -> xproto::Rectangle {
        unsafe {
            std::mem::transmute((*self.ptr).geometry)
        }
    }
    /// Constructs a new NotifyEvent
    /// `response_type` will be set automatically to NOTIFY
    pub fn new(level: u8,
               drawable: xproto::Drawable,
               damage: Damage,
               timestamp: xproto::Timestamp,
               area: xproto::Rectangle,
               geometry: xproto::Rectangle)
            -> NotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_damage_notify_event_t;
            (*raw).response_type = NOTIFY;
            (*raw).level = level;
            (*raw).drawable = drawable;
            (*raw).damage = damage;
            (*raw).timestamp = timestamp;
            (*raw).area = area.base;
            (*raw).geometry = geometry.base;
            NotifyEvent {
                ptr: raw
            }
        }
    }
}
