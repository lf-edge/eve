// Generated automatically from present.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use render;
use randr;
use shape;
use xfixes;
use sync;
use ffi::base::*;
use ffi::present::*;
use ffi::xproto::*;
use ffi::render::*;
use ffi::randr::*;
use ffi::shape::*;
use ffi::xfixes::*;
use ffi::sync::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_present_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 0;

pub type EventEnum = u32;
pub const EVENT_CONFIGURE_NOTIFY: EventEnum = 0x00;
pub const EVENT_COMPLETE_NOTIFY : EventEnum = 0x01;
pub const EVENT_IDLE_NOTIFY     : EventEnum = 0x02;
pub const EVENT_REDIRECT_NOTIFY : EventEnum = 0x03;

pub type EventMask = u32;
pub const EVENT_MASK_NO_EVENT        : EventMask = 0x00;
pub const EVENT_MASK_CONFIGURE_NOTIFY: EventMask = 0x01;
pub const EVENT_MASK_COMPLETE_NOTIFY : EventMask = 0x02;
pub const EVENT_MASK_IDLE_NOTIFY     : EventMask = 0x04;
pub const EVENT_MASK_REDIRECT_NOTIFY : EventMask = 0x08;

pub type Option = u32;
pub const OPTION_NONE : Option = 0x00;
pub const OPTION_ASYNC: Option = 0x01;
pub const OPTION_COPY : Option = 0x02;
pub const OPTION_UST  : Option = 0x04;

pub type Capability = u32;
pub const CAPABILITY_NONE : Capability = 0x00;
pub const CAPABILITY_ASYNC: Capability = 0x01;
pub const CAPABILITY_FENCE: Capability = 0x02;
pub const CAPABILITY_UST  : Capability = 0x04;

pub type CompleteKind = u32;
pub const COMPLETE_KIND_PIXMAP    : CompleteKind = 0x00;
pub const COMPLETE_KIND_NOTIFY_MSC: CompleteKind = 0x01;

pub type CompleteMode = u32;
pub const COMPLETE_MODE_COPY: CompleteMode = 0x00;
pub const COMPLETE_MODE_FLIP: CompleteMode = 0x01;
pub const COMPLETE_MODE_SKIP: CompleteMode = 0x02;

pub type Event = xcb_present_event_t;



#[derive(Copy, Clone)]
pub struct Notify {
    pub base: xcb_present_notify_t,
}

impl Notify {
    #[allow(unused_unsafe)]
    pub fn new(window: xproto::Window,
               serial: u32)
            -> Notify {
        unsafe {
            Notify {
                base: xcb_present_notify_t {
                    window: window,
                    serial: serial,
                }
            }
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            self.base.window
        }
    }
    pub fn serial(&self) -> u32 {
        unsafe {
            self.base.serial
        }
    }
}

pub type NotifyIterator = xcb_present_notify_iterator_t;

impl Iterator for NotifyIterator {
    type Item = Notify;
    fn next(&mut self) -> std::option::Option<Notify> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_present_notify_iterator_t;
                let data = (*iter).data;
                xcb_present_notify_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_present_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_present_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_present_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_present_query_version_reply_t>;

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

pub fn query_version<'a>(c            : &'a base::Connection,
                         major_version: u32,
                         minor_version: u32)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_present_query_version(c.get_raw_conn(),
                                               major_version as u32,  // 0
                                               minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c            : &'a base::Connection,
                                   major_version: u32,
                                   minor_version: u32)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_present_query_version_unchecked(c.get_raw_conn(),
                                                         major_version as u32,  // 0
                                                         minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PIXMAP: u8 = 1;

pub fn pixmap<'a>(c          : &'a base::Connection,
                  window     : xproto::Window,
                  pixmap     : xproto::Pixmap,
                  serial     : u32,
                  valid      : xfixes::Region,
                  update     : xfixes::Region,
                  x_off      : i16,
                  y_off      : i16,
                  target_crtc: randr::Crtc,
                  wait_fence : sync::Fence,
                  idle_fence : sync::Fence,
                  options    : u32,
                  target_msc : u64,
                  divisor    : u64,
                  remainder  : u64,
                  notifies   : &[Notify])
        -> base::VoidCookie<'a> {
    unsafe {
        let notifies_len = notifies.len();
        let notifies_ptr = notifies.as_ptr();
        let cookie = xcb_present_pixmap(c.get_raw_conn(),
                                        window as xcb_window_t,  // 0
                                        pixmap as xcb_pixmap_t,  // 1
                                        serial as u32,  // 2
                                        valid as xcb_xfixes_region_t,  // 3
                                        update as xcb_xfixes_region_t,  // 4
                                        x_off as i16,  // 5
                                        y_off as i16,  // 6
                                        target_crtc as xcb_randr_crtc_t,  // 7
                                        wait_fence as xcb_sync_fence_t,  // 8
                                        idle_fence as xcb_sync_fence_t,  // 9
                                        options as u32,  // 10
                                        target_msc as u64,  // 11
                                        divisor as u64,  // 12
                                        remainder as u64,  // 13
                                        notifies_len as u32,  // 14
                                        notifies_ptr as *const xcb_present_notify_t);  // 15
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn pixmap_checked<'a>(c          : &'a base::Connection,
                          window     : xproto::Window,
                          pixmap     : xproto::Pixmap,
                          serial     : u32,
                          valid      : xfixes::Region,
                          update     : xfixes::Region,
                          x_off      : i16,
                          y_off      : i16,
                          target_crtc: randr::Crtc,
                          wait_fence : sync::Fence,
                          idle_fence : sync::Fence,
                          options    : u32,
                          target_msc : u64,
                          divisor    : u64,
                          remainder  : u64,
                          notifies   : &[Notify])
        -> base::VoidCookie<'a> {
    unsafe {
        let notifies_len = notifies.len();
        let notifies_ptr = notifies.as_ptr();
        let cookie = xcb_present_pixmap_checked(c.get_raw_conn(),
                                                window as xcb_window_t,  // 0
                                                pixmap as xcb_pixmap_t,  // 1
                                                serial as u32,  // 2
                                                valid as xcb_xfixes_region_t,  // 3
                                                update as xcb_xfixes_region_t,  // 4
                                                x_off as i16,  // 5
                                                y_off as i16,  // 6
                                                target_crtc as xcb_randr_crtc_t,  // 7
                                                wait_fence as xcb_sync_fence_t,  // 8
                                                idle_fence as xcb_sync_fence_t,  // 9
                                                options as u32,  // 10
                                                target_msc as u64,  // 11
                                                divisor as u64,  // 12
                                                remainder as u64,  // 13
                                                notifies_len as u32,  // 14
                                                notifies_ptr as *const xcb_present_notify_t);  // 15
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const NOTIFY_MSC: u8 = 2;

pub fn notify_msc<'a>(c         : &'a base::Connection,
                      window    : xproto::Window,
                      serial    : u32,
                      target_msc: u64,
                      divisor   : u64,
                      remainder : u64)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_present_notify_msc(c.get_raw_conn(),
                                            window as xcb_window_t,  // 0
                                            serial as u32,  // 1
                                            target_msc as u64,  // 2
                                            divisor as u64,  // 3
                                            remainder as u64);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn notify_msc_checked<'a>(c         : &'a base::Connection,
                              window    : xproto::Window,
                              serial    : u32,
                              target_msc: u64,
                              divisor   : u64,
                              remainder : u64)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_present_notify_msc_checked(c.get_raw_conn(),
                                                    window as xcb_window_t,  // 0
                                                    serial as u32,  // 1
                                                    target_msc as u64,  // 2
                                                    divisor as u64,  // 3
                                                    remainder as u64);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SELECT_INPUT: u8 = 3;

pub fn select_input<'a>(c         : &'a base::Connection,
                        eid       : Event,
                        window    : xproto::Window,
                        event_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_present_select_input(c.get_raw_conn(),
                                              eid as xcb_present_event_t,  // 0
                                              window as xcb_window_t,  // 1
                                              event_mask as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_input_checked<'a>(c         : &'a base::Connection,
                                eid       : Event,
                                window    : xproto::Window,
                                event_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_present_select_input_checked(c.get_raw_conn(),
                                                      eid as xcb_present_event_t,  // 0
                                                      window as xcb_window_t,  // 1
                                                      event_mask as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_CAPABILITIES: u8 = 4;

pub type QueryCapabilitiesCookie<'a> = base::Cookie<'a, xcb_present_query_capabilities_cookie_t>;

impl<'a> QueryCapabilitiesCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryCapabilitiesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryCapabilitiesReply {
                    ptr: xcb_present_query_capabilities_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryCapabilitiesReply {
                    ptr: xcb_present_query_capabilities_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryCapabilitiesReply = base::Reply<xcb_present_query_capabilities_reply_t>;

impl QueryCapabilitiesReply {
    pub fn capabilities(&self) -> u32 {
        unsafe {
            (*self.ptr).capabilities
        }
    }
}

pub fn query_capabilities<'a>(c     : &'a base::Connection,
                              target: u32)
        -> QueryCapabilitiesCookie<'a> {
    unsafe {
        let cookie = xcb_present_query_capabilities(c.get_raw_conn(),
                                                    target as u32);  // 0
        QueryCapabilitiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_capabilities_unchecked<'a>(c     : &'a base::Connection,
                                        target: u32)
        -> QueryCapabilitiesCookie<'a> {
    unsafe {
        let cookie = xcb_present_query_capabilities_unchecked(c.get_raw_conn(),
                                                              target as u32);  // 0
        QueryCapabilitiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GENERIC: u8 = 0;

pub type GenericEvent = base::Event<xcb_present_generic_event_t>;

impl GenericEvent {
    pub fn extension(&self) -> u8 {
        unsafe {
            (*self.ptr).extension
        }
    }
    pub fn length(&self) -> u32 {
        unsafe {
            (*self.ptr).length
        }
    }
    pub fn evtype(&self) -> u16 {
        unsafe {
            (*self.ptr).evtype
        }
    }
    pub fn event(&self) -> Event {
        unsafe {
            (*self.ptr).event
        }
    }
    /// Constructs a new GenericEvent
    /// `response_type` will be set automatically to GENERIC
    pub fn new(extension: u8,
               length: u32,
               evtype: u16,
               event: Event)
            -> GenericEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_present_generic_event_t;
            (*raw).response_type = GENERIC;
            (*raw).extension = extension;
            (*raw).length = length;
            (*raw).evtype = evtype;
            (*raw).event = event;
            GenericEvent {
                ptr: raw
            }
        }
    }
}

pub const CONFIGURE_NOTIFY: u8 = 0;

pub type ConfigureNotifyEvent = base::Event<xcb_present_configure_notify_event_t>;

impl ConfigureNotifyEvent {
    pub fn event(&self) -> Event {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn x(&self) -> i16 {
        unsafe {
            (*self.ptr).x
        }
    }
    pub fn y(&self) -> i16 {
        unsafe {
            (*self.ptr).y
        }
    }
    pub fn width(&self) -> u16 {
        unsafe {
            (*self.ptr).width
        }
    }
    pub fn height(&self) -> u16 {
        unsafe {
            (*self.ptr).height
        }
    }
    pub fn off_x(&self) -> i16 {
        unsafe {
            (*self.ptr).off_x
        }
    }
    pub fn off_y(&self) -> i16 {
        unsafe {
            (*self.ptr).off_y
        }
    }
    pub fn pixmap_width(&self) -> u16 {
        unsafe {
            (*self.ptr).pixmap_width
        }
    }
    pub fn pixmap_height(&self) -> u16 {
        unsafe {
            (*self.ptr).pixmap_height
        }
    }
    pub fn pixmap_flags(&self) -> u32 {
        unsafe {
            (*self.ptr).pixmap_flags
        }
    }
    /// Constructs a new ConfigureNotifyEvent
    /// `response_type` will be set automatically to CONFIGURE_NOTIFY
    pub fn new(event: Event,
               window: xproto::Window,
               x: i16,
               y: i16,
               width: u16,
               height: u16,
               off_x: i16,
               off_y: i16,
               pixmap_width: u16,
               pixmap_height: u16,
               pixmap_flags: u32)
            -> ConfigureNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_present_configure_notify_event_t;
            (*raw).response_type = CONFIGURE_NOTIFY;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).x = x;
            (*raw).y = y;
            (*raw).width = width;
            (*raw).height = height;
            (*raw).off_x = off_x;
            (*raw).off_y = off_y;
            (*raw).pixmap_width = pixmap_width;
            (*raw).pixmap_height = pixmap_height;
            (*raw).pixmap_flags = pixmap_flags;
            ConfigureNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const COMPLETE_NOTIFY: u8 = 1;

pub type CompleteNotifyEvent = base::Event<xcb_present_complete_notify_event_t>;

impl CompleteNotifyEvent {
    pub fn kind(&self) -> u8 {
        unsafe {
            (*self.ptr).kind
        }
    }
    pub fn mode(&self) -> u8 {
        unsafe {
            (*self.ptr).mode
        }
    }
    pub fn event(&self) -> Event {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn serial(&self) -> u32 {
        unsafe {
            (*self.ptr).serial
        }
    }
    pub fn ust(&self) -> u64 {
        unsafe {
            (*self.ptr).ust
        }
    }
    pub fn msc(&self) -> u64 {
        unsafe {
            (*self.ptr).msc
        }
    }
    /// Constructs a new CompleteNotifyEvent
    /// `response_type` will be set automatically to COMPLETE_NOTIFY
    pub fn new(kind: u8,
               mode: u8,
               event: Event,
               window: xproto::Window,
               serial: u32,
               ust: u64,
               msc: u64)
            -> CompleteNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_present_complete_notify_event_t;
            (*raw).response_type = COMPLETE_NOTIFY;
            (*raw).kind = kind;
            (*raw).mode = mode;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).serial = serial;
            (*raw).ust = ust;
            (*raw).msc = msc;
            CompleteNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const IDLE_NOTIFY: u8 = 2;

pub type IdleNotifyEvent = base::Event<xcb_present_idle_notify_event_t>;

impl IdleNotifyEvent {
    pub fn event(&self) -> Event {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn serial(&self) -> u32 {
        unsafe {
            (*self.ptr).serial
        }
    }
    pub fn pixmap(&self) -> xproto::Pixmap {
        unsafe {
            (*self.ptr).pixmap
        }
    }
    pub fn idle_fence(&self) -> sync::Fence {
        unsafe {
            (*self.ptr).idle_fence
        }
    }
    /// Constructs a new IdleNotifyEvent
    /// `response_type` will be set automatically to IDLE_NOTIFY
    pub fn new(event: Event,
               window: xproto::Window,
               serial: u32,
               pixmap: xproto::Pixmap,
               idle_fence: sync::Fence)
            -> IdleNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_present_idle_notify_event_t;
            (*raw).response_type = IDLE_NOTIFY;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).serial = serial;
            (*raw).pixmap = pixmap;
            (*raw).idle_fence = idle_fence;
            IdleNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const REDIRECT_NOTIFY: u8 = 3;

pub type RedirectNotifyEvent = base::Event<xcb_present_redirect_notify_event_t>;

impl RedirectNotifyEvent {
    pub fn update_window(&self) -> bool {
        unsafe {
            (*self.ptr).update_window != 0
        }
    }
    pub fn event(&self) -> Event {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn event_window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).event_window
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn pixmap(&self) -> xproto::Pixmap {
        unsafe {
            (*self.ptr).pixmap
        }
    }
    pub fn serial(&self) -> u32 {
        unsafe {
            (*self.ptr).serial
        }
    }
    pub fn valid_region(&self) -> xfixes::Region {
        unsafe {
            (*self.ptr).valid_region
        }
    }
    pub fn update_region(&self) -> xfixes::Region {
        unsafe {
            (*self.ptr).update_region
        }
    }
    pub fn valid_rect(&self) -> xproto::Rectangle {
        unsafe {
            std::mem::transmute((*self.ptr).valid_rect)
        }
    }
    pub fn update_rect(&self) -> xproto::Rectangle {
        unsafe {
            std::mem::transmute((*self.ptr).update_rect)
        }
    }
    pub fn x_off(&self) -> i16 {
        unsafe {
            (*self.ptr).x_off
        }
    }
    pub fn y_off(&self) -> i16 {
        unsafe {
            (*self.ptr).y_off
        }
    }
    pub fn target_crtc(&self) -> randr::Crtc {
        unsafe {
            (*self.ptr).target_crtc
        }
    }
    pub fn wait_fence(&self) -> sync::Fence {
        unsafe {
            (*self.ptr).wait_fence
        }
    }
    pub fn idle_fence(&self) -> sync::Fence {
        unsafe {
            (*self.ptr).idle_fence
        }
    }
    pub fn options(&self) -> u32 {
        unsafe {
            (*self.ptr).options
        }
    }
    pub fn target_msc(&self) -> u64 {
        unsafe {
            (*self.ptr).target_msc
        }
    }
    pub fn divisor(&self) -> u64 {
        unsafe {
            (*self.ptr).divisor
        }
    }
    pub fn remainder(&self) -> u64 {
        unsafe {
            (*self.ptr).remainder
        }
    }
    pub fn notifies_len(&self) -> u32 {
        unsafe {
            (*self.ptr).notifies_len
        }
    }
    pub fn notifies(&self) -> NotifyIterator {
        unsafe {
            xcb_present_redirect_notify_notifies_iterator(self.ptr)
        }
    }
    /// Constructs a new RedirectNotifyEvent
    /// `response_type` will be set automatically to REDIRECT_NOTIFY
    pub fn new(update_window: bool,
               event: Event,
               event_window: xproto::Window,
               window: xproto::Window,
               pixmap: xproto::Pixmap,
               serial: u32,
               valid_region: xfixes::Region,
               update_region: xfixes::Region,
               valid_rect: xproto::Rectangle,
               update_rect: xproto::Rectangle,
               x_off: i16,
               y_off: i16,
               target_crtc: randr::Crtc,
               wait_fence: sync::Fence,
               idle_fence: sync::Fence,
               options: u32,
               target_msc: u64,
               divisor: u64,
               remainder: u64,
               notifies_len: u32,
               notifies: Notify)
            -> RedirectNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_present_redirect_notify_event_t;
            (*raw).response_type = REDIRECT_NOTIFY;
            (*raw).update_window = if update_window { 1 } else { 0 };
            (*raw).event = event;
            (*raw).event_window = event_window;
            (*raw).window = window;
            (*raw).pixmap = pixmap;
            (*raw).serial = serial;
            (*raw).valid_region = valid_region;
            (*raw).update_region = update_region;
            (*raw).valid_rect = valid_rect.base;
            (*raw).update_rect = update_rect.base;
            (*raw).x_off = x_off;
            (*raw).y_off = y_off;
            (*raw).target_crtc = target_crtc;
            (*raw).wait_fence = wait_fence;
            (*raw).idle_fence = idle_fence;
            (*raw).options = options;
            (*raw).target_msc = target_msc;
            (*raw).divisor = divisor;
            (*raw).remainder = remainder;
            (*raw).notifies_len = notifies_len;
            (*raw).notifies = notifies;
            RedirectNotifyEvent {
                ptr: raw
            }
        }
    }
}
