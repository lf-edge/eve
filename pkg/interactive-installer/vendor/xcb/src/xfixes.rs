// Generated automatically from xfixes.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use render;
use shape;
use ffi::base::*;
use ffi::xfixes::*;
use ffi::xproto::*;
use ffi::render::*;
use ffi::shape::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_xfixes_id
    }
}

pub const MAJOR_VERSION: u32 = 5;
pub const MINOR_VERSION: u32 = 0;

pub type SaveSetMode = u32;
pub const SAVE_SET_MODE_INSERT: SaveSetMode = 0x00;
pub const SAVE_SET_MODE_DELETE: SaveSetMode = 0x01;

pub type SaveSetTarget = u32;
pub const SAVE_SET_TARGET_NEAREST: SaveSetTarget = 0x00;
pub const SAVE_SET_TARGET_ROOT   : SaveSetTarget = 0x01;

pub type SaveSetMapping = u32;
pub const SAVE_SET_MAPPING_MAP  : SaveSetMapping = 0x00;
pub const SAVE_SET_MAPPING_UNMAP: SaveSetMapping = 0x01;

pub type SelectionEvent = u32;
pub const SELECTION_EVENT_SET_SELECTION_OWNER     : SelectionEvent = 0x00;
pub const SELECTION_EVENT_SELECTION_WINDOW_DESTROY: SelectionEvent = 0x01;
pub const SELECTION_EVENT_SELECTION_CLIENT_CLOSE  : SelectionEvent = 0x02;

pub type SelectionEventMask = u32;
pub const SELECTION_EVENT_MASK_SET_SELECTION_OWNER     : SelectionEventMask = 0x01;
pub const SELECTION_EVENT_MASK_SELECTION_WINDOW_DESTROY: SelectionEventMask = 0x02;
pub const SELECTION_EVENT_MASK_SELECTION_CLIENT_CLOSE  : SelectionEventMask = 0x04;

pub type CursorNotify = u32;
pub const CURSOR_NOTIFY_DISPLAY_CURSOR: CursorNotify = 0x00;

pub type CursorNotifyMask = u32;
pub const CURSOR_NOTIFY_MASK_DISPLAY_CURSOR: CursorNotifyMask = 0x01;

pub type Region = xcb_xfixes_region_t;

pub struct BadRegionError {
    pub base: base::Error<xcb_xfixes_bad_region_error_t>
}

pub type RegionEnum = u32;
pub const REGION_NONE: RegionEnum = 0x00;

pub type Barrier = xcb_xfixes_barrier_t;

pub type BarrierDirections = u32;
pub const BARRIER_DIRECTIONS_POSITIVE_X: BarrierDirections = 0x01;
pub const BARRIER_DIRECTIONS_POSITIVE_Y: BarrierDirections = 0x02;
pub const BARRIER_DIRECTIONS_NEGATIVE_X: BarrierDirections = 0x04;
pub const BARRIER_DIRECTIONS_NEGATIVE_Y: BarrierDirections = 0x08;



pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_xfixes_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_xfixes_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_xfixes_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_xfixes_query_version_reply_t>;

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
        let cookie = xcb_xfixes_query_version(c.get_raw_conn(),
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
        let cookie = xcb_xfixes_query_version_unchecked(c.get_raw_conn(),
                                                        client_major_version as u32,  // 0
                                                        client_minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_SAVE_SET: u8 = 1;

pub fn change_save_set<'a>(c     : &'a base::Connection,
                           mode  : u8,
                           target: u8,
                           map   : u8,
                           window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_change_save_set(c.get_raw_conn(),
                                                mode as u8,  // 0
                                                target as u8,  // 1
                                                map as u8,  // 2
                                                window as xcb_window_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_save_set_checked<'a>(c     : &'a base::Connection,
                                   mode  : u8,
                                   target: u8,
                                   map   : u8,
                                   window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_change_save_set_checked(c.get_raw_conn(),
                                                        mode as u8,  // 0
                                                        target as u8,  // 1
                                                        map as u8,  // 2
                                                        window as xcb_window_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SELECTION_NOTIFY: u8 = 0;

pub type SelectionNotifyEvent = base::Event<xcb_xfixes_selection_notify_event_t>;

impl SelectionNotifyEvent {
    pub fn subtype(&self) -> u8 {
        unsafe {
            (*self.ptr).subtype
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn owner(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).owner
        }
    }
    pub fn selection(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).selection
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn selection_timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).selection_timestamp
        }
    }
    /// Constructs a new SelectionNotifyEvent
    /// `response_type` will be set automatically to SELECTION_NOTIFY
    pub fn new(subtype: u8,
               window: xproto::Window,
               owner: xproto::Window,
               selection: xproto::Atom,
               timestamp: xproto::Timestamp,
               selection_timestamp: xproto::Timestamp)
            -> SelectionNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xfixes_selection_notify_event_t;
            (*raw).response_type = SELECTION_NOTIFY;
            (*raw).subtype = subtype;
            (*raw).window = window;
            (*raw).owner = owner;
            (*raw).selection = selection;
            (*raw).timestamp = timestamp;
            (*raw).selection_timestamp = selection_timestamp;
            SelectionNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const SELECT_SELECTION_INPUT: u8 = 2;

pub fn select_selection_input<'a>(c         : &'a base::Connection,
                                  window    : xproto::Window,
                                  selection : xproto::Atom,
                                  event_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_select_selection_input(c.get_raw_conn(),
                                                       window as xcb_window_t,  // 0
                                                       selection as xcb_atom_t,  // 1
                                                       event_mask as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_selection_input_checked<'a>(c         : &'a base::Connection,
                                          window    : xproto::Window,
                                          selection : xproto::Atom,
                                          event_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_select_selection_input_checked(c.get_raw_conn(),
                                                               window as xcb_window_t,  // 0
                                                               selection as xcb_atom_t,  // 1
                                                               event_mask as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CURSOR_NOTIFY: u8 = 1;

pub type CursorNotifyEvent = base::Event<xcb_xfixes_cursor_notify_event_t>;

impl CursorNotifyEvent {
    pub fn subtype(&self) -> u8 {
        unsafe {
            (*self.ptr).subtype
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn cursor_serial(&self) -> u32 {
        unsafe {
            (*self.ptr).cursor_serial
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn name(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).name
        }
    }
    /// Constructs a new CursorNotifyEvent
    /// `response_type` will be set automatically to CURSOR_NOTIFY
    pub fn new(subtype: u8,
               window: xproto::Window,
               cursor_serial: u32,
               timestamp: xproto::Timestamp,
               name: xproto::Atom)
            -> CursorNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xfixes_cursor_notify_event_t;
            (*raw).response_type = CURSOR_NOTIFY;
            (*raw).subtype = subtype;
            (*raw).window = window;
            (*raw).cursor_serial = cursor_serial;
            (*raw).timestamp = timestamp;
            (*raw).name = name;
            CursorNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const SELECT_CURSOR_INPUT: u8 = 3;

pub fn select_cursor_input<'a>(c         : &'a base::Connection,
                               window    : xproto::Window,
                               event_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_select_cursor_input(c.get_raw_conn(),
                                                    window as xcb_window_t,  // 0
                                                    event_mask as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_cursor_input_checked<'a>(c         : &'a base::Connection,
                                       window    : xproto::Window,
                                       event_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_select_cursor_input_checked(c.get_raw_conn(),
                                                            window as xcb_window_t,  // 0
                                                            event_mask as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_CURSOR_IMAGE: u8 = 4;

pub type GetCursorImageCookie<'a> = base::Cookie<'a, xcb_xfixes_get_cursor_image_cookie_t>;

impl<'a> GetCursorImageCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCursorImageReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCursorImageReply {
                    ptr: xcb_xfixes_get_cursor_image_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCursorImageReply {
                    ptr: xcb_xfixes_get_cursor_image_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCursorImageReply = base::Reply<xcb_xfixes_get_cursor_image_reply_t>;

impl GetCursorImageReply {
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
    pub fn xhot(&self) -> u16 {
        unsafe {
            (*self.ptr).xhot
        }
    }
    pub fn yhot(&self) -> u16 {
        unsafe {
            (*self.ptr).yhot
        }
    }
    pub fn cursor_serial(&self) -> u32 {
        unsafe {
            (*self.ptr).cursor_serial
        }
    }
    pub fn cursor_image(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xfixes_get_cursor_image_cursor_image_length(field) as usize;
            let data = xcb_xfixes_get_cursor_image_cursor_image(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_cursor_image<'a>(c: &'a base::Connection)
        -> GetCursorImageCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_get_cursor_image(c.get_raw_conn());
        GetCursorImageCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_cursor_image_unchecked<'a>(c: &'a base::Connection)
        -> GetCursorImageCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_get_cursor_image_unchecked(c.get_raw_conn());
        GetCursorImageCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const BAD_REGION: u8 = 0;

pub const CREATE_REGION: u8 = 5;

pub fn create_region<'a>(c         : &'a base::Connection,
                         region    : Region,
                         rectangles: &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_xfixes_create_region(c.get_raw_conn(),
                                              region as xcb_xfixes_region_t,  // 0
                                              rectangles_len as u32,  // 1
                                              rectangles_ptr as *const xcb_rectangle_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_region_checked<'a>(c         : &'a base::Connection,
                                 region    : Region,
                                 rectangles: &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_xfixes_create_region_checked(c.get_raw_conn(),
                                                      region as xcb_xfixes_region_t,  // 0
                                                      rectangles_len as u32,  // 1
                                                      rectangles_ptr as *const xcb_rectangle_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_REGION_FROM_BITMAP: u8 = 6;

pub fn create_region_from_bitmap<'a>(c     : &'a base::Connection,
                                     region: Region,
                                     bitmap: xproto::Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_create_region_from_bitmap(c.get_raw_conn(),
                                                          region as xcb_xfixes_region_t,  // 0
                                                          bitmap as xcb_pixmap_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_region_from_bitmap_checked<'a>(c     : &'a base::Connection,
                                             region: Region,
                                             bitmap: xproto::Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_create_region_from_bitmap_checked(c.get_raw_conn(),
                                                                  region as xcb_xfixes_region_t,  // 0
                                                                  bitmap as xcb_pixmap_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_REGION_FROM_WINDOW: u8 = 7;

pub fn create_region_from_window<'a>(c     : &'a base::Connection,
                                     region: Region,
                                     window: xproto::Window,
                                     kind  : shape::Kind)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_create_region_from_window(c.get_raw_conn(),
                                                          region as xcb_xfixes_region_t,  // 0
                                                          window as xcb_window_t,  // 1
                                                          kind as xcb_shape_kind_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_region_from_window_checked<'a>(c     : &'a base::Connection,
                                             region: Region,
                                             window: xproto::Window,
                                             kind  : shape::Kind)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_create_region_from_window_checked(c.get_raw_conn(),
                                                                  region as xcb_xfixes_region_t,  // 0
                                                                  window as xcb_window_t,  // 1
                                                                  kind as xcb_shape_kind_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_REGION_FROM_GC: u8 = 8;

pub fn create_region_from_gc<'a>(c     : &'a base::Connection,
                                 region: Region,
                                 gc    : xproto::Gcontext)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_create_region_from_gc(c.get_raw_conn(),
                                                      region as xcb_xfixes_region_t,  // 0
                                                      gc as xcb_gcontext_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_region_from_gc_checked<'a>(c     : &'a base::Connection,
                                         region: Region,
                                         gc    : xproto::Gcontext)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_create_region_from_gc_checked(c.get_raw_conn(),
                                                              region as xcb_xfixes_region_t,  // 0
                                                              gc as xcb_gcontext_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_REGION_FROM_PICTURE: u8 = 9;

pub fn create_region_from_picture<'a>(c      : &'a base::Connection,
                                      region : Region,
                                      picture: render::Picture)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_create_region_from_picture(c.get_raw_conn(),
                                                           region as xcb_xfixes_region_t,  // 0
                                                           picture as xcb_render_picture_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_region_from_picture_checked<'a>(c      : &'a base::Connection,
                                              region : Region,
                                              picture: render::Picture)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_create_region_from_picture_checked(c.get_raw_conn(),
                                                                   region as xcb_xfixes_region_t,  // 0
                                                                   picture as xcb_render_picture_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_REGION: u8 = 10;

pub fn destroy_region<'a>(c     : &'a base::Connection,
                          region: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_destroy_region(c.get_raw_conn(),
                                               region as xcb_xfixes_region_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_region_checked<'a>(c     : &'a base::Connection,
                                  region: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_destroy_region_checked(c.get_raw_conn(),
                                                       region as xcb_xfixes_region_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_REGION: u8 = 11;

pub fn set_region<'a>(c         : &'a base::Connection,
                      region    : Region,
                      rectangles: &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_xfixes_set_region(c.get_raw_conn(),
                                           region as xcb_xfixes_region_t,  // 0
                                           rectangles_len as u32,  // 1
                                           rectangles_ptr as *const xcb_rectangle_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_region_checked<'a>(c         : &'a base::Connection,
                              region    : Region,
                              rectangles: &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_xfixes_set_region_checked(c.get_raw_conn(),
                                                   region as xcb_xfixes_region_t,  // 0
                                                   rectangles_len as u32,  // 1
                                                   rectangles_ptr as *const xcb_rectangle_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COPY_REGION: u8 = 12;

pub fn copy_region<'a>(c          : &'a base::Connection,
                       source     : Region,
                       destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_copy_region(c.get_raw_conn(),
                                            source as xcb_xfixes_region_t,  // 0
                                            destination as xcb_xfixes_region_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn copy_region_checked<'a>(c          : &'a base::Connection,
                               source     : Region,
                               destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_copy_region_checked(c.get_raw_conn(),
                                                    source as xcb_xfixes_region_t,  // 0
                                                    destination as xcb_xfixes_region_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNION_REGION: u8 = 13;

pub fn union_region<'a>(c          : &'a base::Connection,
                        source1    : Region,
                        source2    : Region,
                        destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_union_region(c.get_raw_conn(),
                                             source1 as xcb_xfixes_region_t,  // 0
                                             source2 as xcb_xfixes_region_t,  // 1
                                             destination as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn union_region_checked<'a>(c          : &'a base::Connection,
                                source1    : Region,
                                source2    : Region,
                                destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_union_region_checked(c.get_raw_conn(),
                                                     source1 as xcb_xfixes_region_t,  // 0
                                                     source2 as xcb_xfixes_region_t,  // 1
                                                     destination as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const INTERSECT_REGION: u8 = 14;

pub fn intersect_region<'a>(c          : &'a base::Connection,
                            source1    : Region,
                            source2    : Region,
                            destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_intersect_region(c.get_raw_conn(),
                                                 source1 as xcb_xfixes_region_t,  // 0
                                                 source2 as xcb_xfixes_region_t,  // 1
                                                 destination as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn intersect_region_checked<'a>(c          : &'a base::Connection,
                                    source1    : Region,
                                    source2    : Region,
                                    destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_intersect_region_checked(c.get_raw_conn(),
                                                         source1 as xcb_xfixes_region_t,  // 0
                                                         source2 as xcb_xfixes_region_t,  // 1
                                                         destination as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SUBTRACT_REGION: u8 = 15;

pub fn subtract_region<'a>(c          : &'a base::Connection,
                           source1    : Region,
                           source2    : Region,
                           destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_subtract_region(c.get_raw_conn(),
                                                source1 as xcb_xfixes_region_t,  // 0
                                                source2 as xcb_xfixes_region_t,  // 1
                                                destination as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn subtract_region_checked<'a>(c          : &'a base::Connection,
                                   source1    : Region,
                                   source2    : Region,
                                   destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_subtract_region_checked(c.get_raw_conn(),
                                                        source1 as xcb_xfixes_region_t,  // 0
                                                        source2 as xcb_xfixes_region_t,  // 1
                                                        destination as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const INVERT_REGION: u8 = 16;

pub fn invert_region<'a>(c          : &'a base::Connection,
                         source     : Region,
                         bounds     : xproto::Rectangle,
                         destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_invert_region(c.get_raw_conn(),
                                              source as xcb_xfixes_region_t,  // 0
                                              bounds.base,  // 1
                                              destination as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn invert_region_checked<'a>(c          : &'a base::Connection,
                                 source     : Region,
                                 bounds     : xproto::Rectangle,
                                 destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_invert_region_checked(c.get_raw_conn(),
                                                      source as xcb_xfixes_region_t,  // 0
                                                      bounds.base,  // 1
                                                      destination as xcb_xfixes_region_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const TRANSLATE_REGION: u8 = 17;

pub fn translate_region<'a>(c     : &'a base::Connection,
                            region: Region,
                            dx    : i16,
                            dy    : i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_translate_region(c.get_raw_conn(),
                                                 region as xcb_xfixes_region_t,  // 0
                                                 dx as i16,  // 1
                                                 dy as i16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn translate_region_checked<'a>(c     : &'a base::Connection,
                                    region: Region,
                                    dx    : i16,
                                    dy    : i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_translate_region_checked(c.get_raw_conn(),
                                                         region as xcb_xfixes_region_t,  // 0
                                                         dx as i16,  // 1
                                                         dy as i16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const REGION_EXTENTS: u8 = 18;

pub fn region_extents<'a>(c          : &'a base::Connection,
                          source     : Region,
                          destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_region_extents(c.get_raw_conn(),
                                               source as xcb_xfixes_region_t,  // 0
                                               destination as xcb_xfixes_region_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn region_extents_checked<'a>(c          : &'a base::Connection,
                                  source     : Region,
                                  destination: Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_region_extents_checked(c.get_raw_conn(),
                                                       source as xcb_xfixes_region_t,  // 0
                                                       destination as xcb_xfixes_region_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FETCH_REGION: u8 = 19;

pub type FetchRegionCookie<'a> = base::Cookie<'a, xcb_xfixes_fetch_region_cookie_t>;

impl<'a> FetchRegionCookie<'a> {
    pub fn get_reply(&self) -> Result<FetchRegionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = FetchRegionReply {
                    ptr: xcb_xfixes_fetch_region_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( FetchRegionReply {
                    ptr: xcb_xfixes_fetch_region_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type FetchRegionReply = base::Reply<xcb_xfixes_fetch_region_reply_t>;

impl FetchRegionReply {
    pub fn extents(&self) -> xproto::Rectangle {
        unsafe {
            std::mem::transmute((*self.ptr).extents)
        }
    }
    pub fn rectangles(&self) -> xproto::RectangleIterator {
        unsafe {
            xcb_xfixes_fetch_region_rectangles_iterator(self.ptr)
        }
    }
}

pub fn fetch_region<'a>(c     : &'a base::Connection,
                        region: Region)
        -> FetchRegionCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_fetch_region(c.get_raw_conn(),
                                             region as xcb_xfixes_region_t);  // 0
        FetchRegionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn fetch_region_unchecked<'a>(c     : &'a base::Connection,
                                  region: Region)
        -> FetchRegionCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_fetch_region_unchecked(c.get_raw_conn(),
                                                       region as xcb_xfixes_region_t);  // 0
        FetchRegionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_GC_CLIP_REGION: u8 = 20;

pub fn set_gc_clip_region<'a>(c       : &'a base::Connection,
                              gc      : xproto::Gcontext,
                              region  : Region,
                              x_origin: i16,
                              y_origin: i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_set_gc_clip_region(c.get_raw_conn(),
                                                   gc as xcb_gcontext_t,  // 0
                                                   region as xcb_xfixes_region_t,  // 1
                                                   x_origin as i16,  // 2
                                                   y_origin as i16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_gc_clip_region_checked<'a>(c       : &'a base::Connection,
                                      gc      : xproto::Gcontext,
                                      region  : Region,
                                      x_origin: i16,
                                      y_origin: i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_set_gc_clip_region_checked(c.get_raw_conn(),
                                                           gc as xcb_gcontext_t,  // 0
                                                           region as xcb_xfixes_region_t,  // 1
                                                           x_origin as i16,  // 2
                                                           y_origin as i16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_WINDOW_SHAPE_REGION: u8 = 21;

pub fn set_window_shape_region<'a>(c        : &'a base::Connection,
                                   dest     : xproto::Window,
                                   dest_kind: shape::Kind,
                                   x_offset : i16,
                                   y_offset : i16,
                                   region   : Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_set_window_shape_region(c.get_raw_conn(),
                                                        dest as xcb_window_t,  // 0
                                                        dest_kind as xcb_shape_kind_t,  // 1
                                                        x_offset as i16,  // 2
                                                        y_offset as i16,  // 3
                                                        region as xcb_xfixes_region_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_window_shape_region_checked<'a>(c        : &'a base::Connection,
                                           dest     : xproto::Window,
                                           dest_kind: shape::Kind,
                                           x_offset : i16,
                                           y_offset : i16,
                                           region   : Region)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_set_window_shape_region_checked(c.get_raw_conn(),
                                                                dest as xcb_window_t,  // 0
                                                                dest_kind as xcb_shape_kind_t,  // 1
                                                                x_offset as i16,  // 2
                                                                y_offset as i16,  // 3
                                                                region as xcb_xfixes_region_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_PICTURE_CLIP_REGION: u8 = 22;

pub fn set_picture_clip_region<'a>(c       : &'a base::Connection,
                                   picture : render::Picture,
                                   region  : Region,
                                   x_origin: i16,
                                   y_origin: i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_set_picture_clip_region(c.get_raw_conn(),
                                                        picture as xcb_render_picture_t,  // 0
                                                        region as xcb_xfixes_region_t,  // 1
                                                        x_origin as i16,  // 2
                                                        y_origin as i16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_picture_clip_region_checked<'a>(c       : &'a base::Connection,
                                           picture : render::Picture,
                                           region  : Region,
                                           x_origin: i16,
                                           y_origin: i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_set_picture_clip_region_checked(c.get_raw_conn(),
                                                                picture as xcb_render_picture_t,  // 0
                                                                region as xcb_xfixes_region_t,  // 1
                                                                x_origin as i16,  // 2
                                                                y_origin as i16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_CURSOR_NAME: u8 = 23;

pub fn set_cursor_name<'a>(c     : &'a base::Connection,
                           cursor: xproto::Cursor,
                           name  : &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_xfixes_set_cursor_name(c.get_raw_conn(),
                                                cursor as xcb_cursor_t,  // 0
                                                name_len as u16,  // 1
                                                name_ptr as *const c_char);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_cursor_name_checked<'a>(c     : &'a base::Connection,
                                   cursor: xproto::Cursor,
                                   name  : &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_xfixes_set_cursor_name_checked(c.get_raw_conn(),
                                                        cursor as xcb_cursor_t,  // 0
                                                        name_len as u16,  // 1
                                                        name_ptr as *const c_char);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_CURSOR_NAME: u8 = 24;

pub type GetCursorNameCookie<'a> = base::Cookie<'a, xcb_xfixes_get_cursor_name_cookie_t>;

impl<'a> GetCursorNameCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCursorNameReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCursorNameReply {
                    ptr: xcb_xfixes_get_cursor_name_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCursorNameReply {
                    ptr: xcb_xfixes_get_cursor_name_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCursorNameReply = base::Reply<xcb_xfixes_get_cursor_name_reply_t>;

impl GetCursorNameReply {
    pub fn atom(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).atom
        }
    }
    pub fn nbytes(&self) -> u16 {
        unsafe {
            (*self.ptr).nbytes
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xfixes_get_cursor_name_name_length(field) as usize;
            let data = xcb_xfixes_get_cursor_name_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_cursor_name<'a>(c     : &'a base::Connection,
                           cursor: xproto::Cursor)
        -> GetCursorNameCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_get_cursor_name(c.get_raw_conn(),
                                                cursor as xcb_cursor_t);  // 0
        GetCursorNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_cursor_name_unchecked<'a>(c     : &'a base::Connection,
                                     cursor: xproto::Cursor)
        -> GetCursorNameCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_get_cursor_name_unchecked(c.get_raw_conn(),
                                                          cursor as xcb_cursor_t);  // 0
        GetCursorNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_CURSOR_IMAGE_AND_NAME: u8 = 25;

pub type GetCursorImageAndNameCookie<'a> = base::Cookie<'a, xcb_xfixes_get_cursor_image_and_name_cookie_t>;

impl<'a> GetCursorImageAndNameCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCursorImageAndNameReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCursorImageAndNameReply {
                    ptr: xcb_xfixes_get_cursor_image_and_name_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCursorImageAndNameReply {
                    ptr: xcb_xfixes_get_cursor_image_and_name_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCursorImageAndNameReply = base::Reply<xcb_xfixes_get_cursor_image_and_name_reply_t>;

impl GetCursorImageAndNameReply {
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
    pub fn xhot(&self) -> u16 {
        unsafe {
            (*self.ptr).xhot
        }
    }
    pub fn yhot(&self) -> u16 {
        unsafe {
            (*self.ptr).yhot
        }
    }
    pub fn cursor_serial(&self) -> u32 {
        unsafe {
            (*self.ptr).cursor_serial
        }
    }
    pub fn cursor_atom(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).cursor_atom
        }
    }
    pub fn nbytes(&self) -> u16 {
        unsafe {
            (*self.ptr).nbytes
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xfixes_get_cursor_image_and_name_name_length(field) as usize;
            let data = xcb_xfixes_get_cursor_image_and_name_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn cursor_image(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xfixes_get_cursor_image_and_name_cursor_image_length(field) as usize;
            let data = xcb_xfixes_get_cursor_image_and_name_cursor_image(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_cursor_image_and_name<'a>(c: &'a base::Connection)
        -> GetCursorImageAndNameCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_get_cursor_image_and_name(c.get_raw_conn());
        GetCursorImageAndNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_cursor_image_and_name_unchecked<'a>(c: &'a base::Connection)
        -> GetCursorImageAndNameCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_get_cursor_image_and_name_unchecked(c.get_raw_conn());
        GetCursorImageAndNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_CURSOR: u8 = 26;

pub fn change_cursor<'a>(c          : &'a base::Connection,
                         source     : xproto::Cursor,
                         destination: xproto::Cursor)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_change_cursor(c.get_raw_conn(),
                                              source as xcb_cursor_t,  // 0
                                              destination as xcb_cursor_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_cursor_checked<'a>(c          : &'a base::Connection,
                                 source     : xproto::Cursor,
                                 destination: xproto::Cursor)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_change_cursor_checked(c.get_raw_conn(),
                                                      source as xcb_cursor_t,  // 0
                                                      destination as xcb_cursor_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_CURSOR_BY_NAME: u8 = 27;

pub fn change_cursor_by_name<'a>(c   : &'a base::Connection,
                                 src : xproto::Cursor,
                                 name: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_xfixes_change_cursor_by_name(c.get_raw_conn(),
                                                      src as xcb_cursor_t,  // 0
                                                      name_len as u16,  // 1
                                                      name_ptr as *const c_char);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_cursor_by_name_checked<'a>(c   : &'a base::Connection,
                                         src : xproto::Cursor,
                                         name: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_xfixes_change_cursor_by_name_checked(c.get_raw_conn(),
                                                              src as xcb_cursor_t,  // 0
                                                              name_len as u16,  // 1
                                                              name_ptr as *const c_char);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const EXPAND_REGION: u8 = 28;

pub fn expand_region<'a>(c          : &'a base::Connection,
                         source     : Region,
                         destination: Region,
                         left       : u16,
                         right      : u16,
                         top        : u16,
                         bottom     : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_expand_region(c.get_raw_conn(),
                                              source as xcb_xfixes_region_t,  // 0
                                              destination as xcb_xfixes_region_t,  // 1
                                              left as u16,  // 2
                                              right as u16,  // 3
                                              top as u16,  // 4
                                              bottom as u16);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn expand_region_checked<'a>(c          : &'a base::Connection,
                                 source     : Region,
                                 destination: Region,
                                 left       : u16,
                                 right      : u16,
                                 top        : u16,
                                 bottom     : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_expand_region_checked(c.get_raw_conn(),
                                                      source as xcb_xfixes_region_t,  // 0
                                                      destination as xcb_xfixes_region_t,  // 1
                                                      left as u16,  // 2
                                                      right as u16,  // 3
                                                      top as u16,  // 4
                                                      bottom as u16);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const HIDE_CURSOR: u8 = 29;

pub fn hide_cursor<'a>(c     : &'a base::Connection,
                       window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_hide_cursor(c.get_raw_conn(),
                                            window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn hide_cursor_checked<'a>(c     : &'a base::Connection,
                               window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_hide_cursor_checked(c.get_raw_conn(),
                                                    window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SHOW_CURSOR: u8 = 30;

pub fn show_cursor<'a>(c     : &'a base::Connection,
                       window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_show_cursor(c.get_raw_conn(),
                                            window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn show_cursor_checked<'a>(c     : &'a base::Connection,
                               window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_show_cursor_checked(c.get_raw_conn(),
                                                    window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_POINTER_BARRIER: u8 = 31;

pub fn create_pointer_barrier<'a>(c         : &'a base::Connection,
                                  barrier   : Barrier,
                                  window    : xproto::Window,
                                  x1        : u16,
                                  y1        : u16,
                                  x2        : u16,
                                  y2        : u16,
                                  directions: u32,
                                  devices   : &[u16])
        -> base::VoidCookie<'a> {
    unsafe {
        let devices_len = devices.len();
        let devices_ptr = devices.as_ptr();
        let cookie = xcb_xfixes_create_pointer_barrier(c.get_raw_conn(),
                                                       barrier as xcb_xfixes_barrier_t,  // 0
                                                       window as xcb_window_t,  // 1
                                                       x1 as u16,  // 2
                                                       y1 as u16,  // 3
                                                       x2 as u16,  // 4
                                                       y2 as u16,  // 5
                                                       directions as u32,  // 6
                                                       devices_len as u16,  // 7
                                                       devices_ptr as *const u16);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_pointer_barrier_checked<'a>(c         : &'a base::Connection,
                                          barrier   : Barrier,
                                          window    : xproto::Window,
                                          x1        : u16,
                                          y1        : u16,
                                          x2        : u16,
                                          y2        : u16,
                                          directions: u32,
                                          devices   : &[u16])
        -> base::VoidCookie<'a> {
    unsafe {
        let devices_len = devices.len();
        let devices_ptr = devices.as_ptr();
        let cookie = xcb_xfixes_create_pointer_barrier_checked(c.get_raw_conn(),
                                                               barrier as xcb_xfixes_barrier_t,  // 0
                                                               window as xcb_window_t,  // 1
                                                               x1 as u16,  // 2
                                                               y1 as u16,  // 3
                                                               x2 as u16,  // 4
                                                               y2 as u16,  // 5
                                                               directions as u32,  // 6
                                                               devices_len as u16,  // 7
                                                               devices_ptr as *const u16);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_POINTER_BARRIER: u8 = 32;

pub fn delete_pointer_barrier<'a>(c      : &'a base::Connection,
                                  barrier: Barrier)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_delete_pointer_barrier(c.get_raw_conn(),
                                                       barrier as xcb_xfixes_barrier_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_pointer_barrier_checked<'a>(c      : &'a base::Connection,
                                          barrier: Barrier)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xfixes_delete_pointer_barrier_checked(c.get_raw_conn(),
                                                               barrier as xcb_xfixes_barrier_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}
