// Generated automatically from shape.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::shape::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_shape_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 1;

pub type Op = xcb_shape_op_t;

pub type Kind = xcb_shape_kind_t;

pub type So = u32;
pub const SO_SET      : So = 0x00;
pub const SO_UNION    : So = 0x01;
pub const SO_INTERSECT: So = 0x02;
pub const SO_SUBTRACT : So = 0x03;
pub const SO_INVERT   : So = 0x04;

pub type Sk = u32;
pub const SK_BOUNDING: Sk = 0x00;
pub const SK_CLIP    : Sk = 0x01;
pub const SK_INPUT   : Sk = 0x02;



pub const NOTIFY: u8 = 0;

pub type NotifyEvent = base::Event<xcb_shape_notify_event_t>;

impl NotifyEvent {
    pub fn shape_kind(&self) -> Kind {
        unsafe {
            (*self.ptr).shape_kind
        }
    }
    pub fn affected_window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).affected_window
        }
    }
    pub fn extents_x(&self) -> i16 {
        unsafe {
            (*self.ptr).extents_x
        }
    }
    pub fn extents_y(&self) -> i16 {
        unsafe {
            (*self.ptr).extents_y
        }
    }
    pub fn extents_width(&self) -> u16 {
        unsafe {
            (*self.ptr).extents_width
        }
    }
    pub fn extents_height(&self) -> u16 {
        unsafe {
            (*self.ptr).extents_height
        }
    }
    pub fn server_time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).server_time
        }
    }
    pub fn shaped(&self) -> bool {
        unsafe {
            (*self.ptr).shaped != 0
        }
    }
    /// Constructs a new NotifyEvent
    /// `response_type` will be set automatically to NOTIFY
    pub fn new(shape_kind: Kind,
               affected_window: xproto::Window,
               extents_x: i16,
               extents_y: i16,
               extents_width: u16,
               extents_height: u16,
               server_time: xproto::Timestamp,
               shaped: bool)
            -> NotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_shape_notify_event_t;
            (*raw).response_type = NOTIFY;
            (*raw).shape_kind = shape_kind;
            (*raw).affected_window = affected_window;
            (*raw).extents_x = extents_x;
            (*raw).extents_y = extents_y;
            (*raw).extents_width = extents_width;
            (*raw).extents_height = extents_height;
            (*raw).server_time = server_time;
            (*raw).shaped = if shaped { 1 } else { 0 };
            NotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_shape_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_shape_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_shape_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_shape_query_version_reply_t>;

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

pub fn query_version<'a>(c: &'a base::Connection)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_shape_query_version(c.get_raw_conn());
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c: &'a base::Connection)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_shape_query_version_unchecked(c.get_raw_conn());
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const RECTANGLES: u8 = 1;

pub fn rectangles<'a>(c                 : &'a base::Connection,
                      operation         : Op,
                      destination_kind  : Kind,
                      ordering          : u8,
                      destination_window: xproto::Window,
                      x_offset          : i16,
                      y_offset          : i16,
                      rectangles        : &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_shape_rectangles(c.get_raw_conn(),
                                          operation as xcb_shape_op_t,  // 0
                                          destination_kind as xcb_shape_kind_t,  // 1
                                          ordering as u8,  // 2
                                          destination_window as xcb_window_t,  // 3
                                          x_offset as i16,  // 4
                                          y_offset as i16,  // 5
                                          rectangles_len as u32,  // 6
                                          rectangles_ptr as *const xcb_rectangle_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn rectangles_checked<'a>(c                 : &'a base::Connection,
                              operation         : Op,
                              destination_kind  : Kind,
                              ordering          : u8,
                              destination_window: xproto::Window,
                              x_offset          : i16,
                              y_offset          : i16,
                              rectangles        : &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_shape_rectangles_checked(c.get_raw_conn(),
                                                  operation as xcb_shape_op_t,  // 0
                                                  destination_kind as xcb_shape_kind_t,  // 1
                                                  ordering as u8,  // 2
                                                  destination_window as xcb_window_t,  // 3
                                                  x_offset as i16,  // 4
                                                  y_offset as i16,  // 5
                                                  rectangles_len as u32,  // 6
                                                  rectangles_ptr as *const xcb_rectangle_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const MASK: u8 = 2;

pub fn mask<'a>(c                 : &'a base::Connection,
                operation         : Op,
                destination_kind  : Kind,
                destination_window: xproto::Window,
                x_offset          : i16,
                y_offset          : i16,
                source_bitmap     : xproto::Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shape_mask(c.get_raw_conn(),
                                    operation as xcb_shape_op_t,  // 0
                                    destination_kind as xcb_shape_kind_t,  // 1
                                    destination_window as xcb_window_t,  // 2
                                    x_offset as i16,  // 3
                                    y_offset as i16,  // 4
                                    source_bitmap as xcb_pixmap_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn mask_checked<'a>(c                 : &'a base::Connection,
                        operation         : Op,
                        destination_kind  : Kind,
                        destination_window: xproto::Window,
                        x_offset          : i16,
                        y_offset          : i16,
                        source_bitmap     : xproto::Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shape_mask_checked(c.get_raw_conn(),
                                            operation as xcb_shape_op_t,  // 0
                                            destination_kind as xcb_shape_kind_t,  // 1
                                            destination_window as xcb_window_t,  // 2
                                            x_offset as i16,  // 3
                                            y_offset as i16,  // 4
                                            source_bitmap as xcb_pixmap_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COMBINE: u8 = 3;

pub fn combine<'a>(c                 : &'a base::Connection,
                   operation         : Op,
                   destination_kind  : Kind,
                   source_kind       : Kind,
                   destination_window: xproto::Window,
                   x_offset          : i16,
                   y_offset          : i16,
                   source_window     : xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shape_combine(c.get_raw_conn(),
                                       operation as xcb_shape_op_t,  // 0
                                       destination_kind as xcb_shape_kind_t,  // 1
                                       source_kind as xcb_shape_kind_t,  // 2
                                       destination_window as xcb_window_t,  // 3
                                       x_offset as i16,  // 4
                                       y_offset as i16,  // 5
                                       source_window as xcb_window_t);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn combine_checked<'a>(c                 : &'a base::Connection,
                           operation         : Op,
                           destination_kind  : Kind,
                           source_kind       : Kind,
                           destination_window: xproto::Window,
                           x_offset          : i16,
                           y_offset          : i16,
                           source_window     : xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shape_combine_checked(c.get_raw_conn(),
                                               operation as xcb_shape_op_t,  // 0
                                               destination_kind as xcb_shape_kind_t,  // 1
                                               source_kind as xcb_shape_kind_t,  // 2
                                               destination_window as xcb_window_t,  // 3
                                               x_offset as i16,  // 4
                                               y_offset as i16,  // 5
                                               source_window as xcb_window_t);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const OFFSET: u8 = 4;

pub fn offset<'a>(c                 : &'a base::Connection,
                  destination_kind  : Kind,
                  destination_window: xproto::Window,
                  x_offset          : i16,
                  y_offset          : i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shape_offset(c.get_raw_conn(),
                                      destination_kind as xcb_shape_kind_t,  // 0
                                      destination_window as xcb_window_t,  // 1
                                      x_offset as i16,  // 2
                                      y_offset as i16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn offset_checked<'a>(c                 : &'a base::Connection,
                          destination_kind  : Kind,
                          destination_window: xproto::Window,
                          x_offset          : i16,
                          y_offset          : i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shape_offset_checked(c.get_raw_conn(),
                                              destination_kind as xcb_shape_kind_t,  // 0
                                              destination_window as xcb_window_t,  // 1
                                              x_offset as i16,  // 2
                                              y_offset as i16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_EXTENTS: u8 = 5;

pub type QueryExtentsCookie<'a> = base::Cookie<'a, xcb_shape_query_extents_cookie_t>;

impl<'a> QueryExtentsCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryExtentsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryExtentsReply {
                    ptr: xcb_shape_query_extents_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryExtentsReply {
                    ptr: xcb_shape_query_extents_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryExtentsReply = base::Reply<xcb_shape_query_extents_reply_t>;

impl QueryExtentsReply {
    pub fn bounding_shaped(&self) -> bool {
        unsafe {
            (*self.ptr).bounding_shaped != 0
        }
    }
    pub fn clip_shaped(&self) -> bool {
        unsafe {
            (*self.ptr).clip_shaped != 0
        }
    }
    pub fn bounding_shape_extents_x(&self) -> i16 {
        unsafe {
            (*self.ptr).bounding_shape_extents_x
        }
    }
    pub fn bounding_shape_extents_y(&self) -> i16 {
        unsafe {
            (*self.ptr).bounding_shape_extents_y
        }
    }
    pub fn bounding_shape_extents_width(&self) -> u16 {
        unsafe {
            (*self.ptr).bounding_shape_extents_width
        }
    }
    pub fn bounding_shape_extents_height(&self) -> u16 {
        unsafe {
            (*self.ptr).bounding_shape_extents_height
        }
    }
    pub fn clip_shape_extents_x(&self) -> i16 {
        unsafe {
            (*self.ptr).clip_shape_extents_x
        }
    }
    pub fn clip_shape_extents_y(&self) -> i16 {
        unsafe {
            (*self.ptr).clip_shape_extents_y
        }
    }
    pub fn clip_shape_extents_width(&self) -> u16 {
        unsafe {
            (*self.ptr).clip_shape_extents_width
        }
    }
    pub fn clip_shape_extents_height(&self) -> u16 {
        unsafe {
            (*self.ptr).clip_shape_extents_height
        }
    }
}

pub fn query_extents<'a>(c                 : &'a base::Connection,
                         destination_window: xproto::Window)
        -> QueryExtentsCookie<'a> {
    unsafe {
        let cookie = xcb_shape_query_extents(c.get_raw_conn(),
                                             destination_window as xcb_window_t);  // 0
        QueryExtentsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_extents_unchecked<'a>(c                 : &'a base::Connection,
                                   destination_window: xproto::Window)
        -> QueryExtentsCookie<'a> {
    unsafe {
        let cookie = xcb_shape_query_extents_unchecked(c.get_raw_conn(),
                                                       destination_window as xcb_window_t);  // 0
        QueryExtentsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SELECT_INPUT: u8 = 6;

pub fn select_input<'a>(c                 : &'a base::Connection,
                        destination_window: xproto::Window,
                        enable            : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shape_select_input(c.get_raw_conn(),
                                            destination_window as xcb_window_t,  // 0
                                            enable as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_input_checked<'a>(c                 : &'a base::Connection,
                                destination_window: xproto::Window,
                                enable            : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shape_select_input_checked(c.get_raw_conn(),
                                                    destination_window as xcb_window_t,  // 0
                                                    enable as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const INPUT_SELECTED: u8 = 7;

pub type InputSelectedCookie<'a> = base::Cookie<'a, xcb_shape_input_selected_cookie_t>;

impl<'a> InputSelectedCookie<'a> {
    pub fn get_reply(&self) -> Result<InputSelectedReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = InputSelectedReply {
                    ptr: xcb_shape_input_selected_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( InputSelectedReply {
                    ptr: xcb_shape_input_selected_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type InputSelectedReply = base::Reply<xcb_shape_input_selected_reply_t>;

impl InputSelectedReply {
    pub fn enabled(&self) -> bool {
        unsafe {
            (*self.ptr).enabled != 0
        }
    }
}

pub fn input_selected<'a>(c                 : &'a base::Connection,
                          destination_window: xproto::Window)
        -> InputSelectedCookie<'a> {
    unsafe {
        let cookie = xcb_shape_input_selected(c.get_raw_conn(),
                                              destination_window as xcb_window_t);  // 0
        InputSelectedCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn input_selected_unchecked<'a>(c                 : &'a base::Connection,
                                    destination_window: xproto::Window)
        -> InputSelectedCookie<'a> {
    unsafe {
        let cookie = xcb_shape_input_selected_unchecked(c.get_raw_conn(),
                                                        destination_window as xcb_window_t);  // 0
        InputSelectedCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_RECTANGLES: u8 = 8;

pub type GetRectanglesCookie<'a> = base::Cookie<'a, xcb_shape_get_rectangles_cookie_t>;

impl<'a> GetRectanglesCookie<'a> {
    pub fn get_reply(&self) -> Result<GetRectanglesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetRectanglesReply {
                    ptr: xcb_shape_get_rectangles_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetRectanglesReply {
                    ptr: xcb_shape_get_rectangles_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetRectanglesReply = base::Reply<xcb_shape_get_rectangles_reply_t>;

impl GetRectanglesReply {
    pub fn ordering(&self) -> u8 {
        unsafe {
            (*self.ptr).ordering
        }
    }
    pub fn rectangles_len(&self) -> u32 {
        unsafe {
            (*self.ptr).rectangles_len
        }
    }
    pub fn rectangles(&self) -> xproto::RectangleIterator {
        unsafe {
            xcb_shape_get_rectangles_rectangles_iterator(self.ptr)
        }
    }
}

pub fn get_rectangles<'a>(c          : &'a base::Connection,
                          window     : xproto::Window,
                          source_kind: Kind)
        -> GetRectanglesCookie<'a> {
    unsafe {
        let cookie = xcb_shape_get_rectangles(c.get_raw_conn(),
                                              window as xcb_window_t,  // 0
                                              source_kind as xcb_shape_kind_t);  // 1
        GetRectanglesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_rectangles_unchecked<'a>(c          : &'a base::Connection,
                                    window     : xproto::Window,
                                    source_kind: Kind)
        -> GetRectanglesCookie<'a> {
    unsafe {
        let cookie = xcb_shape_get_rectangles_unchecked(c.get_raw_conn(),
                                                        window as xcb_window_t,  // 0
                                                        source_kind as xcb_shape_kind_t);  // 1
        GetRectanglesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
