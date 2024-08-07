// Generated automatically from dri2.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::dri2::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_dri2_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 4;

pub type Attachment = u32;
pub const ATTACHMENT_BUFFER_FRONT_LEFT      : Attachment = 0x00;
pub const ATTACHMENT_BUFFER_BACK_LEFT       : Attachment = 0x01;
pub const ATTACHMENT_BUFFER_FRONT_RIGHT     : Attachment = 0x02;
pub const ATTACHMENT_BUFFER_BACK_RIGHT      : Attachment = 0x03;
pub const ATTACHMENT_BUFFER_DEPTH           : Attachment = 0x04;
pub const ATTACHMENT_BUFFER_STENCIL         : Attachment = 0x05;
pub const ATTACHMENT_BUFFER_ACCUM           : Attachment = 0x06;
pub const ATTACHMENT_BUFFER_FAKE_FRONT_LEFT : Attachment = 0x07;
pub const ATTACHMENT_BUFFER_FAKE_FRONT_RIGHT: Attachment = 0x08;
pub const ATTACHMENT_BUFFER_DEPTH_STENCIL   : Attachment = 0x09;
pub const ATTACHMENT_BUFFER_HIZ             : Attachment = 0x0a;

pub type DriverType = u32;
pub const DRIVER_TYPE_DRI  : DriverType = 0x00;
pub const DRIVER_TYPE_VDPAU: DriverType = 0x01;

pub type EventType = u32;
pub const EVENT_TYPE_EXCHANGE_COMPLETE: EventType = 0x01;
pub const EVENT_TYPE_BLIT_COMPLETE    : EventType = 0x02;
pub const EVENT_TYPE_FLIP_COMPLETE    : EventType = 0x03;



#[derive(Copy, Clone)]
pub struct Dri2Buffer {
    pub base: xcb_dri2_dri2_buffer_t,
}

impl Dri2Buffer {
    #[allow(unused_unsafe)]
    pub fn new(attachment: u32,
               name:       u32,
               pitch:      u32,
               cpp:        u32,
               flags:      u32)
            -> Dri2Buffer {
        unsafe {
            Dri2Buffer {
                base: xcb_dri2_dri2_buffer_t {
                    attachment: attachment,
                    name:       name,
                    pitch:      pitch,
                    cpp:        cpp,
                    flags:      flags,
                }
            }
        }
    }
    pub fn attachment(&self) -> u32 {
        unsafe {
            self.base.attachment
        }
    }
    pub fn name(&self) -> u32 {
        unsafe {
            self.base.name
        }
    }
    pub fn pitch(&self) -> u32 {
        unsafe {
            self.base.pitch
        }
    }
    pub fn cpp(&self) -> u32 {
        unsafe {
            self.base.cpp
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            self.base.flags
        }
    }
}

pub type Dri2BufferIterator = xcb_dri2_dri2_buffer_iterator_t;

impl Iterator for Dri2BufferIterator {
    type Item = Dri2Buffer;
    fn next(&mut self) -> std::option::Option<Dri2Buffer> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_dri2_dri2_buffer_iterator_t;
                let data = (*iter).data;
                xcb_dri2_dri2_buffer_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct AttachFormat {
    pub base: xcb_dri2_attach_format_t,
}

impl AttachFormat {
    #[allow(unused_unsafe)]
    pub fn new(attachment: u32,
               format:     u32)
            -> AttachFormat {
        unsafe {
            AttachFormat {
                base: xcb_dri2_attach_format_t {
                    attachment: attachment,
                    format:     format,
                }
            }
        }
    }
    pub fn attachment(&self) -> u32 {
        unsafe {
            self.base.attachment
        }
    }
    pub fn format(&self) -> u32 {
        unsafe {
            self.base.format
        }
    }
}

pub type AttachFormatIterator = xcb_dri2_attach_format_iterator_t;

impl Iterator for AttachFormatIterator {
    type Item = AttachFormat;
    fn next(&mut self) -> std::option::Option<AttachFormat> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_dri2_attach_format_iterator_t;
                let data = (*iter).data;
                xcb_dri2_attach_format_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_dri2_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_dri2_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_dri2_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_dri2_query_version_reply_t>;

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
        let cookie = xcb_dri2_query_version(c.get_raw_conn(),
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
        let cookie = xcb_dri2_query_version_unchecked(c.get_raw_conn(),
                                                      major_version as u32,  // 0
                                                      minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CONNECT: u8 = 1;

pub type ConnectCookie<'a> = base::Cookie<'a, xcb_dri2_connect_cookie_t>;

impl<'a> ConnectCookie<'a> {
    pub fn get_reply(&self) -> Result<ConnectReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ConnectReply {
                    ptr: xcb_dri2_connect_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ConnectReply {
                    ptr: xcb_dri2_connect_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ConnectReply = base::Reply<xcb_dri2_connect_reply_t>;

impl ConnectReply {
    pub fn driver_name_length(&self) -> u32 {
        unsafe {
            (*self.ptr).driver_name_length
        }
    }
    pub fn device_name_length(&self) -> u32 {
        unsafe {
            (*self.ptr).device_name_length
        }
    }
    pub fn driver_name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_dri2_connect_driver_name_length(field) as usize;
            let data = xcb_dri2_connect_driver_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn alignment_pad<T>(&self) -> &[T] {
        unsafe {
            let field = self.ptr;
            let len = xcb_dri2_connect_alignment_pad_length(field) as usize;
            let data = xcb_dri2_connect_alignment_pad(field);
            debug_assert_eq!(len % std::mem::size_of::<T>(), 0);
            std::slice::from_raw_parts(data as *const T, len / std::mem::size_of::<T>())
        }
    }
    pub fn device_name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_dri2_connect_device_name_length(field) as usize;
            let data = xcb_dri2_connect_device_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn connect<'a>(c          : &'a base::Connection,
                   window     : xproto::Window,
                   driver_type: u32)
        -> ConnectCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_connect(c.get_raw_conn(),
                                      window as xcb_window_t,  // 0
                                      driver_type as u32);  // 1
        ConnectCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn connect_unchecked<'a>(c          : &'a base::Connection,
                             window     : xproto::Window,
                             driver_type: u32)
        -> ConnectCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_connect_unchecked(c.get_raw_conn(),
                                                window as xcb_window_t,  // 0
                                                driver_type as u32);  // 1
        ConnectCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const AUTHENTICATE: u8 = 2;

pub type AuthenticateCookie<'a> = base::Cookie<'a, xcb_dri2_authenticate_cookie_t>;

impl<'a> AuthenticateCookie<'a> {
    pub fn get_reply(&self) -> Result<AuthenticateReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = AuthenticateReply {
                    ptr: xcb_dri2_authenticate_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( AuthenticateReply {
                    ptr: xcb_dri2_authenticate_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type AuthenticateReply = base::Reply<xcb_dri2_authenticate_reply_t>;

impl AuthenticateReply {
    pub fn authenticated(&self) -> u32 {
        unsafe {
            (*self.ptr).authenticated
        }
    }
}

pub fn authenticate<'a>(c     : &'a base::Connection,
                        window: xproto::Window,
                        magic : u32)
        -> AuthenticateCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_authenticate(c.get_raw_conn(),
                                           window as xcb_window_t,  // 0
                                           magic as u32);  // 1
        AuthenticateCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn authenticate_unchecked<'a>(c     : &'a base::Connection,
                                  window: xproto::Window,
                                  magic : u32)
        -> AuthenticateCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_authenticate_unchecked(c.get_raw_conn(),
                                                     window as xcb_window_t,  // 0
                                                     magic as u32);  // 1
        AuthenticateCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_DRAWABLE: u8 = 3;

pub fn create_drawable<'a>(c       : &'a base::Connection,
                           drawable: xproto::Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_create_drawable(c.get_raw_conn(),
                                              drawable as xcb_drawable_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_drawable_checked<'a>(c       : &'a base::Connection,
                                   drawable: xproto::Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_create_drawable_checked(c.get_raw_conn(),
                                                      drawable as xcb_drawable_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_DRAWABLE: u8 = 4;

pub fn destroy_drawable<'a>(c       : &'a base::Connection,
                            drawable: xproto::Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_destroy_drawable(c.get_raw_conn(),
                                               drawable as xcb_drawable_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_drawable_checked<'a>(c       : &'a base::Connection,
                                    drawable: xproto::Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_destroy_drawable_checked(c.get_raw_conn(),
                                                       drawable as xcb_drawable_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_BUFFERS: u8 = 5;

pub type GetBuffersCookie<'a> = base::Cookie<'a, xcb_dri2_get_buffers_cookie_t>;

impl<'a> GetBuffersCookie<'a> {
    pub fn get_reply(&self) -> Result<GetBuffersReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetBuffersReply {
                    ptr: xcb_dri2_get_buffers_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetBuffersReply {
                    ptr: xcb_dri2_get_buffers_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetBuffersReply = base::Reply<xcb_dri2_get_buffers_reply_t>;

impl GetBuffersReply {
    pub fn width(&self) -> u32 {
        unsafe {
            (*self.ptr).width
        }
    }
    pub fn height(&self) -> u32 {
        unsafe {
            (*self.ptr).height
        }
    }
    pub fn count(&self) -> u32 {
        unsafe {
            (*self.ptr).count
        }
    }
    pub fn buffers(&self) -> Dri2BufferIterator {
        unsafe {
            xcb_dri2_get_buffers_buffers_iterator(self.ptr)
        }
    }
}

pub fn get_buffers<'a>(c          : &'a base::Connection,
                       drawable   : xproto::Drawable,
                       count      : u32,
                       attachments: &[u32])
        -> GetBuffersCookie<'a> {
    unsafe {
        let attachments_len = attachments.len();
        let attachments_ptr = attachments.as_ptr();
        let cookie = xcb_dri2_get_buffers(c.get_raw_conn(),
                                          drawable as xcb_drawable_t,  // 0
                                          count as u32,  // 1
                                          attachments_len as u32,  // 2
                                          attachments_ptr as *const u32);  // 3
        GetBuffersCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_buffers_unchecked<'a>(c          : &'a base::Connection,
                                 drawable   : xproto::Drawable,
                                 count      : u32,
                                 attachments: &[u32])
        -> GetBuffersCookie<'a> {
    unsafe {
        let attachments_len = attachments.len();
        let attachments_ptr = attachments.as_ptr();
        let cookie = xcb_dri2_get_buffers_unchecked(c.get_raw_conn(),
                                                    drawable as xcb_drawable_t,  // 0
                                                    count as u32,  // 1
                                                    attachments_len as u32,  // 2
                                                    attachments_ptr as *const u32);  // 3
        GetBuffersCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const COPY_REGION: u8 = 6;

pub type CopyRegionCookie<'a> = base::Cookie<'a, xcb_dri2_copy_region_cookie_t>;

impl<'a> CopyRegionCookie<'a> {
    pub fn get_reply(&self) -> Result<CopyRegionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CopyRegionReply {
                    ptr: xcb_dri2_copy_region_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CopyRegionReply {
                    ptr: xcb_dri2_copy_region_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CopyRegionReply = base::Reply<xcb_dri2_copy_region_reply_t>;

impl CopyRegionReply {
}

pub fn copy_region<'a>(c       : &'a base::Connection,
                       drawable: xproto::Drawable,
                       region  : u32,
                       dest    : u32,
                       src     : u32)
        -> CopyRegionCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_copy_region(c.get_raw_conn(),
                                          drawable as xcb_drawable_t,  // 0
                                          region as u32,  // 1
                                          dest as u32,  // 2
                                          src as u32);  // 3
        CopyRegionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn copy_region_unchecked<'a>(c       : &'a base::Connection,
                                 drawable: xproto::Drawable,
                                 region  : u32,
                                 dest    : u32,
                                 src     : u32)
        -> CopyRegionCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_copy_region_unchecked(c.get_raw_conn(),
                                                    drawable as xcb_drawable_t,  // 0
                                                    region as u32,  // 1
                                                    dest as u32,  // 2
                                                    src as u32);  // 3
        CopyRegionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_BUFFERS_WITH_FORMAT: u8 = 7;

pub type GetBuffersWithFormatCookie<'a> = base::Cookie<'a, xcb_dri2_get_buffers_with_format_cookie_t>;

impl<'a> GetBuffersWithFormatCookie<'a> {
    pub fn get_reply(&self) -> Result<GetBuffersWithFormatReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetBuffersWithFormatReply {
                    ptr: xcb_dri2_get_buffers_with_format_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetBuffersWithFormatReply {
                    ptr: xcb_dri2_get_buffers_with_format_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetBuffersWithFormatReply = base::Reply<xcb_dri2_get_buffers_with_format_reply_t>;

impl GetBuffersWithFormatReply {
    pub fn width(&self) -> u32 {
        unsafe {
            (*self.ptr).width
        }
    }
    pub fn height(&self) -> u32 {
        unsafe {
            (*self.ptr).height
        }
    }
    pub fn count(&self) -> u32 {
        unsafe {
            (*self.ptr).count
        }
    }
    pub fn buffers(&self) -> Dri2BufferIterator {
        unsafe {
            xcb_dri2_get_buffers_with_format_buffers_iterator(self.ptr)
        }
    }
}

pub fn get_buffers_with_format<'a>(c          : &'a base::Connection,
                                   drawable   : xproto::Drawable,
                                   count      : u32,
                                   attachments: &[AttachFormat])
        -> GetBuffersWithFormatCookie<'a> {
    unsafe {
        let attachments_len = attachments.len();
        let attachments_ptr = attachments.as_ptr();
        let cookie = xcb_dri2_get_buffers_with_format(c.get_raw_conn(),
                                                      drawable as xcb_drawable_t,  // 0
                                                      count as u32,  // 1
                                                      attachments_len as u32,  // 2
                                                      attachments_ptr as *const xcb_dri2_attach_format_t);  // 3
        GetBuffersWithFormatCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_buffers_with_format_unchecked<'a>(c          : &'a base::Connection,
                                             drawable   : xproto::Drawable,
                                             count      : u32,
                                             attachments: &[AttachFormat])
        -> GetBuffersWithFormatCookie<'a> {
    unsafe {
        let attachments_len = attachments.len();
        let attachments_ptr = attachments.as_ptr();
        let cookie = xcb_dri2_get_buffers_with_format_unchecked(c.get_raw_conn(),
                                                                drawable as xcb_drawable_t,  // 0
                                                                count as u32,  // 1
                                                                attachments_len as u32,  // 2
                                                                attachments_ptr as *const xcb_dri2_attach_format_t);  // 3
        GetBuffersWithFormatCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SWAP_BUFFERS: u8 = 8;

pub type SwapBuffersCookie<'a> = base::Cookie<'a, xcb_dri2_swap_buffers_cookie_t>;

impl<'a> SwapBuffersCookie<'a> {
    pub fn get_reply(&self) -> Result<SwapBuffersReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SwapBuffersReply {
                    ptr: xcb_dri2_swap_buffers_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SwapBuffersReply {
                    ptr: xcb_dri2_swap_buffers_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SwapBuffersReply = base::Reply<xcb_dri2_swap_buffers_reply_t>;

impl SwapBuffersReply {
    pub fn swap_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).swap_hi
        }
    }
    pub fn swap_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).swap_lo
        }
    }
}

pub fn swap_buffers<'a>(c            : &'a base::Connection,
                        drawable     : xproto::Drawable,
                        target_msc_hi: u32,
                        target_msc_lo: u32,
                        divisor_hi   : u32,
                        divisor_lo   : u32,
                        remainder_hi : u32,
                        remainder_lo : u32)
        -> SwapBuffersCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_swap_buffers(c.get_raw_conn(),
                                           drawable as xcb_drawable_t,  // 0
                                           target_msc_hi as u32,  // 1
                                           target_msc_lo as u32,  // 2
                                           divisor_hi as u32,  // 3
                                           divisor_lo as u32,  // 4
                                           remainder_hi as u32,  // 5
                                           remainder_lo as u32);  // 6
        SwapBuffersCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn swap_buffers_unchecked<'a>(c            : &'a base::Connection,
                                  drawable     : xproto::Drawable,
                                  target_msc_hi: u32,
                                  target_msc_lo: u32,
                                  divisor_hi   : u32,
                                  divisor_lo   : u32,
                                  remainder_hi : u32,
                                  remainder_lo : u32)
        -> SwapBuffersCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_swap_buffers_unchecked(c.get_raw_conn(),
                                                     drawable as xcb_drawable_t,  // 0
                                                     target_msc_hi as u32,  // 1
                                                     target_msc_lo as u32,  // 2
                                                     divisor_hi as u32,  // 3
                                                     divisor_lo as u32,  // 4
                                                     remainder_hi as u32,  // 5
                                                     remainder_lo as u32);  // 6
        SwapBuffersCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MSC: u8 = 9;

pub type GetMscCookie<'a> = base::Cookie<'a, xcb_dri2_get_msc_cookie_t>;

impl<'a> GetMscCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMscReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMscReply {
                    ptr: xcb_dri2_get_msc_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMscReply {
                    ptr: xcb_dri2_get_msc_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMscReply = base::Reply<xcb_dri2_get_msc_reply_t>;

impl GetMscReply {
    pub fn ust_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_hi
        }
    }
    pub fn ust_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_lo
        }
    }
    pub fn msc_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_hi
        }
    }
    pub fn msc_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_lo
        }
    }
    pub fn sbc_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).sbc_hi
        }
    }
    pub fn sbc_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).sbc_lo
        }
    }
}

pub fn get_msc<'a>(c       : &'a base::Connection,
                   drawable: xproto::Drawable)
        -> GetMscCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_get_msc(c.get_raw_conn(),
                                      drawable as xcb_drawable_t);  // 0
        GetMscCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_msc_unchecked<'a>(c       : &'a base::Connection,
                             drawable: xproto::Drawable)
        -> GetMscCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_get_msc_unchecked(c.get_raw_conn(),
                                                drawable as xcb_drawable_t);  // 0
        GetMscCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const WAIT_MSC: u8 = 10;

pub type WaitMscCookie<'a> = base::Cookie<'a, xcb_dri2_wait_msc_cookie_t>;

impl<'a> WaitMscCookie<'a> {
    pub fn get_reply(&self) -> Result<WaitMscReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = WaitMscReply {
                    ptr: xcb_dri2_wait_msc_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( WaitMscReply {
                    ptr: xcb_dri2_wait_msc_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type WaitMscReply = base::Reply<xcb_dri2_wait_msc_reply_t>;

impl WaitMscReply {
    pub fn ust_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_hi
        }
    }
    pub fn ust_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_lo
        }
    }
    pub fn msc_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_hi
        }
    }
    pub fn msc_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_lo
        }
    }
    pub fn sbc_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).sbc_hi
        }
    }
    pub fn sbc_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).sbc_lo
        }
    }
}

pub fn wait_msc<'a>(c            : &'a base::Connection,
                    drawable     : xproto::Drawable,
                    target_msc_hi: u32,
                    target_msc_lo: u32,
                    divisor_hi   : u32,
                    divisor_lo   : u32,
                    remainder_hi : u32,
                    remainder_lo : u32)
        -> WaitMscCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_wait_msc(c.get_raw_conn(),
                                       drawable as xcb_drawable_t,  // 0
                                       target_msc_hi as u32,  // 1
                                       target_msc_lo as u32,  // 2
                                       divisor_hi as u32,  // 3
                                       divisor_lo as u32,  // 4
                                       remainder_hi as u32,  // 5
                                       remainder_lo as u32);  // 6
        WaitMscCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn wait_msc_unchecked<'a>(c            : &'a base::Connection,
                              drawable     : xproto::Drawable,
                              target_msc_hi: u32,
                              target_msc_lo: u32,
                              divisor_hi   : u32,
                              divisor_lo   : u32,
                              remainder_hi : u32,
                              remainder_lo : u32)
        -> WaitMscCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_wait_msc_unchecked(c.get_raw_conn(),
                                                 drawable as xcb_drawable_t,  // 0
                                                 target_msc_hi as u32,  // 1
                                                 target_msc_lo as u32,  // 2
                                                 divisor_hi as u32,  // 3
                                                 divisor_lo as u32,  // 4
                                                 remainder_hi as u32,  // 5
                                                 remainder_lo as u32);  // 6
        WaitMscCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const WAIT_SBC: u8 = 11;

pub type WaitSbcCookie<'a> = base::Cookie<'a, xcb_dri2_wait_sbc_cookie_t>;

impl<'a> WaitSbcCookie<'a> {
    pub fn get_reply(&self) -> Result<WaitSbcReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = WaitSbcReply {
                    ptr: xcb_dri2_wait_sbc_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( WaitSbcReply {
                    ptr: xcb_dri2_wait_sbc_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type WaitSbcReply = base::Reply<xcb_dri2_wait_sbc_reply_t>;

impl WaitSbcReply {
    pub fn ust_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_hi
        }
    }
    pub fn ust_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_lo
        }
    }
    pub fn msc_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_hi
        }
    }
    pub fn msc_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_lo
        }
    }
    pub fn sbc_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).sbc_hi
        }
    }
    pub fn sbc_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).sbc_lo
        }
    }
}

pub fn wait_sbc<'a>(c            : &'a base::Connection,
                    drawable     : xproto::Drawable,
                    target_sbc_hi: u32,
                    target_sbc_lo: u32)
        -> WaitSbcCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_wait_sbc(c.get_raw_conn(),
                                       drawable as xcb_drawable_t,  // 0
                                       target_sbc_hi as u32,  // 1
                                       target_sbc_lo as u32);  // 2
        WaitSbcCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn wait_sbc_unchecked<'a>(c            : &'a base::Connection,
                              drawable     : xproto::Drawable,
                              target_sbc_hi: u32,
                              target_sbc_lo: u32)
        -> WaitSbcCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_wait_sbc_unchecked(c.get_raw_conn(),
                                                 drawable as xcb_drawable_t,  // 0
                                                 target_sbc_hi as u32,  // 1
                                                 target_sbc_lo as u32);  // 2
        WaitSbcCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SWAP_INTERVAL: u8 = 12;

pub fn swap_interval<'a>(c       : &'a base::Connection,
                         drawable: xproto::Drawable,
                         interval: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_swap_interval(c.get_raw_conn(),
                                            drawable as xcb_drawable_t,  // 0
                                            interval as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn swap_interval_checked<'a>(c       : &'a base::Connection,
                                 drawable: xproto::Drawable,
                                 interval: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_swap_interval_checked(c.get_raw_conn(),
                                                    drawable as xcb_drawable_t,  // 0
                                                    interval as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_PARAM: u8 = 13;

pub type GetParamCookie<'a> = base::Cookie<'a, xcb_dri2_get_param_cookie_t>;

impl<'a> GetParamCookie<'a> {
    pub fn get_reply(&self) -> Result<GetParamReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetParamReply {
                    ptr: xcb_dri2_get_param_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetParamReply {
                    ptr: xcb_dri2_get_param_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetParamReply = base::Reply<xcb_dri2_get_param_reply_t>;

impl GetParamReply {
    pub fn is_param_recognized(&self) -> bool {
        unsafe {
            (*self.ptr).is_param_recognized != 0
        }
    }
    pub fn value_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).value_hi
        }
    }
    pub fn value_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).value_lo
        }
    }
}

pub fn get_param<'a>(c       : &'a base::Connection,
                     drawable: xproto::Drawable,
                     param   : u32)
        -> GetParamCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_get_param(c.get_raw_conn(),
                                        drawable as xcb_drawable_t,  // 0
                                        param as u32);  // 1
        GetParamCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_param_unchecked<'a>(c       : &'a base::Connection,
                               drawable: xproto::Drawable,
                               param   : u32)
        -> GetParamCookie<'a> {
    unsafe {
        let cookie = xcb_dri2_get_param_unchecked(c.get_raw_conn(),
                                                  drawable as xcb_drawable_t,  // 0
                                                  param as u32);  // 1
        GetParamCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const BUFFER_SWAP_COMPLETE: u8 = 0;

pub type BufferSwapCompleteEvent = base::Event<xcb_dri2_buffer_swap_complete_event_t>;

impl BufferSwapCompleteEvent {
    pub fn event_type(&self) -> u16 {
        unsafe {
            (*self.ptr).event_type
        }
    }
    pub fn drawable(&self) -> xproto::Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    pub fn ust_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_hi
        }
    }
    pub fn ust_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_lo
        }
    }
    pub fn msc_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_hi
        }
    }
    pub fn msc_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_lo
        }
    }
    pub fn sbc(&self) -> u32 {
        unsafe {
            (*self.ptr).sbc
        }
    }
    /// Constructs a new BufferSwapCompleteEvent
    /// `response_type` will be set automatically to BUFFER_SWAP_COMPLETE
    pub fn new(event_type: u16,
               drawable: xproto::Drawable,
               ust_hi: u32,
               ust_lo: u32,
               msc_hi: u32,
               msc_lo: u32,
               sbc: u32)
            -> BufferSwapCompleteEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_dri2_buffer_swap_complete_event_t;
            (*raw).response_type = BUFFER_SWAP_COMPLETE;
            (*raw).event_type = event_type;
            (*raw).drawable = drawable;
            (*raw).ust_hi = ust_hi;
            (*raw).ust_lo = ust_lo;
            (*raw).msc_hi = msc_hi;
            (*raw).msc_lo = msc_lo;
            (*raw).sbc = sbc;
            BufferSwapCompleteEvent {
                ptr: raw
            }
        }
    }
}

pub const INVALIDATE_BUFFERS: u8 = 1;

pub type InvalidateBuffersEvent = base::Event<xcb_dri2_invalidate_buffers_event_t>;

impl InvalidateBuffersEvent {
    pub fn drawable(&self) -> xproto::Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    /// Constructs a new InvalidateBuffersEvent
    /// `response_type` will be set automatically to INVALIDATE_BUFFERS
    pub fn new(drawable: xproto::Drawable)
            -> InvalidateBuffersEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_dri2_invalidate_buffers_event_t;
            (*raw).response_type = INVALIDATE_BUFFERS;
            (*raw).drawable = drawable;
            InvalidateBuffersEvent {
                ptr: raw
            }
        }
    }
}
