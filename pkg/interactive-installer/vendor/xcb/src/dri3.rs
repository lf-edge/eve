// Generated automatically from dri3.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::dri3::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_dri3_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 0;



pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_dri3_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_dri3_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_dri3_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_dri3_query_version_reply_t>;

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
        let cookie = xcb_dri3_query_version(c.get_raw_conn(),
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
        let cookie = xcb_dri3_query_version_unchecked(c.get_raw_conn(),
                                                      major_version as u32,  // 0
                                                      minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const OPEN: u8 = 1;

pub type OpenCookie<'a> = base::Cookie<'a, xcb_dri3_open_cookie_t>;

impl<'a> OpenCookie<'a> {
    pub fn get_reply(&self) -> Result<OpenReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = OpenReply {
                    ptr: xcb_dri3_open_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( OpenReply {
                    ptr: xcb_dri3_open_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type OpenReply = base::Reply<xcb_dri3_open_reply_t>;

impl OpenReply {
    pub fn device_fds(&self, c: &base::Connection) -> &[i32] {
        unsafe {
            let nfd = (*self.ptr).nfd as usize;
            let ptr = xcb_dri3_open_reply_fds(c.get_raw_conn(), self.ptr);

            std::slice::from_raw_parts(ptr, nfd)
        }
    }
}

pub fn open<'a>(c       : &'a base::Connection,
                drawable: xproto::Drawable,
                provider: u32)
        -> OpenCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_open(c.get_raw_conn(),
                                   drawable as xcb_drawable_t,  // 0
                                   provider as u32);  // 1
        OpenCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn open_unchecked<'a>(c       : &'a base::Connection,
                          drawable: xproto::Drawable,
                          provider: u32)
        -> OpenCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_open_unchecked(c.get_raw_conn(),
                                             drawable as xcb_drawable_t,  // 0
                                             provider as u32);  // 1
        OpenCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PIXMAP_FROM_BUFFER: u8 = 2;

pub fn pixmap_from_buffer<'a>(c        : &'a base::Connection,
                              pixmap   : xproto::Pixmap,
                              drawable : xproto::Drawable,
                              size     : u32,
                              width    : u16,
                              height   : u16,
                              stride   : u16,
                              depth    : u8,
                              bpp      : u8,
                              pixmap_fd: i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_pixmap_from_buffer(c.get_raw_conn(),
                                                 pixmap as xcb_pixmap_t,  // 0
                                                 drawable as xcb_drawable_t,  // 1
                                                 size as u32,  // 2
                                                 width as u16,  // 3
                                                 height as u16,  // 4
                                                 stride as u16,  // 5
                                                 depth as u8,  // 6
                                                 bpp as u8,  // 7
                                                 pixmap_fd as i32);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn pixmap_from_buffer_checked<'a>(c        : &'a base::Connection,
                                      pixmap   : xproto::Pixmap,
                                      drawable : xproto::Drawable,
                                      size     : u32,
                                      width    : u16,
                                      height   : u16,
                                      stride   : u16,
                                      depth    : u8,
                                      bpp      : u8,
                                      pixmap_fd: i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_pixmap_from_buffer_checked(c.get_raw_conn(),
                                                         pixmap as xcb_pixmap_t,  // 0
                                                         drawable as xcb_drawable_t,  // 1
                                                         size as u32,  // 2
                                                         width as u16,  // 3
                                                         height as u16,  // 4
                                                         stride as u16,  // 5
                                                         depth as u8,  // 6
                                                         bpp as u8,  // 7
                                                         pixmap_fd as i32);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const BUFFER_FROM_PIXMAP: u8 = 3;

pub type BufferFromPixmapCookie<'a> = base::Cookie<'a, xcb_dri3_buffer_from_pixmap_cookie_t>;

impl<'a> BufferFromPixmapCookie<'a> {
    pub fn get_reply(&self) -> Result<BufferFromPixmapReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = BufferFromPixmapReply {
                    ptr: xcb_dri3_buffer_from_pixmap_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( BufferFromPixmapReply {
                    ptr: xcb_dri3_buffer_from_pixmap_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type BufferFromPixmapReply = base::Reply<xcb_dri3_buffer_from_pixmap_reply_t>;

impl BufferFromPixmapReply {
    pub fn size(&self) -> u32 {
        unsafe {
            (*self.ptr).size
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
    pub fn stride(&self) -> u16 {
        unsafe {
            (*self.ptr).stride
        }
    }
    pub fn depth(&self) -> u8 {
        unsafe {
            (*self.ptr).depth
        }
    }
    pub fn bpp(&self) -> u8 {
        unsafe {
            (*self.ptr).bpp
        }
    }
    pub fn pixmap_fds(&self, c: &base::Connection) -> &[i32] {
        unsafe {
            let nfd = (*self.ptr).nfd as usize;
            let ptr = xcb_dri3_buffer_from_pixmap_reply_fds(c.get_raw_conn(), self.ptr);

            std::slice::from_raw_parts(ptr, nfd)
        }
    }
}

pub fn buffer_from_pixmap<'a>(c     : &'a base::Connection,
                              pixmap: xproto::Pixmap)
        -> BufferFromPixmapCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_buffer_from_pixmap(c.get_raw_conn(),
                                                 pixmap as xcb_pixmap_t);  // 0
        BufferFromPixmapCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn buffer_from_pixmap_unchecked<'a>(c     : &'a base::Connection,
                                        pixmap: xproto::Pixmap)
        -> BufferFromPixmapCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_buffer_from_pixmap_unchecked(c.get_raw_conn(),
                                                           pixmap as xcb_pixmap_t);  // 0
        BufferFromPixmapCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const FENCE_FROM_FD: u8 = 4;

pub fn fence_from_fd<'a>(c                  : &'a base::Connection,
                         drawable           : xproto::Drawable,
                         fence              : u32,
                         initially_triggered: bool,
                         fence_fd           : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_fence_from_fd(c.get_raw_conn(),
                                            drawable as xcb_drawable_t,  // 0
                                            fence as u32,  // 1
                                            initially_triggered as u8,  // 2
                                            fence_fd as i32);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn fence_from_fd_checked<'a>(c                  : &'a base::Connection,
                                 drawable           : xproto::Drawable,
                                 fence              : u32,
                                 initially_triggered: bool,
                                 fence_fd           : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_fence_from_fd_checked(c.get_raw_conn(),
                                                    drawable as xcb_drawable_t,  // 0
                                                    fence as u32,  // 1
                                                    initially_triggered as u8,  // 2
                                                    fence_fd as i32);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FD_FROM_FENCE: u8 = 5;

pub type FdFromFenceCookie<'a> = base::Cookie<'a, xcb_dri3_fd_from_fence_cookie_t>;

impl<'a> FdFromFenceCookie<'a> {
    pub fn get_reply(&self) -> Result<FdFromFenceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = FdFromFenceReply {
                    ptr: xcb_dri3_fd_from_fence_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( FdFromFenceReply {
                    ptr: xcb_dri3_fd_from_fence_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type FdFromFenceReply = base::Reply<xcb_dri3_fd_from_fence_reply_t>;

impl FdFromFenceReply {
    pub fn fence_fds(&self, c: &base::Connection) -> &[i32] {
        unsafe {
            let nfd = (*self.ptr).nfd as usize;
            let ptr = xcb_dri3_fd_from_fence_reply_fds(c.get_raw_conn(), self.ptr);

            std::slice::from_raw_parts(ptr, nfd)
        }
    }
}

pub fn fd_from_fence<'a>(c       : &'a base::Connection,
                         drawable: xproto::Drawable,
                         fence   : u32)
        -> FdFromFenceCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_fd_from_fence(c.get_raw_conn(),
                                            drawable as xcb_drawable_t,  // 0
                                            fence as u32);  // 1
        FdFromFenceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn fd_from_fence_unchecked<'a>(c       : &'a base::Connection,
                                   drawable: xproto::Drawable,
                                   fence   : u32)
        -> FdFromFenceCookie<'a> {
    unsafe {
        let cookie = xcb_dri3_fd_from_fence_unchecked(c.get_raw_conn(),
                                                      drawable as xcb_drawable_t,  // 0
                                                      fence as u32);  // 1
        FdFromFenceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
