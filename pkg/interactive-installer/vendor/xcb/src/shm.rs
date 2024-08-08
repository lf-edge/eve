// Generated automatically from shm.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::shm::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_shm_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 2;

pub type Seg = xcb_shm_seg_t;

pub struct BadSegError {
    pub base: base::Error<xcb_shm_bad_seg_error_t>
}



pub const COMPLETION: u8 = 0;

pub type CompletionEvent = base::Event<xcb_shm_completion_event_t>;

impl CompletionEvent {
    pub fn drawable(&self) -> xproto::Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    pub fn minor_event(&self) -> u16 {
        unsafe {
            (*self.ptr).minor_event
        }
    }
    pub fn major_event(&self) -> u8 {
        unsafe {
            (*self.ptr).major_event
        }
    }
    pub fn shmseg(&self) -> Seg {
        unsafe {
            (*self.ptr).shmseg
        }
    }
    pub fn offset(&self) -> u32 {
        unsafe {
            (*self.ptr).offset
        }
    }
    /// Constructs a new CompletionEvent
    /// `response_type` will be set automatically to COMPLETION
    pub fn new(drawable: xproto::Drawable,
               minor_event: u16,
               major_event: u8,
               shmseg: Seg,
               offset: u32)
            -> CompletionEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_shm_completion_event_t;
            (*raw).response_type = COMPLETION;
            (*raw).drawable = drawable;
            (*raw).minor_event = minor_event;
            (*raw).major_event = major_event;
            (*raw).shmseg = shmseg;
            (*raw).offset = offset;
            CompletionEvent {
                ptr: raw
            }
        }
    }
}

pub const BAD_SEG: u8 = 0;

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_shm_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_shm_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_shm_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_shm_query_version_reply_t>;

impl QueryVersionReply {
    pub fn shared_pixmaps(&self) -> bool {
        unsafe {
            (*self.ptr).shared_pixmaps != 0
        }
    }
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
    pub fn uid(&self) -> u16 {
        unsafe {
            (*self.ptr).uid
        }
    }
    pub fn gid(&self) -> u16 {
        unsafe {
            (*self.ptr).gid
        }
    }
    pub fn pixmap_format(&self) -> u8 {
        unsafe {
            (*self.ptr).pixmap_format
        }
    }
}

pub fn query_version<'a>(c: &'a base::Connection)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_shm_query_version(c.get_raw_conn());
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
        let cookie = xcb_shm_query_version_unchecked(c.get_raw_conn());
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const ATTACH: u8 = 1;

pub fn attach<'a>(c        : &'a base::Connection,
                  shmseg   : Seg,
                  shmid    : u32,
                  read_only: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_attach(c.get_raw_conn(),
                                    shmseg as xcb_shm_seg_t,  // 0
                                    shmid as u32,  // 1
                                    read_only as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn attach_checked<'a>(c        : &'a base::Connection,
                          shmseg   : Seg,
                          shmid    : u32,
                          read_only: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_attach_checked(c.get_raw_conn(),
                                            shmseg as xcb_shm_seg_t,  // 0
                                            shmid as u32,  // 1
                                            read_only as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DETACH: u8 = 2;

pub fn detach<'a>(c     : &'a base::Connection,
                  shmseg: Seg)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_detach(c.get_raw_conn(),
                                    shmseg as xcb_shm_seg_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn detach_checked<'a>(c     : &'a base::Connection,
                          shmseg: Seg)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_detach_checked(c.get_raw_conn(),
                                            shmseg as xcb_shm_seg_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PUT_IMAGE: u8 = 3;

pub fn put_image<'a>(c           : &'a base::Connection,
                     drawable    : xproto::Drawable,
                     gc          : xproto::Gcontext,
                     total_width : u16,
                     total_height: u16,
                     src_x       : u16,
                     src_y       : u16,
                     src_width   : u16,
                     src_height  : u16,
                     dst_x       : i16,
                     dst_y       : i16,
                     depth       : u8,
                     format      : u8,
                     send_event  : u8,
                     shmseg      : Seg,
                     offset      : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_put_image(c.get_raw_conn(),
                                       drawable as xcb_drawable_t,  // 0
                                       gc as xcb_gcontext_t,  // 1
                                       total_width as u16,  // 2
                                       total_height as u16,  // 3
                                       src_x as u16,  // 4
                                       src_y as u16,  // 5
                                       src_width as u16,  // 6
                                       src_height as u16,  // 7
                                       dst_x as i16,  // 8
                                       dst_y as i16,  // 9
                                       depth as u8,  // 10
                                       format as u8,  // 11
                                       send_event as u8,  // 12
                                       shmseg as xcb_shm_seg_t,  // 13
                                       offset as u32);  // 14
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn put_image_checked<'a>(c           : &'a base::Connection,
                             drawable    : xproto::Drawable,
                             gc          : xproto::Gcontext,
                             total_width : u16,
                             total_height: u16,
                             src_x       : u16,
                             src_y       : u16,
                             src_width   : u16,
                             src_height  : u16,
                             dst_x       : i16,
                             dst_y       : i16,
                             depth       : u8,
                             format      : u8,
                             send_event  : u8,
                             shmseg      : Seg,
                             offset      : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_put_image_checked(c.get_raw_conn(),
                                               drawable as xcb_drawable_t,  // 0
                                               gc as xcb_gcontext_t,  // 1
                                               total_width as u16,  // 2
                                               total_height as u16,  // 3
                                               src_x as u16,  // 4
                                               src_y as u16,  // 5
                                               src_width as u16,  // 6
                                               src_height as u16,  // 7
                                               dst_x as i16,  // 8
                                               dst_y as i16,  // 9
                                               depth as u8,  // 10
                                               format as u8,  // 11
                                               send_event as u8,  // 12
                                               shmseg as xcb_shm_seg_t,  // 13
                                               offset as u32);  // 14
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_IMAGE: u8 = 4;

pub type GetImageCookie<'a> = base::Cookie<'a, xcb_shm_get_image_cookie_t>;

impl<'a> GetImageCookie<'a> {
    pub fn get_reply(&self) -> Result<GetImageReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetImageReply {
                    ptr: xcb_shm_get_image_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetImageReply {
                    ptr: xcb_shm_get_image_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetImageReply = base::Reply<xcb_shm_get_image_reply_t>;

impl GetImageReply {
    pub fn depth(&self) -> u8 {
        unsafe {
            (*self.ptr).depth
        }
    }
    pub fn visual(&self) -> xproto::Visualid {
        unsafe {
            (*self.ptr).visual
        }
    }
    pub fn size(&self) -> u32 {
        unsafe {
            (*self.ptr).size
        }
    }
}

pub fn get_image<'a>(c         : &'a base::Connection,
                     drawable  : xproto::Drawable,
                     x         : i16,
                     y         : i16,
                     width     : u16,
                     height    : u16,
                     plane_mask: u32,
                     format    : u8,
                     shmseg    : Seg,
                     offset    : u32)
        -> GetImageCookie<'a> {
    unsafe {
        let cookie = xcb_shm_get_image(c.get_raw_conn(),
                                       drawable as xcb_drawable_t,  // 0
                                       x as i16,  // 1
                                       y as i16,  // 2
                                       width as u16,  // 3
                                       height as u16,  // 4
                                       plane_mask as u32,  // 5
                                       format as u8,  // 6
                                       shmseg as xcb_shm_seg_t,  // 7
                                       offset as u32);  // 8
        GetImageCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_image_unchecked<'a>(c         : &'a base::Connection,
                               drawable  : xproto::Drawable,
                               x         : i16,
                               y         : i16,
                               width     : u16,
                               height    : u16,
                               plane_mask: u32,
                               format    : u8,
                               shmseg    : Seg,
                               offset    : u32)
        -> GetImageCookie<'a> {
    unsafe {
        let cookie = xcb_shm_get_image_unchecked(c.get_raw_conn(),
                                                 drawable as xcb_drawable_t,  // 0
                                                 x as i16,  // 1
                                                 y as i16,  // 2
                                                 width as u16,  // 3
                                                 height as u16,  // 4
                                                 plane_mask as u32,  // 5
                                                 format as u8,  // 6
                                                 shmseg as xcb_shm_seg_t,  // 7
                                                 offset as u32);  // 8
        GetImageCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_PIXMAP: u8 = 5;

pub fn create_pixmap<'a>(c       : &'a base::Connection,
                         pid     : xproto::Pixmap,
                         drawable: xproto::Drawable,
                         width   : u16,
                         height  : u16,
                         depth   : u8,
                         shmseg  : Seg,
                         offset  : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_create_pixmap(c.get_raw_conn(),
                                           pid as xcb_pixmap_t,  // 0
                                           drawable as xcb_drawable_t,  // 1
                                           width as u16,  // 2
                                           height as u16,  // 3
                                           depth as u8,  // 4
                                           shmseg as xcb_shm_seg_t,  // 5
                                           offset as u32);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_pixmap_checked<'a>(c       : &'a base::Connection,
                                 pid     : xproto::Pixmap,
                                 drawable: xproto::Drawable,
                                 width   : u16,
                                 height  : u16,
                                 depth   : u8,
                                 shmseg  : Seg,
                                 offset  : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_create_pixmap_checked(c.get_raw_conn(),
                                                   pid as xcb_pixmap_t,  // 0
                                                   drawable as xcb_drawable_t,  // 1
                                                   width as u16,  // 2
                                                   height as u16,  // 3
                                                   depth as u8,  // 4
                                                   shmseg as xcb_shm_seg_t,  // 5
                                                   offset as u32);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ATTACH_FD: u8 = 6;

pub fn attach_fd<'a>(c        : &'a base::Connection,
                     shmseg   : Seg,
                     shm_fd   : i32,
                     read_only: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_attach_fd(c.get_raw_conn(),
                                       shmseg as xcb_shm_seg_t,  // 0
                                       shm_fd as i32,  // 1
                                       read_only as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn attach_fd_checked<'a>(c        : &'a base::Connection,
                             shmseg   : Seg,
                             shm_fd   : i32,
                             read_only: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_shm_attach_fd_checked(c.get_raw_conn(),
                                               shmseg as xcb_shm_seg_t,  // 0
                                               shm_fd as i32,  // 1
                                               read_only as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_SEGMENT: u8 = 7;

pub type CreateSegmentCookie<'a> = base::Cookie<'a, xcb_shm_create_segment_cookie_t>;

impl<'a> CreateSegmentCookie<'a> {
    pub fn get_reply(&self) -> Result<CreateSegmentReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CreateSegmentReply {
                    ptr: xcb_shm_create_segment_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CreateSegmentReply {
                    ptr: xcb_shm_create_segment_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CreateSegmentReply = base::Reply<xcb_shm_create_segment_reply_t>;

impl CreateSegmentReply {
    pub fn shm_fds(&self, c: &base::Connection) -> &[i32] {
        unsafe {
            let nfd = (*self.ptr).nfd as usize;
            let ptr = xcb_shm_create_segment_reply_fds(c.get_raw_conn(), self.ptr);

            std::slice::from_raw_parts(ptr, nfd)
        }
    }
}

pub fn create_segment<'a>(c        : &'a base::Connection,
                          shmseg   : Seg,
                          size     : u32,
                          read_only: bool)
        -> CreateSegmentCookie<'a> {
    unsafe {
        let cookie = xcb_shm_create_segment(c.get_raw_conn(),
                                            shmseg as xcb_shm_seg_t,  // 0
                                            size as u32,  // 1
                                            read_only as u8);  // 2
        CreateSegmentCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn create_segment_unchecked<'a>(c        : &'a base::Connection,
                                    shmseg   : Seg,
                                    size     : u32,
                                    read_only: bool)
        -> CreateSegmentCookie<'a> {
    unsafe {
        let cookie = xcb_shm_create_segment_unchecked(c.get_raw_conn(),
                                                      shmseg as xcb_shm_seg_t,  // 0
                                                      size as u32,  // 1
                                                      read_only as u8);  // 2
        CreateSegmentCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
