// Generated automatically from xf86dri.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::xf86dri::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_xf86dri_id
    }
}

pub const MAJOR_VERSION: u32 = 4;
pub const MINOR_VERSION: u32 = 1;



#[derive(Copy, Clone)]
pub struct DrmClipRect {
    pub base: xcb_xf86dri_drm_clip_rect_t,
}

impl DrmClipRect {
    #[allow(unused_unsafe)]
    pub fn new(x1: i16,
               y1: i16,
               x2: i16,
               x3: i16)
            -> DrmClipRect {
        unsafe {
            DrmClipRect {
                base: xcb_xf86dri_drm_clip_rect_t {
                    x1: x1,
                    y1: y1,
                    x2: x2,
                    x3: x3,
                }
            }
        }
    }
    pub fn x1(&self) -> i16 {
        unsafe {
            self.base.x1
        }
    }
    pub fn y1(&self) -> i16 {
        unsafe {
            self.base.y1
        }
    }
    pub fn x2(&self) -> i16 {
        unsafe {
            self.base.x2
        }
    }
    pub fn x3(&self) -> i16 {
        unsafe {
            self.base.x3
        }
    }
}

pub type DrmClipRectIterator = xcb_xf86dri_drm_clip_rect_iterator_t;

impl Iterator for DrmClipRectIterator {
    type Item = DrmClipRect;
    fn next(&mut self) -> std::option::Option<DrmClipRect> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xf86dri_drm_clip_rect_iterator_t;
                let data = (*iter).data;
                xcb_xf86dri_drm_clip_rect_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_xf86dri_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_xf86dri_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_xf86dri_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_xf86dri_query_version_reply_t>;

impl QueryVersionReply {
    pub fn dri_major_version(&self) -> u16 {
        unsafe {
            (*self.ptr).dri_major_version
        }
    }
    pub fn dri_minor_version(&self) -> u16 {
        unsafe {
            (*self.ptr).dri_minor_version
        }
    }
    pub fn dri_minor_patch(&self) -> u32 {
        unsafe {
            (*self.ptr).dri_minor_patch
        }
    }
}

pub fn query_version<'a>(c: &'a base::Connection)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_query_version(c.get_raw_conn());
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
        let cookie = xcb_xf86dri_query_version_unchecked(c.get_raw_conn());
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_DIRECT_RENDERING_CAPABLE: u8 = 1;

pub type QueryDirectRenderingCapableCookie<'a> = base::Cookie<'a, xcb_xf86dri_query_direct_rendering_capable_cookie_t>;

impl<'a> QueryDirectRenderingCapableCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryDirectRenderingCapableReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryDirectRenderingCapableReply {
                    ptr: xcb_xf86dri_query_direct_rendering_capable_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryDirectRenderingCapableReply {
                    ptr: xcb_xf86dri_query_direct_rendering_capable_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryDirectRenderingCapableReply = base::Reply<xcb_xf86dri_query_direct_rendering_capable_reply_t>;

impl QueryDirectRenderingCapableReply {
    pub fn is_capable(&self) -> bool {
        unsafe {
            (*self.ptr).is_capable != 0
        }
    }
}

pub fn query_direct_rendering_capable<'a>(c     : &'a base::Connection,
                                          screen: u32)
        -> QueryDirectRenderingCapableCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_query_direct_rendering_capable(c.get_raw_conn(),
                                                                screen as u32);  // 0
        QueryDirectRenderingCapableCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_direct_rendering_capable_unchecked<'a>(c     : &'a base::Connection,
                                                    screen: u32)
        -> QueryDirectRenderingCapableCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_query_direct_rendering_capable_unchecked(c.get_raw_conn(),
                                                                          screen as u32);  // 0
        QueryDirectRenderingCapableCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const OPEN_CONNECTION: u8 = 2;

pub type OpenConnectionCookie<'a> = base::Cookie<'a, xcb_xf86dri_open_connection_cookie_t>;

impl<'a> OpenConnectionCookie<'a> {
    pub fn get_reply(&self) -> Result<OpenConnectionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = OpenConnectionReply {
                    ptr: xcb_xf86dri_open_connection_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( OpenConnectionReply {
                    ptr: xcb_xf86dri_open_connection_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type OpenConnectionReply = base::Reply<xcb_xf86dri_open_connection_reply_t>;

impl OpenConnectionReply {
    pub fn sarea_handle_low(&self) -> u32 {
        unsafe {
            (*self.ptr).sarea_handle_low
        }
    }
    pub fn sarea_handle_high(&self) -> u32 {
        unsafe {
            (*self.ptr).sarea_handle_high
        }
    }
    pub fn bus_id_len(&self) -> u32 {
        unsafe {
            (*self.ptr).bus_id_len
        }
    }
    pub fn bus_id(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86dri_open_connection_bus_id_length(field) as usize;
            let data = xcb_xf86dri_open_connection_bus_id(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn open_connection<'a>(c     : &'a base::Connection,
                           screen: u32)
        -> OpenConnectionCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_open_connection(c.get_raw_conn(),
                                                 screen as u32);  // 0
        OpenConnectionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn open_connection_unchecked<'a>(c     : &'a base::Connection,
                                     screen: u32)
        -> OpenConnectionCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_open_connection_unchecked(c.get_raw_conn(),
                                                           screen as u32);  // 0
        OpenConnectionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CLOSE_CONNECTION: u8 = 3;

pub fn close_connection<'a>(c     : &'a base::Connection,
                            screen: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_close_connection(c.get_raw_conn(),
                                                  screen as u32);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn close_connection_checked<'a>(c     : &'a base::Connection,
                                    screen: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_close_connection_checked(c.get_raw_conn(),
                                                          screen as u32);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_CLIENT_DRIVER_NAME: u8 = 4;

pub type GetClientDriverNameCookie<'a> = base::Cookie<'a, xcb_xf86dri_get_client_driver_name_cookie_t>;

impl<'a> GetClientDriverNameCookie<'a> {
    pub fn get_reply(&self) -> Result<GetClientDriverNameReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetClientDriverNameReply {
                    ptr: xcb_xf86dri_get_client_driver_name_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetClientDriverNameReply {
                    ptr: xcb_xf86dri_get_client_driver_name_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetClientDriverNameReply = base::Reply<xcb_xf86dri_get_client_driver_name_reply_t>;

impl GetClientDriverNameReply {
    pub fn client_driver_major_version(&self) -> u32 {
        unsafe {
            (*self.ptr).client_driver_major_version
        }
    }
    pub fn client_driver_minor_version(&self) -> u32 {
        unsafe {
            (*self.ptr).client_driver_minor_version
        }
    }
    pub fn client_driver_patch_version(&self) -> u32 {
        unsafe {
            (*self.ptr).client_driver_patch_version
        }
    }
    pub fn client_driver_name_len(&self) -> u32 {
        unsafe {
            (*self.ptr).client_driver_name_len
        }
    }
    pub fn client_driver_name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86dri_get_client_driver_name_client_driver_name_length(field) as usize;
            let data = xcb_xf86dri_get_client_driver_name_client_driver_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_client_driver_name<'a>(c     : &'a base::Connection,
                                  screen: u32)
        -> GetClientDriverNameCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_get_client_driver_name(c.get_raw_conn(),
                                                        screen as u32);  // 0
        GetClientDriverNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_client_driver_name_unchecked<'a>(c     : &'a base::Connection,
                                            screen: u32)
        -> GetClientDriverNameCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_get_client_driver_name_unchecked(c.get_raw_conn(),
                                                                  screen as u32);  // 0
        GetClientDriverNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_CONTEXT: u8 = 5;

pub type CreateContextCookie<'a> = base::Cookie<'a, xcb_xf86dri_create_context_cookie_t>;

impl<'a> CreateContextCookie<'a> {
    pub fn get_reply(&self) -> Result<CreateContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CreateContextReply {
                    ptr: xcb_xf86dri_create_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CreateContextReply {
                    ptr: xcb_xf86dri_create_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CreateContextReply = base::Reply<xcb_xf86dri_create_context_reply_t>;

impl CreateContextReply {
    pub fn hw_context(&self) -> u32 {
        unsafe {
            (*self.ptr).hw_context
        }
    }
}

pub fn create_context<'a>(c      : &'a base::Connection,
                          screen : u32,
                          visual : u32,
                          context: u32)
        -> CreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_create_context(c.get_raw_conn(),
                                                screen as u32,  // 0
                                                visual as u32,  // 1
                                                context as u32);  // 2
        CreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn create_context_unchecked<'a>(c      : &'a base::Connection,
                                    screen : u32,
                                    visual : u32,
                                    context: u32)
        -> CreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_create_context_unchecked(c.get_raw_conn(),
                                                          screen as u32,  // 0
                                                          visual as u32,  // 1
                                                          context as u32);  // 2
        CreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DESTROY_CONTEXT: u8 = 6;

pub fn destroy_context<'a>(c      : &'a base::Connection,
                           screen : u32,
                           context: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_destroy_context(c.get_raw_conn(),
                                                 screen as u32,  // 0
                                                 context as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_context_checked<'a>(c      : &'a base::Connection,
                                   screen : u32,
                                   context: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_destroy_context_checked(c.get_raw_conn(),
                                                         screen as u32,  // 0
                                                         context as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_DRAWABLE: u8 = 7;

pub type CreateDrawableCookie<'a> = base::Cookie<'a, xcb_xf86dri_create_drawable_cookie_t>;

impl<'a> CreateDrawableCookie<'a> {
    pub fn get_reply(&self) -> Result<CreateDrawableReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CreateDrawableReply {
                    ptr: xcb_xf86dri_create_drawable_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CreateDrawableReply {
                    ptr: xcb_xf86dri_create_drawable_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CreateDrawableReply = base::Reply<xcb_xf86dri_create_drawable_reply_t>;

impl CreateDrawableReply {
    pub fn hw_drawable_handle(&self) -> u32 {
        unsafe {
            (*self.ptr).hw_drawable_handle
        }
    }
}

pub fn create_drawable<'a>(c       : &'a base::Connection,
                           screen  : u32,
                           drawable: u32)
        -> CreateDrawableCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_create_drawable(c.get_raw_conn(),
                                                 screen as u32,  // 0
                                                 drawable as u32);  // 1
        CreateDrawableCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn create_drawable_unchecked<'a>(c       : &'a base::Connection,
                                     screen  : u32,
                                     drawable: u32)
        -> CreateDrawableCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_create_drawable_unchecked(c.get_raw_conn(),
                                                           screen as u32,  // 0
                                                           drawable as u32);  // 1
        CreateDrawableCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DESTROY_DRAWABLE: u8 = 8;

pub fn destroy_drawable<'a>(c       : &'a base::Connection,
                            screen  : u32,
                            drawable: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_destroy_drawable(c.get_raw_conn(),
                                                  screen as u32,  // 0
                                                  drawable as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_drawable_checked<'a>(c       : &'a base::Connection,
                                    screen  : u32,
                                    drawable: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_destroy_drawable_checked(c.get_raw_conn(),
                                                          screen as u32,  // 0
                                                          drawable as u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DRAWABLE_INFO: u8 = 9;

pub type GetDrawableInfoCookie<'a> = base::Cookie<'a, xcb_xf86dri_get_drawable_info_cookie_t>;

impl<'a> GetDrawableInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDrawableInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDrawableInfoReply {
                    ptr: xcb_xf86dri_get_drawable_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDrawableInfoReply {
                    ptr: xcb_xf86dri_get_drawable_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDrawableInfoReply = base::Reply<xcb_xf86dri_get_drawable_info_reply_t>;

impl GetDrawableInfoReply {
    pub fn drawable_table_index(&self) -> u32 {
        unsafe {
            (*self.ptr).drawable_table_index
        }
    }
    pub fn drawable_table_stamp(&self) -> u32 {
        unsafe {
            (*self.ptr).drawable_table_stamp
        }
    }
    pub fn drawable_origin__x(&self) -> i16 {
        unsafe {
            (*self.ptr).drawable_origin_X
        }
    }
    pub fn drawable_origin__y(&self) -> i16 {
        unsafe {
            (*self.ptr).drawable_origin_Y
        }
    }
    pub fn drawable_size__w(&self) -> i16 {
        unsafe {
            (*self.ptr).drawable_size_W
        }
    }
    pub fn drawable_size__h(&self) -> i16 {
        unsafe {
            (*self.ptr).drawable_size_H
        }
    }
    pub fn num_clip_rects(&self) -> u32 {
        unsafe {
            (*self.ptr).num_clip_rects
        }
    }
    pub fn back_x(&self) -> i16 {
        unsafe {
            (*self.ptr).back_x
        }
    }
    pub fn back_y(&self) -> i16 {
        unsafe {
            (*self.ptr).back_y
        }
    }
    pub fn num_back_clip_rects(&self) -> u32 {
        unsafe {
            (*self.ptr).num_back_clip_rects
        }
    }
    pub fn clip_rects(&self) -> DrmClipRectIterator {
        unsafe {
            xcb_xf86dri_get_drawable_info_clip_rects_iterator(self.ptr)
        }
    }
    pub fn back_clip_rects(&self) -> DrmClipRectIterator {
        unsafe {
            xcb_xf86dri_get_drawable_info_back_clip_rects_iterator(self.ptr)
        }
    }
}

pub fn get_drawable_info<'a>(c       : &'a base::Connection,
                             screen  : u32,
                             drawable: u32)
        -> GetDrawableInfoCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_get_drawable_info(c.get_raw_conn(),
                                                   screen as u32,  // 0
                                                   drawable as u32);  // 1
        GetDrawableInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_drawable_info_unchecked<'a>(c       : &'a base::Connection,
                                       screen  : u32,
                                       drawable: u32)
        -> GetDrawableInfoCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_get_drawable_info_unchecked(c.get_raw_conn(),
                                                             screen as u32,  // 0
                                                             drawable as u32);  // 1
        GetDrawableInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_DEVICE_INFO: u8 = 10;

pub type GetDeviceInfoCookie<'a> = base::Cookie<'a, xcb_xf86dri_get_device_info_cookie_t>;

impl<'a> GetDeviceInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceInfoReply {
                    ptr: xcb_xf86dri_get_device_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceInfoReply {
                    ptr: xcb_xf86dri_get_device_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceInfoReply = base::Reply<xcb_xf86dri_get_device_info_reply_t>;

impl GetDeviceInfoReply {
    pub fn framebuffer_handle_low(&self) -> u32 {
        unsafe {
            (*self.ptr).framebuffer_handle_low
        }
    }
    pub fn framebuffer_handle_high(&self) -> u32 {
        unsafe {
            (*self.ptr).framebuffer_handle_high
        }
    }
    pub fn framebuffer_origin_offset(&self) -> u32 {
        unsafe {
            (*self.ptr).framebuffer_origin_offset
        }
    }
    pub fn framebuffer_size(&self) -> u32 {
        unsafe {
            (*self.ptr).framebuffer_size
        }
    }
    pub fn framebuffer_stride(&self) -> u32 {
        unsafe {
            (*self.ptr).framebuffer_stride
        }
    }
    pub fn device_private_size(&self) -> u32 {
        unsafe {
            (*self.ptr).device_private_size
        }
    }
    pub fn device_private(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86dri_get_device_info_device_private_length(field) as usize;
            let data = xcb_xf86dri_get_device_info_device_private(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_device_info<'a>(c     : &'a base::Connection,
                           screen: u32)
        -> GetDeviceInfoCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_get_device_info(c.get_raw_conn(),
                                                 screen as u32);  // 0
        GetDeviceInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_info_unchecked<'a>(c     : &'a base::Connection,
                                     screen: u32)
        -> GetDeviceInfoCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_get_device_info_unchecked(c.get_raw_conn(),
                                                           screen as u32);  // 0
        GetDeviceInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const AUTH_CONNECTION: u8 = 11;

pub type AuthConnectionCookie<'a> = base::Cookie<'a, xcb_xf86dri_auth_connection_cookie_t>;

impl<'a> AuthConnectionCookie<'a> {
    pub fn get_reply(&self) -> Result<AuthConnectionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = AuthConnectionReply {
                    ptr: xcb_xf86dri_auth_connection_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( AuthConnectionReply {
                    ptr: xcb_xf86dri_auth_connection_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type AuthConnectionReply = base::Reply<xcb_xf86dri_auth_connection_reply_t>;

impl AuthConnectionReply {
    pub fn authenticated(&self) -> u32 {
        unsafe {
            (*self.ptr).authenticated
        }
    }
}

pub fn auth_connection<'a>(c     : &'a base::Connection,
                           screen: u32,
                           magic : u32)
        -> AuthConnectionCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_auth_connection(c.get_raw_conn(),
                                                 screen as u32,  // 0
                                                 magic as u32);  // 1
        AuthConnectionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn auth_connection_unchecked<'a>(c     : &'a base::Connection,
                                     screen: u32,
                                     magic : u32)
        -> AuthConnectionCookie<'a> {
    unsafe {
        let cookie = xcb_xf86dri_auth_connection_unchecked(c.get_raw_conn(),
                                                           screen as u32,  // 0
                                                           magic as u32);  // 1
        AuthConnectionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
