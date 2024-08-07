// Generated automatically from xvmc.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use shm;
use xv;
use ffi::base::*;
use ffi::xvmc::*;
use ffi::xproto::*;
use ffi::shm::*;
use ffi::xv::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_xvmc_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 1;

pub type Context = xcb_xvmc_context_t;

pub type Surface = xcb_xvmc_surface_t;

pub type Subpicture = xcb_xvmc_subpicture_t;



#[derive(Copy, Clone)]
pub struct SurfaceInfo {
    pub base: xcb_xvmc_surface_info_t,
}

impl SurfaceInfo {
    #[allow(unused_unsafe)]
    pub fn new(id:                    Surface,
               chroma_format:         u16,
               pad0:                  u16,
               max_width:             u16,
               max_height:            u16,
               subpicture_max_width:  u16,
               subpicture_max_height: u16,
               mc_type:               u32,
               flags:                 u32)
            -> SurfaceInfo {
        unsafe {
            SurfaceInfo {
                base: xcb_xvmc_surface_info_t {
                    id:                    id,
                    chroma_format:         chroma_format,
                    pad0:                  pad0,
                    max_width:             max_width,
                    max_height:            max_height,
                    subpicture_max_width:  subpicture_max_width,
                    subpicture_max_height: subpicture_max_height,
                    mc_type:               mc_type,
                    flags:                 flags,
                }
            }
        }
    }
    pub fn id(&self) -> Surface {
        unsafe {
            self.base.id
        }
    }
    pub fn chroma_format(&self) -> u16 {
        unsafe {
            self.base.chroma_format
        }
    }
    pub fn pad0(&self) -> u16 {
        unsafe {
            self.base.pad0
        }
    }
    pub fn max_width(&self) -> u16 {
        unsafe {
            self.base.max_width
        }
    }
    pub fn max_height(&self) -> u16 {
        unsafe {
            self.base.max_height
        }
    }
    pub fn subpicture_max_width(&self) -> u16 {
        unsafe {
            self.base.subpicture_max_width
        }
    }
    pub fn subpicture_max_height(&self) -> u16 {
        unsafe {
            self.base.subpicture_max_height
        }
    }
    pub fn mc_type(&self) -> u32 {
        unsafe {
            self.base.mc_type
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            self.base.flags
        }
    }
}

pub type SurfaceInfoIterator = xcb_xvmc_surface_info_iterator_t;

impl Iterator for SurfaceInfoIterator {
    type Item = SurfaceInfo;
    fn next(&mut self) -> std::option::Option<SurfaceInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xvmc_surface_info_iterator_t;
                let data = (*iter).data;
                xcb_xvmc_surface_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_xvmc_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_xvmc_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_xvmc_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_xvmc_query_version_reply_t>;

impl QueryVersionReply {
    pub fn major(&self) -> u32 {
        unsafe {
            (*self.ptr).major
        }
    }
    pub fn minor(&self) -> u32 {
        unsafe {
            (*self.ptr).minor
        }
    }
}

pub fn query_version<'a>(c: &'a base::Connection)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_query_version(c.get_raw_conn());
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
        let cookie = xcb_xvmc_query_version_unchecked(c.get_raw_conn());
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_SURFACE_TYPES: u8 = 1;

pub type ListSurfaceTypesCookie<'a> = base::Cookie<'a, xcb_xvmc_list_surface_types_cookie_t>;

impl<'a> ListSurfaceTypesCookie<'a> {
    pub fn get_reply(&self) -> Result<ListSurfaceTypesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListSurfaceTypesReply {
                    ptr: xcb_xvmc_list_surface_types_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListSurfaceTypesReply {
                    ptr: xcb_xvmc_list_surface_types_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListSurfaceTypesReply = base::Reply<xcb_xvmc_list_surface_types_reply_t>;

impl ListSurfaceTypesReply {
    pub fn num(&self) -> u32 {
        unsafe {
            (*self.ptr).num
        }
    }
    pub fn surfaces(&self) -> SurfaceInfoIterator {
        unsafe {
            xcb_xvmc_list_surface_types_surfaces_iterator(self.ptr)
        }
    }
}

pub fn list_surface_types<'a>(c      : &'a base::Connection,
                              port_id: xv::Port)
        -> ListSurfaceTypesCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_list_surface_types(c.get_raw_conn(),
                                                 port_id as xcb_xv_port_t);  // 0
        ListSurfaceTypesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_surface_types_unchecked<'a>(c      : &'a base::Connection,
                                        port_id: xv::Port)
        -> ListSurfaceTypesCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_list_surface_types_unchecked(c.get_raw_conn(),
                                                           port_id as xcb_xv_port_t);  // 0
        ListSurfaceTypesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_CONTEXT: u8 = 2;

pub type CreateContextCookie<'a> = base::Cookie<'a, xcb_xvmc_create_context_cookie_t>;

impl<'a> CreateContextCookie<'a> {
    pub fn get_reply(&self) -> Result<CreateContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CreateContextReply {
                    ptr: xcb_xvmc_create_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CreateContextReply {
                    ptr: xcb_xvmc_create_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CreateContextReply = base::Reply<xcb_xvmc_create_context_reply_t>;

impl CreateContextReply {
    pub fn width_actual(&self) -> u16 {
        unsafe {
            (*self.ptr).width_actual
        }
    }
    pub fn height_actual(&self) -> u16 {
        unsafe {
            (*self.ptr).height_actual
        }
    }
    pub fn flags_return(&self) -> u32 {
        unsafe {
            (*self.ptr).flags_return
        }
    }
    pub fn priv_data(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xvmc_create_context_priv_data_length(field) as usize;
            let data = xcb_xvmc_create_context_priv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn create_context<'a>(c         : &'a base::Connection,
                          context_id: Context,
                          port_id   : xv::Port,
                          surface_id: Surface,
                          width     : u16,
                          height    : u16,
                          flags     : u32)
        -> CreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_create_context(c.get_raw_conn(),
                                             context_id as xcb_xvmc_context_t,  // 0
                                             port_id as xcb_xv_port_t,  // 1
                                             surface_id as xcb_xvmc_surface_t,  // 2
                                             width as u16,  // 3
                                             height as u16,  // 4
                                             flags as u32);  // 5
        CreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn create_context_unchecked<'a>(c         : &'a base::Connection,
                                    context_id: Context,
                                    port_id   : xv::Port,
                                    surface_id: Surface,
                                    width     : u16,
                                    height    : u16,
                                    flags     : u32)
        -> CreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_create_context_unchecked(c.get_raw_conn(),
                                                       context_id as xcb_xvmc_context_t,  // 0
                                                       port_id as xcb_xv_port_t,  // 1
                                                       surface_id as xcb_xvmc_surface_t,  // 2
                                                       width as u16,  // 3
                                                       height as u16,  // 4
                                                       flags as u32);  // 5
        CreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DESTROY_CONTEXT: u8 = 3;

pub fn destroy_context<'a>(c         : &'a base::Connection,
                           context_id: Context)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_destroy_context(c.get_raw_conn(),
                                              context_id as xcb_xvmc_context_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_context_checked<'a>(c         : &'a base::Connection,
                                   context_id: Context)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_destroy_context_checked(c.get_raw_conn(),
                                                      context_id as xcb_xvmc_context_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_SURFACE: u8 = 4;

pub type CreateSurfaceCookie<'a> = base::Cookie<'a, xcb_xvmc_create_surface_cookie_t>;

impl<'a> CreateSurfaceCookie<'a> {
    pub fn get_reply(&self) -> Result<CreateSurfaceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CreateSurfaceReply {
                    ptr: xcb_xvmc_create_surface_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CreateSurfaceReply {
                    ptr: xcb_xvmc_create_surface_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CreateSurfaceReply = base::Reply<xcb_xvmc_create_surface_reply_t>;

impl CreateSurfaceReply {
    pub fn priv_data(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xvmc_create_surface_priv_data_length(field) as usize;
            let data = xcb_xvmc_create_surface_priv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn create_surface<'a>(c         : &'a base::Connection,
                          surface_id: Surface,
                          context_id: Context)
        -> CreateSurfaceCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_create_surface(c.get_raw_conn(),
                                             surface_id as xcb_xvmc_surface_t,  // 0
                                             context_id as xcb_xvmc_context_t);  // 1
        CreateSurfaceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn create_surface_unchecked<'a>(c         : &'a base::Connection,
                                    surface_id: Surface,
                                    context_id: Context)
        -> CreateSurfaceCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_create_surface_unchecked(c.get_raw_conn(),
                                                       surface_id as xcb_xvmc_surface_t,  // 0
                                                       context_id as xcb_xvmc_context_t);  // 1
        CreateSurfaceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DESTROY_SURFACE: u8 = 5;

pub fn destroy_surface<'a>(c         : &'a base::Connection,
                           surface_id: Surface)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_destroy_surface(c.get_raw_conn(),
                                              surface_id as xcb_xvmc_surface_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_surface_checked<'a>(c         : &'a base::Connection,
                                   surface_id: Surface)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_destroy_surface_checked(c.get_raw_conn(),
                                                      surface_id as xcb_xvmc_surface_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_SUBPICTURE: u8 = 6;

pub type CreateSubpictureCookie<'a> = base::Cookie<'a, xcb_xvmc_create_subpicture_cookie_t>;

impl<'a> CreateSubpictureCookie<'a> {
    pub fn get_reply(&self) -> Result<CreateSubpictureReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CreateSubpictureReply {
                    ptr: xcb_xvmc_create_subpicture_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CreateSubpictureReply {
                    ptr: xcb_xvmc_create_subpicture_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CreateSubpictureReply = base::Reply<xcb_xvmc_create_subpicture_reply_t>;

impl CreateSubpictureReply {
    pub fn width_actual(&self) -> u16 {
        unsafe {
            (*self.ptr).width_actual
        }
    }
    pub fn height_actual(&self) -> u16 {
        unsafe {
            (*self.ptr).height_actual
        }
    }
    pub fn num_palette_entries(&self) -> u16 {
        unsafe {
            (*self.ptr).num_palette_entries
        }
    }
    pub fn entry_bytes(&self) -> u16 {
        unsafe {
            (*self.ptr).entry_bytes
        }
    }
    pub fn component_order(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).component_order
        }
    }
    pub fn priv_data(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xvmc_create_subpicture_priv_data_length(field) as usize;
            let data = xcb_xvmc_create_subpicture_priv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn create_subpicture<'a>(c            : &'a base::Connection,
                             subpicture_id: Subpicture,
                             context      : Context,
                             xvimage_id   : u32,
                             width        : u16,
                             height       : u16)
        -> CreateSubpictureCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_create_subpicture(c.get_raw_conn(),
                                                subpicture_id as xcb_xvmc_subpicture_t,  // 0
                                                context as xcb_xvmc_context_t,  // 1
                                                xvimage_id as u32,  // 2
                                                width as u16,  // 3
                                                height as u16);  // 4
        CreateSubpictureCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn create_subpicture_unchecked<'a>(c            : &'a base::Connection,
                                       subpicture_id: Subpicture,
                                       context      : Context,
                                       xvimage_id   : u32,
                                       width        : u16,
                                       height       : u16)
        -> CreateSubpictureCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_create_subpicture_unchecked(c.get_raw_conn(),
                                                          subpicture_id as xcb_xvmc_subpicture_t,  // 0
                                                          context as xcb_xvmc_context_t,  // 1
                                                          xvimage_id as u32,  // 2
                                                          width as u16,  // 3
                                                          height as u16);  // 4
        CreateSubpictureCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DESTROY_SUBPICTURE: u8 = 7;

pub fn destroy_subpicture<'a>(c            : &'a base::Connection,
                              subpicture_id: Subpicture)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_destroy_subpicture(c.get_raw_conn(),
                                                 subpicture_id as xcb_xvmc_subpicture_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_subpicture_checked<'a>(c            : &'a base::Connection,
                                      subpicture_id: Subpicture)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_destroy_subpicture_checked(c.get_raw_conn(),
                                                         subpicture_id as xcb_xvmc_subpicture_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const LIST_SUBPICTURE_TYPES: u8 = 8;

pub type ListSubpictureTypesCookie<'a> = base::Cookie<'a, xcb_xvmc_list_subpicture_types_cookie_t>;

impl<'a> ListSubpictureTypesCookie<'a> {
    pub fn get_reply(&self) -> Result<ListSubpictureTypesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListSubpictureTypesReply {
                    ptr: xcb_xvmc_list_subpicture_types_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListSubpictureTypesReply {
                    ptr: xcb_xvmc_list_subpicture_types_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListSubpictureTypesReply = base::Reply<xcb_xvmc_list_subpicture_types_reply_t>;

impl ListSubpictureTypesReply {
    pub fn num(&self) -> u32 {
        unsafe {
            (*self.ptr).num
        }
    }
    pub fn types(&self) -> xv::ImageFormatInfoIterator {
        unsafe {
            xcb_xvmc_list_subpicture_types_types_iterator(self.ptr)
        }
    }
}

pub fn list_subpicture_types<'a>(c         : &'a base::Connection,
                                 port_id   : xv::Port,
                                 surface_id: Surface)
        -> ListSubpictureTypesCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_list_subpicture_types(c.get_raw_conn(),
                                                    port_id as xcb_xv_port_t,  // 0
                                                    surface_id as xcb_xvmc_surface_t);  // 1
        ListSubpictureTypesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_subpicture_types_unchecked<'a>(c         : &'a base::Connection,
                                           port_id   : xv::Port,
                                           surface_id: Surface)
        -> ListSubpictureTypesCookie<'a> {
    unsafe {
        let cookie = xcb_xvmc_list_subpicture_types_unchecked(c.get_raw_conn(),
                                                              port_id as xcb_xv_port_t,  // 0
                                                              surface_id as xcb_xvmc_surface_t);  // 1
        ListSubpictureTypesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
