// Generated automatically from xselinux.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::selinux::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_selinux_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 0;



pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_selinux_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_selinux_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_selinux_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_selinux_query_version_reply_t>;

impl QueryVersionReply {
    pub fn server_major(&self) -> u16 {
        unsafe {
            (*self.ptr).server_major
        }
    }
    pub fn server_minor(&self) -> u16 {
        unsafe {
            (*self.ptr).server_minor
        }
    }
}

pub fn query_version<'a>(c           : &'a base::Connection,
                         client_major: u8,
                         client_minor: u8)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_query_version(c.get_raw_conn(),
                                               client_major as u8,  // 0
                                               client_minor as u8);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c           : &'a base::Connection,
                                   client_major: u8,
                                   client_minor: u8)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_query_version_unchecked(c.get_raw_conn(),
                                                         client_major as u8,  // 0
                                                         client_minor as u8);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_DEVICE_CREATE_CONTEXT: u8 = 1;

pub fn set_device_create_context<'a>(c      : &'a base::Connection,
                                     context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_device_create_context(c.get_raw_conn(),
                                                           context_len as u32,  // 0
                                                           context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_device_create_context_checked<'a>(c      : &'a base::Connection,
                                             context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_device_create_context_checked(c.get_raw_conn(),
                                                                   context_len as u32,  // 0
                                                                   context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DEVICE_CREATE_CONTEXT: u8 = 2;

pub type GetDeviceCreateContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_device_create_context_cookie_t>;

impl<'a> GetDeviceCreateContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceCreateContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceCreateContextReply {
                    ptr: xcb_selinux_get_device_create_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceCreateContextReply {
                    ptr: xcb_selinux_get_device_create_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceCreateContextReply = base::Reply<xcb_selinux_get_device_create_context_reply_t>;

impl GetDeviceCreateContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_device_create_context_context_length(field) as usize;
            let data = xcb_selinux_get_device_create_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_device_create_context<'a>(c: &'a base::Connection)
        -> GetDeviceCreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_device_create_context(c.get_raw_conn());
        GetDeviceCreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_create_context_unchecked<'a>(c: &'a base::Connection)
        -> GetDeviceCreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_device_create_context_unchecked(c.get_raw_conn());
        GetDeviceCreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_DEVICE_CONTEXT: u8 = 3;

pub fn set_device_context<'a>(c      : &'a base::Connection,
                              device : u32,
                              context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_device_context(c.get_raw_conn(),
                                                    device as u32,  // 0
                                                    context_len as u32,  // 1
                                                    context_ptr as *const c_char);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_device_context_checked<'a>(c      : &'a base::Connection,
                                      device : u32,
                                      context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_device_context_checked(c.get_raw_conn(),
                                                            device as u32,  // 0
                                                            context_len as u32,  // 1
                                                            context_ptr as *const c_char);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DEVICE_CONTEXT: u8 = 4;

pub type GetDeviceContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_device_context_cookie_t>;

impl<'a> GetDeviceContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceContextReply {
                    ptr: xcb_selinux_get_device_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceContextReply {
                    ptr: xcb_selinux_get_device_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceContextReply = base::Reply<xcb_selinux_get_device_context_reply_t>;

impl GetDeviceContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_device_context_context_length(field) as usize;
            let data = xcb_selinux_get_device_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_device_context<'a>(c     : &'a base::Connection,
                              device: u32)
        -> GetDeviceContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_device_context(c.get_raw_conn(),
                                                    device as u32);  // 0
        GetDeviceContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_context_unchecked<'a>(c     : &'a base::Connection,
                                        device: u32)
        -> GetDeviceContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_device_context_unchecked(c.get_raw_conn(),
                                                              device as u32);  // 0
        GetDeviceContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_WINDOW_CREATE_CONTEXT: u8 = 5;

pub fn set_window_create_context<'a>(c      : &'a base::Connection,
                                     context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_window_create_context(c.get_raw_conn(),
                                                           context_len as u32,  // 0
                                                           context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_window_create_context_checked<'a>(c      : &'a base::Connection,
                                             context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_window_create_context_checked(c.get_raw_conn(),
                                                                   context_len as u32,  // 0
                                                                   context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_WINDOW_CREATE_CONTEXT: u8 = 6;

pub type GetWindowCreateContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_window_create_context_cookie_t>;

impl<'a> GetWindowCreateContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetWindowCreateContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetWindowCreateContextReply {
                    ptr: xcb_selinux_get_window_create_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetWindowCreateContextReply {
                    ptr: xcb_selinux_get_window_create_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetWindowCreateContextReply = base::Reply<xcb_selinux_get_window_create_context_reply_t>;

impl GetWindowCreateContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_window_create_context_context_length(field) as usize;
            let data = xcb_selinux_get_window_create_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_window_create_context<'a>(c: &'a base::Connection)
        -> GetWindowCreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_window_create_context(c.get_raw_conn());
        GetWindowCreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_window_create_context_unchecked<'a>(c: &'a base::Connection)
        -> GetWindowCreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_window_create_context_unchecked(c.get_raw_conn());
        GetWindowCreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_WINDOW_CONTEXT: u8 = 7;

pub type GetWindowContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_window_context_cookie_t>;

impl<'a> GetWindowContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetWindowContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetWindowContextReply {
                    ptr: xcb_selinux_get_window_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetWindowContextReply {
                    ptr: xcb_selinux_get_window_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetWindowContextReply = base::Reply<xcb_selinux_get_window_context_reply_t>;

impl GetWindowContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_window_context_context_length(field) as usize;
            let data = xcb_selinux_get_window_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_window_context<'a>(c     : &'a base::Connection,
                              window: xproto::Window)
        -> GetWindowContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_window_context(c.get_raw_conn(),
                                                    window as xcb_window_t);  // 0
        GetWindowContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_window_context_unchecked<'a>(c     : &'a base::Connection,
                                        window: xproto::Window)
        -> GetWindowContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_window_context_unchecked(c.get_raw_conn(),
                                                              window as xcb_window_t);  // 0
        GetWindowContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type ListItem<'a> = base::StructPtr<'a, xcb_selinux_list_item_t>;

impl<'a> ListItem<'a> {
    pub fn name(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).name
        }
    }
    pub fn object_context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).object_context_len
        }
    }
    pub fn data_context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).data_context_len
        }
    }
    pub fn object_context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_list_item_object_context_length(field) as usize;
            let data = xcb_selinux_list_item_object_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn data_context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_list_item_data_context_length(field) as usize;
            let data = xcb_selinux_list_item_data_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type ListItemIterator<'a> = xcb_selinux_list_item_iterator_t<'a>;

impl<'a> Iterator for ListItemIterator<'a> {
    type Item = ListItem<'a>;
    fn next(&mut self) -> std::option::Option<ListItem<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_selinux_list_item_iterator_t;
                let data = (*iter).data;
                xcb_selinux_list_item_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const SET_PROPERTY_CREATE_CONTEXT: u8 = 8;

pub fn set_property_create_context<'a>(c      : &'a base::Connection,
                                       context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_property_create_context(c.get_raw_conn(),
                                                             context_len as u32,  // 0
                                                             context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_property_create_context_checked<'a>(c      : &'a base::Connection,
                                               context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_property_create_context_checked(c.get_raw_conn(),
                                                                     context_len as u32,  // 0
                                                                     context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_PROPERTY_CREATE_CONTEXT: u8 = 9;

pub type GetPropertyCreateContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_property_create_context_cookie_t>;

impl<'a> GetPropertyCreateContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPropertyCreateContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPropertyCreateContextReply {
                    ptr: xcb_selinux_get_property_create_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPropertyCreateContextReply {
                    ptr: xcb_selinux_get_property_create_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPropertyCreateContextReply = base::Reply<xcb_selinux_get_property_create_context_reply_t>;

impl GetPropertyCreateContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_property_create_context_context_length(field) as usize;
            let data = xcb_selinux_get_property_create_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_property_create_context<'a>(c: &'a base::Connection)
        -> GetPropertyCreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_property_create_context(c.get_raw_conn());
        GetPropertyCreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_property_create_context_unchecked<'a>(c: &'a base::Connection)
        -> GetPropertyCreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_property_create_context_unchecked(c.get_raw_conn());
        GetPropertyCreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_PROPERTY_USE_CONTEXT: u8 = 10;

pub fn set_property_use_context<'a>(c      : &'a base::Connection,
                                    context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_property_use_context(c.get_raw_conn(),
                                                          context_len as u32,  // 0
                                                          context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_property_use_context_checked<'a>(c      : &'a base::Connection,
                                            context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_property_use_context_checked(c.get_raw_conn(),
                                                                  context_len as u32,  // 0
                                                                  context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_PROPERTY_USE_CONTEXT: u8 = 11;

pub type GetPropertyUseContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_property_use_context_cookie_t>;

impl<'a> GetPropertyUseContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPropertyUseContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPropertyUseContextReply {
                    ptr: xcb_selinux_get_property_use_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPropertyUseContextReply {
                    ptr: xcb_selinux_get_property_use_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPropertyUseContextReply = base::Reply<xcb_selinux_get_property_use_context_reply_t>;

impl GetPropertyUseContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_property_use_context_context_length(field) as usize;
            let data = xcb_selinux_get_property_use_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_property_use_context<'a>(c: &'a base::Connection)
        -> GetPropertyUseContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_property_use_context(c.get_raw_conn());
        GetPropertyUseContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_property_use_context_unchecked<'a>(c: &'a base::Connection)
        -> GetPropertyUseContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_property_use_context_unchecked(c.get_raw_conn());
        GetPropertyUseContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PROPERTY_CONTEXT: u8 = 12;

pub type GetPropertyContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_property_context_cookie_t>;

impl<'a> GetPropertyContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPropertyContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPropertyContextReply {
                    ptr: xcb_selinux_get_property_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPropertyContextReply {
                    ptr: xcb_selinux_get_property_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPropertyContextReply = base::Reply<xcb_selinux_get_property_context_reply_t>;

impl GetPropertyContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_property_context_context_length(field) as usize;
            let data = xcb_selinux_get_property_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_property_context<'a>(c       : &'a base::Connection,
                                window  : xproto::Window,
                                property: xproto::Atom)
        -> GetPropertyContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_property_context(c.get_raw_conn(),
                                                      window as xcb_window_t,  // 0
                                                      property as xcb_atom_t);  // 1
        GetPropertyContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_property_context_unchecked<'a>(c       : &'a base::Connection,
                                          window  : xproto::Window,
                                          property: xproto::Atom)
        -> GetPropertyContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_property_context_unchecked(c.get_raw_conn(),
                                                                window as xcb_window_t,  // 0
                                                                property as xcb_atom_t);  // 1
        GetPropertyContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PROPERTY_DATA_CONTEXT: u8 = 13;

pub type GetPropertyDataContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_property_data_context_cookie_t>;

impl<'a> GetPropertyDataContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPropertyDataContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPropertyDataContextReply {
                    ptr: xcb_selinux_get_property_data_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPropertyDataContextReply {
                    ptr: xcb_selinux_get_property_data_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPropertyDataContextReply = base::Reply<xcb_selinux_get_property_data_context_reply_t>;

impl GetPropertyDataContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_property_data_context_context_length(field) as usize;
            let data = xcb_selinux_get_property_data_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_property_data_context<'a>(c       : &'a base::Connection,
                                     window  : xproto::Window,
                                     property: xproto::Atom)
        -> GetPropertyDataContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_property_data_context(c.get_raw_conn(),
                                                           window as xcb_window_t,  // 0
                                                           property as xcb_atom_t);  // 1
        GetPropertyDataContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_property_data_context_unchecked<'a>(c       : &'a base::Connection,
                                               window  : xproto::Window,
                                               property: xproto::Atom)
        -> GetPropertyDataContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_property_data_context_unchecked(c.get_raw_conn(),
                                                                     window as xcb_window_t,  // 0
                                                                     property as xcb_atom_t);  // 1
        GetPropertyDataContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_PROPERTIES: u8 = 14;

pub type ListPropertiesCookie<'a> = base::Cookie<'a, xcb_selinux_list_properties_cookie_t>;

impl<'a> ListPropertiesCookie<'a> {
    pub fn get_reply(&self) -> Result<ListPropertiesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListPropertiesReply {
                    ptr: xcb_selinux_list_properties_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListPropertiesReply {
                    ptr: xcb_selinux_list_properties_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListPropertiesReply = base::Reply<xcb_selinux_list_properties_reply_t>;

impl ListPropertiesReply {
    pub fn properties_len(&self) -> u32 {
        unsafe {
            (*self.ptr).properties_len
        }
    }
    pub fn properties(&self) -> ListItemIterator {
        unsafe {
            xcb_selinux_list_properties_properties_iterator(self.ptr)
        }
    }
}

pub fn list_properties<'a>(c     : &'a base::Connection,
                           window: xproto::Window)
        -> ListPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_list_properties(c.get_raw_conn(),
                                                 window as xcb_window_t);  // 0
        ListPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_properties_unchecked<'a>(c     : &'a base::Connection,
                                     window: xproto::Window)
        -> ListPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_list_properties_unchecked(c.get_raw_conn(),
                                                           window as xcb_window_t);  // 0
        ListPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_SELECTION_CREATE_CONTEXT: u8 = 15;

pub fn set_selection_create_context<'a>(c      : &'a base::Connection,
                                        context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_selection_create_context(c.get_raw_conn(),
                                                              context_len as u32,  // 0
                                                              context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_selection_create_context_checked<'a>(c      : &'a base::Connection,
                                                context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_selection_create_context_checked(c.get_raw_conn(),
                                                                      context_len as u32,  // 0
                                                                      context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_SELECTION_CREATE_CONTEXT: u8 = 16;

pub type GetSelectionCreateContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_selection_create_context_cookie_t>;

impl<'a> GetSelectionCreateContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetSelectionCreateContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetSelectionCreateContextReply {
                    ptr: xcb_selinux_get_selection_create_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetSelectionCreateContextReply {
                    ptr: xcb_selinux_get_selection_create_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetSelectionCreateContextReply = base::Reply<xcb_selinux_get_selection_create_context_reply_t>;

impl GetSelectionCreateContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_selection_create_context_context_length(field) as usize;
            let data = xcb_selinux_get_selection_create_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_selection_create_context<'a>(c: &'a base::Connection)
        -> GetSelectionCreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_selection_create_context(c.get_raw_conn());
        GetSelectionCreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_selection_create_context_unchecked<'a>(c: &'a base::Connection)
        -> GetSelectionCreateContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_selection_create_context_unchecked(c.get_raw_conn());
        GetSelectionCreateContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_SELECTION_USE_CONTEXT: u8 = 17;

pub fn set_selection_use_context<'a>(c      : &'a base::Connection,
                                     context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_selection_use_context(c.get_raw_conn(),
                                                           context_len as u32,  // 0
                                                           context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_selection_use_context_checked<'a>(c      : &'a base::Connection,
                                             context: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let context = context.as_bytes();
        let context_len = context.len();
        let context_ptr = context.as_ptr();
        let cookie = xcb_selinux_set_selection_use_context_checked(c.get_raw_conn(),
                                                                   context_len as u32,  // 0
                                                                   context_ptr as *const c_char);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_SELECTION_USE_CONTEXT: u8 = 18;

pub type GetSelectionUseContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_selection_use_context_cookie_t>;

impl<'a> GetSelectionUseContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetSelectionUseContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetSelectionUseContextReply {
                    ptr: xcb_selinux_get_selection_use_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetSelectionUseContextReply {
                    ptr: xcb_selinux_get_selection_use_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetSelectionUseContextReply = base::Reply<xcb_selinux_get_selection_use_context_reply_t>;

impl GetSelectionUseContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_selection_use_context_context_length(field) as usize;
            let data = xcb_selinux_get_selection_use_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_selection_use_context<'a>(c: &'a base::Connection)
        -> GetSelectionUseContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_selection_use_context(c.get_raw_conn());
        GetSelectionUseContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_selection_use_context_unchecked<'a>(c: &'a base::Connection)
        -> GetSelectionUseContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_selection_use_context_unchecked(c.get_raw_conn());
        GetSelectionUseContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_SELECTION_CONTEXT: u8 = 19;

pub type GetSelectionContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_selection_context_cookie_t>;

impl<'a> GetSelectionContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetSelectionContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetSelectionContextReply {
                    ptr: xcb_selinux_get_selection_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetSelectionContextReply {
                    ptr: xcb_selinux_get_selection_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetSelectionContextReply = base::Reply<xcb_selinux_get_selection_context_reply_t>;

impl GetSelectionContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_selection_context_context_length(field) as usize;
            let data = xcb_selinux_get_selection_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_selection_context<'a>(c        : &'a base::Connection,
                                 selection: xproto::Atom)
        -> GetSelectionContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_selection_context(c.get_raw_conn(),
                                                       selection as xcb_atom_t);  // 0
        GetSelectionContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_selection_context_unchecked<'a>(c        : &'a base::Connection,
                                           selection: xproto::Atom)
        -> GetSelectionContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_selection_context_unchecked(c.get_raw_conn(),
                                                                 selection as xcb_atom_t);  // 0
        GetSelectionContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_SELECTION_DATA_CONTEXT: u8 = 20;

pub type GetSelectionDataContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_selection_data_context_cookie_t>;

impl<'a> GetSelectionDataContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetSelectionDataContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetSelectionDataContextReply {
                    ptr: xcb_selinux_get_selection_data_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetSelectionDataContextReply {
                    ptr: xcb_selinux_get_selection_data_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetSelectionDataContextReply = base::Reply<xcb_selinux_get_selection_data_context_reply_t>;

impl GetSelectionDataContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_selection_data_context_context_length(field) as usize;
            let data = xcb_selinux_get_selection_data_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_selection_data_context<'a>(c        : &'a base::Connection,
                                      selection: xproto::Atom)
        -> GetSelectionDataContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_selection_data_context(c.get_raw_conn(),
                                                            selection as xcb_atom_t);  // 0
        GetSelectionDataContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_selection_data_context_unchecked<'a>(c        : &'a base::Connection,
                                                selection: xproto::Atom)
        -> GetSelectionDataContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_selection_data_context_unchecked(c.get_raw_conn(),
                                                                      selection as xcb_atom_t);  // 0
        GetSelectionDataContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_SELECTIONS: u8 = 21;

pub type ListSelectionsCookie<'a> = base::Cookie<'a, xcb_selinux_list_selections_cookie_t>;

impl<'a> ListSelectionsCookie<'a> {
    pub fn get_reply(&self) -> Result<ListSelectionsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListSelectionsReply {
                    ptr: xcb_selinux_list_selections_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListSelectionsReply {
                    ptr: xcb_selinux_list_selections_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListSelectionsReply = base::Reply<xcb_selinux_list_selections_reply_t>;

impl ListSelectionsReply {
    pub fn selections_len(&self) -> u32 {
        unsafe {
            (*self.ptr).selections_len
        }
    }
    pub fn selections(&self) -> ListItemIterator {
        unsafe {
            xcb_selinux_list_selections_selections_iterator(self.ptr)
        }
    }
}

pub fn list_selections<'a>(c: &'a base::Connection)
        -> ListSelectionsCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_list_selections(c.get_raw_conn());
        ListSelectionsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_selections_unchecked<'a>(c: &'a base::Connection)
        -> ListSelectionsCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_list_selections_unchecked(c.get_raw_conn());
        ListSelectionsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_CLIENT_CONTEXT: u8 = 22;

pub type GetClientContextCookie<'a> = base::Cookie<'a, xcb_selinux_get_client_context_cookie_t>;

impl<'a> GetClientContextCookie<'a> {
    pub fn get_reply(&self) -> Result<GetClientContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetClientContextReply {
                    ptr: xcb_selinux_get_client_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetClientContextReply {
                    ptr: xcb_selinux_get_client_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetClientContextReply = base::Reply<xcb_selinux_get_client_context_reply_t>;

impl GetClientContextReply {
    pub fn context_len(&self) -> u32 {
        unsafe {
            (*self.ptr).context_len
        }
    }
    pub fn context(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_selinux_get_client_context_context_length(field) as usize;
            let data = xcb_selinux_get_client_context_context(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_client_context<'a>(c       : &'a base::Connection,
                              resource: u32)
        -> GetClientContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_client_context(c.get_raw_conn(),
                                                    resource as u32);  // 0
        GetClientContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_client_context_unchecked<'a>(c       : &'a base::Connection,
                                        resource: u32)
        -> GetClientContextCookie<'a> {
    unsafe {
        let cookie = xcb_selinux_get_client_context_unchecked(c.get_raw_conn(),
                                                              resource as u32);  // 0
        GetClientContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
