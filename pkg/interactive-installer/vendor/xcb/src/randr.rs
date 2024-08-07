// Generated automatically from randr.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use render;
use ffi::base::*;
use ffi::randr::*;
use ffi::xproto::*;
use ffi::render::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_randr_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 4;

pub type Mode = xcb_randr_mode_t;

pub type Crtc = xcb_randr_crtc_t;

pub type Output = xcb_randr_output_t;

pub type Provider = xcb_randr_provider_t;

pub struct BadOutputError {
    pub base: base::Error<xcb_randr_bad_output_error_t>
}

pub struct BadCrtcError {
    pub base: base::Error<xcb_randr_bad_crtc_error_t>
}

pub struct BadModeError {
    pub base: base::Error<xcb_randr_bad_mode_error_t>
}

pub struct BadProviderError {
    pub base: base::Error<xcb_randr_bad_provider_error_t>
}

pub type Rotation = u32;
pub const ROTATION_ROTATE_0  : Rotation = 0x01;
pub const ROTATION_ROTATE_90 : Rotation = 0x02;
pub const ROTATION_ROTATE_180: Rotation = 0x04;
pub const ROTATION_ROTATE_270: Rotation = 0x08;
pub const ROTATION_REFLECT_X : Rotation = 0x10;
pub const ROTATION_REFLECT_Y : Rotation = 0x20;

pub type SetConfig = u32;
pub const SET_CONFIG_SUCCESS            : SetConfig = 0x00;
pub const SET_CONFIG_INVALID_CONFIG_TIME: SetConfig = 0x01;
pub const SET_CONFIG_INVALID_TIME       : SetConfig = 0x02;
pub const SET_CONFIG_FAILED             : SetConfig = 0x03;

pub type NotifyMask = u32;
pub const NOTIFY_MASK_SCREEN_CHANGE    : NotifyMask = 0x01;
pub const NOTIFY_MASK_CRTC_CHANGE      : NotifyMask = 0x02;
pub const NOTIFY_MASK_OUTPUT_CHANGE    : NotifyMask = 0x04;
pub const NOTIFY_MASK_OUTPUT_PROPERTY  : NotifyMask = 0x08;
pub const NOTIFY_MASK_PROVIDER_CHANGE  : NotifyMask = 0x10;
pub const NOTIFY_MASK_PROVIDER_PROPERTY: NotifyMask = 0x20;
pub const NOTIFY_MASK_RESOURCE_CHANGE  : NotifyMask = 0x40;

pub type ModeFlag = u32;
pub const MODE_FLAG_HSYNC_POSITIVE : ModeFlag =   0x01;
pub const MODE_FLAG_HSYNC_NEGATIVE : ModeFlag =   0x02;
pub const MODE_FLAG_VSYNC_POSITIVE : ModeFlag =   0x04;
pub const MODE_FLAG_VSYNC_NEGATIVE : ModeFlag =   0x08;
pub const MODE_FLAG_INTERLACE      : ModeFlag =   0x10;
pub const MODE_FLAG_DOUBLE_SCAN    : ModeFlag =   0x20;
pub const MODE_FLAG_CSYNC          : ModeFlag =   0x40;
pub const MODE_FLAG_CSYNC_POSITIVE : ModeFlag =   0x80;
pub const MODE_FLAG_CSYNC_NEGATIVE : ModeFlag =  0x100;
pub const MODE_FLAG_HSKEW_PRESENT  : ModeFlag =  0x200;
pub const MODE_FLAG_BCAST          : ModeFlag =  0x400;
pub const MODE_FLAG_PIXEL_MULTIPLEX: ModeFlag =  0x800;
pub const MODE_FLAG_DOUBLE_CLOCK   : ModeFlag = 0x1000;
pub const MODE_FLAG_HALVE_CLOCK    : ModeFlag = 0x2000;

pub type Connection = u32;
pub const CONNECTION_CONNECTED   : Connection = 0x00;
pub const CONNECTION_DISCONNECTED: Connection = 0x01;
pub const CONNECTION_UNKNOWN     : Connection = 0x02;

pub type Transform = u32;
pub const TRANSFORM_UNIT      : Transform = 0x01;
pub const TRANSFORM_SCALE_UP  : Transform = 0x02;
pub const TRANSFORM_SCALE_DOWN: Transform = 0x04;
pub const TRANSFORM_PROJECTIVE: Transform = 0x08;

pub type ProviderCapability = u32;
pub const PROVIDER_CAPABILITY_SOURCE_OUTPUT : ProviderCapability = 0x01;
pub const PROVIDER_CAPABILITY_SINK_OUTPUT   : ProviderCapability = 0x02;
pub const PROVIDER_CAPABILITY_SOURCE_OFFLOAD: ProviderCapability = 0x04;
pub const PROVIDER_CAPABILITY_SINK_OFFLOAD  : ProviderCapability = 0x08;

pub type Notify = u32;
pub const NOTIFY_CRTC_CHANGE      : Notify = 0x00;
pub const NOTIFY_OUTPUT_CHANGE    : Notify = 0x01;
pub const NOTIFY_OUTPUT_PROPERTY  : Notify = 0x02;
pub const NOTIFY_PROVIDER_CHANGE  : Notify = 0x03;
pub const NOTIFY_PROVIDER_PROPERTY: Notify = 0x04;
pub const NOTIFY_RESOURCE_CHANGE  : Notify = 0x05;



pub const BAD_OUTPUT: u8 = 0;

pub const BAD_CRTC: u8 = 1;

pub const BAD_MODE: u8 = 2;

pub const BAD_PROVIDER: u8 = 3;

#[derive(Copy, Clone)]
pub struct ScreenSize {
    pub base: xcb_randr_screen_size_t,
}

impl ScreenSize {
    #[allow(unused_unsafe)]
    pub fn new(width:   u16,
               height:  u16,
               mwidth:  u16,
               mheight: u16)
            -> ScreenSize {
        unsafe {
            ScreenSize {
                base: xcb_randr_screen_size_t {
                    width:   width,
                    height:  height,
                    mwidth:  mwidth,
                    mheight: mheight,
                }
            }
        }
    }
    pub fn width(&self) -> u16 {
        unsafe {
            self.base.width
        }
    }
    pub fn height(&self) -> u16 {
        unsafe {
            self.base.height
        }
    }
    pub fn mwidth(&self) -> u16 {
        unsafe {
            self.base.mwidth
        }
    }
    pub fn mheight(&self) -> u16 {
        unsafe {
            self.base.mheight
        }
    }
}

pub type ScreenSizeIterator = xcb_randr_screen_size_iterator_t;

impl Iterator for ScreenSizeIterator {
    type Item = ScreenSize;
    fn next(&mut self) -> std::option::Option<ScreenSize> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_screen_size_iterator_t;
                let data = (*iter).data;
                xcb_randr_screen_size_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type RefreshRates<'a> = base::StructPtr<'a, xcb_randr_refresh_rates_t>;

impl<'a> RefreshRates<'a> {
    pub fn n_rates(&self) -> u16 {
        unsafe {
            (*self.ptr).nRates
        }
    }
    pub fn rates(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_refresh_rates_rates_length(field) as usize;
            let data = xcb_randr_refresh_rates_rates(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type RefreshRatesIterator<'a> = xcb_randr_refresh_rates_iterator_t<'a>;

impl<'a> Iterator for RefreshRatesIterator<'a> {
    type Item = RefreshRates<'a>;
    fn next(&mut self) -> std::option::Option<RefreshRates<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_refresh_rates_iterator_t;
                let data = (*iter).data;
                xcb_randr_refresh_rates_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_randr_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_randr_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_randr_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_randr_query_version_reply_t>;

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
        let cookie = xcb_randr_query_version(c.get_raw_conn(),
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
        let cookie = xcb_randr_query_version_unchecked(c.get_raw_conn(),
                                                       major_version as u32,  // 0
                                                       minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_SCREEN_CONFIG: u8 = 2;

pub type SetScreenConfigCookie<'a> = base::Cookie<'a, xcb_randr_set_screen_config_cookie_t>;

impl<'a> SetScreenConfigCookie<'a> {
    pub fn get_reply(&self) -> Result<SetScreenConfigReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetScreenConfigReply {
                    ptr: xcb_randr_set_screen_config_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetScreenConfigReply {
                    ptr: xcb_randr_set_screen_config_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetScreenConfigReply = base::Reply<xcb_randr_set_screen_config_reply_t>;

impl SetScreenConfigReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn new_timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).new_timestamp
        }
    }
    pub fn config_timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).config_timestamp
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn subpixel_order(&self) -> u16 {
        unsafe {
            (*self.ptr).subpixel_order
        }
    }
}

pub fn set_screen_config<'a>(c               : &'a base::Connection,
                             window          : xproto::Window,
                             timestamp       : xproto::Timestamp,
                             config_timestamp: xproto::Timestamp,
                             size_i_d        : u16,
                             rotation        : u16,
                             rate            : u16)
        -> SetScreenConfigCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_screen_config(c.get_raw_conn(),
                                                 window as xcb_window_t,  // 0
                                                 timestamp as xcb_timestamp_t,  // 1
                                                 config_timestamp as xcb_timestamp_t,  // 2
                                                 size_i_d as u16,  // 3
                                                 rotation as u16,  // 4
                                                 rate as u16);  // 5
        SetScreenConfigCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_screen_config_unchecked<'a>(c               : &'a base::Connection,
                                       window          : xproto::Window,
                                       timestamp       : xproto::Timestamp,
                                       config_timestamp: xproto::Timestamp,
                                       size_i_d        : u16,
                                       rotation        : u16,
                                       rate            : u16)
        -> SetScreenConfigCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_screen_config_unchecked(c.get_raw_conn(),
                                                           window as xcb_window_t,  // 0
                                                           timestamp as xcb_timestamp_t,  // 1
                                                           config_timestamp as xcb_timestamp_t,  // 2
                                                           size_i_d as u16,  // 3
                                                           rotation as u16,  // 4
                                                           rate as u16);  // 5
        SetScreenConfigCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SELECT_INPUT: u8 = 4;

pub fn select_input<'a>(c     : &'a base::Connection,
                        window: xproto::Window,
                        enable: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_select_input(c.get_raw_conn(),
                                            window as xcb_window_t,  // 0
                                            enable as u16);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_input_checked<'a>(c     : &'a base::Connection,
                                window: xproto::Window,
                                enable: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_select_input_checked(c.get_raw_conn(),
                                                    window as xcb_window_t,  // 0
                                                    enable as u16);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_SCREEN_INFO: u8 = 5;

pub type GetScreenInfoCookie<'a> = base::Cookie<'a, xcb_randr_get_screen_info_cookie_t>;

impl<'a> GetScreenInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<GetScreenInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetScreenInfoReply {
                    ptr: xcb_randr_get_screen_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetScreenInfoReply {
                    ptr: xcb_randr_get_screen_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetScreenInfoReply = base::Reply<xcb_randr_get_screen_info_reply_t>;

impl GetScreenInfoReply {
    pub fn rotations(&self) -> u8 {
        unsafe {
            (*self.ptr).rotations
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn config_timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).config_timestamp
        }
    }
    pub fn n_sizes(&self) -> u16 {
        unsafe {
            (*self.ptr).nSizes
        }
    }
    pub fn size_i_d(&self) -> u16 {
        unsafe {
            (*self.ptr).sizeID
        }
    }
    pub fn rotation(&self) -> u16 {
        unsafe {
            (*self.ptr).rotation
        }
    }
    pub fn rate(&self) -> u16 {
        unsafe {
            (*self.ptr).rate
        }
    }
    pub fn n_info(&self) -> u16 {
        unsafe {
            (*self.ptr).nInfo
        }
    }
    pub fn sizes(&self) -> ScreenSizeIterator {
        unsafe {
            xcb_randr_get_screen_info_sizes_iterator(self.ptr)
        }
    }
    pub fn rates(&self) -> RefreshRatesIterator {
        unsafe {
            xcb_randr_get_screen_info_rates_iterator(self.ptr)
        }
    }
}

pub fn get_screen_info<'a>(c     : &'a base::Connection,
                           window: xproto::Window)
        -> GetScreenInfoCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_screen_info(c.get_raw_conn(),
                                               window as xcb_window_t);  // 0
        GetScreenInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_screen_info_unchecked<'a>(c     : &'a base::Connection,
                                     window: xproto::Window)
        -> GetScreenInfoCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_screen_info_unchecked(c.get_raw_conn(),
                                                         window as xcb_window_t);  // 0
        GetScreenInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_SCREEN_SIZE_RANGE: u8 = 6;

pub type GetScreenSizeRangeCookie<'a> = base::Cookie<'a, xcb_randr_get_screen_size_range_cookie_t>;

impl<'a> GetScreenSizeRangeCookie<'a> {
    pub fn get_reply(&self) -> Result<GetScreenSizeRangeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetScreenSizeRangeReply {
                    ptr: xcb_randr_get_screen_size_range_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetScreenSizeRangeReply {
                    ptr: xcb_randr_get_screen_size_range_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetScreenSizeRangeReply = base::Reply<xcb_randr_get_screen_size_range_reply_t>;

impl GetScreenSizeRangeReply {
    pub fn min_width(&self) -> u16 {
        unsafe {
            (*self.ptr).min_width
        }
    }
    pub fn min_height(&self) -> u16 {
        unsafe {
            (*self.ptr).min_height
        }
    }
    pub fn max_width(&self) -> u16 {
        unsafe {
            (*self.ptr).max_width
        }
    }
    pub fn max_height(&self) -> u16 {
        unsafe {
            (*self.ptr).max_height
        }
    }
}

pub fn get_screen_size_range<'a>(c     : &'a base::Connection,
                                 window: xproto::Window)
        -> GetScreenSizeRangeCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_screen_size_range(c.get_raw_conn(),
                                                     window as xcb_window_t);  // 0
        GetScreenSizeRangeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_screen_size_range_unchecked<'a>(c     : &'a base::Connection,
                                           window: xproto::Window)
        -> GetScreenSizeRangeCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_screen_size_range_unchecked(c.get_raw_conn(),
                                                               window as xcb_window_t);  // 0
        GetScreenSizeRangeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_SCREEN_SIZE: u8 = 7;

pub fn set_screen_size<'a>(c        : &'a base::Connection,
                           window   : xproto::Window,
                           width    : u16,
                           height   : u16,
                           mm_width : u32,
                           mm_height: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_screen_size(c.get_raw_conn(),
                                               window as xcb_window_t,  // 0
                                               width as u16,  // 1
                                               height as u16,  // 2
                                               mm_width as u32,  // 3
                                               mm_height as u32);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_screen_size_checked<'a>(c        : &'a base::Connection,
                                   window   : xproto::Window,
                                   width    : u16,
                                   height   : u16,
                                   mm_width : u32,
                                   mm_height: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_screen_size_checked(c.get_raw_conn(),
                                                       window as xcb_window_t,  // 0
                                                       width as u16,  // 1
                                                       height as u16,  // 2
                                                       mm_width as u32,  // 3
                                                       mm_height as u32);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct ModeInfo {
    pub base: xcb_randr_mode_info_t,
}

impl ModeInfo {
    #[allow(unused_unsafe)]
    pub fn new(id:          u32,
               width:       u16,
               height:      u16,
               dot_clock:   u32,
               hsync_start: u16,
               hsync_end:   u16,
               htotal:      u16,
               hskew:       u16,
               vsync_start: u16,
               vsync_end:   u16,
               vtotal:      u16,
               name_len:    u16,
               mode_flags:  u32)
            -> ModeInfo {
        unsafe {
            ModeInfo {
                base: xcb_randr_mode_info_t {
                    id:          id,
                    width:       width,
                    height:      height,
                    dot_clock:   dot_clock,
                    hsync_start: hsync_start,
                    hsync_end:   hsync_end,
                    htotal:      htotal,
                    hskew:       hskew,
                    vsync_start: vsync_start,
                    vsync_end:   vsync_end,
                    vtotal:      vtotal,
                    name_len:    name_len,
                    mode_flags:  mode_flags,
                }
            }
        }
    }
    pub fn id(&self) -> u32 {
        unsafe {
            self.base.id
        }
    }
    pub fn width(&self) -> u16 {
        unsafe {
            self.base.width
        }
    }
    pub fn height(&self) -> u16 {
        unsafe {
            self.base.height
        }
    }
    pub fn dot_clock(&self) -> u32 {
        unsafe {
            self.base.dot_clock
        }
    }
    pub fn hsync_start(&self) -> u16 {
        unsafe {
            self.base.hsync_start
        }
    }
    pub fn hsync_end(&self) -> u16 {
        unsafe {
            self.base.hsync_end
        }
    }
    pub fn htotal(&self) -> u16 {
        unsafe {
            self.base.htotal
        }
    }
    pub fn hskew(&self) -> u16 {
        unsafe {
            self.base.hskew
        }
    }
    pub fn vsync_start(&self) -> u16 {
        unsafe {
            self.base.vsync_start
        }
    }
    pub fn vsync_end(&self) -> u16 {
        unsafe {
            self.base.vsync_end
        }
    }
    pub fn vtotal(&self) -> u16 {
        unsafe {
            self.base.vtotal
        }
    }
    pub fn name_len(&self) -> u16 {
        unsafe {
            self.base.name_len
        }
    }
    pub fn mode_flags(&self) -> u32 {
        unsafe {
            self.base.mode_flags
        }
    }
}

pub type ModeInfoIterator = xcb_randr_mode_info_iterator_t;

impl Iterator for ModeInfoIterator {
    type Item = ModeInfo;
    fn next(&mut self) -> std::option::Option<ModeInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_mode_info_iterator_t;
                let data = (*iter).data;
                xcb_randr_mode_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const GET_SCREEN_RESOURCES: u8 = 8;

pub type GetScreenResourcesCookie<'a> = base::Cookie<'a, xcb_randr_get_screen_resources_cookie_t>;

impl<'a> GetScreenResourcesCookie<'a> {
    pub fn get_reply(&self) -> Result<GetScreenResourcesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetScreenResourcesReply {
                    ptr: xcb_randr_get_screen_resources_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetScreenResourcesReply {
                    ptr: xcb_randr_get_screen_resources_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetScreenResourcesReply = base::Reply<xcb_randr_get_screen_resources_reply_t>;

impl GetScreenResourcesReply {
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn config_timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).config_timestamp
        }
    }
    pub fn num_crtcs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_crtcs
        }
    }
    pub fn num_outputs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_outputs
        }
    }
    pub fn num_modes(&self) -> u16 {
        unsafe {
            (*self.ptr).num_modes
        }
    }
    pub fn names_len(&self) -> u16 {
        unsafe {
            (*self.ptr).names_len
        }
    }
    pub fn crtcs(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_screen_resources_crtcs_length(field) as usize;
            let data = xcb_randr_get_screen_resources_crtcs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn outputs(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_screen_resources_outputs_length(field) as usize;
            let data = xcb_randr_get_screen_resources_outputs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn modes(&self) -> ModeInfoIterator {
        unsafe {
            xcb_randr_get_screen_resources_modes_iterator(self.ptr)
        }
    }
    pub fn names(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_screen_resources_names_length(field) as usize;
            let data = xcb_randr_get_screen_resources_names(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_screen_resources<'a>(c     : &'a base::Connection,
                                window: xproto::Window)
        -> GetScreenResourcesCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_screen_resources(c.get_raw_conn(),
                                                    window as xcb_window_t);  // 0
        GetScreenResourcesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_screen_resources_unchecked<'a>(c     : &'a base::Connection,
                                          window: xproto::Window)
        -> GetScreenResourcesCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_screen_resources_unchecked(c.get_raw_conn(),
                                                              window as xcb_window_t);  // 0
        GetScreenResourcesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_OUTPUT_INFO: u8 = 9;

pub type GetOutputInfoCookie<'a> = base::Cookie<'a, xcb_randr_get_output_info_cookie_t>;

impl<'a> GetOutputInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<GetOutputInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetOutputInfoReply {
                    ptr: xcb_randr_get_output_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetOutputInfoReply {
                    ptr: xcb_randr_get_output_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetOutputInfoReply = base::Reply<xcb_randr_get_output_info_reply_t>;

impl GetOutputInfoReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn crtc(&self) -> Crtc {
        unsafe {
            (*self.ptr).crtc
        }
    }
    pub fn mm_width(&self) -> u32 {
        unsafe {
            (*self.ptr).mm_width
        }
    }
    pub fn mm_height(&self) -> u32 {
        unsafe {
            (*self.ptr).mm_height
        }
    }
    pub fn connection(&self) -> u8 {
        unsafe {
            (*self.ptr).connection
        }
    }
    pub fn subpixel_order(&self) -> u8 {
        unsafe {
            (*self.ptr).subpixel_order
        }
    }
    pub fn num_crtcs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_crtcs
        }
    }
    pub fn num_modes(&self) -> u16 {
        unsafe {
            (*self.ptr).num_modes
        }
    }
    pub fn num_preferred(&self) -> u16 {
        unsafe {
            (*self.ptr).num_preferred
        }
    }
    pub fn num_clones(&self) -> u16 {
        unsafe {
            (*self.ptr).num_clones
        }
    }
    pub fn name_len(&self) -> u16 {
        unsafe {
            (*self.ptr).name_len
        }
    }
    pub fn crtcs(&self) -> &[Output] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_output_info_crtcs_length(field) as usize;
            let data = xcb_randr_get_output_info_crtcs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn modes(&self) -> &[Output] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_output_info_modes_length(field) as usize;
            let data = xcb_randr_get_output_info_modes(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn clones(&self) -> &[Output] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_output_info_clones_length(field) as usize;
            let data = xcb_randr_get_output_info_clones(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn name(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_output_info_name_length(field) as usize;
            let data = xcb_randr_get_output_info_name(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_output_info<'a>(c               : &'a base::Connection,
                           output          : Output,
                           config_timestamp: xproto::Timestamp)
        -> GetOutputInfoCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_output_info(c.get_raw_conn(),
                                               output as xcb_randr_output_t,  // 0
                                               config_timestamp as xcb_timestamp_t);  // 1
        GetOutputInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_output_info_unchecked<'a>(c               : &'a base::Connection,
                                     output          : Output,
                                     config_timestamp: xproto::Timestamp)
        -> GetOutputInfoCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_output_info_unchecked(c.get_raw_conn(),
                                                         output as xcb_randr_output_t,  // 0
                                                         config_timestamp as xcb_timestamp_t);  // 1
        GetOutputInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_OUTPUT_PROPERTIES: u8 = 10;

pub type ListOutputPropertiesCookie<'a> = base::Cookie<'a, xcb_randr_list_output_properties_cookie_t>;

impl<'a> ListOutputPropertiesCookie<'a> {
    pub fn get_reply(&self) -> Result<ListOutputPropertiesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListOutputPropertiesReply {
                    ptr: xcb_randr_list_output_properties_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListOutputPropertiesReply {
                    ptr: xcb_randr_list_output_properties_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListOutputPropertiesReply = base::Reply<xcb_randr_list_output_properties_reply_t>;

impl ListOutputPropertiesReply {
    pub fn num_atoms(&self) -> u16 {
        unsafe {
            (*self.ptr).num_atoms
        }
    }
    pub fn atoms(&self) -> &[xproto::Atom] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_list_output_properties_atoms_length(field) as usize;
            let data = xcb_randr_list_output_properties_atoms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn list_output_properties<'a>(c     : &'a base::Connection,
                                  output: Output)
        -> ListOutputPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_randr_list_output_properties(c.get_raw_conn(),
                                                      output as xcb_randr_output_t);  // 0
        ListOutputPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_output_properties_unchecked<'a>(c     : &'a base::Connection,
                                            output: Output)
        -> ListOutputPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_randr_list_output_properties_unchecked(c.get_raw_conn(),
                                                                output as xcb_randr_output_t);  // 0
        ListOutputPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_OUTPUT_PROPERTY: u8 = 11;

pub type QueryOutputPropertyCookie<'a> = base::Cookie<'a, xcb_randr_query_output_property_cookie_t>;

impl<'a> QueryOutputPropertyCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryOutputPropertyReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryOutputPropertyReply {
                    ptr: xcb_randr_query_output_property_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryOutputPropertyReply {
                    ptr: xcb_randr_query_output_property_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryOutputPropertyReply = base::Reply<xcb_randr_query_output_property_reply_t>;

impl QueryOutputPropertyReply {
    pub fn pending(&self) -> bool {
        unsafe {
            (*self.ptr).pending != 0
        }
    }
    pub fn range(&self) -> bool {
        unsafe {
            (*self.ptr).range != 0
        }
    }
    pub fn immutable(&self) -> bool {
        unsafe {
            (*self.ptr).immutable != 0
        }
    }
    pub fn valid_values(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_query_output_property_valid_values_length(field) as usize;
            let data = xcb_randr_query_output_property_valid_values(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn query_output_property<'a>(c       : &'a base::Connection,
                                 output  : Output,
                                 property: xproto::Atom)
        -> QueryOutputPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_randr_query_output_property(c.get_raw_conn(),
                                                     output as xcb_randr_output_t,  // 0
                                                     property as xcb_atom_t);  // 1
        QueryOutputPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_output_property_unchecked<'a>(c       : &'a base::Connection,
                                           output  : Output,
                                           property: xproto::Atom)
        -> QueryOutputPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_randr_query_output_property_unchecked(c.get_raw_conn(),
                                                               output as xcb_randr_output_t,  // 0
                                                               property as xcb_atom_t);  // 1
        QueryOutputPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CONFIGURE_OUTPUT_PROPERTY: u8 = 12;

pub fn configure_output_property<'a>(c       : &'a base::Connection,
                                     output  : Output,
                                     property: xproto::Atom,
                                     pending : bool,
                                     range   : bool,
                                     values  : &[i32])
        -> base::VoidCookie<'a> {
    unsafe {
        let values_len = values.len();
        let values_ptr = values.as_ptr();
        let cookie = xcb_randr_configure_output_property(c.get_raw_conn(),
                                                         output as xcb_randr_output_t,  // 0
                                                         property as xcb_atom_t,  // 1
                                                         pending as u8,  // 2
                                                         range as u8,  // 3
                                                         values_len as u32,  // 4
                                                         values_ptr as *const i32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn configure_output_property_checked<'a>(c       : &'a base::Connection,
                                             output  : Output,
                                             property: xproto::Atom,
                                             pending : bool,
                                             range   : bool,
                                             values  : &[i32])
        -> base::VoidCookie<'a> {
    unsafe {
        let values_len = values.len();
        let values_ptr = values.as_ptr();
        let cookie = xcb_randr_configure_output_property_checked(c.get_raw_conn(),
                                                                 output as xcb_randr_output_t,  // 0
                                                                 property as xcb_atom_t,  // 1
                                                                 pending as u8,  // 2
                                                                 range as u8,  // 3
                                                                 values_len as u32,  // 4
                                                                 values_ptr as *const i32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_OUTPUT_PROPERTY: u8 = 13;

pub fn change_output_property<'a, T>(c       : &'a base::Connection,
                                     output  : Output,
                                     property: xproto::Atom,
                                     type_   : xproto::Atom,
                                     format  : u8,
                                     mode    : u8,
                                     data    : &[T])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_randr_change_output_property(c.get_raw_conn(),
                                                      output as xcb_randr_output_t,  // 0
                                                      property as xcb_atom_t,  // 1
                                                      type_ as xcb_atom_t,  // 2
                                                      format as u8,  // 3
                                                      mode as u8,  // 4
                                                      data_len as u32,  // 5
                                                      data_ptr as *const c_void);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_output_property_checked<'a, T>(c       : &'a base::Connection,
                                             output  : Output,
                                             property: xproto::Atom,
                                             type_   : xproto::Atom,
                                             format  : u8,
                                             mode    : u8,
                                             data    : &[T])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_randr_change_output_property_checked(c.get_raw_conn(),
                                                              output as xcb_randr_output_t,  // 0
                                                              property as xcb_atom_t,  // 1
                                                              type_ as xcb_atom_t,  // 2
                                                              format as u8,  // 3
                                                              mode as u8,  // 4
                                                              data_len as u32,  // 5
                                                              data_ptr as *const c_void);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_OUTPUT_PROPERTY: u8 = 14;

pub fn delete_output_property<'a>(c       : &'a base::Connection,
                                  output  : Output,
                                  property: xproto::Atom)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_delete_output_property(c.get_raw_conn(),
                                                      output as xcb_randr_output_t,  // 0
                                                      property as xcb_atom_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_output_property_checked<'a>(c       : &'a base::Connection,
                                          output  : Output,
                                          property: xproto::Atom)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_delete_output_property_checked(c.get_raw_conn(),
                                                              output as xcb_randr_output_t,  // 0
                                                              property as xcb_atom_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_OUTPUT_PROPERTY: u8 = 15;

pub type GetOutputPropertyCookie<'a> = base::Cookie<'a, xcb_randr_get_output_property_cookie_t>;

impl<'a> GetOutputPropertyCookie<'a> {
    pub fn get_reply(&self) -> Result<GetOutputPropertyReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetOutputPropertyReply {
                    ptr: xcb_randr_get_output_property_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetOutputPropertyReply {
                    ptr: xcb_randr_get_output_property_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetOutputPropertyReply = base::Reply<xcb_randr_get_output_property_reply_t>;

impl GetOutputPropertyReply {
    pub fn format(&self) -> u8 {
        unsafe {
            (*self.ptr).format
        }
    }
    pub fn type_(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn bytes_after(&self) -> u32 {
        unsafe {
            (*self.ptr).bytes_after
        }
    }
    pub fn num_items(&self) -> u32 {
        unsafe {
            (*self.ptr).num_items
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_output_property_data_length(field) as usize;
            let data = xcb_randr_get_output_property_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_output_property<'a>(c          : &'a base::Connection,
                               output     : Output,
                               property   : xproto::Atom,
                               type_      : xproto::Atom,
                               long_offset: u32,
                               long_length: u32,
                               delete     : bool,
                               pending    : bool)
        -> GetOutputPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_output_property(c.get_raw_conn(),
                                                   output as xcb_randr_output_t,  // 0
                                                   property as xcb_atom_t,  // 1
                                                   type_ as xcb_atom_t,  // 2
                                                   long_offset as u32,  // 3
                                                   long_length as u32,  // 4
                                                   delete as u8,  // 5
                                                   pending as u8);  // 6
        GetOutputPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_output_property_unchecked<'a>(c          : &'a base::Connection,
                                         output     : Output,
                                         property   : xproto::Atom,
                                         type_      : xproto::Atom,
                                         long_offset: u32,
                                         long_length: u32,
                                         delete     : bool,
                                         pending    : bool)
        -> GetOutputPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_output_property_unchecked(c.get_raw_conn(),
                                                             output as xcb_randr_output_t,  // 0
                                                             property as xcb_atom_t,  // 1
                                                             type_ as xcb_atom_t,  // 2
                                                             long_offset as u32,  // 3
                                                             long_length as u32,  // 4
                                                             delete as u8,  // 5
                                                             pending as u8);  // 6
        GetOutputPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_MODE: u8 = 16;

pub type CreateModeCookie<'a> = base::Cookie<'a, xcb_randr_create_mode_cookie_t>;

impl<'a> CreateModeCookie<'a> {
    pub fn get_reply(&self) -> Result<CreateModeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = CreateModeReply {
                    ptr: xcb_randr_create_mode_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( CreateModeReply {
                    ptr: xcb_randr_create_mode_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type CreateModeReply = base::Reply<xcb_randr_create_mode_reply_t>;

impl CreateModeReply {
    pub fn mode(&self) -> Mode {
        unsafe {
            (*self.ptr).mode
        }
    }
}

pub fn create_mode<'a>(c        : &'a base::Connection,
                       window   : xproto::Window,
                       mode_info: ModeInfo,
                       name     : &str)
        -> CreateModeCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_randr_create_mode(c.get_raw_conn(),
                                           window as xcb_window_t,  // 0
                                           mode_info.base,  // 1
                                           name_len as u32,  // 2
                                           name_ptr as *const c_char);  // 3
        CreateModeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn create_mode_unchecked<'a>(c        : &'a base::Connection,
                                 window   : xproto::Window,
                                 mode_info: ModeInfo,
                                 name     : &str)
        -> CreateModeCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_randr_create_mode_unchecked(c.get_raw_conn(),
                                                     window as xcb_window_t,  // 0
                                                     mode_info.base,  // 1
                                                     name_len as u32,  // 2
                                                     name_ptr as *const c_char);  // 3
        CreateModeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DESTROY_MODE: u8 = 17;

pub fn destroy_mode<'a>(c   : &'a base::Connection,
                        mode: Mode)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_destroy_mode(c.get_raw_conn(),
                                            mode as xcb_randr_mode_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_mode_checked<'a>(c   : &'a base::Connection,
                                mode: Mode)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_destroy_mode_checked(c.get_raw_conn(),
                                                    mode as xcb_randr_mode_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ADD_OUTPUT_MODE: u8 = 18;

pub fn add_output_mode<'a>(c     : &'a base::Connection,
                           output: Output,
                           mode  : Mode)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_add_output_mode(c.get_raw_conn(),
                                               output as xcb_randr_output_t,  // 0
                                               mode as xcb_randr_mode_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn add_output_mode_checked<'a>(c     : &'a base::Connection,
                                   output: Output,
                                   mode  : Mode)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_add_output_mode_checked(c.get_raw_conn(),
                                                       output as xcb_randr_output_t,  // 0
                                                       mode as xcb_randr_mode_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_OUTPUT_MODE: u8 = 19;

pub fn delete_output_mode<'a>(c     : &'a base::Connection,
                              output: Output,
                              mode  : Mode)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_delete_output_mode(c.get_raw_conn(),
                                                  output as xcb_randr_output_t,  // 0
                                                  mode as xcb_randr_mode_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_output_mode_checked<'a>(c     : &'a base::Connection,
                                      output: Output,
                                      mode  : Mode)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_delete_output_mode_checked(c.get_raw_conn(),
                                                          output as xcb_randr_output_t,  // 0
                                                          mode as xcb_randr_mode_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_CRTC_INFO: u8 = 20;

pub type GetCrtcInfoCookie<'a> = base::Cookie<'a, xcb_randr_get_crtc_info_cookie_t>;

impl<'a> GetCrtcInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCrtcInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCrtcInfoReply {
                    ptr: xcb_randr_get_crtc_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCrtcInfoReply {
                    ptr: xcb_randr_get_crtc_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCrtcInfoReply = base::Reply<xcb_randr_get_crtc_info_reply_t>;

impl GetCrtcInfoReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
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
    pub fn mode(&self) -> Mode {
        unsafe {
            (*self.ptr).mode
        }
    }
    pub fn rotation(&self) -> u16 {
        unsafe {
            (*self.ptr).rotation
        }
    }
    pub fn rotations(&self) -> u16 {
        unsafe {
            (*self.ptr).rotations
        }
    }
    pub fn num_outputs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_outputs
        }
    }
    pub fn num_possible_outputs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_possible_outputs
        }
    }
    pub fn outputs(&self) -> &[Output] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_info_outputs_length(field) as usize;
            let data = xcb_randr_get_crtc_info_outputs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn possible(&self) -> &[Output] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_info_possible_length(field) as usize;
            let data = xcb_randr_get_crtc_info_possible(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_crtc_info<'a>(c               : &'a base::Connection,
                         crtc            : Crtc,
                         config_timestamp: xproto::Timestamp)
        -> GetCrtcInfoCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_crtc_info(c.get_raw_conn(),
                                             crtc as xcb_randr_crtc_t,  // 0
                                             config_timestamp as xcb_timestamp_t);  // 1
        GetCrtcInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_crtc_info_unchecked<'a>(c               : &'a base::Connection,
                                   crtc            : Crtc,
                                   config_timestamp: xproto::Timestamp)
        -> GetCrtcInfoCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_crtc_info_unchecked(c.get_raw_conn(),
                                                       crtc as xcb_randr_crtc_t,  // 0
                                                       config_timestamp as xcb_timestamp_t);  // 1
        GetCrtcInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_CRTC_CONFIG: u8 = 21;

pub type SetCrtcConfigCookie<'a> = base::Cookie<'a, xcb_randr_set_crtc_config_cookie_t>;

impl<'a> SetCrtcConfigCookie<'a> {
    pub fn get_reply(&self) -> Result<SetCrtcConfigReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetCrtcConfigReply {
                    ptr: xcb_randr_set_crtc_config_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetCrtcConfigReply {
                    ptr: xcb_randr_set_crtc_config_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetCrtcConfigReply = base::Reply<xcb_randr_set_crtc_config_reply_t>;

impl SetCrtcConfigReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
}

pub fn set_crtc_config<'a>(c               : &'a base::Connection,
                           crtc            : Crtc,
                           timestamp       : xproto::Timestamp,
                           config_timestamp: xproto::Timestamp,
                           x               : i16,
                           y               : i16,
                           mode            : Mode,
                           rotation        : u16,
                           outputs         : &[Output])
        -> SetCrtcConfigCookie<'a> {
    unsafe {
        let outputs_len = outputs.len();
        let outputs_ptr = outputs.as_ptr();
        let cookie = xcb_randr_set_crtc_config(c.get_raw_conn(),
                                               crtc as xcb_randr_crtc_t,  // 0
                                               timestamp as xcb_timestamp_t,  // 1
                                               config_timestamp as xcb_timestamp_t,  // 2
                                               x as i16,  // 3
                                               y as i16,  // 4
                                               mode as xcb_randr_mode_t,  // 5
                                               rotation as u16,  // 6
                                               outputs_len as u32,  // 7
                                               outputs_ptr as *const xcb_randr_output_t);  // 8
        SetCrtcConfigCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_crtc_config_unchecked<'a>(c               : &'a base::Connection,
                                     crtc            : Crtc,
                                     timestamp       : xproto::Timestamp,
                                     config_timestamp: xproto::Timestamp,
                                     x               : i16,
                                     y               : i16,
                                     mode            : Mode,
                                     rotation        : u16,
                                     outputs         : &[Output])
        -> SetCrtcConfigCookie<'a> {
    unsafe {
        let outputs_len = outputs.len();
        let outputs_ptr = outputs.as_ptr();
        let cookie = xcb_randr_set_crtc_config_unchecked(c.get_raw_conn(),
                                                         crtc as xcb_randr_crtc_t,  // 0
                                                         timestamp as xcb_timestamp_t,  // 1
                                                         config_timestamp as xcb_timestamp_t,  // 2
                                                         x as i16,  // 3
                                                         y as i16,  // 4
                                                         mode as xcb_randr_mode_t,  // 5
                                                         rotation as u16,  // 6
                                                         outputs_len as u32,  // 7
                                                         outputs_ptr as *const xcb_randr_output_t);  // 8
        SetCrtcConfigCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_CRTC_GAMMA_SIZE: u8 = 22;

pub type GetCrtcGammaSizeCookie<'a> = base::Cookie<'a, xcb_randr_get_crtc_gamma_size_cookie_t>;

impl<'a> GetCrtcGammaSizeCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCrtcGammaSizeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCrtcGammaSizeReply {
                    ptr: xcb_randr_get_crtc_gamma_size_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCrtcGammaSizeReply {
                    ptr: xcb_randr_get_crtc_gamma_size_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCrtcGammaSizeReply = base::Reply<xcb_randr_get_crtc_gamma_size_reply_t>;

impl GetCrtcGammaSizeReply {
    pub fn size(&self) -> u16 {
        unsafe {
            (*self.ptr).size
        }
    }
}

pub fn get_crtc_gamma_size<'a>(c   : &'a base::Connection,
                               crtc: Crtc)
        -> GetCrtcGammaSizeCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_crtc_gamma_size(c.get_raw_conn(),
                                                   crtc as xcb_randr_crtc_t);  // 0
        GetCrtcGammaSizeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_crtc_gamma_size_unchecked<'a>(c   : &'a base::Connection,
                                         crtc: Crtc)
        -> GetCrtcGammaSizeCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_crtc_gamma_size_unchecked(c.get_raw_conn(),
                                                             crtc as xcb_randr_crtc_t);  // 0
        GetCrtcGammaSizeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_CRTC_GAMMA: u8 = 23;

pub type GetCrtcGammaCookie<'a> = base::Cookie<'a, xcb_randr_get_crtc_gamma_cookie_t>;

impl<'a> GetCrtcGammaCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCrtcGammaReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCrtcGammaReply {
                    ptr: xcb_randr_get_crtc_gamma_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCrtcGammaReply {
                    ptr: xcb_randr_get_crtc_gamma_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCrtcGammaReply = base::Reply<xcb_randr_get_crtc_gamma_reply_t>;

impl GetCrtcGammaReply {
    pub fn size(&self) -> u16 {
        unsafe {
            (*self.ptr).size
        }
    }
    pub fn red(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_gamma_red_length(field) as usize;
            let data = xcb_randr_get_crtc_gamma_red(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn green(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_gamma_green_length(field) as usize;
            let data = xcb_randr_get_crtc_gamma_green(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn blue(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_gamma_blue_length(field) as usize;
            let data = xcb_randr_get_crtc_gamma_blue(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_crtc_gamma<'a>(c   : &'a base::Connection,
                          crtc: Crtc)
        -> GetCrtcGammaCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_crtc_gamma(c.get_raw_conn(),
                                              crtc as xcb_randr_crtc_t);  // 0
        GetCrtcGammaCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_crtc_gamma_unchecked<'a>(c   : &'a base::Connection,
                                    crtc: Crtc)
        -> GetCrtcGammaCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_crtc_gamma_unchecked(c.get_raw_conn(),
                                                        crtc as xcb_randr_crtc_t);  // 0
        GetCrtcGammaCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_CRTC_GAMMA: u8 = 24;

pub fn set_crtc_gamma<'a>(c    : &'a base::Connection,
                          crtc : Crtc,
                          red  : &[u16],
                          green: &[u16],
                          blue : &[u16])
        -> base::VoidCookie<'a> {
    unsafe {
        let red_len = red.len();
        let red_ptr = red.as_ptr();
        let green_ptr = green.as_ptr();
        let blue_ptr = blue.as_ptr();
        let cookie = xcb_randr_set_crtc_gamma(c.get_raw_conn(),
                                              crtc as xcb_randr_crtc_t,  // 0
                                              red_len as u16,  // 1
                                              red_ptr as *const u16,  // 2
                                              green_ptr as *const u16,  // 3
                                              blue_ptr as *const u16);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_crtc_gamma_checked<'a>(c    : &'a base::Connection,
                                  crtc : Crtc,
                                  red  : &[u16],
                                  green: &[u16],
                                  blue : &[u16])
        -> base::VoidCookie<'a> {
    unsafe {
        let red_len = red.len();
        let red_ptr = red.as_ptr();
        let green_ptr = green.as_ptr();
        let blue_ptr = blue.as_ptr();
        let cookie = xcb_randr_set_crtc_gamma_checked(c.get_raw_conn(),
                                                      crtc as xcb_randr_crtc_t,  // 0
                                                      red_len as u16,  // 1
                                                      red_ptr as *const u16,  // 2
                                                      green_ptr as *const u16,  // 3
                                                      blue_ptr as *const u16);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_SCREEN_RESOURCES_CURRENT: u8 = 25;

pub type GetScreenResourcesCurrentCookie<'a> = base::Cookie<'a, xcb_randr_get_screen_resources_current_cookie_t>;

impl<'a> GetScreenResourcesCurrentCookie<'a> {
    pub fn get_reply(&self) -> Result<GetScreenResourcesCurrentReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetScreenResourcesCurrentReply {
                    ptr: xcb_randr_get_screen_resources_current_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetScreenResourcesCurrentReply {
                    ptr: xcb_randr_get_screen_resources_current_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetScreenResourcesCurrentReply = base::Reply<xcb_randr_get_screen_resources_current_reply_t>;

impl GetScreenResourcesCurrentReply {
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn config_timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).config_timestamp
        }
    }
    pub fn num_crtcs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_crtcs
        }
    }
    pub fn num_outputs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_outputs
        }
    }
    pub fn num_modes(&self) -> u16 {
        unsafe {
            (*self.ptr).num_modes
        }
    }
    pub fn names_len(&self) -> u16 {
        unsafe {
            (*self.ptr).names_len
        }
    }
    pub fn crtcs(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_screen_resources_current_crtcs_length(field) as usize;
            let data = xcb_randr_get_screen_resources_current_crtcs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn outputs(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_screen_resources_current_outputs_length(field) as usize;
            let data = xcb_randr_get_screen_resources_current_outputs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn modes(&self) -> ModeInfoIterator {
        unsafe {
            xcb_randr_get_screen_resources_current_modes_iterator(self.ptr)
        }
    }
    pub fn names(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_screen_resources_current_names_length(field) as usize;
            let data = xcb_randr_get_screen_resources_current_names(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_screen_resources_current<'a>(c     : &'a base::Connection,
                                        window: xproto::Window)
        -> GetScreenResourcesCurrentCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_screen_resources_current(c.get_raw_conn(),
                                                            window as xcb_window_t);  // 0
        GetScreenResourcesCurrentCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_screen_resources_current_unchecked<'a>(c     : &'a base::Connection,
                                                  window: xproto::Window)
        -> GetScreenResourcesCurrentCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_screen_resources_current_unchecked(c.get_raw_conn(),
                                                                      window as xcb_window_t);  // 0
        GetScreenResourcesCurrentCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_CRTC_TRANSFORM: u8 = 26;

pub fn set_crtc_transform<'a>(c            : &'a base::Connection,
                              crtc         : Crtc,
                              transform    : render::Transform,
                              filter_name  : &str,
                              filter_params: &[render::Fixed])
        -> base::VoidCookie<'a> {
    unsafe {
        let filter_name = filter_name.as_bytes();
        let filter_name_len = filter_name.len();
        let filter_name_ptr = filter_name.as_ptr();
        let filter_params_len = filter_params.len();
        let filter_params_ptr = filter_params.as_ptr();
        let cookie = xcb_randr_set_crtc_transform(c.get_raw_conn(),
                                                  crtc as xcb_randr_crtc_t,  // 0
                                                  transform.base,  // 1
                                                  filter_name_len as u16,  // 2
                                                  filter_name_ptr as *const c_char,  // 3
                                                  filter_params_len as u32,  // 4
                                                  filter_params_ptr as *const xcb_render_fixed_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_crtc_transform_checked<'a>(c            : &'a base::Connection,
                                      crtc         : Crtc,
                                      transform    : render::Transform,
                                      filter_name  : &str,
                                      filter_params: &[render::Fixed])
        -> base::VoidCookie<'a> {
    unsafe {
        let filter_name = filter_name.as_bytes();
        let filter_name_len = filter_name.len();
        let filter_name_ptr = filter_name.as_ptr();
        let filter_params_len = filter_params.len();
        let filter_params_ptr = filter_params.as_ptr();
        let cookie = xcb_randr_set_crtc_transform_checked(c.get_raw_conn(),
                                                          crtc as xcb_randr_crtc_t,  // 0
                                                          transform.base,  // 1
                                                          filter_name_len as u16,  // 2
                                                          filter_name_ptr as *const c_char,  // 3
                                                          filter_params_len as u32,  // 4
                                                          filter_params_ptr as *const xcb_render_fixed_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_CRTC_TRANSFORM: u8 = 27;

pub type GetCrtcTransformCookie<'a> = base::Cookie<'a, xcb_randr_get_crtc_transform_cookie_t>;

impl<'a> GetCrtcTransformCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCrtcTransformReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCrtcTransformReply {
                    ptr: xcb_randr_get_crtc_transform_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCrtcTransformReply {
                    ptr: xcb_randr_get_crtc_transform_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCrtcTransformReply = base::Reply<xcb_randr_get_crtc_transform_reply_t>;

impl GetCrtcTransformReply {
    pub fn pending_transform(&self) -> render::Transform {
        unsafe {
            std::mem::transmute((*self.ptr).pending_transform)
        }
    }
    pub fn has_transforms(&self) -> bool {
        unsafe {
            (*self.ptr).has_transforms != 0
        }
    }
    pub fn current_transform(&self) -> render::Transform {
        unsafe {
            std::mem::transmute((*self.ptr).current_transform)
        }
    }
    pub fn pending_len(&self) -> u16 {
        unsafe {
            (*self.ptr).pending_len
        }
    }
    pub fn pending_nparams(&self) -> u16 {
        unsafe {
            (*self.ptr).pending_nparams
        }
    }
    pub fn current_len(&self) -> u16 {
        unsafe {
            (*self.ptr).current_len
        }
    }
    pub fn current_nparams(&self) -> u16 {
        unsafe {
            (*self.ptr).current_nparams
        }
    }
    pub fn pending_filter_name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_transform_pending_filter_name_length(field) as usize;
            let data = xcb_randr_get_crtc_transform_pending_filter_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn pending_params(&self) -> &[render::Fixed] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_transform_pending_params_length(field) as usize;
            let data = xcb_randr_get_crtc_transform_pending_params(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn current_filter_name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_transform_current_filter_name_length(field) as usize;
            let data = xcb_randr_get_crtc_transform_current_filter_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn current_params(&self) -> &[render::Fixed] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_crtc_transform_current_params_length(field) as usize;
            let data = xcb_randr_get_crtc_transform_current_params(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_crtc_transform<'a>(c   : &'a base::Connection,
                              crtc: Crtc)
        -> GetCrtcTransformCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_crtc_transform(c.get_raw_conn(),
                                                  crtc as xcb_randr_crtc_t);  // 0
        GetCrtcTransformCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_crtc_transform_unchecked<'a>(c   : &'a base::Connection,
                                        crtc: Crtc)
        -> GetCrtcTransformCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_crtc_transform_unchecked(c.get_raw_conn(),
                                                            crtc as xcb_randr_crtc_t);  // 0
        GetCrtcTransformCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PANNING: u8 = 28;

pub type GetPanningCookie<'a> = base::Cookie<'a, xcb_randr_get_panning_cookie_t>;

impl<'a> GetPanningCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPanningReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPanningReply {
                    ptr: xcb_randr_get_panning_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPanningReply {
                    ptr: xcb_randr_get_panning_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPanningReply = base::Reply<xcb_randr_get_panning_reply_t>;

impl GetPanningReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn left(&self) -> u16 {
        unsafe {
            (*self.ptr).left
        }
    }
    pub fn top(&self) -> u16 {
        unsafe {
            (*self.ptr).top
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
    pub fn track_left(&self) -> u16 {
        unsafe {
            (*self.ptr).track_left
        }
    }
    pub fn track_top(&self) -> u16 {
        unsafe {
            (*self.ptr).track_top
        }
    }
    pub fn track_width(&self) -> u16 {
        unsafe {
            (*self.ptr).track_width
        }
    }
    pub fn track_height(&self) -> u16 {
        unsafe {
            (*self.ptr).track_height
        }
    }
    pub fn border_left(&self) -> i16 {
        unsafe {
            (*self.ptr).border_left
        }
    }
    pub fn border_top(&self) -> i16 {
        unsafe {
            (*self.ptr).border_top
        }
    }
    pub fn border_right(&self) -> i16 {
        unsafe {
            (*self.ptr).border_right
        }
    }
    pub fn border_bottom(&self) -> i16 {
        unsafe {
            (*self.ptr).border_bottom
        }
    }
}

pub fn get_panning<'a>(c   : &'a base::Connection,
                       crtc: Crtc)
        -> GetPanningCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_panning(c.get_raw_conn(),
                                           crtc as xcb_randr_crtc_t);  // 0
        GetPanningCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_panning_unchecked<'a>(c   : &'a base::Connection,
                                 crtc: Crtc)
        -> GetPanningCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_panning_unchecked(c.get_raw_conn(),
                                                     crtc as xcb_randr_crtc_t);  // 0
        GetPanningCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_PANNING: u8 = 29;

pub type SetPanningCookie<'a> = base::Cookie<'a, xcb_randr_set_panning_cookie_t>;

impl<'a> SetPanningCookie<'a> {
    pub fn get_reply(&self) -> Result<SetPanningReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetPanningReply {
                    ptr: xcb_randr_set_panning_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetPanningReply {
                    ptr: xcb_randr_set_panning_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetPanningReply = base::Reply<xcb_randr_set_panning_reply_t>;

impl SetPanningReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
}

pub fn set_panning<'a>(c            : &'a base::Connection,
                       crtc         : Crtc,
                       timestamp    : xproto::Timestamp,
                       left         : u16,
                       top          : u16,
                       width        : u16,
                       height       : u16,
                       track_left   : u16,
                       track_top    : u16,
                       track_width  : u16,
                       track_height : u16,
                       border_left  : i16,
                       border_top   : i16,
                       border_right : i16,
                       border_bottom: i16)
        -> SetPanningCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_panning(c.get_raw_conn(),
                                           crtc as xcb_randr_crtc_t,  // 0
                                           timestamp as xcb_timestamp_t,  // 1
                                           left as u16,  // 2
                                           top as u16,  // 3
                                           width as u16,  // 4
                                           height as u16,  // 5
                                           track_left as u16,  // 6
                                           track_top as u16,  // 7
                                           track_width as u16,  // 8
                                           track_height as u16,  // 9
                                           border_left as i16,  // 10
                                           border_top as i16,  // 11
                                           border_right as i16,  // 12
                                           border_bottom as i16);  // 13
        SetPanningCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_panning_unchecked<'a>(c            : &'a base::Connection,
                                 crtc         : Crtc,
                                 timestamp    : xproto::Timestamp,
                                 left         : u16,
                                 top          : u16,
                                 width        : u16,
                                 height       : u16,
                                 track_left   : u16,
                                 track_top    : u16,
                                 track_width  : u16,
                                 track_height : u16,
                                 border_left  : i16,
                                 border_top   : i16,
                                 border_right : i16,
                                 border_bottom: i16)
        -> SetPanningCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_panning_unchecked(c.get_raw_conn(),
                                                     crtc as xcb_randr_crtc_t,  // 0
                                                     timestamp as xcb_timestamp_t,  // 1
                                                     left as u16,  // 2
                                                     top as u16,  // 3
                                                     width as u16,  // 4
                                                     height as u16,  // 5
                                                     track_left as u16,  // 6
                                                     track_top as u16,  // 7
                                                     track_width as u16,  // 8
                                                     track_height as u16,  // 9
                                                     border_left as i16,  // 10
                                                     border_top as i16,  // 11
                                                     border_right as i16,  // 12
                                                     border_bottom as i16);  // 13
        SetPanningCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_OUTPUT_PRIMARY: u8 = 30;

pub fn set_output_primary<'a>(c     : &'a base::Connection,
                              window: xproto::Window,
                              output: Output)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_output_primary(c.get_raw_conn(),
                                                  window as xcb_window_t,  // 0
                                                  output as xcb_randr_output_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_output_primary_checked<'a>(c     : &'a base::Connection,
                                      window: xproto::Window,
                                      output: Output)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_output_primary_checked(c.get_raw_conn(),
                                                          window as xcb_window_t,  // 0
                                                          output as xcb_randr_output_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_OUTPUT_PRIMARY: u8 = 31;

pub type GetOutputPrimaryCookie<'a> = base::Cookie<'a, xcb_randr_get_output_primary_cookie_t>;

impl<'a> GetOutputPrimaryCookie<'a> {
    pub fn get_reply(&self) -> Result<GetOutputPrimaryReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetOutputPrimaryReply {
                    ptr: xcb_randr_get_output_primary_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetOutputPrimaryReply {
                    ptr: xcb_randr_get_output_primary_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetOutputPrimaryReply = base::Reply<xcb_randr_get_output_primary_reply_t>;

impl GetOutputPrimaryReply {
    pub fn output(&self) -> Output {
        unsafe {
            (*self.ptr).output
        }
    }
}

pub fn get_output_primary<'a>(c     : &'a base::Connection,
                              window: xproto::Window)
        -> GetOutputPrimaryCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_output_primary(c.get_raw_conn(),
                                                  window as xcb_window_t);  // 0
        GetOutputPrimaryCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_output_primary_unchecked<'a>(c     : &'a base::Connection,
                                        window: xproto::Window)
        -> GetOutputPrimaryCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_output_primary_unchecked(c.get_raw_conn(),
                                                            window as xcb_window_t);  // 0
        GetOutputPrimaryCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PROVIDERS: u8 = 32;

pub type GetProvidersCookie<'a> = base::Cookie<'a, xcb_randr_get_providers_cookie_t>;

impl<'a> GetProvidersCookie<'a> {
    pub fn get_reply(&self) -> Result<GetProvidersReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetProvidersReply {
                    ptr: xcb_randr_get_providers_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetProvidersReply {
                    ptr: xcb_randr_get_providers_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetProvidersReply = base::Reply<xcb_randr_get_providers_reply_t>;

impl GetProvidersReply {
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn num_providers(&self) -> u16 {
        unsafe {
            (*self.ptr).num_providers
        }
    }
    pub fn providers(&self) -> &[Provider] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_providers_providers_length(field) as usize;
            let data = xcb_randr_get_providers_providers(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_providers<'a>(c     : &'a base::Connection,
                         window: xproto::Window)
        -> GetProvidersCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_providers(c.get_raw_conn(),
                                             window as xcb_window_t);  // 0
        GetProvidersCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_providers_unchecked<'a>(c     : &'a base::Connection,
                                   window: xproto::Window)
        -> GetProvidersCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_providers_unchecked(c.get_raw_conn(),
                                                       window as xcb_window_t);  // 0
        GetProvidersCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PROVIDER_INFO: u8 = 33;

pub type GetProviderInfoCookie<'a> = base::Cookie<'a, xcb_randr_get_provider_info_cookie_t>;

impl<'a> GetProviderInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<GetProviderInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetProviderInfoReply {
                    ptr: xcb_randr_get_provider_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetProviderInfoReply {
                    ptr: xcb_randr_get_provider_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetProviderInfoReply = base::Reply<xcb_randr_get_provider_info_reply_t>;

impl GetProviderInfoReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn capabilities(&self) -> u32 {
        unsafe {
            (*self.ptr).capabilities
        }
    }
    pub fn num_crtcs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_crtcs
        }
    }
    pub fn num_outputs(&self) -> u16 {
        unsafe {
            (*self.ptr).num_outputs
        }
    }
    pub fn num_associated_providers(&self) -> u16 {
        unsafe {
            (*self.ptr).num_associated_providers
        }
    }
    pub fn name_len(&self) -> u16 {
        unsafe {
            (*self.ptr).name_len
        }
    }
    pub fn crtcs(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_provider_info_crtcs_length(field) as usize;
            let data = xcb_randr_get_provider_info_crtcs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn outputs(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_provider_info_outputs_length(field) as usize;
            let data = xcb_randr_get_provider_info_outputs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn associated_providers(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_provider_info_associated_providers_length(field) as usize;
            let data = xcb_randr_get_provider_info_associated_providers(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn associated_capability(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_provider_info_associated_capability_length(field) as usize;
            let data = xcb_randr_get_provider_info_associated_capability(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_provider_info_name_length(field) as usize;
            let data = xcb_randr_get_provider_info_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_provider_info<'a>(c               : &'a base::Connection,
                             provider        : Provider,
                             config_timestamp: xproto::Timestamp)
        -> GetProviderInfoCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_provider_info(c.get_raw_conn(),
                                                 provider as xcb_randr_provider_t,  // 0
                                                 config_timestamp as xcb_timestamp_t);  // 1
        GetProviderInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_provider_info_unchecked<'a>(c               : &'a base::Connection,
                                       provider        : Provider,
                                       config_timestamp: xproto::Timestamp)
        -> GetProviderInfoCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_provider_info_unchecked(c.get_raw_conn(),
                                                           provider as xcb_randr_provider_t,  // 0
                                                           config_timestamp as xcb_timestamp_t);  // 1
        GetProviderInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_PROVIDER_OFFLOAD_SINK: u8 = 34;

pub fn set_provider_offload_sink<'a>(c               : &'a base::Connection,
                                     provider        : Provider,
                                     sink_provider   : Provider,
                                     config_timestamp: xproto::Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_provider_offload_sink(c.get_raw_conn(),
                                                         provider as xcb_randr_provider_t,  // 0
                                                         sink_provider as xcb_randr_provider_t,  // 1
                                                         config_timestamp as xcb_timestamp_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_provider_offload_sink_checked<'a>(c               : &'a base::Connection,
                                             provider        : Provider,
                                             sink_provider   : Provider,
                                             config_timestamp: xproto::Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_provider_offload_sink_checked(c.get_raw_conn(),
                                                                 provider as xcb_randr_provider_t,  // 0
                                                                 sink_provider as xcb_randr_provider_t,  // 1
                                                                 config_timestamp as xcb_timestamp_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_PROVIDER_OUTPUT_SOURCE: u8 = 35;

pub fn set_provider_output_source<'a>(c               : &'a base::Connection,
                                      provider        : Provider,
                                      source_provider : Provider,
                                      config_timestamp: xproto::Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_provider_output_source(c.get_raw_conn(),
                                                          provider as xcb_randr_provider_t,  // 0
                                                          source_provider as xcb_randr_provider_t,  // 1
                                                          config_timestamp as xcb_timestamp_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_provider_output_source_checked<'a>(c               : &'a base::Connection,
                                              provider        : Provider,
                                              source_provider : Provider,
                                              config_timestamp: xproto::Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_set_provider_output_source_checked(c.get_raw_conn(),
                                                                  provider as xcb_randr_provider_t,  // 0
                                                                  source_provider as xcb_randr_provider_t,  // 1
                                                                  config_timestamp as xcb_timestamp_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const LIST_PROVIDER_PROPERTIES: u8 = 36;

pub type ListProviderPropertiesCookie<'a> = base::Cookie<'a, xcb_randr_list_provider_properties_cookie_t>;

impl<'a> ListProviderPropertiesCookie<'a> {
    pub fn get_reply(&self) -> Result<ListProviderPropertiesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListProviderPropertiesReply {
                    ptr: xcb_randr_list_provider_properties_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListProviderPropertiesReply {
                    ptr: xcb_randr_list_provider_properties_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListProviderPropertiesReply = base::Reply<xcb_randr_list_provider_properties_reply_t>;

impl ListProviderPropertiesReply {
    pub fn num_atoms(&self) -> u16 {
        unsafe {
            (*self.ptr).num_atoms
        }
    }
    pub fn atoms(&self) -> &[xproto::Atom] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_list_provider_properties_atoms_length(field) as usize;
            let data = xcb_randr_list_provider_properties_atoms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn list_provider_properties<'a>(c       : &'a base::Connection,
                                    provider: Provider)
        -> ListProviderPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_randr_list_provider_properties(c.get_raw_conn(),
                                                        provider as xcb_randr_provider_t);  // 0
        ListProviderPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_provider_properties_unchecked<'a>(c       : &'a base::Connection,
                                              provider: Provider)
        -> ListProviderPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_randr_list_provider_properties_unchecked(c.get_raw_conn(),
                                                                  provider as xcb_randr_provider_t);  // 0
        ListProviderPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_PROVIDER_PROPERTY: u8 = 37;

pub type QueryProviderPropertyCookie<'a> = base::Cookie<'a, xcb_randr_query_provider_property_cookie_t>;

impl<'a> QueryProviderPropertyCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryProviderPropertyReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryProviderPropertyReply {
                    ptr: xcb_randr_query_provider_property_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryProviderPropertyReply {
                    ptr: xcb_randr_query_provider_property_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryProviderPropertyReply = base::Reply<xcb_randr_query_provider_property_reply_t>;

impl QueryProviderPropertyReply {
    pub fn pending(&self) -> bool {
        unsafe {
            (*self.ptr).pending != 0
        }
    }
    pub fn range(&self) -> bool {
        unsafe {
            (*self.ptr).range != 0
        }
    }
    pub fn immutable(&self) -> bool {
        unsafe {
            (*self.ptr).immutable != 0
        }
    }
    pub fn valid_values(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_query_provider_property_valid_values_length(field) as usize;
            let data = xcb_randr_query_provider_property_valid_values(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn query_provider_property<'a>(c       : &'a base::Connection,
                                   provider: Provider,
                                   property: xproto::Atom)
        -> QueryProviderPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_randr_query_provider_property(c.get_raw_conn(),
                                                       provider as xcb_randr_provider_t,  // 0
                                                       property as xcb_atom_t);  // 1
        QueryProviderPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_provider_property_unchecked<'a>(c       : &'a base::Connection,
                                             provider: Provider,
                                             property: xproto::Atom)
        -> QueryProviderPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_randr_query_provider_property_unchecked(c.get_raw_conn(),
                                                                 provider as xcb_randr_provider_t,  // 0
                                                                 property as xcb_atom_t);  // 1
        QueryProviderPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CONFIGURE_PROVIDER_PROPERTY: u8 = 38;

pub fn configure_provider_property<'a>(c       : &'a base::Connection,
                                       provider: Provider,
                                       property: xproto::Atom,
                                       pending : bool,
                                       range   : bool,
                                       values  : &[i32])
        -> base::VoidCookie<'a> {
    unsafe {
        let values_len = values.len();
        let values_ptr = values.as_ptr();
        let cookie = xcb_randr_configure_provider_property(c.get_raw_conn(),
                                                           provider as xcb_randr_provider_t,  // 0
                                                           property as xcb_atom_t,  // 1
                                                           pending as u8,  // 2
                                                           range as u8,  // 3
                                                           values_len as u32,  // 4
                                                           values_ptr as *const i32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn configure_provider_property_checked<'a>(c       : &'a base::Connection,
                                               provider: Provider,
                                               property: xproto::Atom,
                                               pending : bool,
                                               range   : bool,
                                               values  : &[i32])
        -> base::VoidCookie<'a> {
    unsafe {
        let values_len = values.len();
        let values_ptr = values.as_ptr();
        let cookie = xcb_randr_configure_provider_property_checked(c.get_raw_conn(),
                                                                   provider as xcb_randr_provider_t,  // 0
                                                                   property as xcb_atom_t,  // 1
                                                                   pending as u8,  // 2
                                                                   range as u8,  // 3
                                                                   values_len as u32,  // 4
                                                                   values_ptr as *const i32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_PROVIDER_PROPERTY: u8 = 39;

pub fn change_provider_property<'a, T>(c       : &'a base::Connection,
                                       provider: Provider,
                                       property: xproto::Atom,
                                       type_   : xproto::Atom,
                                       format  : u8,
                                       mode    : u8,
                                       data    : &[T])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_randr_change_provider_property(c.get_raw_conn(),
                                                        provider as xcb_randr_provider_t,  // 0
                                                        property as xcb_atom_t,  // 1
                                                        type_ as xcb_atom_t,  // 2
                                                        format as u8,  // 3
                                                        mode as u8,  // 4
                                                        data_len as u32,  // 5
                                                        data_ptr as *const c_void);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_provider_property_checked<'a, T>(c       : &'a base::Connection,
                                               provider: Provider,
                                               property: xproto::Atom,
                                               type_   : xproto::Atom,
                                               format  : u8,
                                               mode    : u8,
                                               data    : &[T])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_randr_change_provider_property_checked(c.get_raw_conn(),
                                                                provider as xcb_randr_provider_t,  // 0
                                                                property as xcb_atom_t,  // 1
                                                                type_ as xcb_atom_t,  // 2
                                                                format as u8,  // 3
                                                                mode as u8,  // 4
                                                                data_len as u32,  // 5
                                                                data_ptr as *const c_void);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_PROVIDER_PROPERTY: u8 = 40;

pub fn delete_provider_property<'a>(c       : &'a base::Connection,
                                    provider: Provider,
                                    property: xproto::Atom)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_delete_provider_property(c.get_raw_conn(),
                                                        provider as xcb_randr_provider_t,  // 0
                                                        property as xcb_atom_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_provider_property_checked<'a>(c       : &'a base::Connection,
                                            provider: Provider,
                                            property: xproto::Atom)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_randr_delete_provider_property_checked(c.get_raw_conn(),
                                                                provider as xcb_randr_provider_t,  // 0
                                                                property as xcb_atom_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_PROVIDER_PROPERTY: u8 = 41;

pub type GetProviderPropertyCookie<'a> = base::Cookie<'a, xcb_randr_get_provider_property_cookie_t>;

impl<'a> GetProviderPropertyCookie<'a> {
    pub fn get_reply(&self) -> Result<GetProviderPropertyReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetProviderPropertyReply {
                    ptr: xcb_randr_get_provider_property_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetProviderPropertyReply {
                    ptr: xcb_randr_get_provider_property_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetProviderPropertyReply = base::Reply<xcb_randr_get_provider_property_reply_t>;

impl GetProviderPropertyReply {
    pub fn format(&self) -> u8 {
        unsafe {
            (*self.ptr).format
        }
    }
    pub fn type_(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn bytes_after(&self) -> u32 {
        unsafe {
            (*self.ptr).bytes_after
        }
    }
    pub fn num_items(&self) -> u32 {
        unsafe {
            (*self.ptr).num_items
        }
    }
    pub fn data<T>(&self) -> &[T] {
        unsafe {
            let field = self.ptr;
            let len = xcb_randr_get_provider_property_data_length(field) as usize;
            let data = xcb_randr_get_provider_property_data(field);
            debug_assert_eq!(len % std::mem::size_of::<T>(), 0);
            std::slice::from_raw_parts(data as *const T, len / std::mem::size_of::<T>())
        }
    }
}

pub fn get_provider_property<'a>(c          : &'a base::Connection,
                                 provider   : Provider,
                                 property   : xproto::Atom,
                                 type_      : xproto::Atom,
                                 long_offset: u32,
                                 long_length: u32,
                                 delete     : bool,
                                 pending    : bool)
        -> GetProviderPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_provider_property(c.get_raw_conn(),
                                                     provider as xcb_randr_provider_t,  // 0
                                                     property as xcb_atom_t,  // 1
                                                     type_ as xcb_atom_t,  // 2
                                                     long_offset as u32,  // 3
                                                     long_length as u32,  // 4
                                                     delete as u8,  // 5
                                                     pending as u8);  // 6
        GetProviderPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_provider_property_unchecked<'a>(c          : &'a base::Connection,
                                           provider   : Provider,
                                           property   : xproto::Atom,
                                           type_      : xproto::Atom,
                                           long_offset: u32,
                                           long_length: u32,
                                           delete     : bool,
                                           pending    : bool)
        -> GetProviderPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_randr_get_provider_property_unchecked(c.get_raw_conn(),
                                                               provider as xcb_randr_provider_t,  // 0
                                                               property as xcb_atom_t,  // 1
                                                               type_ as xcb_atom_t,  // 2
                                                               long_offset as u32,  // 3
                                                               long_length as u32,  // 4
                                                               delete as u8,  // 5
                                                               pending as u8);  // 6
        GetProviderPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SCREEN_CHANGE_NOTIFY: u8 = 0;

pub type ScreenChangeNotifyEvent = base::Event<xcb_randr_screen_change_notify_event_t>;

impl ScreenChangeNotifyEvent {
    pub fn rotation(&self) -> u8 {
        unsafe {
            (*self.ptr).rotation
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn config_timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).config_timestamp
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn request_window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).request_window
        }
    }
    pub fn size_i_d(&self) -> u16 {
        unsafe {
            (*self.ptr).sizeID
        }
    }
    pub fn subpixel_order(&self) -> u16 {
        unsafe {
            (*self.ptr).subpixel_order
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
    pub fn mwidth(&self) -> u16 {
        unsafe {
            (*self.ptr).mwidth
        }
    }
    pub fn mheight(&self) -> u16 {
        unsafe {
            (*self.ptr).mheight
        }
    }
    /// Constructs a new ScreenChangeNotifyEvent
    /// `response_type` will be set automatically to SCREEN_CHANGE_NOTIFY
    pub fn new(rotation: u8,
               timestamp: xproto::Timestamp,
               config_timestamp: xproto::Timestamp,
               root: xproto::Window,
               request_window: xproto::Window,
               size_i_d: u16,
               subpixel_order: u16,
               width: u16,
               height: u16,
               mwidth: u16,
               mheight: u16)
            -> ScreenChangeNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_randr_screen_change_notify_event_t;
            (*raw).response_type = SCREEN_CHANGE_NOTIFY;
            (*raw).rotation = rotation;
            (*raw).timestamp = timestamp;
            (*raw).config_timestamp = config_timestamp;
            (*raw).root = root;
            (*raw).request_window = request_window;
            (*raw).sizeID = size_i_d;
            (*raw).subpixel_order = subpixel_order;
            (*raw).width = width;
            (*raw).height = height;
            (*raw).mwidth = mwidth;
            (*raw).mheight = mheight;
            ScreenChangeNotifyEvent {
                ptr: raw
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct CrtcChange {
    pub base: xcb_randr_crtc_change_t,
}

impl CrtcChange {
    #[allow(unused_unsafe)]
    pub fn new(timestamp: xproto::Timestamp,
               window:    xproto::Window,
               crtc:      Crtc,
               mode:      Mode,
               rotation:  u16,
               x:         i16,
               y:         i16,
               width:     u16,
               height:    u16)
            -> CrtcChange {
        unsafe {
            CrtcChange {
                base: xcb_randr_crtc_change_t {
                    timestamp: timestamp,
                    window:    window,
                    crtc:      crtc,
                    mode:      mode,
                    rotation:  rotation,
                    pad0:      [0; 2],
                    x:         x,
                    y:         y,
                    width:     width,
                    height:    height,
                }
            }
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            self.base.timestamp
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            self.base.window
        }
    }
    pub fn crtc(&self) -> Crtc {
        unsafe {
            self.base.crtc
        }
    }
    pub fn mode(&self) -> Mode {
        unsafe {
            self.base.mode
        }
    }
    pub fn rotation(&self) -> u16 {
        unsafe {
            self.base.rotation
        }
    }
    pub fn x(&self) -> i16 {
        unsafe {
            self.base.x
        }
    }
    pub fn y(&self) -> i16 {
        unsafe {
            self.base.y
        }
    }
    pub fn width(&self) -> u16 {
        unsafe {
            self.base.width
        }
    }
    pub fn height(&self) -> u16 {
        unsafe {
            self.base.height
        }
    }
}

pub type CrtcChangeIterator = xcb_randr_crtc_change_iterator_t;

impl Iterator for CrtcChangeIterator {
    type Item = CrtcChange;
    fn next(&mut self) -> std::option::Option<CrtcChange> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_crtc_change_iterator_t;
                let data = (*iter).data;
                xcb_randr_crtc_change_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct OutputChange {
    pub base: xcb_randr_output_change_t,
}

impl OutputChange {
    #[allow(unused_unsafe)]
    pub fn new(timestamp:        xproto::Timestamp,
               config_timestamp: xproto::Timestamp,
               window:           xproto::Window,
               output:           Output,
               crtc:             Crtc,
               mode:             Mode,
               rotation:         u16,
               connection:       u8,
               subpixel_order:   u8)
            -> OutputChange {
        unsafe {
            OutputChange {
                base: xcb_randr_output_change_t {
                    timestamp:        timestamp,
                    config_timestamp: config_timestamp,
                    window:           window,
                    output:           output,
                    crtc:             crtc,
                    mode:             mode,
                    rotation:         rotation,
                    connection:       connection,
                    subpixel_order:   subpixel_order,
                }
            }
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            self.base.timestamp
        }
    }
    pub fn config_timestamp(&self) -> xproto::Timestamp {
        unsafe {
            self.base.config_timestamp
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            self.base.window
        }
    }
    pub fn output(&self) -> Output {
        unsafe {
            self.base.output
        }
    }
    pub fn crtc(&self) -> Crtc {
        unsafe {
            self.base.crtc
        }
    }
    pub fn mode(&self) -> Mode {
        unsafe {
            self.base.mode
        }
    }
    pub fn rotation(&self) -> u16 {
        unsafe {
            self.base.rotation
        }
    }
    pub fn connection(&self) -> u8 {
        unsafe {
            self.base.connection
        }
    }
    pub fn subpixel_order(&self) -> u8 {
        unsafe {
            self.base.subpixel_order
        }
    }
}

pub type OutputChangeIterator = xcb_randr_output_change_iterator_t;

impl Iterator for OutputChangeIterator {
    type Item = OutputChange;
    fn next(&mut self) -> std::option::Option<OutputChange> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_output_change_iterator_t;
                let data = (*iter).data;
                xcb_randr_output_change_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct OutputProperty {
    pub base: xcb_randr_output_property_t,
}

impl OutputProperty {
    #[allow(unused_unsafe)]
    pub fn new(window:    xproto::Window,
               output:    Output,
               atom:      xproto::Atom,
               timestamp: xproto::Timestamp,
               status:    u8)
            -> OutputProperty {
        unsafe {
            OutputProperty {
                base: xcb_randr_output_property_t {
                    window:    window,
                    output:    output,
                    atom:      atom,
                    timestamp: timestamp,
                    status:    status,
                    pad0:      [0; 11],
                }
            }
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            self.base.window
        }
    }
    pub fn output(&self) -> Output {
        unsafe {
            self.base.output
        }
    }
    pub fn atom(&self) -> xproto::Atom {
        unsafe {
            self.base.atom
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            self.base.timestamp
        }
    }
    pub fn status(&self) -> u8 {
        unsafe {
            self.base.status
        }
    }
}

pub type OutputPropertyIterator = xcb_randr_output_property_iterator_t;

impl Iterator for OutputPropertyIterator {
    type Item = OutputProperty;
    fn next(&mut self) -> std::option::Option<OutputProperty> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_output_property_iterator_t;
                let data = (*iter).data;
                xcb_randr_output_property_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ProviderChange {
    pub base: xcb_randr_provider_change_t,
}

impl ProviderChange {
    #[allow(unused_unsafe)]
    pub fn new(timestamp: xproto::Timestamp,
               window:    xproto::Window,
               provider:  Provider)
            -> ProviderChange {
        unsafe {
            ProviderChange {
                base: xcb_randr_provider_change_t {
                    timestamp: timestamp,
                    window:    window,
                    provider:  provider,
                    pad0:      [0; 16],
                }
            }
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            self.base.timestamp
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            self.base.window
        }
    }
    pub fn provider(&self) -> Provider {
        unsafe {
            self.base.provider
        }
    }
}

pub type ProviderChangeIterator = xcb_randr_provider_change_iterator_t;

impl Iterator for ProviderChangeIterator {
    type Item = ProviderChange;
    fn next(&mut self) -> std::option::Option<ProviderChange> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_provider_change_iterator_t;
                let data = (*iter).data;
                xcb_randr_provider_change_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ProviderProperty {
    pub base: xcb_randr_provider_property_t,
}

impl ProviderProperty {
    #[allow(unused_unsafe)]
    pub fn new(window:    xproto::Window,
               provider:  Provider,
               atom:      xproto::Atom,
               timestamp: xproto::Timestamp,
               state:     u8)
            -> ProviderProperty {
        unsafe {
            ProviderProperty {
                base: xcb_randr_provider_property_t {
                    window:    window,
                    provider:  provider,
                    atom:      atom,
                    timestamp: timestamp,
                    state:     state,
                    pad0:      [0; 11],
                }
            }
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            self.base.window
        }
    }
    pub fn provider(&self) -> Provider {
        unsafe {
            self.base.provider
        }
    }
    pub fn atom(&self) -> xproto::Atom {
        unsafe {
            self.base.atom
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            self.base.timestamp
        }
    }
    pub fn state(&self) -> u8 {
        unsafe {
            self.base.state
        }
    }
}

pub type ProviderPropertyIterator = xcb_randr_provider_property_iterator_t;

impl Iterator for ProviderPropertyIterator {
    type Item = ProviderProperty;
    fn next(&mut self) -> std::option::Option<ProviderProperty> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_provider_property_iterator_t;
                let data = (*iter).data;
                xcb_randr_provider_property_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ResourceChange {
    pub base: xcb_randr_resource_change_t,
}

impl ResourceChange {
    #[allow(unused_unsafe)]
    pub fn new(timestamp: xproto::Timestamp,
               window:    xproto::Window)
            -> ResourceChange {
        unsafe {
            ResourceChange {
                base: xcb_randr_resource_change_t {
                    timestamp: timestamp,
                    window:    window,
                    pad0:      [0; 20],
                }
            }
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            self.base.timestamp
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            self.base.window
        }
    }
}

pub type ResourceChangeIterator = xcb_randr_resource_change_iterator_t;

impl Iterator for ResourceChangeIterator {
    type Item = ResourceChange;
    fn next(&mut self) -> std::option::Option<ResourceChange> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_resource_change_iterator_t;
                let data = (*iter).data;
                xcb_randr_resource_change_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type NotifyData = xcb_randr_notify_data_t;

impl NotifyData {
    pub fn cc(&self) -> CrtcChange {
        unsafe {
            let _ptr = self.data.as_ptr() as *const CrtcChange;
            *_ptr
        }
    }
    pub fn from_cc(cc: CrtcChange) -> NotifyData {
        unsafe {
            let mut res = NotifyData { data: [0; 28] };
            let res_ptr = res.data.as_mut_ptr() as *mut CrtcChange;
            *res_ptr = cc;
            res
        }
    }
    pub fn oc(&self) -> OutputChange {
        unsafe {
            let _ptr = self.data.as_ptr() as *const OutputChange;
            *_ptr
        }
    }
    pub fn from_oc(oc: OutputChange) -> NotifyData {
        unsafe {
            let mut res = NotifyData { data: [0; 28] };
            let res_ptr = res.data.as_mut_ptr() as *mut OutputChange;
            *res_ptr = oc;
            res
        }
    }
    pub fn op(&self) -> OutputProperty {
        unsafe {
            let _ptr = self.data.as_ptr() as *const OutputProperty;
            *_ptr
        }
    }
    pub fn from_op(op: OutputProperty) -> NotifyData {
        unsafe {
            let mut res = NotifyData { data: [0; 28] };
            let res_ptr = res.data.as_mut_ptr() as *mut OutputProperty;
            *res_ptr = op;
            res
        }
    }
    pub fn pc(&self) -> ProviderChange {
        unsafe {
            let _ptr = self.data.as_ptr() as *const ProviderChange;
            *_ptr
        }
    }
    pub fn from_pc(pc: ProviderChange) -> NotifyData {
        unsafe {
            let mut res = NotifyData { data: [0; 28] };
            let res_ptr = res.data.as_mut_ptr() as *mut ProviderChange;
            *res_ptr = pc;
            res
        }
    }
    pub fn pp(&self) -> ProviderProperty {
        unsafe {
            let _ptr = self.data.as_ptr() as *const ProviderProperty;
            *_ptr
        }
    }
    pub fn from_pp(pp: ProviderProperty) -> NotifyData {
        unsafe {
            let mut res = NotifyData { data: [0; 28] };
            let res_ptr = res.data.as_mut_ptr() as *mut ProviderProperty;
            *res_ptr = pp;
            res
        }
    }
    pub fn rc(&self) -> ResourceChange {
        unsafe {
            let _ptr = self.data.as_ptr() as *const ResourceChange;
            *_ptr
        }
    }
    pub fn from_rc(rc: ResourceChange) -> NotifyData {
        unsafe {
            let mut res = NotifyData { data: [0; 28] };
            let res_ptr = res.data.as_mut_ptr() as *mut ResourceChange;
            *res_ptr = rc;
            res
        }
    }
}

pub type NotifyDataIterator = xcb_randr_notify_data_iterator_t;

impl Iterator for NotifyDataIterator {
    type Item = NotifyData;
    fn next(&mut self) -> std::option::Option<NotifyData> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_randr_notify_data_iterator_t;
                let data = (*iter).data;
                xcb_randr_notify_data_next(iter);
                Some(*data)
            }
        }
    }
}

pub const NOTIFY: u8 = 1;

pub type NotifyEvent = base::Event<xcb_randr_notify_event_t>;

impl NotifyEvent {
    pub fn sub_code(&self) -> u8 {
        unsafe {
            (*self.ptr).subCode
        }
    }
    pub fn u<'a>(&'a self) -> &'a NotifyData {
        unsafe {
            &(*self.ptr).u
        }
    }
    /// Constructs a new NotifyEvent
    /// `response_type` will be set automatically to NOTIFY
    pub fn new(sub_code: u8,
               u: NotifyData)
            -> NotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_randr_notify_event_t;
            (*raw).response_type = NOTIFY;
            (*raw).subCode = sub_code;
            (*raw).u = u;
            NotifyEvent {
                ptr: raw
            }
        }
    }
}
