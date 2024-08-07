// Generated automatically from xf86vidmode.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::xf86vidmode::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_xf86vidmode_id
    }
}

pub const MAJOR_VERSION: u32 = 2;
pub const MINOR_VERSION: u32 = 2;

pub type Syncrange = xcb_xf86vidmode_syncrange_t;

pub type Dotclock = xcb_xf86vidmode_dotclock_t;

pub type ModeFlag = u32;
pub const MODE_FLAG_POSITIVE_H_SYNC: ModeFlag =   0x01;
pub const MODE_FLAG_NEGATIVE_H_SYNC: ModeFlag =   0x02;
pub const MODE_FLAG_POSITIVE_V_SYNC: ModeFlag =   0x04;
pub const MODE_FLAG_NEGATIVE_V_SYNC: ModeFlag =   0x08;
pub const MODE_FLAG_INTERLACE      : ModeFlag =   0x10;
pub const MODE_FLAG_COMPOSITE_SYNC : ModeFlag =   0x20;
pub const MODE_FLAG_POSITIVE_C_SYNC: ModeFlag =   0x40;
pub const MODE_FLAG_NEGATIVE_C_SYNC: ModeFlag =   0x80;
pub const MODE_FLAG_H_SKEW         : ModeFlag =  0x100;
pub const MODE_FLAG_BROADCAST      : ModeFlag =  0x200;
pub const MODE_FLAG_PIXMUX         : ModeFlag =  0x400;
pub const MODE_FLAG_DOUBLE_CLOCK   : ModeFlag =  0x800;
pub const MODE_FLAG_HALF_CLOCK     : ModeFlag = 0x1000;

pub type ClockFlag = u32;
pub const CLOCK_FLAG_PROGRAMABLE: ClockFlag = 0x01;

pub type Permission = u32;
pub const PERMISSION_READ : Permission = 0x01;
pub const PERMISSION_WRITE: Permission = 0x02;

pub struct BadClockError {
    pub base: base::Error<xcb_xf86vidmode_bad_clock_error_t>
}

pub struct BadHTimingsError {
    pub base: base::Error<xcb_xf86vidmode_bad_h_timings_error_t>
}

pub struct BadVTimingsError {
    pub base: base::Error<xcb_xf86vidmode_bad_v_timings_error_t>
}

pub struct ModeUnsuitableError {
    pub base: base::Error<xcb_xf86vidmode_mode_unsuitable_error_t>
}

pub struct ExtensionDisabledError {
    pub base: base::Error<xcb_xf86vidmode_extension_disabled_error_t>
}

pub struct ClientNotLocalError {
    pub base: base::Error<xcb_xf86vidmode_client_not_local_error_t>
}

pub struct ZoomLockedError {
    pub base: base::Error<xcb_xf86vidmode_zoom_locked_error_t>
}



#[derive(Copy, Clone)]
pub struct ModeInfo {
    pub base: xcb_xf86vidmode_mode_info_t,
}

impl ModeInfo {
    #[allow(unused_unsafe)]
    pub fn new(dotclock:   Dotclock,
               hdisplay:   u16,
               hsyncstart: u16,
               hsyncend:   u16,
               htotal:     u16,
               hskew:      u32,
               vdisplay:   u16,
               vsyncstart: u16,
               vsyncend:   u16,
               vtotal:     u16,
               flags:      u32,
               privsize:   u32)
            -> ModeInfo {
        unsafe {
            ModeInfo {
                base: xcb_xf86vidmode_mode_info_t {
                    dotclock:   dotclock,
                    hdisplay:   hdisplay,
                    hsyncstart: hsyncstart,
                    hsyncend:   hsyncend,
                    htotal:     htotal,
                    hskew:      hskew,
                    vdisplay:   vdisplay,
                    vsyncstart: vsyncstart,
                    vsyncend:   vsyncend,
                    vtotal:     vtotal,
                    pad0:       [0; 4],
                    flags:      flags,
                    pad1:       [0; 12],
                    privsize:   privsize,
                }
            }
        }
    }
    pub fn dotclock(&self) -> Dotclock {
        unsafe {
            self.base.dotclock
        }
    }
    pub fn hdisplay(&self) -> u16 {
        unsafe {
            self.base.hdisplay
        }
    }
    pub fn hsyncstart(&self) -> u16 {
        unsafe {
            self.base.hsyncstart
        }
    }
    pub fn hsyncend(&self) -> u16 {
        unsafe {
            self.base.hsyncend
        }
    }
    pub fn htotal(&self) -> u16 {
        unsafe {
            self.base.htotal
        }
    }
    pub fn hskew(&self) -> u32 {
        unsafe {
            self.base.hskew
        }
    }
    pub fn vdisplay(&self) -> u16 {
        unsafe {
            self.base.vdisplay
        }
    }
    pub fn vsyncstart(&self) -> u16 {
        unsafe {
            self.base.vsyncstart
        }
    }
    pub fn vsyncend(&self) -> u16 {
        unsafe {
            self.base.vsyncend
        }
    }
    pub fn vtotal(&self) -> u16 {
        unsafe {
            self.base.vtotal
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            self.base.flags
        }
    }
    pub fn privsize(&self) -> u32 {
        unsafe {
            self.base.privsize
        }
    }
}

pub type ModeInfoIterator = xcb_xf86vidmode_mode_info_iterator_t;

impl Iterator for ModeInfoIterator {
    type Item = ModeInfo;
    fn next(&mut self) -> std::option::Option<ModeInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xf86vidmode_mode_info_iterator_t;
                let data = (*iter).data;
                xcb_xf86vidmode_mode_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_xf86vidmode_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_xf86vidmode_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_xf86vidmode_query_version_reply_t>;

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
        let cookie = xcb_xf86vidmode_query_version(c.get_raw_conn());
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
        let cookie = xcb_xf86vidmode_query_version_unchecked(c.get_raw_conn());
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MODE_LINE: u8 = 1;

pub type GetModeLineCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_mode_line_cookie_t>;

impl<'a> GetModeLineCookie<'a> {
    pub fn get_reply(&self) -> Result<GetModeLineReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetModeLineReply {
                    ptr: xcb_xf86vidmode_get_mode_line_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetModeLineReply {
                    ptr: xcb_xf86vidmode_get_mode_line_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetModeLineReply = base::Reply<xcb_xf86vidmode_get_mode_line_reply_t>;

impl GetModeLineReply {
    pub fn dotclock(&self) -> Dotclock {
        unsafe {
            (*self.ptr).dotclock
        }
    }
    pub fn hdisplay(&self) -> u16 {
        unsafe {
            (*self.ptr).hdisplay
        }
    }
    pub fn hsyncstart(&self) -> u16 {
        unsafe {
            (*self.ptr).hsyncstart
        }
    }
    pub fn hsyncend(&self) -> u16 {
        unsafe {
            (*self.ptr).hsyncend
        }
    }
    pub fn htotal(&self) -> u16 {
        unsafe {
            (*self.ptr).htotal
        }
    }
    pub fn hskew(&self) -> u16 {
        unsafe {
            (*self.ptr).hskew
        }
    }
    pub fn vdisplay(&self) -> u16 {
        unsafe {
            (*self.ptr).vdisplay
        }
    }
    pub fn vsyncstart(&self) -> u16 {
        unsafe {
            (*self.ptr).vsyncstart
        }
    }
    pub fn vsyncend(&self) -> u16 {
        unsafe {
            (*self.ptr).vsyncend
        }
    }
    pub fn vtotal(&self) -> u16 {
        unsafe {
            (*self.ptr).vtotal
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn privsize(&self) -> u32 {
        unsafe {
            (*self.ptr).privsize
        }
    }
    pub fn private(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_mode_line_private_length(field) as usize;
            let data = xcb_xf86vidmode_get_mode_line_private(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_mode_line<'a>(c     : &'a base::Connection,
                         screen: u16)
        -> GetModeLineCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_mode_line(c.get_raw_conn(),
                                                   screen as u16);  // 0
        GetModeLineCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_mode_line_unchecked<'a>(c     : &'a base::Connection,
                                   screen: u16)
        -> GetModeLineCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_mode_line_unchecked(c.get_raw_conn(),
                                                             screen as u16);  // 0
        GetModeLineCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const MOD_MODE_LINE: u8 = 2;

pub fn mod_mode_line<'a>(c         : &'a base::Connection,
                         screen    : u32,
                         hdisplay  : u16,
                         hsyncstart: u16,
                         hsyncend  : u16,
                         htotal    : u16,
                         hskew     : u16,
                         vdisplay  : u16,
                         vsyncstart: u16,
                         vsyncend  : u16,
                         vtotal    : u16,
                         flags     : u32,
                         private   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_mod_mode_line(c.get_raw_conn(),
                                                   screen as u32,  // 0
                                                   hdisplay as u16,  // 1
                                                   hsyncstart as u16,  // 2
                                                   hsyncend as u16,  // 3
                                                   htotal as u16,  // 4
                                                   hskew as u16,  // 5
                                                   vdisplay as u16,  // 6
                                                   vsyncstart as u16,  // 7
                                                   vsyncend as u16,  // 8
                                                   vtotal as u16,  // 9
                                                   flags as u32,  // 10
                                                   private_len as u32,  // 11
                                                   private_ptr as *const u8);  // 12
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn mod_mode_line_checked<'a>(c         : &'a base::Connection,
                                 screen    : u32,
                                 hdisplay  : u16,
                                 hsyncstart: u16,
                                 hsyncend  : u16,
                                 htotal    : u16,
                                 hskew     : u16,
                                 vdisplay  : u16,
                                 vsyncstart: u16,
                                 vsyncend  : u16,
                                 vtotal    : u16,
                                 flags     : u32,
                                 private   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_mod_mode_line_checked(c.get_raw_conn(),
                                                           screen as u32,  // 0
                                                           hdisplay as u16,  // 1
                                                           hsyncstart as u16,  // 2
                                                           hsyncend as u16,  // 3
                                                           htotal as u16,  // 4
                                                           hskew as u16,  // 5
                                                           vdisplay as u16,  // 6
                                                           vsyncstart as u16,  // 7
                                                           vsyncend as u16,  // 8
                                                           vtotal as u16,  // 9
                                                           flags as u32,  // 10
                                                           private_len as u32,  // 11
                                                           private_ptr as *const u8);  // 12
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SWITCH_MODE: u8 = 3;

pub fn switch_mode<'a>(c     : &'a base::Connection,
                       screen: u16,
                       zoom  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_switch_mode(c.get_raw_conn(),
                                                 screen as u16,  // 0
                                                 zoom as u16);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn switch_mode_checked<'a>(c     : &'a base::Connection,
                               screen: u16,
                               zoom  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_switch_mode_checked(c.get_raw_conn(),
                                                         screen as u16,  // 0
                                                         zoom as u16);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_MONITOR: u8 = 4;

pub type GetMonitorCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_monitor_cookie_t>;

impl<'a> GetMonitorCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMonitorReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMonitorReply {
                    ptr: xcb_xf86vidmode_get_monitor_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMonitorReply {
                    ptr: xcb_xf86vidmode_get_monitor_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMonitorReply = base::Reply<xcb_xf86vidmode_get_monitor_reply_t>;

impl GetMonitorReply {
    pub fn vendor_length(&self) -> u8 {
        unsafe {
            (*self.ptr).vendor_length
        }
    }
    pub fn model_length(&self) -> u8 {
        unsafe {
            (*self.ptr).model_length
        }
    }
    pub fn num_hsync(&self) -> u8 {
        unsafe {
            (*self.ptr).num_hsync
        }
    }
    pub fn num_vsync(&self) -> u8 {
        unsafe {
            (*self.ptr).num_vsync
        }
    }
    pub fn hsync(&self) -> &[Syncrange] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_monitor_hsync_length(field) as usize;
            let data = xcb_xf86vidmode_get_monitor_hsync(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn vsync(&self) -> &[Syncrange] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_monitor_vsync_length(field) as usize;
            let data = xcb_xf86vidmode_get_monitor_vsync(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn vendor(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_monitor_vendor_length(field) as usize;
            let data = xcb_xf86vidmode_get_monitor_vendor(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn alignment_pad<T>(&self) -> &[T] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_monitor_alignment_pad_length(field) as usize;
            let data = xcb_xf86vidmode_get_monitor_alignment_pad(field);
            debug_assert_eq!(len % std::mem::size_of::<T>(), 0);
            std::slice::from_raw_parts(data as *const T, len / std::mem::size_of::<T>())
        }
    }
    pub fn model(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_monitor_model_length(field) as usize;
            let data = xcb_xf86vidmode_get_monitor_model(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_monitor<'a>(c     : &'a base::Connection,
                       screen: u16)
        -> GetMonitorCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_monitor(c.get_raw_conn(),
                                                 screen as u16);  // 0
        GetMonitorCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_monitor_unchecked<'a>(c     : &'a base::Connection,
                                 screen: u16)
        -> GetMonitorCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_monitor_unchecked(c.get_raw_conn(),
                                                           screen as u16);  // 0
        GetMonitorCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LOCK_MODE_SWITCH: u8 = 5;

pub fn lock_mode_switch<'a>(c     : &'a base::Connection,
                            screen: u16,
                            lock  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_lock_mode_switch(c.get_raw_conn(),
                                                      screen as u16,  // 0
                                                      lock as u16);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn lock_mode_switch_checked<'a>(c     : &'a base::Connection,
                                    screen: u16,
                                    lock  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_lock_mode_switch_checked(c.get_raw_conn(),
                                                              screen as u16,  // 0
                                                              lock as u16);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_ALL_MODE_LINES: u8 = 6;

pub type GetAllModeLinesCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_all_mode_lines_cookie_t>;

impl<'a> GetAllModeLinesCookie<'a> {
    pub fn get_reply(&self) -> Result<GetAllModeLinesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetAllModeLinesReply {
                    ptr: xcb_xf86vidmode_get_all_mode_lines_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetAllModeLinesReply {
                    ptr: xcb_xf86vidmode_get_all_mode_lines_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetAllModeLinesReply = base::Reply<xcb_xf86vidmode_get_all_mode_lines_reply_t>;

impl GetAllModeLinesReply {
    pub fn modecount(&self) -> u32 {
        unsafe {
            (*self.ptr).modecount
        }
    }
    pub fn modeinfo(&self) -> ModeInfoIterator {
        unsafe {
            xcb_xf86vidmode_get_all_mode_lines_modeinfo_iterator(self.ptr)
        }
    }
}

pub fn get_all_mode_lines<'a>(c     : &'a base::Connection,
                              screen: u16)
        -> GetAllModeLinesCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_all_mode_lines(c.get_raw_conn(),
                                                        screen as u16);  // 0
        GetAllModeLinesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_all_mode_lines_unchecked<'a>(c     : &'a base::Connection,
                                        screen: u16)
        -> GetAllModeLinesCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_all_mode_lines_unchecked(c.get_raw_conn(),
                                                                  screen as u16);  // 0
        GetAllModeLinesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const ADD_MODE_LINE: u8 = 7;

pub fn add_mode_line<'a>(c               : &'a base::Connection,
                         screen          : u32,
                         dotclock        : Dotclock,
                         hdisplay        : u16,
                         hsyncstart      : u16,
                         hsyncend        : u16,
                         htotal          : u16,
                         hskew           : u16,
                         vdisplay        : u16,
                         vsyncstart      : u16,
                         vsyncend        : u16,
                         vtotal          : u16,
                         flags           : u32,
                         after_dotclock  : Dotclock,
                         after_hdisplay  : u16,
                         after_hsyncstart: u16,
                         after_hsyncend  : u16,
                         after_htotal    : u16,
                         after_hskew     : u16,
                         after_vdisplay  : u16,
                         after_vsyncstart: u16,
                         after_vsyncend  : u16,
                         after_vtotal    : u16,
                         after_flags     : u32,
                         private         : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_add_mode_line(c.get_raw_conn(),
                                                   screen as u32,  // 0
                                                   dotclock as xcb_xf86vidmode_dotclock_t,  // 1
                                                   hdisplay as u16,  // 2
                                                   hsyncstart as u16,  // 3
                                                   hsyncend as u16,  // 4
                                                   htotal as u16,  // 5
                                                   hskew as u16,  // 6
                                                   vdisplay as u16,  // 7
                                                   vsyncstart as u16,  // 8
                                                   vsyncend as u16,  // 9
                                                   vtotal as u16,  // 10
                                                   flags as u32,  // 11
                                                   private_len as u32,  // 12
                                                   after_dotclock as xcb_xf86vidmode_dotclock_t,  // 13
                                                   after_hdisplay as u16,  // 14
                                                   after_hsyncstart as u16,  // 15
                                                   after_hsyncend as u16,  // 16
                                                   after_htotal as u16,  // 17
                                                   after_hskew as u16,  // 18
                                                   after_vdisplay as u16,  // 19
                                                   after_vsyncstart as u16,  // 20
                                                   after_vsyncend as u16,  // 21
                                                   after_vtotal as u16,  // 22
                                                   after_flags as u32,  // 23
                                                   private_ptr as *const u8);  // 24
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn add_mode_line_checked<'a>(c               : &'a base::Connection,
                                 screen          : u32,
                                 dotclock        : Dotclock,
                                 hdisplay        : u16,
                                 hsyncstart      : u16,
                                 hsyncend        : u16,
                                 htotal          : u16,
                                 hskew           : u16,
                                 vdisplay        : u16,
                                 vsyncstart      : u16,
                                 vsyncend        : u16,
                                 vtotal          : u16,
                                 flags           : u32,
                                 after_dotclock  : Dotclock,
                                 after_hdisplay  : u16,
                                 after_hsyncstart: u16,
                                 after_hsyncend  : u16,
                                 after_htotal    : u16,
                                 after_hskew     : u16,
                                 after_vdisplay  : u16,
                                 after_vsyncstart: u16,
                                 after_vsyncend  : u16,
                                 after_vtotal    : u16,
                                 after_flags     : u32,
                                 private         : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_add_mode_line_checked(c.get_raw_conn(),
                                                           screen as u32,  // 0
                                                           dotclock as xcb_xf86vidmode_dotclock_t,  // 1
                                                           hdisplay as u16,  // 2
                                                           hsyncstart as u16,  // 3
                                                           hsyncend as u16,  // 4
                                                           htotal as u16,  // 5
                                                           hskew as u16,  // 6
                                                           vdisplay as u16,  // 7
                                                           vsyncstart as u16,  // 8
                                                           vsyncend as u16,  // 9
                                                           vtotal as u16,  // 10
                                                           flags as u32,  // 11
                                                           private_len as u32,  // 12
                                                           after_dotclock as xcb_xf86vidmode_dotclock_t,  // 13
                                                           after_hdisplay as u16,  // 14
                                                           after_hsyncstart as u16,  // 15
                                                           after_hsyncend as u16,  // 16
                                                           after_htotal as u16,  // 17
                                                           after_hskew as u16,  // 18
                                                           after_vdisplay as u16,  // 19
                                                           after_vsyncstart as u16,  // 20
                                                           after_vsyncend as u16,  // 21
                                                           after_vtotal as u16,  // 22
                                                           after_flags as u32,  // 23
                                                           private_ptr as *const u8);  // 24
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_MODE_LINE: u8 = 8;

pub fn delete_mode_line<'a>(c         : &'a base::Connection,
                            screen    : u32,
                            dotclock  : Dotclock,
                            hdisplay  : u16,
                            hsyncstart: u16,
                            hsyncend  : u16,
                            htotal    : u16,
                            hskew     : u16,
                            vdisplay  : u16,
                            vsyncstart: u16,
                            vsyncend  : u16,
                            vtotal    : u16,
                            flags     : u32,
                            private   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_delete_mode_line(c.get_raw_conn(),
                                                      screen as u32,  // 0
                                                      dotclock as xcb_xf86vidmode_dotclock_t,  // 1
                                                      hdisplay as u16,  // 2
                                                      hsyncstart as u16,  // 3
                                                      hsyncend as u16,  // 4
                                                      htotal as u16,  // 5
                                                      hskew as u16,  // 6
                                                      vdisplay as u16,  // 7
                                                      vsyncstart as u16,  // 8
                                                      vsyncend as u16,  // 9
                                                      vtotal as u16,  // 10
                                                      flags as u32,  // 11
                                                      private_len as u32,  // 12
                                                      private_ptr as *const u8);  // 13
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_mode_line_checked<'a>(c         : &'a base::Connection,
                                    screen    : u32,
                                    dotclock  : Dotclock,
                                    hdisplay  : u16,
                                    hsyncstart: u16,
                                    hsyncend  : u16,
                                    htotal    : u16,
                                    hskew     : u16,
                                    vdisplay  : u16,
                                    vsyncstart: u16,
                                    vsyncend  : u16,
                                    vtotal    : u16,
                                    flags     : u32,
                                    private   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_delete_mode_line_checked(c.get_raw_conn(),
                                                              screen as u32,  // 0
                                                              dotclock as xcb_xf86vidmode_dotclock_t,  // 1
                                                              hdisplay as u16,  // 2
                                                              hsyncstart as u16,  // 3
                                                              hsyncend as u16,  // 4
                                                              htotal as u16,  // 5
                                                              hskew as u16,  // 6
                                                              vdisplay as u16,  // 7
                                                              vsyncstart as u16,  // 8
                                                              vsyncend as u16,  // 9
                                                              vtotal as u16,  // 10
                                                              flags as u32,  // 11
                                                              private_len as u32,  // 12
                                                              private_ptr as *const u8);  // 13
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const VALIDATE_MODE_LINE: u8 = 9;

pub type ValidateModeLineCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_validate_mode_line_cookie_t>;

impl<'a> ValidateModeLineCookie<'a> {
    pub fn get_reply(&self) -> Result<ValidateModeLineReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ValidateModeLineReply {
                    ptr: xcb_xf86vidmode_validate_mode_line_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ValidateModeLineReply {
                    ptr: xcb_xf86vidmode_validate_mode_line_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ValidateModeLineReply = base::Reply<xcb_xf86vidmode_validate_mode_line_reply_t>;

impl ValidateModeLineReply {
    pub fn status(&self) -> u32 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn validate_mode_line<'a>(c         : &'a base::Connection,
                              screen    : u32,
                              dotclock  : Dotclock,
                              hdisplay  : u16,
                              hsyncstart: u16,
                              hsyncend  : u16,
                              htotal    : u16,
                              hskew     : u16,
                              vdisplay  : u16,
                              vsyncstart: u16,
                              vsyncend  : u16,
                              vtotal    : u16,
                              flags     : u32,
                              private   : &[u8])
        -> ValidateModeLineCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_validate_mode_line(c.get_raw_conn(),
                                                        screen as u32,  // 0
                                                        dotclock as xcb_xf86vidmode_dotclock_t,  // 1
                                                        hdisplay as u16,  // 2
                                                        hsyncstart as u16,  // 3
                                                        hsyncend as u16,  // 4
                                                        htotal as u16,  // 5
                                                        hskew as u16,  // 6
                                                        vdisplay as u16,  // 7
                                                        vsyncstart as u16,  // 8
                                                        vsyncend as u16,  // 9
                                                        vtotal as u16,  // 10
                                                        flags as u32,  // 11
                                                        private_len as u32,  // 12
                                                        private_ptr as *const u8);  // 13
        ValidateModeLineCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn validate_mode_line_unchecked<'a>(c         : &'a base::Connection,
                                        screen    : u32,
                                        dotclock  : Dotclock,
                                        hdisplay  : u16,
                                        hsyncstart: u16,
                                        hsyncend  : u16,
                                        htotal    : u16,
                                        hskew     : u16,
                                        vdisplay  : u16,
                                        vsyncstart: u16,
                                        vsyncend  : u16,
                                        vtotal    : u16,
                                        flags     : u32,
                                        private   : &[u8])
        -> ValidateModeLineCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_validate_mode_line_unchecked(c.get_raw_conn(),
                                                                  screen as u32,  // 0
                                                                  dotclock as xcb_xf86vidmode_dotclock_t,  // 1
                                                                  hdisplay as u16,  // 2
                                                                  hsyncstart as u16,  // 3
                                                                  hsyncend as u16,  // 4
                                                                  htotal as u16,  // 5
                                                                  hskew as u16,  // 6
                                                                  vdisplay as u16,  // 7
                                                                  vsyncstart as u16,  // 8
                                                                  vsyncend as u16,  // 9
                                                                  vtotal as u16,  // 10
                                                                  flags as u32,  // 11
                                                                  private_len as u32,  // 12
                                                                  private_ptr as *const u8);  // 13
        ValidateModeLineCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SWITCH_TO_MODE: u8 = 10;

pub fn switch_to_mode<'a>(c         : &'a base::Connection,
                          screen    : u32,
                          dotclock  : Dotclock,
                          hdisplay  : u16,
                          hsyncstart: u16,
                          hsyncend  : u16,
                          htotal    : u16,
                          hskew     : u16,
                          vdisplay  : u16,
                          vsyncstart: u16,
                          vsyncend  : u16,
                          vtotal    : u16,
                          flags     : u32,
                          private   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_switch_to_mode(c.get_raw_conn(),
                                                    screen as u32,  // 0
                                                    dotclock as xcb_xf86vidmode_dotclock_t,  // 1
                                                    hdisplay as u16,  // 2
                                                    hsyncstart as u16,  // 3
                                                    hsyncend as u16,  // 4
                                                    htotal as u16,  // 5
                                                    hskew as u16,  // 6
                                                    vdisplay as u16,  // 7
                                                    vsyncstart as u16,  // 8
                                                    vsyncend as u16,  // 9
                                                    vtotal as u16,  // 10
                                                    flags as u32,  // 11
                                                    private_len as u32,  // 12
                                                    private_ptr as *const u8);  // 13
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn switch_to_mode_checked<'a>(c         : &'a base::Connection,
                                  screen    : u32,
                                  dotclock  : Dotclock,
                                  hdisplay  : u16,
                                  hsyncstart: u16,
                                  hsyncend  : u16,
                                  htotal    : u16,
                                  hskew     : u16,
                                  vdisplay  : u16,
                                  vsyncstart: u16,
                                  vsyncend  : u16,
                                  vtotal    : u16,
                                  flags     : u32,
                                  private   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let private_len = private.len();
        let private_ptr = private.as_ptr();
        let cookie = xcb_xf86vidmode_switch_to_mode_checked(c.get_raw_conn(),
                                                            screen as u32,  // 0
                                                            dotclock as xcb_xf86vidmode_dotclock_t,  // 1
                                                            hdisplay as u16,  // 2
                                                            hsyncstart as u16,  // 3
                                                            hsyncend as u16,  // 4
                                                            htotal as u16,  // 5
                                                            hskew as u16,  // 6
                                                            vdisplay as u16,  // 7
                                                            vsyncstart as u16,  // 8
                                                            vsyncend as u16,  // 9
                                                            vtotal as u16,  // 10
                                                            flags as u32,  // 11
                                                            private_len as u32,  // 12
                                                            private_ptr as *const u8);  // 13
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_VIEW_PORT: u8 = 11;

pub type GetViewPortCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_view_port_cookie_t>;

impl<'a> GetViewPortCookie<'a> {
    pub fn get_reply(&self) -> Result<GetViewPortReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetViewPortReply {
                    ptr: xcb_xf86vidmode_get_view_port_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetViewPortReply {
                    ptr: xcb_xf86vidmode_get_view_port_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetViewPortReply = base::Reply<xcb_xf86vidmode_get_view_port_reply_t>;

impl GetViewPortReply {
    pub fn x(&self) -> u32 {
        unsafe {
            (*self.ptr).x
        }
    }
    pub fn y(&self) -> u32 {
        unsafe {
            (*self.ptr).y
        }
    }
}

pub fn get_view_port<'a>(c     : &'a base::Connection,
                         screen: u16)
        -> GetViewPortCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_view_port(c.get_raw_conn(),
                                                   screen as u16);  // 0
        GetViewPortCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_view_port_unchecked<'a>(c     : &'a base::Connection,
                                   screen: u16)
        -> GetViewPortCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_view_port_unchecked(c.get_raw_conn(),
                                                             screen as u16);  // 0
        GetViewPortCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_VIEW_PORT: u8 = 12;

pub fn set_view_port<'a>(c     : &'a base::Connection,
                         screen: u16,
                         x     : u32,
                         y     : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_set_view_port(c.get_raw_conn(),
                                                   screen as u16,  // 0
                                                   x as u32,  // 1
                                                   y as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_view_port_checked<'a>(c     : &'a base::Connection,
                                 screen: u16,
                                 x     : u32,
                                 y     : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_set_view_port_checked(c.get_raw_conn(),
                                                           screen as u16,  // 0
                                                           x as u32,  // 1
                                                           y as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DOT_CLOCKS: u8 = 13;

pub type GetDotClocksCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_dot_clocks_cookie_t>;

impl<'a> GetDotClocksCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDotClocksReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDotClocksReply {
                    ptr: xcb_xf86vidmode_get_dot_clocks_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDotClocksReply {
                    ptr: xcb_xf86vidmode_get_dot_clocks_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDotClocksReply = base::Reply<xcb_xf86vidmode_get_dot_clocks_reply_t>;

impl GetDotClocksReply {
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn clocks(&self) -> u32 {
        unsafe {
            (*self.ptr).clocks
        }
    }
    pub fn maxclocks(&self) -> u32 {
        unsafe {
            (*self.ptr).maxclocks
        }
    }
    pub fn clock(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_dot_clocks_clock_length(field) as usize;
            let data = xcb_xf86vidmode_get_dot_clocks_clock(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_dot_clocks<'a>(c     : &'a base::Connection,
                          screen: u16)
        -> GetDotClocksCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_dot_clocks(c.get_raw_conn(),
                                                    screen as u16);  // 0
        GetDotClocksCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_dot_clocks_unchecked<'a>(c     : &'a base::Connection,
                                    screen: u16)
        -> GetDotClocksCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_dot_clocks_unchecked(c.get_raw_conn(),
                                                              screen as u16);  // 0
        GetDotClocksCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_CLIENT_VERSION: u8 = 14;

pub fn set_client_version<'a>(c    : &'a base::Connection,
                              major: u16,
                              minor: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_set_client_version(c.get_raw_conn(),
                                                        major as u16,  // 0
                                                        minor as u16);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_client_version_checked<'a>(c    : &'a base::Connection,
                                      major: u16,
                                      minor: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_set_client_version_checked(c.get_raw_conn(),
                                                                major as u16,  // 0
                                                                minor as u16);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_GAMMA: u8 = 15;

pub fn set_gamma<'a>(c     : &'a base::Connection,
                     screen: u16,
                     red   : u32,
                     green : u32,
                     blue  : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_set_gamma(c.get_raw_conn(),
                                               screen as u16,  // 0
                                               red as u32,  // 1
                                               green as u32,  // 2
                                               blue as u32);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_gamma_checked<'a>(c     : &'a base::Connection,
                             screen: u16,
                             red   : u32,
                             green : u32,
                             blue  : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_set_gamma_checked(c.get_raw_conn(),
                                                       screen as u16,  // 0
                                                       red as u32,  // 1
                                                       green as u32,  // 2
                                                       blue as u32);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_GAMMA: u8 = 16;

pub type GetGammaCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_gamma_cookie_t>;

impl<'a> GetGammaCookie<'a> {
    pub fn get_reply(&self) -> Result<GetGammaReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetGammaReply {
                    ptr: xcb_xf86vidmode_get_gamma_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetGammaReply {
                    ptr: xcb_xf86vidmode_get_gamma_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetGammaReply = base::Reply<xcb_xf86vidmode_get_gamma_reply_t>;

impl GetGammaReply {
    pub fn red(&self) -> u32 {
        unsafe {
            (*self.ptr).red
        }
    }
    pub fn green(&self) -> u32 {
        unsafe {
            (*self.ptr).green
        }
    }
    pub fn blue(&self) -> u32 {
        unsafe {
            (*self.ptr).blue
        }
    }
}

pub fn get_gamma<'a>(c     : &'a base::Connection,
                     screen: u16)
        -> GetGammaCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_gamma(c.get_raw_conn(),
                                               screen as u16);  // 0
        GetGammaCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_gamma_unchecked<'a>(c     : &'a base::Connection,
                               screen: u16)
        -> GetGammaCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_gamma_unchecked(c.get_raw_conn(),
                                                         screen as u16);  // 0
        GetGammaCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_GAMMA_RAMP: u8 = 17;

pub type GetGammaRampCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_gamma_ramp_cookie_t>;

impl<'a> GetGammaRampCookie<'a> {
    pub fn get_reply(&self) -> Result<GetGammaRampReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetGammaRampReply {
                    ptr: xcb_xf86vidmode_get_gamma_ramp_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetGammaRampReply {
                    ptr: xcb_xf86vidmode_get_gamma_ramp_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetGammaRampReply = base::Reply<xcb_xf86vidmode_get_gamma_ramp_reply_t>;

impl GetGammaRampReply {
    pub fn size(&self) -> u16 {
        unsafe {
            (*self.ptr).size
        }
    }
    pub fn red(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_gamma_ramp_red_length(field) as usize;
            let data = xcb_xf86vidmode_get_gamma_ramp_red(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn green(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_gamma_ramp_green_length(field) as usize;
            let data = xcb_xf86vidmode_get_gamma_ramp_green(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn blue(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xf86vidmode_get_gamma_ramp_blue_length(field) as usize;
            let data = xcb_xf86vidmode_get_gamma_ramp_blue(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_gamma_ramp<'a>(c     : &'a base::Connection,
                          screen: u16,
                          size  : u16)
        -> GetGammaRampCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_gamma_ramp(c.get_raw_conn(),
                                                    screen as u16,  // 0
                                                    size as u16);  // 1
        GetGammaRampCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_gamma_ramp_unchecked<'a>(c     : &'a base::Connection,
                                    screen: u16,
                                    size  : u16)
        -> GetGammaRampCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_gamma_ramp_unchecked(c.get_raw_conn(),
                                                              screen as u16,  // 0
                                                              size as u16);  // 1
        GetGammaRampCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_GAMMA_RAMP: u8 = 18;

pub fn set_gamma_ramp<'a>(c     : &'a base::Connection,
                          screen: u16,
                          red   : &[u16],
                          green : &[u16],
                          blue  : &[u16])
        -> base::VoidCookie<'a> {
    unsafe {
        let red_len = red.len();
        let red_ptr = red.as_ptr();
        let green_ptr = green.as_ptr();
        let blue_ptr = blue.as_ptr();
        let cookie = xcb_xf86vidmode_set_gamma_ramp(c.get_raw_conn(),
                                                    screen as u16,  // 0
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

pub fn set_gamma_ramp_checked<'a>(c     : &'a base::Connection,
                                  screen: u16,
                                  red   : &[u16],
                                  green : &[u16],
                                  blue  : &[u16])
        -> base::VoidCookie<'a> {
    unsafe {
        let red_len = red.len();
        let red_ptr = red.as_ptr();
        let green_ptr = green.as_ptr();
        let blue_ptr = blue.as_ptr();
        let cookie = xcb_xf86vidmode_set_gamma_ramp_checked(c.get_raw_conn(),
                                                            screen as u16,  // 0
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

pub const GET_GAMMA_RAMP_SIZE: u8 = 19;

pub type GetGammaRampSizeCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_gamma_ramp_size_cookie_t>;

impl<'a> GetGammaRampSizeCookie<'a> {
    pub fn get_reply(&self) -> Result<GetGammaRampSizeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetGammaRampSizeReply {
                    ptr: xcb_xf86vidmode_get_gamma_ramp_size_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetGammaRampSizeReply {
                    ptr: xcb_xf86vidmode_get_gamma_ramp_size_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetGammaRampSizeReply = base::Reply<xcb_xf86vidmode_get_gamma_ramp_size_reply_t>;

impl GetGammaRampSizeReply {
    pub fn size(&self) -> u16 {
        unsafe {
            (*self.ptr).size
        }
    }
}

pub fn get_gamma_ramp_size<'a>(c     : &'a base::Connection,
                               screen: u16)
        -> GetGammaRampSizeCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_gamma_ramp_size(c.get_raw_conn(),
                                                         screen as u16);  // 0
        GetGammaRampSizeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_gamma_ramp_size_unchecked<'a>(c     : &'a base::Connection,
                                         screen: u16)
        -> GetGammaRampSizeCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_gamma_ramp_size_unchecked(c.get_raw_conn(),
                                                                   screen as u16);  // 0
        GetGammaRampSizeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PERMISSIONS: u8 = 20;

pub type GetPermissionsCookie<'a> = base::Cookie<'a, xcb_xf86vidmode_get_permissions_cookie_t>;

impl<'a> GetPermissionsCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPermissionsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPermissionsReply {
                    ptr: xcb_xf86vidmode_get_permissions_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPermissionsReply {
                    ptr: xcb_xf86vidmode_get_permissions_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPermissionsReply = base::Reply<xcb_xf86vidmode_get_permissions_reply_t>;

impl GetPermissionsReply {
    pub fn permissions(&self) -> u32 {
        unsafe {
            (*self.ptr).permissions
        }
    }
}

pub fn get_permissions<'a>(c     : &'a base::Connection,
                           screen: u16)
        -> GetPermissionsCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_permissions(c.get_raw_conn(),
                                                     screen as u16);  // 0
        GetPermissionsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_permissions_unchecked<'a>(c     : &'a base::Connection,
                                     screen: u16)
        -> GetPermissionsCookie<'a> {
    unsafe {
        let cookie = xcb_xf86vidmode_get_permissions_unchecked(c.get_raw_conn(),
                                                               screen as u16);  // 0
        GetPermissionsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const BAD_CLOCK: u8 = 0;

pub const BAD_H_TIMINGS: u8 = 1;

pub const BAD_V_TIMINGS: u8 = 2;

pub const MODE_UNSUITABLE: u8 = 3;

pub const EXTENSION_DISABLED: u8 = 4;

pub const CLIENT_NOT_LOCAL: u8 = 5;

pub const ZOOM_LOCKED: u8 = 6;
