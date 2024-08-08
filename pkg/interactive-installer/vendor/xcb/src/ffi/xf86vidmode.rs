// Generated automatically from xf86vidmode.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_XF86VIDMODE_MAJOR_VERSION: u32 = 2;
pub const XCB_XF86VIDMODE_MINOR_VERSION: u32 = 2;

pub type xcb_xf86vidmode_syncrange_t = u32;

#[repr(C)]
pub struct xcb_xf86vidmode_syncrange_iterator_t {
    pub data:  *mut xcb_xf86vidmode_syncrange_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_xf86vidmode_dotclock_t = u32;

#[repr(C)]
pub struct xcb_xf86vidmode_dotclock_iterator_t {
    pub data:  *mut xcb_xf86vidmode_dotclock_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_xf86vidmode_mode_flag_t = u32;
pub const XCB_XF86VIDMODE_MODE_FLAG_POSITIVE_H_SYNC: xcb_xf86vidmode_mode_flag_t =   0x01;
pub const XCB_XF86VIDMODE_MODE_FLAG_NEGATIVE_H_SYNC: xcb_xf86vidmode_mode_flag_t =   0x02;
pub const XCB_XF86VIDMODE_MODE_FLAG_POSITIVE_V_SYNC: xcb_xf86vidmode_mode_flag_t =   0x04;
pub const XCB_XF86VIDMODE_MODE_FLAG_NEGATIVE_V_SYNC: xcb_xf86vidmode_mode_flag_t =   0x08;
pub const XCB_XF86VIDMODE_MODE_FLAG_INTERLACE      : xcb_xf86vidmode_mode_flag_t =   0x10;
pub const XCB_XF86VIDMODE_MODE_FLAG_COMPOSITE_SYNC : xcb_xf86vidmode_mode_flag_t =   0x20;
pub const XCB_XF86VIDMODE_MODE_FLAG_POSITIVE_C_SYNC: xcb_xf86vidmode_mode_flag_t =   0x40;
pub const XCB_XF86VIDMODE_MODE_FLAG_NEGATIVE_C_SYNC: xcb_xf86vidmode_mode_flag_t =   0x80;
pub const XCB_XF86VIDMODE_MODE_FLAG_H_SKEW         : xcb_xf86vidmode_mode_flag_t =  0x100;
pub const XCB_XF86VIDMODE_MODE_FLAG_BROADCAST      : xcb_xf86vidmode_mode_flag_t =  0x200;
pub const XCB_XF86VIDMODE_MODE_FLAG_PIXMUX         : xcb_xf86vidmode_mode_flag_t =  0x400;
pub const XCB_XF86VIDMODE_MODE_FLAG_DOUBLE_CLOCK   : xcb_xf86vidmode_mode_flag_t =  0x800;
pub const XCB_XF86VIDMODE_MODE_FLAG_HALF_CLOCK     : xcb_xf86vidmode_mode_flag_t = 0x1000;

pub type xcb_xf86vidmode_clock_flag_t = u32;
pub const XCB_XF86VIDMODE_CLOCK_FLAG_PROGRAMABLE: xcb_xf86vidmode_clock_flag_t = 0x01;

pub type xcb_xf86vidmode_permission_t = u32;
pub const XCB_XF86VIDMODE_PERMISSION_READ : xcb_xf86vidmode_permission_t = 0x01;
pub const XCB_XF86VIDMODE_PERMISSION_WRITE: xcb_xf86vidmode_permission_t = 0x02;

#[repr(C)]
pub struct xcb_xf86vidmode_mode_info_t {
    pub dotclock:   xcb_xf86vidmode_dotclock_t,
    pub hdisplay:   u16,
    pub hsyncstart: u16,
    pub hsyncend:   u16,
    pub htotal:     u16,
    pub hskew:      u32,
    pub vdisplay:   u16,
    pub vsyncstart: u16,
    pub vsyncend:   u16,
    pub vtotal:     u16,
    pub pad0:       [u8; 4],
    pub flags:      u32,
    pub pad1:       [u8; 12],
    pub privsize:   u32,
}

impl Copy for xcb_xf86vidmode_mode_info_t {}
impl Clone for xcb_xf86vidmode_mode_info_t {
    fn clone(&self) -> xcb_xf86vidmode_mode_info_t { *self }
}

#[repr(C)]
pub struct xcb_xf86vidmode_mode_info_iterator_t {
    pub data:  *mut xcb_xf86vidmode_mode_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_XF86VIDMODE_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_xf86vidmode_query_version_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_xf86vidmode_query_version_request_t {}
impl Clone for xcb_xf86vidmode_query_version_request_t {
    fn clone(&self) -> xcb_xf86vidmode_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub major_version: u16,
    pub minor_version: u16,
}

impl Copy for xcb_xf86vidmode_query_version_reply_t {}
impl Clone for xcb_xf86vidmode_query_version_reply_t {
    fn clone(&self) -> xcb_xf86vidmode_query_version_reply_t { *self }
}

pub const XCB_XF86VIDMODE_GET_MODE_LINE: u8 = 1;

#[repr(C)]
pub struct xcb_xf86vidmode_get_mode_line_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_xf86vidmode_get_mode_line_request_t {}
impl Clone for xcb_xf86vidmode_get_mode_line_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_mode_line_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_mode_line_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_mode_line_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub dotclock:      xcb_xf86vidmode_dotclock_t,
    pub hdisplay:      u16,
    pub hsyncstart:    u16,
    pub hsyncend:      u16,
    pub htotal:        u16,
    pub hskew:         u16,
    pub vdisplay:      u16,
    pub vsyncstart:    u16,
    pub vsyncend:      u16,
    pub vtotal:        u16,
    pub pad1:          [u8; 2],
    pub flags:         u32,
    pub pad2:          [u8; 12],
    pub privsize:      u32,
}

pub const XCB_XF86VIDMODE_MOD_MODE_LINE: u8 = 2;

#[repr(C)]
pub struct xcb_xf86vidmode_mod_mode_line_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u32,
    pub hdisplay:     u16,
    pub hsyncstart:   u16,
    pub hsyncend:     u16,
    pub htotal:       u16,
    pub hskew:        u16,
    pub vdisplay:     u16,
    pub vsyncstart:   u16,
    pub vsyncend:     u16,
    pub vtotal:       u16,
    pub pad0:         [u8; 2],
    pub flags:        u32,
    pub pad1:         [u8; 12],
    pub privsize:     u32,
}

pub const XCB_XF86VIDMODE_SWITCH_MODE: u8 = 3;

#[repr(C)]
pub struct xcb_xf86vidmode_switch_mode_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub zoom:         u16,
}

impl Copy for xcb_xf86vidmode_switch_mode_request_t {}
impl Clone for xcb_xf86vidmode_switch_mode_request_t {
    fn clone(&self) -> xcb_xf86vidmode_switch_mode_request_t { *self }
}

pub const XCB_XF86VIDMODE_GET_MONITOR: u8 = 4;

#[repr(C)]
pub struct xcb_xf86vidmode_get_monitor_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_xf86vidmode_get_monitor_request_t {}
impl Clone for xcb_xf86vidmode_get_monitor_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_monitor_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_monitor_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_monitor_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub vendor_length: u8,
    pub model_length:  u8,
    pub num_hsync:     u8,
    pub num_vsync:     u8,
    pub pad1:          [u8; 20],
}

pub const XCB_XF86VIDMODE_LOCK_MODE_SWITCH: u8 = 5;

#[repr(C)]
pub struct xcb_xf86vidmode_lock_mode_switch_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub lock:         u16,
}

impl Copy for xcb_xf86vidmode_lock_mode_switch_request_t {}
impl Clone for xcb_xf86vidmode_lock_mode_switch_request_t {
    fn clone(&self) -> xcb_xf86vidmode_lock_mode_switch_request_t { *self }
}

pub const XCB_XF86VIDMODE_GET_ALL_MODE_LINES: u8 = 6;

#[repr(C)]
pub struct xcb_xf86vidmode_get_all_mode_lines_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_xf86vidmode_get_all_mode_lines_request_t {}
impl Clone for xcb_xf86vidmode_get_all_mode_lines_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_all_mode_lines_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_all_mode_lines_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_all_mode_lines_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub modecount:     u32,
    pub pad1:          [u8; 20],
}

pub const XCB_XF86VIDMODE_ADD_MODE_LINE: u8 = 7;

#[repr(C)]
pub struct xcb_xf86vidmode_add_mode_line_request_t {
    pub major_opcode:     u8,
    pub minor_opcode:     u8,
    pub length:           u16,
    pub screen:           u32,
    pub dotclock:         xcb_xf86vidmode_dotclock_t,
    pub hdisplay:         u16,
    pub hsyncstart:       u16,
    pub hsyncend:         u16,
    pub htotal:           u16,
    pub hskew:            u16,
    pub vdisplay:         u16,
    pub vsyncstart:       u16,
    pub vsyncend:         u16,
    pub vtotal:           u16,
    pub pad0:             [u8; 2],
    pub flags:            u32,
    pub pad1:             [u8; 12],
    pub privsize:         u32,
    pub after_dotclock:   xcb_xf86vidmode_dotclock_t,
    pub after_hdisplay:   u16,
    pub after_hsyncstart: u16,
    pub after_hsyncend:   u16,
    pub after_htotal:     u16,
    pub after_hskew:      u16,
    pub after_vdisplay:   u16,
    pub after_vsyncstart: u16,
    pub after_vsyncend:   u16,
    pub after_vtotal:     u16,
    pub pad2:             [u8; 2],
    pub after_flags:      u32,
    pub pad3:             [u8; 12],
}

pub const XCB_XF86VIDMODE_DELETE_MODE_LINE: u8 = 8;

#[repr(C)]
pub struct xcb_xf86vidmode_delete_mode_line_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u32,
    pub dotclock:     xcb_xf86vidmode_dotclock_t,
    pub hdisplay:     u16,
    pub hsyncstart:   u16,
    pub hsyncend:     u16,
    pub htotal:       u16,
    pub hskew:        u16,
    pub vdisplay:     u16,
    pub vsyncstart:   u16,
    pub vsyncend:     u16,
    pub vtotal:       u16,
    pub pad0:         [u8; 2],
    pub flags:        u32,
    pub pad1:         [u8; 12],
    pub privsize:     u32,
}

pub const XCB_XF86VIDMODE_VALIDATE_MODE_LINE: u8 = 9;

#[repr(C)]
pub struct xcb_xf86vidmode_validate_mode_line_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u32,
    pub dotclock:     xcb_xf86vidmode_dotclock_t,
    pub hdisplay:     u16,
    pub hsyncstart:   u16,
    pub hsyncend:     u16,
    pub htotal:       u16,
    pub hskew:        u16,
    pub vdisplay:     u16,
    pub vsyncstart:   u16,
    pub vsyncend:     u16,
    pub vtotal:       u16,
    pub pad0:         [u8; 2],
    pub flags:        u32,
    pub pad1:         [u8; 12],
    pub privsize:     u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_validate_mode_line_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_validate_mode_line_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u32,
    pub pad1:          [u8; 20],
}

impl Copy for xcb_xf86vidmode_validate_mode_line_reply_t {}
impl Clone for xcb_xf86vidmode_validate_mode_line_reply_t {
    fn clone(&self) -> xcb_xf86vidmode_validate_mode_line_reply_t { *self }
}

pub const XCB_XF86VIDMODE_SWITCH_TO_MODE: u8 = 10;

#[repr(C)]
pub struct xcb_xf86vidmode_switch_to_mode_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u32,
    pub dotclock:     xcb_xf86vidmode_dotclock_t,
    pub hdisplay:     u16,
    pub hsyncstart:   u16,
    pub hsyncend:     u16,
    pub htotal:       u16,
    pub hskew:        u16,
    pub vdisplay:     u16,
    pub vsyncstart:   u16,
    pub vsyncend:     u16,
    pub vtotal:       u16,
    pub pad0:         [u8; 2],
    pub flags:        u32,
    pub pad1:         [u8; 12],
    pub privsize:     u32,
}

pub const XCB_XF86VIDMODE_GET_VIEW_PORT: u8 = 11;

#[repr(C)]
pub struct xcb_xf86vidmode_get_view_port_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_xf86vidmode_get_view_port_request_t {}
impl Clone for xcb_xf86vidmode_get_view_port_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_view_port_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_view_port_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_view_port_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub x:             u32,
    pub y:             u32,
    pub pad1:          [u8; 16],
}

impl Copy for xcb_xf86vidmode_get_view_port_reply_t {}
impl Clone for xcb_xf86vidmode_get_view_port_reply_t {
    fn clone(&self) -> xcb_xf86vidmode_get_view_port_reply_t { *self }
}

pub const XCB_XF86VIDMODE_SET_VIEW_PORT: u8 = 12;

#[repr(C)]
pub struct xcb_xf86vidmode_set_view_port_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
    pub x:            u32,
    pub y:            u32,
}

impl Copy for xcb_xf86vidmode_set_view_port_request_t {}
impl Clone for xcb_xf86vidmode_set_view_port_request_t {
    fn clone(&self) -> xcb_xf86vidmode_set_view_port_request_t { *self }
}

pub const XCB_XF86VIDMODE_GET_DOT_CLOCKS: u8 = 13;

#[repr(C)]
pub struct xcb_xf86vidmode_get_dot_clocks_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_xf86vidmode_get_dot_clocks_request_t {}
impl Clone for xcb_xf86vidmode_get_dot_clocks_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_dot_clocks_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_dot_clocks_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_dot_clocks_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub flags:         u32,
    pub clocks:        u32,
    pub maxclocks:     u32,
    pub pad1:          [u8; 12],
}

pub const XCB_XF86VIDMODE_SET_CLIENT_VERSION: u8 = 14;

#[repr(C)]
pub struct xcb_xf86vidmode_set_client_version_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub major:        u16,
    pub minor:        u16,
}

impl Copy for xcb_xf86vidmode_set_client_version_request_t {}
impl Clone for xcb_xf86vidmode_set_client_version_request_t {
    fn clone(&self) -> xcb_xf86vidmode_set_client_version_request_t { *self }
}

pub const XCB_XF86VIDMODE_SET_GAMMA: u8 = 15;

#[repr(C)]
pub struct xcb_xf86vidmode_set_gamma_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
    pub red:          u32,
    pub green:        u32,
    pub blue:         u32,
    pub pad1:         [u8; 12],
}

impl Copy for xcb_xf86vidmode_set_gamma_request_t {}
impl Clone for xcb_xf86vidmode_set_gamma_request_t {
    fn clone(&self) -> xcb_xf86vidmode_set_gamma_request_t { *self }
}

pub const XCB_XF86VIDMODE_GET_GAMMA: u8 = 16;

#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 26],
}

impl Copy for xcb_xf86vidmode_get_gamma_request_t {}
impl Clone for xcb_xf86vidmode_get_gamma_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_gamma_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub red:           u32,
    pub green:         u32,
    pub blue:          u32,
    pub pad1:          [u8; 12],
}

impl Copy for xcb_xf86vidmode_get_gamma_reply_t {}
impl Clone for xcb_xf86vidmode_get_gamma_reply_t {
    fn clone(&self) -> xcb_xf86vidmode_get_gamma_reply_t { *self }
}

pub const XCB_XF86VIDMODE_GET_GAMMA_RAMP: u8 = 17;

#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_ramp_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub size:         u16,
}

impl Copy for xcb_xf86vidmode_get_gamma_ramp_request_t {}
impl Clone for xcb_xf86vidmode_get_gamma_ramp_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_gamma_ramp_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_ramp_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_ramp_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub size:          u16,
    pub pad1:          [u8; 22],
}

pub const XCB_XF86VIDMODE_SET_GAMMA_RAMP: u8 = 18;

#[repr(C)]
pub struct xcb_xf86vidmode_set_gamma_ramp_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub size:         u16,
}

pub const XCB_XF86VIDMODE_GET_GAMMA_RAMP_SIZE: u8 = 19;

#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_ramp_size_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_xf86vidmode_get_gamma_ramp_size_request_t {}
impl Clone for xcb_xf86vidmode_get_gamma_ramp_size_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_gamma_ramp_size_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_ramp_size_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_gamma_ramp_size_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub size:          u16,
    pub pad1:          [u8; 22],
}

impl Copy for xcb_xf86vidmode_get_gamma_ramp_size_reply_t {}
impl Clone for xcb_xf86vidmode_get_gamma_ramp_size_reply_t {
    fn clone(&self) -> xcb_xf86vidmode_get_gamma_ramp_size_reply_t { *self }
}

pub const XCB_XF86VIDMODE_GET_PERMISSIONS: u8 = 20;

#[repr(C)]
pub struct xcb_xf86vidmode_get_permissions_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub screen:       u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_xf86vidmode_get_permissions_request_t {}
impl Clone for xcb_xf86vidmode_get_permissions_request_t {
    fn clone(&self) -> xcb_xf86vidmode_get_permissions_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xf86vidmode_get_permissions_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xf86vidmode_get_permissions_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub permissions:   u32,
    pub pad1:          [u8; 20],
}

impl Copy for xcb_xf86vidmode_get_permissions_reply_t {}
impl Clone for xcb_xf86vidmode_get_permissions_reply_t {
    fn clone(&self) -> xcb_xf86vidmode_get_permissions_reply_t { *self }
}

pub const XCB_XF86VIDMODE_BAD_CLOCK: u8 = 0;

#[repr(C)]
pub struct xcb_xf86vidmode_bad_clock_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_xf86vidmode_bad_clock_error_t {}
impl Clone for xcb_xf86vidmode_bad_clock_error_t {
    fn clone(&self) -> xcb_xf86vidmode_bad_clock_error_t { *self }
}

pub const XCB_XF86VIDMODE_BAD_H_TIMINGS: u8 = 1;

#[repr(C)]
pub struct xcb_xf86vidmode_bad_h_timings_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_xf86vidmode_bad_h_timings_error_t {}
impl Clone for xcb_xf86vidmode_bad_h_timings_error_t {
    fn clone(&self) -> xcb_xf86vidmode_bad_h_timings_error_t { *self }
}

pub const XCB_XF86VIDMODE_BAD_V_TIMINGS: u8 = 2;

#[repr(C)]
pub struct xcb_xf86vidmode_bad_v_timings_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_xf86vidmode_bad_v_timings_error_t {}
impl Clone for xcb_xf86vidmode_bad_v_timings_error_t {
    fn clone(&self) -> xcb_xf86vidmode_bad_v_timings_error_t { *self }
}

pub const XCB_XF86VIDMODE_MODE_UNSUITABLE: u8 = 3;

#[repr(C)]
pub struct xcb_xf86vidmode_mode_unsuitable_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_xf86vidmode_mode_unsuitable_error_t {}
impl Clone for xcb_xf86vidmode_mode_unsuitable_error_t {
    fn clone(&self) -> xcb_xf86vidmode_mode_unsuitable_error_t { *self }
}

pub const XCB_XF86VIDMODE_EXTENSION_DISABLED: u8 = 4;

#[repr(C)]
pub struct xcb_xf86vidmode_extension_disabled_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_xf86vidmode_extension_disabled_error_t {}
impl Clone for xcb_xf86vidmode_extension_disabled_error_t {
    fn clone(&self) -> xcb_xf86vidmode_extension_disabled_error_t { *self }
}

pub const XCB_XF86VIDMODE_CLIENT_NOT_LOCAL: u8 = 5;

#[repr(C)]
pub struct xcb_xf86vidmode_client_not_local_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_xf86vidmode_client_not_local_error_t {}
impl Clone for xcb_xf86vidmode_client_not_local_error_t {
    fn clone(&self) -> xcb_xf86vidmode_client_not_local_error_t { *self }
}

pub const XCB_XF86VIDMODE_ZOOM_LOCKED: u8 = 6;

#[repr(C)]
pub struct xcb_xf86vidmode_zoom_locked_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_xf86vidmode_zoom_locked_error_t {}
impl Clone for xcb_xf86vidmode_zoom_locked_error_t {
    fn clone(&self) -> xcb_xf86vidmode_zoom_locked_error_t { *self }
}


#[link(name="xcb-xf86vidmode")]
extern {

    pub static mut xcb_xf86vidmode_id: xcb_extension_t;

    pub fn xcb_xf86vidmode_syncrange_next (i: *mut xcb_xf86vidmode_syncrange_iterator_t);

    pub fn xcb_xf86vidmode_syncrange_end (i: *mut xcb_xf86vidmode_syncrange_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xf86vidmode_dotclock_next (i: *mut xcb_xf86vidmode_dotclock_iterator_t);

    pub fn xcb_xf86vidmode_dotclock_end (i: *mut xcb_xf86vidmode_dotclock_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xf86vidmode_mode_info_next (i: *mut xcb_xf86vidmode_mode_info_iterator_t);

    pub fn xcb_xf86vidmode_mode_info_end (i: *mut xcb_xf86vidmode_mode_info_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_query_version_reply (c:      *mut xcb_connection_t,
                                                cookie: xcb_xf86vidmode_query_version_cookie_t,
                                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_query_version_reply_t;

    pub fn xcb_xf86vidmode_query_version (c: *mut xcb_connection_t)
            -> xcb_xf86vidmode_query_version_cookie_t;

    pub fn xcb_xf86vidmode_query_version_unchecked (c: *mut xcb_connection_t)
            -> xcb_xf86vidmode_query_version_cookie_t;

    pub fn xcb_xf86vidmode_get_mode_line_private (R: *const xcb_xf86vidmode_get_mode_line_reply_t)
            -> *mut u8;

    pub fn xcb_xf86vidmode_get_mode_line_private_length (R: *const xcb_xf86vidmode_get_mode_line_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_mode_line_private_end (R: *const xcb_xf86vidmode_get_mode_line_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_mode_line_reply (c:      *mut xcb_connection_t,
                                                cookie: xcb_xf86vidmode_get_mode_line_cookie_t,
                                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_mode_line_reply_t;

    pub fn xcb_xf86vidmode_get_mode_line (c:      *mut xcb_connection_t,
                                          screen: u16)
            -> xcb_xf86vidmode_get_mode_line_cookie_t;

    pub fn xcb_xf86vidmode_get_mode_line_unchecked (c:      *mut xcb_connection_t,
                                                    screen: u16)
            -> xcb_xf86vidmode_get_mode_line_cookie_t;

    pub fn xcb_xf86vidmode_mod_mode_line (c:          *mut xcb_connection_t,
                                          screen:     u32,
                                          hdisplay:   u16,
                                          hsyncstart: u16,
                                          hsyncend:   u16,
                                          htotal:     u16,
                                          hskew:      u16,
                                          vdisplay:   u16,
                                          vsyncstart: u16,
                                          vsyncend:   u16,
                                          vtotal:     u16,
                                          flags:      u32,
                                          privsize:   u32,
                                          private:    *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_mod_mode_line_checked (c:          *mut xcb_connection_t,
                                                  screen:     u32,
                                                  hdisplay:   u16,
                                                  hsyncstart: u16,
                                                  hsyncend:   u16,
                                                  htotal:     u16,
                                                  hskew:      u16,
                                                  vdisplay:   u16,
                                                  vsyncstart: u16,
                                                  vsyncend:   u16,
                                                  vtotal:     u16,
                                                  flags:      u32,
                                                  privsize:   u32,
                                                  private:    *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_switch_mode (c:      *mut xcb_connection_t,
                                        screen: u16,
                                        zoom:   u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_switch_mode_checked (c:      *mut xcb_connection_t,
                                                screen: u16,
                                                zoom:   u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_get_monitor_hsync (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> *mut xcb_xf86vidmode_syncrange_t;

    pub fn xcb_xf86vidmode_get_monitor_hsync_length (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_monitor_hsync_end (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xf86vidmode_get_monitor_vsync (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> *mut xcb_xf86vidmode_syncrange_t;

    pub fn xcb_xf86vidmode_get_monitor_vsync_length (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_monitor_vsync_end (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xf86vidmode_get_monitor_vendor (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> *mut c_char;

    pub fn xcb_xf86vidmode_get_monitor_vendor_length (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_monitor_vendor_end (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xf86vidmode_get_monitor_alignment_pad (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> *mut c_void;

    pub fn xcb_xf86vidmode_get_monitor_alignment_pad_length (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_monitor_alignment_pad_end (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xf86vidmode_get_monitor_model (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> *mut c_char;

    pub fn xcb_xf86vidmode_get_monitor_model_length (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_monitor_model_end (R: *const xcb_xf86vidmode_get_monitor_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_monitor_reply (c:      *mut xcb_connection_t,
                                              cookie: xcb_xf86vidmode_get_monitor_cookie_t,
                                              error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_monitor_reply_t;

    pub fn xcb_xf86vidmode_get_monitor (c:      *mut xcb_connection_t,
                                        screen: u16)
            -> xcb_xf86vidmode_get_monitor_cookie_t;

    pub fn xcb_xf86vidmode_get_monitor_unchecked (c:      *mut xcb_connection_t,
                                                  screen: u16)
            -> xcb_xf86vidmode_get_monitor_cookie_t;

    pub fn xcb_xf86vidmode_lock_mode_switch (c:      *mut xcb_connection_t,
                                             screen: u16,
                                             lock:   u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_lock_mode_switch_checked (c:      *mut xcb_connection_t,
                                                     screen: u16,
                                                     lock:   u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_get_all_mode_lines_modeinfo (R: *const xcb_xf86vidmode_get_all_mode_lines_reply_t)
            -> *mut xcb_xf86vidmode_mode_info_t;

    pub fn xcb_xf86vidmode_get_all_mode_lines_modeinfo_length (R: *const xcb_xf86vidmode_get_all_mode_lines_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_all_mode_lines_modeinfo_iterator (R: *const xcb_xf86vidmode_get_all_mode_lines_reply_t)
            -> xcb_xf86vidmode_mode_info_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_all_mode_lines_reply (c:      *mut xcb_connection_t,
                                                     cookie: xcb_xf86vidmode_get_all_mode_lines_cookie_t,
                                                     error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_all_mode_lines_reply_t;

    pub fn xcb_xf86vidmode_get_all_mode_lines (c:      *mut xcb_connection_t,
                                               screen: u16)
            -> xcb_xf86vidmode_get_all_mode_lines_cookie_t;

    pub fn xcb_xf86vidmode_get_all_mode_lines_unchecked (c:      *mut xcb_connection_t,
                                                         screen: u16)
            -> xcb_xf86vidmode_get_all_mode_lines_cookie_t;

    pub fn xcb_xf86vidmode_add_mode_line (c:                *mut xcb_connection_t,
                                          screen:           u32,
                                          dotclock:         xcb_xf86vidmode_dotclock_t,
                                          hdisplay:         u16,
                                          hsyncstart:       u16,
                                          hsyncend:         u16,
                                          htotal:           u16,
                                          hskew:            u16,
                                          vdisplay:         u16,
                                          vsyncstart:       u16,
                                          vsyncend:         u16,
                                          vtotal:           u16,
                                          flags:            u32,
                                          privsize:         u32,
                                          after_dotclock:   xcb_xf86vidmode_dotclock_t,
                                          after_hdisplay:   u16,
                                          after_hsyncstart: u16,
                                          after_hsyncend:   u16,
                                          after_htotal:     u16,
                                          after_hskew:      u16,
                                          after_vdisplay:   u16,
                                          after_vsyncstart: u16,
                                          after_vsyncend:   u16,
                                          after_vtotal:     u16,
                                          after_flags:      u32,
                                          private:          *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_add_mode_line_checked (c:                *mut xcb_connection_t,
                                                  screen:           u32,
                                                  dotclock:         xcb_xf86vidmode_dotclock_t,
                                                  hdisplay:         u16,
                                                  hsyncstart:       u16,
                                                  hsyncend:         u16,
                                                  htotal:           u16,
                                                  hskew:            u16,
                                                  vdisplay:         u16,
                                                  vsyncstart:       u16,
                                                  vsyncend:         u16,
                                                  vtotal:           u16,
                                                  flags:            u32,
                                                  privsize:         u32,
                                                  after_dotclock:   xcb_xf86vidmode_dotclock_t,
                                                  after_hdisplay:   u16,
                                                  after_hsyncstart: u16,
                                                  after_hsyncend:   u16,
                                                  after_htotal:     u16,
                                                  after_hskew:      u16,
                                                  after_vdisplay:   u16,
                                                  after_vsyncstart: u16,
                                                  after_vsyncend:   u16,
                                                  after_vtotal:     u16,
                                                  after_flags:      u32,
                                                  private:          *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_delete_mode_line (c:          *mut xcb_connection_t,
                                             screen:     u32,
                                             dotclock:   xcb_xf86vidmode_dotclock_t,
                                             hdisplay:   u16,
                                             hsyncstart: u16,
                                             hsyncend:   u16,
                                             htotal:     u16,
                                             hskew:      u16,
                                             vdisplay:   u16,
                                             vsyncstart: u16,
                                             vsyncend:   u16,
                                             vtotal:     u16,
                                             flags:      u32,
                                             privsize:   u32,
                                             private:    *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_delete_mode_line_checked (c:          *mut xcb_connection_t,
                                                     screen:     u32,
                                                     dotclock:   xcb_xf86vidmode_dotclock_t,
                                                     hdisplay:   u16,
                                                     hsyncstart: u16,
                                                     hsyncend:   u16,
                                                     htotal:     u16,
                                                     hskew:      u16,
                                                     vdisplay:   u16,
                                                     vsyncstart: u16,
                                                     vsyncend:   u16,
                                                     vtotal:     u16,
                                                     flags:      u32,
                                                     privsize:   u32,
                                                     private:    *const u8)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_validate_mode_line_reply (c:      *mut xcb_connection_t,
                                                     cookie: xcb_xf86vidmode_validate_mode_line_cookie_t,
                                                     error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_validate_mode_line_reply_t;

    pub fn xcb_xf86vidmode_validate_mode_line (c:          *mut xcb_connection_t,
                                               screen:     u32,
                                               dotclock:   xcb_xf86vidmode_dotclock_t,
                                               hdisplay:   u16,
                                               hsyncstart: u16,
                                               hsyncend:   u16,
                                               htotal:     u16,
                                               hskew:      u16,
                                               vdisplay:   u16,
                                               vsyncstart: u16,
                                               vsyncend:   u16,
                                               vtotal:     u16,
                                               flags:      u32,
                                               privsize:   u32,
                                               private:    *const u8)
            -> xcb_xf86vidmode_validate_mode_line_cookie_t;

    pub fn xcb_xf86vidmode_validate_mode_line_unchecked (c:          *mut xcb_connection_t,
                                                         screen:     u32,
                                                         dotclock:   xcb_xf86vidmode_dotclock_t,
                                                         hdisplay:   u16,
                                                         hsyncstart: u16,
                                                         hsyncend:   u16,
                                                         htotal:     u16,
                                                         hskew:      u16,
                                                         vdisplay:   u16,
                                                         vsyncstart: u16,
                                                         vsyncend:   u16,
                                                         vtotal:     u16,
                                                         flags:      u32,
                                                         privsize:   u32,
                                                         private:    *const u8)
            -> xcb_xf86vidmode_validate_mode_line_cookie_t;

    pub fn xcb_xf86vidmode_switch_to_mode (c:          *mut xcb_connection_t,
                                           screen:     u32,
                                           dotclock:   xcb_xf86vidmode_dotclock_t,
                                           hdisplay:   u16,
                                           hsyncstart: u16,
                                           hsyncend:   u16,
                                           htotal:     u16,
                                           hskew:      u16,
                                           vdisplay:   u16,
                                           vsyncstart: u16,
                                           vsyncend:   u16,
                                           vtotal:     u16,
                                           flags:      u32,
                                           privsize:   u32,
                                           private:    *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_switch_to_mode_checked (c:          *mut xcb_connection_t,
                                                   screen:     u32,
                                                   dotclock:   xcb_xf86vidmode_dotclock_t,
                                                   hdisplay:   u16,
                                                   hsyncstart: u16,
                                                   hsyncend:   u16,
                                                   htotal:     u16,
                                                   hskew:      u16,
                                                   vdisplay:   u16,
                                                   vsyncstart: u16,
                                                   vsyncend:   u16,
                                                   vtotal:     u16,
                                                   flags:      u32,
                                                   privsize:   u32,
                                                   private:    *const u8)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_view_port_reply (c:      *mut xcb_connection_t,
                                                cookie: xcb_xf86vidmode_get_view_port_cookie_t,
                                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_view_port_reply_t;

    pub fn xcb_xf86vidmode_get_view_port (c:      *mut xcb_connection_t,
                                          screen: u16)
            -> xcb_xf86vidmode_get_view_port_cookie_t;

    pub fn xcb_xf86vidmode_get_view_port_unchecked (c:      *mut xcb_connection_t,
                                                    screen: u16)
            -> xcb_xf86vidmode_get_view_port_cookie_t;

    pub fn xcb_xf86vidmode_set_view_port (c:      *mut xcb_connection_t,
                                          screen: u16,
                                          x:      u32,
                                          y:      u32)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_set_view_port_checked (c:      *mut xcb_connection_t,
                                                  screen: u16,
                                                  x:      u32,
                                                  y:      u32)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_get_dot_clocks_clock (R: *const xcb_xf86vidmode_get_dot_clocks_reply_t)
            -> *mut u32;

    pub fn xcb_xf86vidmode_get_dot_clocks_clock_length (R: *const xcb_xf86vidmode_get_dot_clocks_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_dot_clocks_clock_end (R: *const xcb_xf86vidmode_get_dot_clocks_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_dot_clocks_reply (c:      *mut xcb_connection_t,
                                                 cookie: xcb_xf86vidmode_get_dot_clocks_cookie_t,
                                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_dot_clocks_reply_t;

    pub fn xcb_xf86vidmode_get_dot_clocks (c:      *mut xcb_connection_t,
                                           screen: u16)
            -> xcb_xf86vidmode_get_dot_clocks_cookie_t;

    pub fn xcb_xf86vidmode_get_dot_clocks_unchecked (c:      *mut xcb_connection_t,
                                                     screen: u16)
            -> xcb_xf86vidmode_get_dot_clocks_cookie_t;

    pub fn xcb_xf86vidmode_set_client_version (c:     *mut xcb_connection_t,
                                               major: u16,
                                               minor: u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_set_client_version_checked (c:     *mut xcb_connection_t,
                                                       major: u16,
                                                       minor: u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_set_gamma (c:      *mut xcb_connection_t,
                                      screen: u16,
                                      red:    u32,
                                      green:  u32,
                                      blue:   u32)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_set_gamma_checked (c:      *mut xcb_connection_t,
                                              screen: u16,
                                              red:    u32,
                                              green:  u32,
                                              blue:   u32)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_gamma_reply (c:      *mut xcb_connection_t,
                                            cookie: xcb_xf86vidmode_get_gamma_cookie_t,
                                            error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_gamma_reply_t;

    pub fn xcb_xf86vidmode_get_gamma (c:      *mut xcb_connection_t,
                                      screen: u16)
            -> xcb_xf86vidmode_get_gamma_cookie_t;

    pub fn xcb_xf86vidmode_get_gamma_unchecked (c:      *mut xcb_connection_t,
                                                screen: u16)
            -> xcb_xf86vidmode_get_gamma_cookie_t;

    pub fn xcb_xf86vidmode_get_gamma_ramp_red (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> *mut u16;

    pub fn xcb_xf86vidmode_get_gamma_ramp_red_length (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_gamma_ramp_red_end (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xf86vidmode_get_gamma_ramp_green (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> *mut u16;

    pub fn xcb_xf86vidmode_get_gamma_ramp_green_length (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_gamma_ramp_green_end (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xf86vidmode_get_gamma_ramp_blue (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> *mut u16;

    pub fn xcb_xf86vidmode_get_gamma_ramp_blue_length (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> c_int;

    pub fn xcb_xf86vidmode_get_gamma_ramp_blue_end (R: *const xcb_xf86vidmode_get_gamma_ramp_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_gamma_ramp_reply (c:      *mut xcb_connection_t,
                                                 cookie: xcb_xf86vidmode_get_gamma_ramp_cookie_t,
                                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_gamma_ramp_reply_t;

    pub fn xcb_xf86vidmode_get_gamma_ramp (c:      *mut xcb_connection_t,
                                           screen: u16,
                                           size:   u16)
            -> xcb_xf86vidmode_get_gamma_ramp_cookie_t;

    pub fn xcb_xf86vidmode_get_gamma_ramp_unchecked (c:      *mut xcb_connection_t,
                                                     screen: u16,
                                                     size:   u16)
            -> xcb_xf86vidmode_get_gamma_ramp_cookie_t;

    pub fn xcb_xf86vidmode_set_gamma_ramp (c:      *mut xcb_connection_t,
                                           screen: u16,
                                           size:   u16,
                                           red:    *const u16,
                                           green:  *const u16,
                                           blue:   *const u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xf86vidmode_set_gamma_ramp_checked (c:      *mut xcb_connection_t,
                                                   screen: u16,
                                                   size:   u16,
                                                   red:    *const u16,
                                                   green:  *const u16,
                                                   blue:   *const u16)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_gamma_ramp_size_reply (c:      *mut xcb_connection_t,
                                                      cookie: xcb_xf86vidmode_get_gamma_ramp_size_cookie_t,
                                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_gamma_ramp_size_reply_t;

    pub fn xcb_xf86vidmode_get_gamma_ramp_size (c:      *mut xcb_connection_t,
                                                screen: u16)
            -> xcb_xf86vidmode_get_gamma_ramp_size_cookie_t;

    pub fn xcb_xf86vidmode_get_gamma_ramp_size_unchecked (c:      *mut xcb_connection_t,
                                                          screen: u16)
            -> xcb_xf86vidmode_get_gamma_ramp_size_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xf86vidmode_get_permissions_reply (c:      *mut xcb_connection_t,
                                                  cookie: xcb_xf86vidmode_get_permissions_cookie_t,
                                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xf86vidmode_get_permissions_reply_t;

    pub fn xcb_xf86vidmode_get_permissions (c:      *mut xcb_connection_t,
                                            screen: u16)
            -> xcb_xf86vidmode_get_permissions_cookie_t;

    pub fn xcb_xf86vidmode_get_permissions_unchecked (c:      *mut xcb_connection_t,
                                                      screen: u16)
            -> xcb_xf86vidmode_get_permissions_cookie_t;

} // extern
