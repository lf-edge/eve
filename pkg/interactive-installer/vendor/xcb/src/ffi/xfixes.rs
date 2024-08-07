// Generated automatically from xfixes.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;
use ffi::render::*;
use ffi::shape::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_XFIXES_MAJOR_VERSION: u32 = 5;
pub const XCB_XFIXES_MINOR_VERSION: u32 = 0;

pub const XCB_XFIXES_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_xfixes_query_version_request_t {
    pub major_opcode:         u8,
    pub minor_opcode:         u8,
    pub length:               u16,
    pub client_major_version: u32,
    pub client_minor_version: u32,
}

impl Copy for xcb_xfixes_query_version_request_t {}
impl Clone for xcb_xfixes_query_version_request_t {
    fn clone(&self) -> xcb_xfixes_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xfixes_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xfixes_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub pad1:          [u8; 16],
}

impl Copy for xcb_xfixes_query_version_reply_t {}
impl Clone for xcb_xfixes_query_version_reply_t {
    fn clone(&self) -> xcb_xfixes_query_version_reply_t { *self }
}

pub type xcb_xfixes_save_set_mode_t = u32;
pub const XCB_XFIXES_SAVE_SET_MODE_INSERT: xcb_xfixes_save_set_mode_t = 0x00;
pub const XCB_XFIXES_SAVE_SET_MODE_DELETE: xcb_xfixes_save_set_mode_t = 0x01;

pub type xcb_xfixes_save_set_target_t = u32;
pub const XCB_XFIXES_SAVE_SET_TARGET_NEAREST: xcb_xfixes_save_set_target_t = 0x00;
pub const XCB_XFIXES_SAVE_SET_TARGET_ROOT   : xcb_xfixes_save_set_target_t = 0x01;

pub type xcb_xfixes_save_set_mapping_t = u32;
pub const XCB_XFIXES_SAVE_SET_MAPPING_MAP  : xcb_xfixes_save_set_mapping_t = 0x00;
pub const XCB_XFIXES_SAVE_SET_MAPPING_UNMAP: xcb_xfixes_save_set_mapping_t = 0x01;

pub const XCB_XFIXES_CHANGE_SAVE_SET: u8 = 1;

#[repr(C)]
pub struct xcb_xfixes_change_save_set_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub mode:         u8,
    pub target:       u8,
    pub map:          u8,
    pub pad0:         u8,
    pub window:       xcb_window_t,
}

impl Copy for xcb_xfixes_change_save_set_request_t {}
impl Clone for xcb_xfixes_change_save_set_request_t {
    fn clone(&self) -> xcb_xfixes_change_save_set_request_t { *self }
}

pub type xcb_xfixes_selection_event_t = u32;
pub const XCB_XFIXES_SELECTION_EVENT_SET_SELECTION_OWNER     : xcb_xfixes_selection_event_t = 0x00;
pub const XCB_XFIXES_SELECTION_EVENT_SELECTION_WINDOW_DESTROY: xcb_xfixes_selection_event_t = 0x01;
pub const XCB_XFIXES_SELECTION_EVENT_SELECTION_CLIENT_CLOSE  : xcb_xfixes_selection_event_t = 0x02;

pub type xcb_xfixes_selection_event_mask_t = u32;
pub const XCB_XFIXES_SELECTION_EVENT_MASK_SET_SELECTION_OWNER     : xcb_xfixes_selection_event_mask_t = 0x01;
pub const XCB_XFIXES_SELECTION_EVENT_MASK_SELECTION_WINDOW_DESTROY: xcb_xfixes_selection_event_mask_t = 0x02;
pub const XCB_XFIXES_SELECTION_EVENT_MASK_SELECTION_CLIENT_CLOSE  : xcb_xfixes_selection_event_mask_t = 0x04;

pub const XCB_XFIXES_SELECTION_NOTIFY: u8 = 0;

#[repr(C)]
pub struct xcb_xfixes_selection_notify_event_t {
    pub response_type:       u8,
    pub subtype:             u8,
    pub sequence:            u16,
    pub window:              xcb_window_t,
    pub owner:               xcb_window_t,
    pub selection:           xcb_atom_t,
    pub timestamp:           xcb_timestamp_t,
    pub selection_timestamp: xcb_timestamp_t,
    pub pad0:                [u8; 8],
}

impl Copy for xcb_xfixes_selection_notify_event_t {}
impl Clone for xcb_xfixes_selection_notify_event_t {
    fn clone(&self) -> xcb_xfixes_selection_notify_event_t { *self }
}

pub const XCB_XFIXES_SELECT_SELECTION_INPUT: u8 = 2;

#[repr(C)]
pub struct xcb_xfixes_select_selection_input_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub selection:    xcb_atom_t,
    pub event_mask:   u32,
}

impl Copy for xcb_xfixes_select_selection_input_request_t {}
impl Clone for xcb_xfixes_select_selection_input_request_t {
    fn clone(&self) -> xcb_xfixes_select_selection_input_request_t { *self }
}

pub type xcb_xfixes_cursor_notify_t = u32;
pub const XCB_XFIXES_CURSOR_NOTIFY_DISPLAY_CURSOR: xcb_xfixes_cursor_notify_t = 0x00;

pub type xcb_xfixes_cursor_notify_mask_t = u32;
pub const XCB_XFIXES_CURSOR_NOTIFY_MASK_DISPLAY_CURSOR: xcb_xfixes_cursor_notify_mask_t = 0x01;

pub const XCB_XFIXES_CURSOR_NOTIFY: u8 = 1;

#[repr(C)]
pub struct xcb_xfixes_cursor_notify_event_t {
    pub response_type: u8,
    pub subtype:       u8,
    pub sequence:      u16,
    pub window:        xcb_window_t,
    pub cursor_serial: u32,
    pub timestamp:     xcb_timestamp_t,
    pub name:          xcb_atom_t,
    pub pad0:          [u8; 12],
}

impl Copy for xcb_xfixes_cursor_notify_event_t {}
impl Clone for xcb_xfixes_cursor_notify_event_t {
    fn clone(&self) -> xcb_xfixes_cursor_notify_event_t { *self }
}

pub const XCB_XFIXES_SELECT_CURSOR_INPUT: u8 = 3;

#[repr(C)]
pub struct xcb_xfixes_select_cursor_input_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub event_mask:   u32,
}

impl Copy for xcb_xfixes_select_cursor_input_request_t {}
impl Clone for xcb_xfixes_select_cursor_input_request_t {
    fn clone(&self) -> xcb_xfixes_select_cursor_input_request_t { *self }
}

pub const XCB_XFIXES_GET_CURSOR_IMAGE: u8 = 4;

#[repr(C)]
pub struct xcb_xfixes_get_cursor_image_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_xfixes_get_cursor_image_request_t {}
impl Clone for xcb_xfixes_get_cursor_image_request_t {
    fn clone(&self) -> xcb_xfixes_get_cursor_image_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xfixes_get_cursor_image_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xfixes_get_cursor_image_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub x:             i16,
    pub y:             i16,
    pub width:         u16,
    pub height:        u16,
    pub xhot:          u16,
    pub yhot:          u16,
    pub cursor_serial: u32,
    pub pad1:          [u8; 8],
}

pub type xcb_xfixes_region_t = u32;

#[repr(C)]
pub struct xcb_xfixes_region_iterator_t {
    pub data:  *mut xcb_xfixes_region_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_XFIXES_BAD_REGION: u8 = 0;

#[repr(C)]
pub struct xcb_xfixes_bad_region_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_xfixes_bad_region_error_t {}
impl Clone for xcb_xfixes_bad_region_error_t {
    fn clone(&self) -> xcb_xfixes_bad_region_error_t { *self }
}

pub type xcb_xfixes_region_enum_t = u32;
pub const XCB_XFIXES_REGION_NONE: xcb_xfixes_region_enum_t = 0x00;

pub const XCB_XFIXES_CREATE_REGION: u8 = 5;

#[repr(C)]
pub struct xcb_xfixes_create_region_request_t {
    pub major_opcode:   u8,
    pub minor_opcode:   u8,
    pub length:         u16,
    pub region:         xcb_xfixes_region_t,
}

pub const XCB_XFIXES_CREATE_REGION_FROM_BITMAP: u8 = 6;

#[repr(C)]
pub struct xcb_xfixes_create_region_from_bitmap_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub region:       xcb_xfixes_region_t,
    pub bitmap:       xcb_pixmap_t,
}

impl Copy for xcb_xfixes_create_region_from_bitmap_request_t {}
impl Clone for xcb_xfixes_create_region_from_bitmap_request_t {
    fn clone(&self) -> xcb_xfixes_create_region_from_bitmap_request_t { *self }
}

pub const XCB_XFIXES_CREATE_REGION_FROM_WINDOW: u8 = 7;

#[repr(C)]
pub struct xcb_xfixes_create_region_from_window_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub region:       xcb_xfixes_region_t,
    pub window:       xcb_window_t,
    pub kind:         xcb_shape_kind_t,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_xfixes_create_region_from_window_request_t {}
impl Clone for xcb_xfixes_create_region_from_window_request_t {
    fn clone(&self) -> xcb_xfixes_create_region_from_window_request_t { *self }
}

pub const XCB_XFIXES_CREATE_REGION_FROM_GC: u8 = 8;

#[repr(C)]
pub struct xcb_xfixes_create_region_from_gc_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub region:       xcb_xfixes_region_t,
    pub gc:           xcb_gcontext_t,
}

impl Copy for xcb_xfixes_create_region_from_gc_request_t {}
impl Clone for xcb_xfixes_create_region_from_gc_request_t {
    fn clone(&self) -> xcb_xfixes_create_region_from_gc_request_t { *self }
}

pub const XCB_XFIXES_CREATE_REGION_FROM_PICTURE: u8 = 9;

#[repr(C)]
pub struct xcb_xfixes_create_region_from_picture_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub region:       xcb_xfixes_region_t,
    pub picture:      xcb_render_picture_t,
}

impl Copy for xcb_xfixes_create_region_from_picture_request_t {}
impl Clone for xcb_xfixes_create_region_from_picture_request_t {
    fn clone(&self) -> xcb_xfixes_create_region_from_picture_request_t { *self }
}

pub const XCB_XFIXES_DESTROY_REGION: u8 = 10;

#[repr(C)]
pub struct xcb_xfixes_destroy_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub region:       xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_destroy_region_request_t {}
impl Clone for xcb_xfixes_destroy_region_request_t {
    fn clone(&self) -> xcb_xfixes_destroy_region_request_t { *self }
}

pub const XCB_XFIXES_SET_REGION: u8 = 11;

#[repr(C)]
pub struct xcb_xfixes_set_region_request_t {
    pub major_opcode:   u8,
    pub minor_opcode:   u8,
    pub length:         u16,
    pub region:         xcb_xfixes_region_t,
}

pub const XCB_XFIXES_COPY_REGION: u8 = 12;

#[repr(C)]
pub struct xcb_xfixes_copy_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub source:       xcb_xfixes_region_t,
    pub destination:  xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_copy_region_request_t {}
impl Clone for xcb_xfixes_copy_region_request_t {
    fn clone(&self) -> xcb_xfixes_copy_region_request_t { *self }
}

pub const XCB_XFIXES_UNION_REGION: u8 = 13;

#[repr(C)]
pub struct xcb_xfixes_union_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub source1:      xcb_xfixes_region_t,
    pub source2:      xcb_xfixes_region_t,
    pub destination:  xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_union_region_request_t {}
impl Clone for xcb_xfixes_union_region_request_t {
    fn clone(&self) -> xcb_xfixes_union_region_request_t { *self }
}

pub const XCB_XFIXES_INTERSECT_REGION: u8 = 14;

#[repr(C)]
pub struct xcb_xfixes_intersect_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub source1:      xcb_xfixes_region_t,
    pub source2:      xcb_xfixes_region_t,
    pub destination:  xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_intersect_region_request_t {}
impl Clone for xcb_xfixes_intersect_region_request_t {
    fn clone(&self) -> xcb_xfixes_intersect_region_request_t { *self }
}

pub const XCB_XFIXES_SUBTRACT_REGION: u8 = 15;

#[repr(C)]
pub struct xcb_xfixes_subtract_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub source1:      xcb_xfixes_region_t,
    pub source2:      xcb_xfixes_region_t,
    pub destination:  xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_subtract_region_request_t {}
impl Clone for xcb_xfixes_subtract_region_request_t {
    fn clone(&self) -> xcb_xfixes_subtract_region_request_t { *self }
}

pub const XCB_XFIXES_INVERT_REGION: u8 = 16;

#[repr(C)]
pub struct xcb_xfixes_invert_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub source:       xcb_xfixes_region_t,
    pub bounds:       xcb_rectangle_t,
    pub destination:  xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_invert_region_request_t {}
impl Clone for xcb_xfixes_invert_region_request_t {
    fn clone(&self) -> xcb_xfixes_invert_region_request_t { *self }
}

pub const XCB_XFIXES_TRANSLATE_REGION: u8 = 17;

#[repr(C)]
pub struct xcb_xfixes_translate_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub region:       xcb_xfixes_region_t,
    pub dx:           i16,
    pub dy:           i16,
}

impl Copy for xcb_xfixes_translate_region_request_t {}
impl Clone for xcb_xfixes_translate_region_request_t {
    fn clone(&self) -> xcb_xfixes_translate_region_request_t { *self }
}

pub const XCB_XFIXES_REGION_EXTENTS: u8 = 18;

#[repr(C)]
pub struct xcb_xfixes_region_extents_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub source:       xcb_xfixes_region_t,
    pub destination:  xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_region_extents_request_t {}
impl Clone for xcb_xfixes_region_extents_request_t {
    fn clone(&self) -> xcb_xfixes_region_extents_request_t { *self }
}

pub const XCB_XFIXES_FETCH_REGION: u8 = 19;

#[repr(C)]
pub struct xcb_xfixes_fetch_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub region:       xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_fetch_region_request_t {}
impl Clone for xcb_xfixes_fetch_region_request_t {
    fn clone(&self) -> xcb_xfixes_fetch_region_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xfixes_fetch_region_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xfixes_fetch_region_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub extents:       xcb_rectangle_t,
    pub pad1:          [u8; 16],
}

pub const XCB_XFIXES_SET_GC_CLIP_REGION: u8 = 20;

#[repr(C)]
pub struct xcb_xfixes_set_gc_clip_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub gc:           xcb_gcontext_t,
    pub region:       xcb_xfixes_region_t,
    pub x_origin:     i16,
    pub y_origin:     i16,
}

impl Copy for xcb_xfixes_set_gc_clip_region_request_t {}
impl Clone for xcb_xfixes_set_gc_clip_region_request_t {
    fn clone(&self) -> xcb_xfixes_set_gc_clip_region_request_t { *self }
}

pub const XCB_XFIXES_SET_WINDOW_SHAPE_REGION: u8 = 21;

#[repr(C)]
pub struct xcb_xfixes_set_window_shape_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub dest:         xcb_window_t,
    pub dest_kind:    xcb_shape_kind_t,
    pub pad0:         [u8; 3],
    pub x_offset:     i16,
    pub y_offset:     i16,
    pub region:       xcb_xfixes_region_t,
}

impl Copy for xcb_xfixes_set_window_shape_region_request_t {}
impl Clone for xcb_xfixes_set_window_shape_region_request_t {
    fn clone(&self) -> xcb_xfixes_set_window_shape_region_request_t { *self }
}

pub const XCB_XFIXES_SET_PICTURE_CLIP_REGION: u8 = 22;

#[repr(C)]
pub struct xcb_xfixes_set_picture_clip_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub picture:      xcb_render_picture_t,
    pub region:       xcb_xfixes_region_t,
    pub x_origin:     i16,
    pub y_origin:     i16,
}

impl Copy for xcb_xfixes_set_picture_clip_region_request_t {}
impl Clone for xcb_xfixes_set_picture_clip_region_request_t {
    fn clone(&self) -> xcb_xfixes_set_picture_clip_region_request_t { *self }
}

pub const XCB_XFIXES_SET_CURSOR_NAME: u8 = 23;

#[repr(C)]
pub struct xcb_xfixes_set_cursor_name_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub cursor:       xcb_cursor_t,
    pub nbytes:       u16,
    pub pad0:         [u8; 2],
}

pub const XCB_XFIXES_GET_CURSOR_NAME: u8 = 24;

#[repr(C)]
pub struct xcb_xfixes_get_cursor_name_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub cursor:       xcb_cursor_t,
}

impl Copy for xcb_xfixes_get_cursor_name_request_t {}
impl Clone for xcb_xfixes_get_cursor_name_request_t {
    fn clone(&self) -> xcb_xfixes_get_cursor_name_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xfixes_get_cursor_name_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xfixes_get_cursor_name_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub atom:          xcb_atom_t,
    pub nbytes:        u16,
    pub pad1:          [u8; 18],
}

pub const XCB_XFIXES_GET_CURSOR_IMAGE_AND_NAME: u8 = 25;

#[repr(C)]
pub struct xcb_xfixes_get_cursor_image_and_name_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_xfixes_get_cursor_image_and_name_request_t {}
impl Clone for xcb_xfixes_get_cursor_image_and_name_request_t {
    fn clone(&self) -> xcb_xfixes_get_cursor_image_and_name_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_xfixes_get_cursor_image_and_name_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_xfixes_get_cursor_image_and_name_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub x:             i16,
    pub y:             i16,
    pub width:         u16,
    pub height:        u16,
    pub xhot:          u16,
    pub yhot:          u16,
    pub cursor_serial: u32,
    pub cursor_atom:   xcb_atom_t,
    pub nbytes:        u16,
    pub pad1:          [u8; 2],
}

pub const XCB_XFIXES_CHANGE_CURSOR: u8 = 26;

#[repr(C)]
pub struct xcb_xfixes_change_cursor_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub source:       xcb_cursor_t,
    pub destination:  xcb_cursor_t,
}

impl Copy for xcb_xfixes_change_cursor_request_t {}
impl Clone for xcb_xfixes_change_cursor_request_t {
    fn clone(&self) -> xcb_xfixes_change_cursor_request_t { *self }
}

pub const XCB_XFIXES_CHANGE_CURSOR_BY_NAME: u8 = 27;

#[repr(C)]
pub struct xcb_xfixes_change_cursor_by_name_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub src:          xcb_cursor_t,
    pub nbytes:       u16,
    pub pad0:         [u8; 2],
}

pub const XCB_XFIXES_EXPAND_REGION: u8 = 28;

#[repr(C)]
pub struct xcb_xfixes_expand_region_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub source:       xcb_xfixes_region_t,
    pub destination:  xcb_xfixes_region_t,
    pub left:         u16,
    pub right:        u16,
    pub top:          u16,
    pub bottom:       u16,
}

impl Copy for xcb_xfixes_expand_region_request_t {}
impl Clone for xcb_xfixes_expand_region_request_t {
    fn clone(&self) -> xcb_xfixes_expand_region_request_t { *self }
}

pub const XCB_XFIXES_HIDE_CURSOR: u8 = 29;

#[repr(C)]
pub struct xcb_xfixes_hide_cursor_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_xfixes_hide_cursor_request_t {}
impl Clone for xcb_xfixes_hide_cursor_request_t {
    fn clone(&self) -> xcb_xfixes_hide_cursor_request_t { *self }
}

pub const XCB_XFIXES_SHOW_CURSOR: u8 = 30;

#[repr(C)]
pub struct xcb_xfixes_show_cursor_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_xfixes_show_cursor_request_t {}
impl Clone for xcb_xfixes_show_cursor_request_t {
    fn clone(&self) -> xcb_xfixes_show_cursor_request_t { *self }
}

pub type xcb_xfixes_barrier_t = u32;

#[repr(C)]
pub struct xcb_xfixes_barrier_iterator_t {
    pub data:  *mut xcb_xfixes_barrier_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_xfixes_barrier_directions_t = u32;
pub const XCB_XFIXES_BARRIER_DIRECTIONS_POSITIVE_X: xcb_xfixes_barrier_directions_t = 0x01;
pub const XCB_XFIXES_BARRIER_DIRECTIONS_POSITIVE_Y: xcb_xfixes_barrier_directions_t = 0x02;
pub const XCB_XFIXES_BARRIER_DIRECTIONS_NEGATIVE_X: xcb_xfixes_barrier_directions_t = 0x04;
pub const XCB_XFIXES_BARRIER_DIRECTIONS_NEGATIVE_Y: xcb_xfixes_barrier_directions_t = 0x08;

pub const XCB_XFIXES_CREATE_POINTER_BARRIER: u8 = 31;

#[repr(C)]
pub struct xcb_xfixes_create_pointer_barrier_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub barrier:      xcb_xfixes_barrier_t,
    pub window:       xcb_window_t,
    pub x1:           u16,
    pub y1:           u16,
    pub x2:           u16,
    pub y2:           u16,
    pub directions:   u32,
    pub pad0:         [u8; 2],
    pub num_devices:  u16,
}

pub const XCB_XFIXES_DELETE_POINTER_BARRIER: u8 = 32;

#[repr(C)]
pub struct xcb_xfixes_delete_pointer_barrier_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub barrier:      xcb_xfixes_barrier_t,
}

impl Copy for xcb_xfixes_delete_pointer_barrier_request_t {}
impl Clone for xcb_xfixes_delete_pointer_barrier_request_t {
    fn clone(&self) -> xcb_xfixes_delete_pointer_barrier_request_t { *self }
}


#[link(name="xcb-xfixes")]
extern {

    pub static mut xcb_xfixes_id: xcb_extension_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xfixes_query_version_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_xfixes_query_version_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xfixes_query_version_reply_t;

    pub fn xcb_xfixes_query_version (c:                    *mut xcb_connection_t,
                                     client_major_version: u32,
                                     client_minor_version: u32)
            -> xcb_xfixes_query_version_cookie_t;

    pub fn xcb_xfixes_query_version_unchecked (c:                    *mut xcb_connection_t,
                                               client_major_version: u32,
                                               client_minor_version: u32)
            -> xcb_xfixes_query_version_cookie_t;

    pub fn xcb_xfixes_change_save_set (c:      *mut xcb_connection_t,
                                       mode:   u8,
                                       target: u8,
                                       map:    u8,
                                       window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_change_save_set_checked (c:      *mut xcb_connection_t,
                                               mode:   u8,
                                               target: u8,
                                               map:    u8,
                                               window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_select_selection_input (c:          *mut xcb_connection_t,
                                              window:     xcb_window_t,
                                              selection:  xcb_atom_t,
                                              event_mask: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_select_selection_input_checked (c:          *mut xcb_connection_t,
                                                      window:     xcb_window_t,
                                                      selection:  xcb_atom_t,
                                                      event_mask: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_select_cursor_input (c:          *mut xcb_connection_t,
                                           window:     xcb_window_t,
                                           event_mask: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_select_cursor_input_checked (c:          *mut xcb_connection_t,
                                                   window:     xcb_window_t,
                                                   event_mask: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_get_cursor_image_cursor_image (R: *const xcb_xfixes_get_cursor_image_reply_t)
            -> *mut u32;

    pub fn xcb_xfixes_get_cursor_image_cursor_image_length (R: *const xcb_xfixes_get_cursor_image_reply_t)
            -> c_int;

    pub fn xcb_xfixes_get_cursor_image_cursor_image_end (R: *const xcb_xfixes_get_cursor_image_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xfixes_get_cursor_image_reply (c:      *mut xcb_connection_t,
                                              cookie: xcb_xfixes_get_cursor_image_cookie_t,
                                              error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xfixes_get_cursor_image_reply_t;

    pub fn xcb_xfixes_get_cursor_image (c: *mut xcb_connection_t)
            -> xcb_xfixes_get_cursor_image_cookie_t;

    pub fn xcb_xfixes_get_cursor_image_unchecked (c: *mut xcb_connection_t)
            -> xcb_xfixes_get_cursor_image_cookie_t;

    pub fn xcb_xfixes_region_next (i: *mut xcb_xfixes_region_iterator_t);

    pub fn xcb_xfixes_region_end (i: *mut xcb_xfixes_region_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xfixes_create_region (c:              *mut xcb_connection_t,
                                     region:         xcb_xfixes_region_t,
                                     rectangles_len: u32,
                                     rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_checked (c:              *mut xcb_connection_t,
                                             region:         xcb_xfixes_region_t,
                                             rectangles_len: u32,
                                             rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_from_bitmap (c:      *mut xcb_connection_t,
                                                 region: xcb_xfixes_region_t,
                                                 bitmap: xcb_pixmap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_from_bitmap_checked (c:      *mut xcb_connection_t,
                                                         region: xcb_xfixes_region_t,
                                                         bitmap: xcb_pixmap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_from_window (c:      *mut xcb_connection_t,
                                                 region: xcb_xfixes_region_t,
                                                 window: xcb_window_t,
                                                 kind:   xcb_shape_kind_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_from_window_checked (c:      *mut xcb_connection_t,
                                                         region: xcb_xfixes_region_t,
                                                         window: xcb_window_t,
                                                         kind:   xcb_shape_kind_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_from_gc (c:      *mut xcb_connection_t,
                                             region: xcb_xfixes_region_t,
                                             gc:     xcb_gcontext_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_from_gc_checked (c:      *mut xcb_connection_t,
                                                     region: xcb_xfixes_region_t,
                                                     gc:     xcb_gcontext_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_from_picture (c:       *mut xcb_connection_t,
                                                  region:  xcb_xfixes_region_t,
                                                  picture: xcb_render_picture_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_region_from_picture_checked (c:       *mut xcb_connection_t,
                                                          region:  xcb_xfixes_region_t,
                                                          picture: xcb_render_picture_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_destroy_region (c:      *mut xcb_connection_t,
                                      region: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_destroy_region_checked (c:      *mut xcb_connection_t,
                                              region: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_region (c:              *mut xcb_connection_t,
                                  region:         xcb_xfixes_region_t,
                                  rectangles_len: u32,
                                  rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_region_checked (c:              *mut xcb_connection_t,
                                          region:         xcb_xfixes_region_t,
                                          rectangles_len: u32,
                                          rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_copy_region (c:           *mut xcb_connection_t,
                                   source:      xcb_xfixes_region_t,
                                   destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_copy_region_checked (c:           *mut xcb_connection_t,
                                           source:      xcb_xfixes_region_t,
                                           destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_union_region (c:           *mut xcb_connection_t,
                                    source1:     xcb_xfixes_region_t,
                                    source2:     xcb_xfixes_region_t,
                                    destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_union_region_checked (c:           *mut xcb_connection_t,
                                            source1:     xcb_xfixes_region_t,
                                            source2:     xcb_xfixes_region_t,
                                            destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_intersect_region (c:           *mut xcb_connection_t,
                                        source1:     xcb_xfixes_region_t,
                                        source2:     xcb_xfixes_region_t,
                                        destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_intersect_region_checked (c:           *mut xcb_connection_t,
                                                source1:     xcb_xfixes_region_t,
                                                source2:     xcb_xfixes_region_t,
                                                destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_subtract_region (c:           *mut xcb_connection_t,
                                       source1:     xcb_xfixes_region_t,
                                       source2:     xcb_xfixes_region_t,
                                       destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_subtract_region_checked (c:           *mut xcb_connection_t,
                                               source1:     xcb_xfixes_region_t,
                                               source2:     xcb_xfixes_region_t,
                                               destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_invert_region (c:           *mut xcb_connection_t,
                                     source:      xcb_xfixes_region_t,
                                     bounds:      xcb_rectangle_t,
                                     destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_invert_region_checked (c:           *mut xcb_connection_t,
                                             source:      xcb_xfixes_region_t,
                                             bounds:      xcb_rectangle_t,
                                             destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_translate_region (c:      *mut xcb_connection_t,
                                        region: xcb_xfixes_region_t,
                                        dx:     i16,
                                        dy:     i16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_translate_region_checked (c:      *mut xcb_connection_t,
                                                region: xcb_xfixes_region_t,
                                                dx:     i16,
                                                dy:     i16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_region_extents (c:           *mut xcb_connection_t,
                                      source:      xcb_xfixes_region_t,
                                      destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_region_extents_checked (c:           *mut xcb_connection_t,
                                              source:      xcb_xfixes_region_t,
                                              destination: xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_fetch_region_rectangles (R: *const xcb_xfixes_fetch_region_reply_t)
            -> *mut xcb_rectangle_t;

    pub fn xcb_xfixes_fetch_region_rectangles_length (R: *const xcb_xfixes_fetch_region_reply_t)
            -> c_int;

    pub fn xcb_xfixes_fetch_region_rectangles_iterator (R: *const xcb_xfixes_fetch_region_reply_t)
            -> xcb_rectangle_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xfixes_fetch_region_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_xfixes_fetch_region_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xfixes_fetch_region_reply_t;

    pub fn xcb_xfixes_fetch_region (c:      *mut xcb_connection_t,
                                    region: xcb_xfixes_region_t)
            -> xcb_xfixes_fetch_region_cookie_t;

    pub fn xcb_xfixes_fetch_region_unchecked (c:      *mut xcb_connection_t,
                                              region: xcb_xfixes_region_t)
            -> xcb_xfixes_fetch_region_cookie_t;

    pub fn xcb_xfixes_set_gc_clip_region (c:        *mut xcb_connection_t,
                                          gc:       xcb_gcontext_t,
                                          region:   xcb_xfixes_region_t,
                                          x_origin: i16,
                                          y_origin: i16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_gc_clip_region_checked (c:        *mut xcb_connection_t,
                                                  gc:       xcb_gcontext_t,
                                                  region:   xcb_xfixes_region_t,
                                                  x_origin: i16,
                                                  y_origin: i16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_window_shape_region (c:         *mut xcb_connection_t,
                                               dest:      xcb_window_t,
                                               dest_kind: xcb_shape_kind_t,
                                               x_offset:  i16,
                                               y_offset:  i16,
                                               region:    xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_window_shape_region_checked (c:         *mut xcb_connection_t,
                                                       dest:      xcb_window_t,
                                                       dest_kind: xcb_shape_kind_t,
                                                       x_offset:  i16,
                                                       y_offset:  i16,
                                                       region:    xcb_xfixes_region_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_picture_clip_region (c:        *mut xcb_connection_t,
                                               picture:  xcb_render_picture_t,
                                               region:   xcb_xfixes_region_t,
                                               x_origin: i16,
                                               y_origin: i16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_picture_clip_region_checked (c:        *mut xcb_connection_t,
                                                       picture:  xcb_render_picture_t,
                                                       region:   xcb_xfixes_region_t,
                                                       x_origin: i16,
                                                       y_origin: i16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_cursor_name (c:      *mut xcb_connection_t,
                                       cursor: xcb_cursor_t,
                                       nbytes: u16,
                                       name:   *const c_char)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_set_cursor_name_checked (c:      *mut xcb_connection_t,
                                               cursor: xcb_cursor_t,
                                               nbytes: u16,
                                               name:   *const c_char)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_get_cursor_name_name (R: *const xcb_xfixes_get_cursor_name_reply_t)
            -> *mut c_char;

    pub fn xcb_xfixes_get_cursor_name_name_length (R: *const xcb_xfixes_get_cursor_name_reply_t)
            -> c_int;

    pub fn xcb_xfixes_get_cursor_name_name_end (R: *const xcb_xfixes_get_cursor_name_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xfixes_get_cursor_name_reply (c:      *mut xcb_connection_t,
                                             cookie: xcb_xfixes_get_cursor_name_cookie_t,
                                             error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xfixes_get_cursor_name_reply_t;

    pub fn xcb_xfixes_get_cursor_name (c:      *mut xcb_connection_t,
                                       cursor: xcb_cursor_t)
            -> xcb_xfixes_get_cursor_name_cookie_t;

    pub fn xcb_xfixes_get_cursor_name_unchecked (c:      *mut xcb_connection_t,
                                                 cursor: xcb_cursor_t)
            -> xcb_xfixes_get_cursor_name_cookie_t;

    pub fn xcb_xfixes_get_cursor_image_and_name_name (R: *const xcb_xfixes_get_cursor_image_and_name_reply_t)
            -> *mut c_char;

    pub fn xcb_xfixes_get_cursor_image_and_name_name_length (R: *const xcb_xfixes_get_cursor_image_and_name_reply_t)
            -> c_int;

    pub fn xcb_xfixes_get_cursor_image_and_name_name_end (R: *const xcb_xfixes_get_cursor_image_and_name_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xfixes_get_cursor_image_and_name_cursor_image (R: *const xcb_xfixes_get_cursor_image_and_name_reply_t)
            -> *mut u32;

    pub fn xcb_xfixes_get_cursor_image_and_name_cursor_image_length (R: *const xcb_xfixes_get_cursor_image_and_name_reply_t)
            -> c_int;

    pub fn xcb_xfixes_get_cursor_image_and_name_cursor_image_end (R: *const xcb_xfixes_get_cursor_image_and_name_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_xfixes_get_cursor_image_and_name_reply (c:      *mut xcb_connection_t,
                                                       cookie: xcb_xfixes_get_cursor_image_and_name_cookie_t,
                                                       error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_xfixes_get_cursor_image_and_name_reply_t;

    pub fn xcb_xfixes_get_cursor_image_and_name (c: *mut xcb_connection_t)
            -> xcb_xfixes_get_cursor_image_and_name_cookie_t;

    pub fn xcb_xfixes_get_cursor_image_and_name_unchecked (c: *mut xcb_connection_t)
            -> xcb_xfixes_get_cursor_image_and_name_cookie_t;

    pub fn xcb_xfixes_change_cursor (c:           *mut xcb_connection_t,
                                     source:      xcb_cursor_t,
                                     destination: xcb_cursor_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_change_cursor_checked (c:           *mut xcb_connection_t,
                                             source:      xcb_cursor_t,
                                             destination: xcb_cursor_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_change_cursor_by_name (c:      *mut xcb_connection_t,
                                             src:    xcb_cursor_t,
                                             nbytes: u16,
                                             name:   *const c_char)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_change_cursor_by_name_checked (c:      *mut xcb_connection_t,
                                                     src:    xcb_cursor_t,
                                                     nbytes: u16,
                                                     name:   *const c_char)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_expand_region (c:           *mut xcb_connection_t,
                                     source:      xcb_xfixes_region_t,
                                     destination: xcb_xfixes_region_t,
                                     left:        u16,
                                     right:       u16,
                                     top:         u16,
                                     bottom:      u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_expand_region_checked (c:           *mut xcb_connection_t,
                                             source:      xcb_xfixes_region_t,
                                             destination: xcb_xfixes_region_t,
                                             left:        u16,
                                             right:       u16,
                                             top:         u16,
                                             bottom:      u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_hide_cursor (c:      *mut xcb_connection_t,
                                   window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_hide_cursor_checked (c:      *mut xcb_connection_t,
                                           window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_show_cursor (c:      *mut xcb_connection_t,
                                   window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_show_cursor_checked (c:      *mut xcb_connection_t,
                                           window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_barrier_next (i: *mut xcb_xfixes_barrier_iterator_t);

    pub fn xcb_xfixes_barrier_end (i: *mut xcb_xfixes_barrier_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_xfixes_create_pointer_barrier (c:           *mut xcb_connection_t,
                                              barrier:     xcb_xfixes_barrier_t,
                                              window:      xcb_window_t,
                                              x1:          u16,
                                              y1:          u16,
                                              x2:          u16,
                                              y2:          u16,
                                              directions:  u32,
                                              num_devices: u16,
                                              devices:     *const u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_create_pointer_barrier_checked (c:           *mut xcb_connection_t,
                                                      barrier:     xcb_xfixes_barrier_t,
                                                      window:      xcb_window_t,
                                                      x1:          u16,
                                                      y1:          u16,
                                                      x2:          u16,
                                                      y2:          u16,
                                                      directions:  u32,
                                                      num_devices: u16,
                                                      devices:     *const u16)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_delete_pointer_barrier (c:       *mut xcb_connection_t,
                                              barrier: xcb_xfixes_barrier_t)
            -> xcb_void_cookie_t;

    pub fn xcb_xfixes_delete_pointer_barrier_checked (c:       *mut xcb_connection_t,
                                                      barrier: xcb_xfixes_barrier_t)
            -> xcb_void_cookie_t;

} // extern
