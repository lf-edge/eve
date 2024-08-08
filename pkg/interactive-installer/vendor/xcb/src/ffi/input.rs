// Generated automatically from xinput.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;
use ffi::render::*;
use ffi::shape::*;
use ffi::xfixes::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_INPUT_MAJOR_VERSION: u32 = 2;
pub const XCB_INPUT_MINOR_VERSION: u32 = 3;

pub type xcb_input_event_class_t = u32;

#[repr(C)]
pub struct xcb_input_event_class_iterator_t {
    pub data:  *mut xcb_input_event_class_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_input_key_code_t = u8;

#[repr(C)]
pub struct xcb_input_key_code_iterator_t {
    pub data:  *mut xcb_input_key_code_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_input_device_id_t = u16;

#[repr(C)]
pub struct xcb_input_device_id_iterator_t {
    pub data:  *mut xcb_input_device_id_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_input_fp1616_t = i32;

#[repr(C)]
pub struct xcb_input_fp1616_iterator_t {
    pub data:  *mut xcb_input_fp1616_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_fp3232_t {
    pub integral: i32,
    pub frac:     u32,
}

impl Copy for xcb_input_fp3232_t {}
impl Clone for xcb_input_fp3232_t {
    fn clone(&self) -> xcb_input_fp3232_t { *self }
}

#[repr(C)]
pub struct xcb_input_fp3232_iterator_t {
    pub data:  *mut xcb_input_fp3232_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_INPUT_GET_EXTENSION_VERSION: u8 = 1;

#[repr(C)]
pub struct xcb_input_get_extension_version_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub name_len:     u16,
    pub pad0:         [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_extension_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_extension_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub server_major:  u16,
    pub server_minor:  u16,
    pub present:       u8,
    pub pad1:          [u8; 19],
}

impl Copy for xcb_input_get_extension_version_reply_t {}
impl Clone for xcb_input_get_extension_version_reply_t {
    fn clone(&self) -> xcb_input_get_extension_version_reply_t { *self }
}

pub type xcb_input_device_use_t = u32;
pub const XCB_INPUT_DEVICE_USE_IS_X_POINTER           : xcb_input_device_use_t = 0x00;
pub const XCB_INPUT_DEVICE_USE_IS_X_KEYBOARD          : xcb_input_device_use_t = 0x01;
pub const XCB_INPUT_DEVICE_USE_IS_X_EXTENSION_DEVICE  : xcb_input_device_use_t = 0x02;
pub const XCB_INPUT_DEVICE_USE_IS_X_EXTENSION_KEYBOARD: xcb_input_device_use_t = 0x03;
pub const XCB_INPUT_DEVICE_USE_IS_X_EXTENSION_POINTER : xcb_input_device_use_t = 0x04;

pub type xcb_input_input_class_t = u32;
pub const XCB_INPUT_INPUT_CLASS_KEY      : xcb_input_input_class_t = 0x00;
pub const XCB_INPUT_INPUT_CLASS_BUTTON   : xcb_input_input_class_t = 0x01;
pub const XCB_INPUT_INPUT_CLASS_VALUATOR : xcb_input_input_class_t = 0x02;
pub const XCB_INPUT_INPUT_CLASS_FEEDBACK : xcb_input_input_class_t = 0x03;
pub const XCB_INPUT_INPUT_CLASS_PROXIMITY: xcb_input_input_class_t = 0x04;
pub const XCB_INPUT_INPUT_CLASS_FOCUS    : xcb_input_input_class_t = 0x05;
pub const XCB_INPUT_INPUT_CLASS_OTHER    : xcb_input_input_class_t = 0x06;

pub type xcb_input_valuator_mode_t = u32;
pub const XCB_INPUT_VALUATOR_MODE_RELATIVE: xcb_input_valuator_mode_t = 0x00;
pub const XCB_INPUT_VALUATOR_MODE_ABSOLUTE: xcb_input_valuator_mode_t = 0x01;

#[repr(C)]
pub struct xcb_input_device_info_t {
    pub device_type:    xcb_atom_t,
    pub device_id:      u8,
    pub num_class_info: u8,
    pub device_use:     u8,
    pub pad0:           u8,
}

impl Copy for xcb_input_device_info_t {}
impl Clone for xcb_input_device_info_t {
    fn clone(&self) -> xcb_input_device_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_info_iterator_t {
    pub data:  *mut xcb_input_device_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_key_info_t {
    pub class_id:    u8,
    pub len:         u8,
    pub min_keycode: xcb_input_key_code_t,
    pub max_keycode: xcb_input_key_code_t,
    pub num_keys:    u16,
    pub pad0:        [u8; 2],
}

impl Copy for xcb_input_key_info_t {}
impl Clone for xcb_input_key_info_t {
    fn clone(&self) -> xcb_input_key_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_key_info_iterator_t {
    pub data:  *mut xcb_input_key_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_button_info_t {
    pub class_id:    u8,
    pub len:         u8,
    pub num_buttons: u16,
}

impl Copy for xcb_input_button_info_t {}
impl Clone for xcb_input_button_info_t {
    fn clone(&self) -> xcb_input_button_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_button_info_iterator_t {
    pub data:  *mut xcb_input_button_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_axis_info_t {
    pub resolution: u32,
    pub minimum:    i32,
    pub maximum:    i32,
}

impl Copy for xcb_input_axis_info_t {}
impl Clone for xcb_input_axis_info_t {
    fn clone(&self) -> xcb_input_axis_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_axis_info_iterator_t {
    pub data:  *mut xcb_input_axis_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_valuator_info_t {
    pub class_id:    u8,
    pub len:         u8,
    pub axes_len:    u8,
    pub mode:        u8,
    pub motion_size: u32,
}

#[repr(C)]
pub struct xcb_input_valuator_info_iterator_t<'a> {
    pub data:  *mut xcb_input_valuator_info_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_valuator_info_t>,
}

#[repr(C)]
pub struct xcb_input_input_info_t {
    pub class_id: u8,
    pub len:      u8,
}

impl Copy for xcb_input_input_info_t {}
impl Clone for xcb_input_input_info_t {
    fn clone(&self) -> xcb_input_input_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_input_info_iterator_t {
    pub data:  *mut xcb_input_input_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_name_t {
    pub len:    u8,
}

#[repr(C)]
pub struct xcb_input_device_name_iterator_t<'a> {
    pub data:  *mut xcb_input_device_name_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_device_name_t>,
}

pub const XCB_INPUT_LIST_INPUT_DEVICES: u8 = 2;

#[repr(C)]
pub struct xcb_input_list_input_devices_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_input_list_input_devices_request_t {}
impl Clone for xcb_input_list_input_devices_request_t {
    fn clone(&self) -> xcb_input_list_input_devices_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_list_input_devices_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_list_input_devices_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub devices_len:   u8,
    pub pad1:          [u8; 23],
}

#[repr(C)]
pub struct xcb_input_input_class_info_t {
    pub class_id:        u8,
    pub event_type_base: u8,
}

impl Copy for xcb_input_input_class_info_t {}
impl Clone for xcb_input_input_class_info_t {
    fn clone(&self) -> xcb_input_input_class_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_input_class_info_iterator_t {
    pub data:  *mut xcb_input_input_class_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_INPUT_OPEN_DEVICE: u8 = 3;

#[repr(C)]
pub struct xcb_input_open_device_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_open_device_request_t {}
impl Clone for xcb_input_open_device_request_t {
    fn clone(&self) -> xcb_input_open_device_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_open_device_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_open_device_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_classes:   u8,
    pub pad1:          [u8; 23],
}

pub const XCB_INPUT_CLOSE_DEVICE: u8 = 4;

#[repr(C)]
pub struct xcb_input_close_device_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_close_device_request_t {}
impl Clone for xcb_input_close_device_request_t {
    fn clone(&self) -> xcb_input_close_device_request_t { *self }
}

pub const XCB_INPUT_SET_DEVICE_MODE: u8 = 5;

#[repr(C)]
pub struct xcb_input_set_device_mode_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub mode:         u8,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_set_device_mode_request_t {}
impl Clone for xcb_input_set_device_mode_request_t {
    fn clone(&self) -> xcb_input_set_device_mode_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_set_device_mode_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_set_device_mode_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_set_device_mode_reply_t {}
impl Clone for xcb_input_set_device_mode_reply_t {
    fn clone(&self) -> xcb_input_set_device_mode_reply_t { *self }
}

pub const XCB_INPUT_SELECT_EXTENSION_EVENT: u8 = 6;

#[repr(C)]
pub struct xcb_input_select_extension_event_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub num_classes:  u16,
    pub pad0:         [u8; 2],
}

pub const XCB_INPUT_GET_SELECTED_EXTENSION_EVENTS: u8 = 7;

#[repr(C)]
pub struct xcb_input_get_selected_extension_events_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_input_get_selected_extension_events_request_t {}
impl Clone for xcb_input_get_selected_extension_events_request_t {
    fn clone(&self) -> xcb_input_get_selected_extension_events_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_selected_extension_events_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_selected_extension_events_reply_t {
    pub response_type:    u8,
    pub pad0:             u8,
    pub sequence:         u16,
    pub length:           u32,
    pub num_this_classes: u16,
    pub num_all_classes:  u16,
    pub pad1:             [u8; 20],
}

pub type xcb_input_propagate_mode_t = u32;
pub const XCB_INPUT_PROPAGATE_MODE_ADD_TO_LIST     : xcb_input_propagate_mode_t = 0x00;
pub const XCB_INPUT_PROPAGATE_MODE_DELETE_FROM_LIST: xcb_input_propagate_mode_t = 0x01;

pub const XCB_INPUT_CHANGE_DEVICE_DONT_PROPAGATE_LIST: u8 = 8;

#[repr(C)]
pub struct xcb_input_change_device_dont_propagate_list_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub num_classes:  u16,
    pub mode:         u8,
    pub pad0:         u8,
}

pub const XCB_INPUT_GET_DEVICE_DONT_PROPAGATE_LIST: u8 = 9;

#[repr(C)]
pub struct xcb_input_get_device_dont_propagate_list_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_input_get_device_dont_propagate_list_request_t {}
impl Clone for xcb_input_get_device_dont_propagate_list_request_t {
    fn clone(&self) -> xcb_input_get_device_dont_propagate_list_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_device_dont_propagate_list_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_device_dont_propagate_list_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_classes:   u16,
    pub pad1:          [u8; 22],
}

#[repr(C)]
pub struct xcb_input_device_time_coord_t {
    pub time: xcb_timestamp_t,
}

impl Copy for xcb_input_device_time_coord_t {}
impl Clone for xcb_input_device_time_coord_t {
    fn clone(&self) -> xcb_input_device_time_coord_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_time_coord_iterator_t {
    pub data:  *mut xcb_input_device_time_coord_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_INPUT_GET_DEVICE_MOTION_EVENTS: u8 = 10;

#[repr(C)]
pub struct xcb_input_get_device_motion_events_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub start:        xcb_timestamp_t,
    pub stop:         xcb_timestamp_t,
    pub device_id:    u8,
}

impl Copy for xcb_input_get_device_motion_events_request_t {}
impl Clone for xcb_input_get_device_motion_events_request_t {
    fn clone(&self) -> xcb_input_get_device_motion_events_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_device_motion_events_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_device_motion_events_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_events:    u32,
    pub num_axes:      u8,
    pub device_mode:   u8,
    pub pad1:          [u8; 18],
}

impl Copy for xcb_input_get_device_motion_events_reply_t {}
impl Clone for xcb_input_get_device_motion_events_reply_t {
    fn clone(&self) -> xcb_input_get_device_motion_events_reply_t { *self }
}

pub const XCB_INPUT_CHANGE_KEYBOARD_DEVICE: u8 = 11;

#[repr(C)]
pub struct xcb_input_change_keyboard_device_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_change_keyboard_device_request_t {}
impl Clone for xcb_input_change_keyboard_device_request_t {
    fn clone(&self) -> xcb_input_change_keyboard_device_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_change_keyboard_device_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_change_keyboard_device_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_change_keyboard_device_reply_t {}
impl Clone for xcb_input_change_keyboard_device_reply_t {
    fn clone(&self) -> xcb_input_change_keyboard_device_reply_t { *self }
}

pub const XCB_INPUT_CHANGE_POINTER_DEVICE: u8 = 12;

#[repr(C)]
pub struct xcb_input_change_pointer_device_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub x_axis:       u8,
    pub y_axis:       u8,
    pub device_id:    u8,
    pub pad0:         u8,
}

impl Copy for xcb_input_change_pointer_device_request_t {}
impl Clone for xcb_input_change_pointer_device_request_t {
    fn clone(&self) -> xcb_input_change_pointer_device_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_change_pointer_device_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_change_pointer_device_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_change_pointer_device_reply_t {}
impl Clone for xcb_input_change_pointer_device_reply_t {
    fn clone(&self) -> xcb_input_change_pointer_device_reply_t { *self }
}

pub const XCB_INPUT_GRAB_DEVICE: u8 = 13;

#[repr(C)]
pub struct xcb_input_grab_device_request_t {
    pub major_opcode:      u8,
    pub minor_opcode:      u8,
    pub length:            u16,
    pub grab_window:       xcb_window_t,
    pub time:              xcb_timestamp_t,
    pub num_classes:       u16,
    pub this_device_mode:  u8,
    pub other_device_mode: u8,
    pub owner_events:      u8,
    pub device_id:         u8,
    pub pad0:              [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_grab_device_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_grab_device_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_grab_device_reply_t {}
impl Clone for xcb_input_grab_device_reply_t {
    fn clone(&self) -> xcb_input_grab_device_reply_t { *self }
}

pub const XCB_INPUT_UNGRAB_DEVICE: u8 = 14;

#[repr(C)]
pub struct xcb_input_ungrab_device_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub time:         xcb_timestamp_t,
    pub device_id:    u8,
}

impl Copy for xcb_input_ungrab_device_request_t {}
impl Clone for xcb_input_ungrab_device_request_t {
    fn clone(&self) -> xcb_input_ungrab_device_request_t { *self }
}

pub const XCB_INPUT_GRAB_DEVICE_KEY: u8 = 15;

#[repr(C)]
pub struct xcb_input_grab_device_key_request_t {
    pub major_opcode:      u8,
    pub minor_opcode:      u8,
    pub length:            u16,
    pub grab_window:       xcb_window_t,
    pub num_classes:       u16,
    pub modifiers:         u16,
    pub modifier_device:   u8,
    pub grabbed_device:    u8,
    pub key:               u8,
    pub this_device_mode:  u8,
    pub other_device_mode: u8,
    pub owner_events:      u8,
    pub pad0:              [u8; 2],
}

pub const XCB_INPUT_UNGRAB_DEVICE_KEY: u8 = 16;

#[repr(C)]
pub struct xcb_input_ungrab_device_key_request_t {
    pub major_opcode:    u8,
    pub minor_opcode:    u8,
    pub length:          u16,
    pub grabWindow:      xcb_window_t,
    pub modifiers:       u16,
    pub modifier_device: u8,
    pub key:             u8,
    pub grabbed_device:  u8,
}

impl Copy for xcb_input_ungrab_device_key_request_t {}
impl Clone for xcb_input_ungrab_device_key_request_t {
    fn clone(&self) -> xcb_input_ungrab_device_key_request_t { *self }
}

pub const XCB_INPUT_GRAB_DEVICE_BUTTON: u8 = 17;

#[repr(C)]
pub struct xcb_input_grab_device_button_request_t {
    pub major_opcode:      u8,
    pub minor_opcode:      u8,
    pub length:            u16,
    pub grab_window:       xcb_window_t,
    pub grabbed_device:    u8,
    pub modifier_device:   u8,
    pub num_classes:       u16,
    pub modifiers:         u16,
    pub this_device_mode:  u8,
    pub other_device_mode: u8,
    pub button:            u8,
    pub owner_events:      u8,
    pub pad0:              [u8; 2],
}

pub const XCB_INPUT_UNGRAB_DEVICE_BUTTON: u8 = 18;

#[repr(C)]
pub struct xcb_input_ungrab_device_button_request_t {
    pub major_opcode:    u8,
    pub minor_opcode:    u8,
    pub length:          u16,
    pub grab_window:     xcb_window_t,
    pub modifiers:       u16,
    pub modifier_device: u8,
    pub button:          u8,
    pub grabbed_device:  u8,
}

impl Copy for xcb_input_ungrab_device_button_request_t {}
impl Clone for xcb_input_ungrab_device_button_request_t {
    fn clone(&self) -> xcb_input_ungrab_device_button_request_t { *self }
}

pub type xcb_input_device_input_mode_t = u32;
pub const XCB_INPUT_DEVICE_INPUT_MODE_ASYNC_THIS_DEVICE  : xcb_input_device_input_mode_t = 0x00;
pub const XCB_INPUT_DEVICE_INPUT_MODE_SYNC_THIS_DEVICE   : xcb_input_device_input_mode_t = 0x01;
pub const XCB_INPUT_DEVICE_INPUT_MODE_REPLAY_THIS_DEVICE : xcb_input_device_input_mode_t = 0x02;
pub const XCB_INPUT_DEVICE_INPUT_MODE_ASYNC_OTHER_DEVICES: xcb_input_device_input_mode_t = 0x03;
pub const XCB_INPUT_DEVICE_INPUT_MODE_ASYNC_ALL          : xcb_input_device_input_mode_t = 0x04;
pub const XCB_INPUT_DEVICE_INPUT_MODE_SYNC_ALL           : xcb_input_device_input_mode_t = 0x05;

pub const XCB_INPUT_ALLOW_DEVICE_EVENTS: u8 = 19;

#[repr(C)]
pub struct xcb_input_allow_device_events_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub time:         xcb_timestamp_t,
    pub mode:         u8,
    pub device_id:    u8,
}

impl Copy for xcb_input_allow_device_events_request_t {}
impl Clone for xcb_input_allow_device_events_request_t {
    fn clone(&self) -> xcb_input_allow_device_events_request_t { *self }
}

pub const XCB_INPUT_GET_DEVICE_FOCUS: u8 = 20;

#[repr(C)]
pub struct xcb_input_get_device_focus_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_get_device_focus_request_t {}
impl Clone for xcb_input_get_device_focus_request_t {
    fn clone(&self) -> xcb_input_get_device_focus_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_device_focus_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_device_focus_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub focus:         xcb_window_t,
    pub time:          xcb_timestamp_t,
    pub revert_to:     u8,
    pub pad1:          [u8; 15],
}

impl Copy for xcb_input_get_device_focus_reply_t {}
impl Clone for xcb_input_get_device_focus_reply_t {
    fn clone(&self) -> xcb_input_get_device_focus_reply_t { *self }
}

pub const XCB_INPUT_SET_DEVICE_FOCUS: u8 = 21;

#[repr(C)]
pub struct xcb_input_set_device_focus_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub focus:        xcb_window_t,
    pub time:         xcb_timestamp_t,
    pub revert_to:    u8,
    pub device_id:    u8,
}

impl Copy for xcb_input_set_device_focus_request_t {}
impl Clone for xcb_input_set_device_focus_request_t {
    fn clone(&self) -> xcb_input_set_device_focus_request_t { *self }
}

pub type xcb_input_feedback_class_t = u32;
pub const XCB_INPUT_FEEDBACK_CLASS_KEYBOARD: xcb_input_feedback_class_t = 0x00;
pub const XCB_INPUT_FEEDBACK_CLASS_POINTER : xcb_input_feedback_class_t = 0x01;
pub const XCB_INPUT_FEEDBACK_CLASS_STRING  : xcb_input_feedback_class_t = 0x02;
pub const XCB_INPUT_FEEDBACK_CLASS_INTEGER : xcb_input_feedback_class_t = 0x03;
pub const XCB_INPUT_FEEDBACK_CLASS_LED     : xcb_input_feedback_class_t = 0x04;
pub const XCB_INPUT_FEEDBACK_CLASS_BELL    : xcb_input_feedback_class_t = 0x05;

#[repr(C)]
pub struct xcb_input_kbd_feedback_state_t {
    pub class_id:           u8,
    pub feedback_id:        u8,
    pub len:                u16,
    pub pitch:              u16,
    pub duration:           u16,
    pub led_mask:           u32,
    pub led_values:         u32,
    pub global_auto_repeat: u8,
    pub click:              u8,
    pub percent:            u8,
    pub pad0:               u8,
    pub auto_repeats:       [u8; 32],
}

impl Copy for xcb_input_kbd_feedback_state_t {}
impl Clone for xcb_input_kbd_feedback_state_t {
    fn clone(&self) -> xcb_input_kbd_feedback_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_kbd_feedback_state_iterator_t<'a> {
    pub data:  *mut xcb_input_kbd_feedback_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_kbd_feedback_state_t>,
}

#[repr(C)]
pub struct xcb_input_ptr_feedback_state_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub pad0:        [u8; 2],
    pub accel_num:   u16,
    pub accel_denom: u16,
    pub threshold:   u16,
}

impl Copy for xcb_input_ptr_feedback_state_t {}
impl Clone for xcb_input_ptr_feedback_state_t {
    fn clone(&self) -> xcb_input_ptr_feedback_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_ptr_feedback_state_iterator_t {
    pub data:  *mut xcb_input_ptr_feedback_state_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_integer_feedback_state_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub resolution:  u32,
    pub min_value:   i32,
    pub max_value:   i32,
}

impl Copy for xcb_input_integer_feedback_state_t {}
impl Clone for xcb_input_integer_feedback_state_t {
    fn clone(&self) -> xcb_input_integer_feedback_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_integer_feedback_state_iterator_t {
    pub data:  *mut xcb_input_integer_feedback_state_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_string_feedback_state_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub max_symbols: u16,
    pub num_keysyms: u16,
}

#[repr(C)]
pub struct xcb_input_string_feedback_state_iterator_t<'a> {
    pub data:  *mut xcb_input_string_feedback_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_string_feedback_state_t>,
}

#[repr(C)]
pub struct xcb_input_bell_feedback_state_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub percent:     u8,
    pub pad0:        [u8; 3],
    pub pitch:       u16,
    pub duration:    u16,
}

impl Copy for xcb_input_bell_feedback_state_t {}
impl Clone for xcb_input_bell_feedback_state_t {
    fn clone(&self) -> xcb_input_bell_feedback_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_bell_feedback_state_iterator_t {
    pub data:  *mut xcb_input_bell_feedback_state_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_led_feedback_state_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub led_mask:    u32,
    pub led_values:  u32,
}

impl Copy for xcb_input_led_feedback_state_t {}
impl Clone for xcb_input_led_feedback_state_t {
    fn clone(&self) -> xcb_input_led_feedback_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_led_feedback_state_iterator_t {
    pub data:  *mut xcb_input_led_feedback_state_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_feedback_state_t {
    pub class_id:           u8,
    pub feedback_id:        u8,
    pub len:                u16,
}

#[repr(C)]
pub struct xcb_input_feedback_state_iterator_t<'a> {
    pub data:  *mut xcb_input_feedback_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_feedback_state_t>,
}

pub const XCB_INPUT_GET_FEEDBACK_CONTROL: u8 = 22;

#[repr(C)]
pub struct xcb_input_get_feedback_control_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_get_feedback_control_request_t {}
impl Clone for xcb_input_get_feedback_control_request_t {
    fn clone(&self) -> xcb_input_get_feedback_control_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_feedback_control_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_feedback_control_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_feedbacks: u16,
    pub pad1:          [u8; 22],
}

#[repr(C)]
pub struct xcb_input_kbd_feedback_ctl_t {
    pub class_id:          u8,
    pub feedback_id:       u8,
    pub len:               u16,
    pub key:               xcb_input_key_code_t,
    pub auto_repeat_mode:  u8,
    pub key_click_percent: i8,
    pub bell_percent:      i8,
    pub bell_pitch:        i16,
    pub bell_duration:     i16,
    pub led_mask:          u32,
    pub led_values:        u32,
}

impl Copy for xcb_input_kbd_feedback_ctl_t {}
impl Clone for xcb_input_kbd_feedback_ctl_t {
    fn clone(&self) -> xcb_input_kbd_feedback_ctl_t { *self }
}

#[repr(C)]
pub struct xcb_input_kbd_feedback_ctl_iterator_t {
    pub data:  *mut xcb_input_kbd_feedback_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_ptr_feedback_ctl_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub pad0:        [u8; 2],
    pub num:         i16,
    pub denom:       i16,
    pub threshold:   i16,
}

impl Copy for xcb_input_ptr_feedback_ctl_t {}
impl Clone for xcb_input_ptr_feedback_ctl_t {
    fn clone(&self) -> xcb_input_ptr_feedback_ctl_t { *self }
}

#[repr(C)]
pub struct xcb_input_ptr_feedback_ctl_iterator_t {
    pub data:  *mut xcb_input_ptr_feedback_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_integer_feedback_ctl_t {
    pub class_id:       u8,
    pub feedback_id:    u8,
    pub len:            u16,
    pub int_to_display: i32,
}

impl Copy for xcb_input_integer_feedback_ctl_t {}
impl Clone for xcb_input_integer_feedback_ctl_t {
    fn clone(&self) -> xcb_input_integer_feedback_ctl_t { *self }
}

#[repr(C)]
pub struct xcb_input_integer_feedback_ctl_iterator_t {
    pub data:  *mut xcb_input_integer_feedback_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_string_feedback_ctl_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub pad0:        [u8; 2],
    pub num_keysyms: u16,
}

#[repr(C)]
pub struct xcb_input_string_feedback_ctl_iterator_t<'a> {
    pub data:  *mut xcb_input_string_feedback_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_string_feedback_ctl_t>,
}

#[repr(C)]
pub struct xcb_input_bell_feedback_ctl_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub percent:     i8,
    pub pad0:        [u8; 3],
    pub pitch:       i16,
    pub duration:    i16,
}

impl Copy for xcb_input_bell_feedback_ctl_t {}
impl Clone for xcb_input_bell_feedback_ctl_t {
    fn clone(&self) -> xcb_input_bell_feedback_ctl_t { *self }
}

#[repr(C)]
pub struct xcb_input_bell_feedback_ctl_iterator_t {
    pub data:  *mut xcb_input_bell_feedback_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_led_feedback_ctl_t {
    pub class_id:    u8,
    pub feedback_id: u8,
    pub len:         u16,
    pub led_mask:    u32,
    pub led_values:  u32,
}

impl Copy for xcb_input_led_feedback_ctl_t {}
impl Clone for xcb_input_led_feedback_ctl_t {
    fn clone(&self) -> xcb_input_led_feedback_ctl_t { *self }
}

#[repr(C)]
pub struct xcb_input_led_feedback_ctl_iterator_t {
    pub data:  *mut xcb_input_led_feedback_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_feedback_ctl_t {
    pub class_id:           u8,
    pub feedback_id:        u8,
    pub len:                u16,
}

#[repr(C)]
pub struct xcb_input_feedback_ctl_iterator_t<'a> {
    pub data:  *mut xcb_input_feedback_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_feedback_ctl_t>,
}

pub const XCB_INPUT_CHANGE_FEEDBACK_CONTROL: u8 = 23;

#[repr(C)]
pub struct xcb_input_change_feedback_control_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub mask:         u32,
    pub device_id:    u8,
    pub feedback_id:  u8,
}

pub const XCB_INPUT_GET_DEVICE_KEY_MAPPING: u8 = 24;

#[repr(C)]
pub struct xcb_input_get_device_key_mapping_request_t {
    pub major_opcode:  u8,
    pub minor_opcode:  u8,
    pub length:        u16,
    pub device_id:     u8,
    pub first_keycode: xcb_input_key_code_t,
    pub count:         u8,
}

impl Copy for xcb_input_get_device_key_mapping_request_t {}
impl Clone for xcb_input_get_device_key_mapping_request_t {
    fn clone(&self) -> xcb_input_get_device_key_mapping_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_device_key_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_device_key_mapping_reply_t {
    pub response_type:       u8,
    pub pad0:                u8,
    pub sequence:            u16,
    pub length:              u32,
    pub keysyms_per_keycode: u8,
    pub pad1:                [u8; 23],
}

pub const XCB_INPUT_CHANGE_DEVICE_KEY_MAPPING: u8 = 25;

#[repr(C)]
pub struct xcb_input_change_device_key_mapping_request_t {
    pub major_opcode:        u8,
    pub minor_opcode:        u8,
    pub length:              u16,
    pub device_id:           u8,
    pub first_keycode:       xcb_input_key_code_t,
    pub keysyms_per_keycode: u8,
    pub keycode_count:       u8,
}

pub const XCB_INPUT_GET_DEVICE_MODIFIER_MAPPING: u8 = 26;

#[repr(C)]
pub struct xcb_input_get_device_modifier_mapping_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_get_device_modifier_mapping_request_t {}
impl Clone for xcb_input_get_device_modifier_mapping_request_t {
    fn clone(&self) -> xcb_input_get_device_modifier_mapping_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_device_modifier_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_device_modifier_mapping_reply_t {
    pub response_type:         u8,
    pub pad0:                  u8,
    pub sequence:              u16,
    pub length:                u32,
    pub keycodes_per_modifier: u8,
    pub pad1:                  [u8; 23],
}

pub const XCB_INPUT_SET_DEVICE_MODIFIER_MAPPING: u8 = 27;

#[repr(C)]
pub struct xcb_input_set_device_modifier_mapping_request_t {
    pub major_opcode:          u8,
    pub minor_opcode:          u8,
    pub length:                u16,
    pub device_id:             u8,
    pub keycodes_per_modifier: u8,
    pub pad0:                  u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_set_device_modifier_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_set_device_modifier_mapping_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_set_device_modifier_mapping_reply_t {}
impl Clone for xcb_input_set_device_modifier_mapping_reply_t {
    fn clone(&self) -> xcb_input_set_device_modifier_mapping_reply_t { *self }
}

pub const XCB_INPUT_GET_DEVICE_BUTTON_MAPPING: u8 = 28;

#[repr(C)]
pub struct xcb_input_get_device_button_mapping_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_get_device_button_mapping_request_t {}
impl Clone for xcb_input_get_device_button_mapping_request_t {
    fn clone(&self) -> xcb_input_get_device_button_mapping_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_device_button_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_device_button_mapping_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub map_size:      u8,
    pub pad1:          [u8; 23],
}

pub const XCB_INPUT_SET_DEVICE_BUTTON_MAPPING: u8 = 29;

#[repr(C)]
pub struct xcb_input_set_device_button_mapping_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub map_size:     u8,
    pub pad0:         [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_set_device_button_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_set_device_button_mapping_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_set_device_button_mapping_reply_t {}
impl Clone for xcb_input_set_device_button_mapping_reply_t {
    fn clone(&self) -> xcb_input_set_device_button_mapping_reply_t { *self }
}

#[repr(C)]
pub struct xcb_input_key_state_t {
    pub class_id: u8,
    pub len:      u8,
    pub num_keys: u8,
    pub pad0:     u8,
    pub keys:     [u8; 32],
}

impl Copy for xcb_input_key_state_t {}
impl Clone for xcb_input_key_state_t {
    fn clone(&self) -> xcb_input_key_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_key_state_iterator_t<'a> {
    pub data:  *mut xcb_input_key_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_key_state_t>,
}

#[repr(C)]
pub struct xcb_input_button_state_t {
    pub class_id:    u8,
    pub len:         u8,
    pub num_buttons: u8,
    pub pad0:        u8,
    pub buttons:     [u8; 32],
}

impl Copy for xcb_input_button_state_t {}
impl Clone for xcb_input_button_state_t {
    fn clone(&self) -> xcb_input_button_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_button_state_iterator_t<'a> {
    pub data:  *mut xcb_input_button_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_button_state_t>,
}

#[repr(C)]
pub struct xcb_input_valuator_state_t {
    pub class_id:      u8,
    pub len:           u8,
    pub num_valuators: u8,
    pub mode:          u8,
}

#[repr(C)]
pub struct xcb_input_valuator_state_iterator_t<'a> {
    pub data:  *mut xcb_input_valuator_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_valuator_state_t>,
}

#[repr(C)]
pub struct xcb_input_input_state_t {
    pub class_id:           u8,
    pub len:                u8,
    pub num_items:          u8,
    pub pad0:               u8,
}

#[repr(C)]
pub struct xcb_input_input_state_iterator_t<'a> {
    pub data:  *mut xcb_input_input_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_input_state_t>,
}

pub const XCB_INPUT_QUERY_DEVICE_STATE: u8 = 30;

#[repr(C)]
pub struct xcb_input_query_device_state_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_query_device_state_request_t {}
impl Clone for xcb_input_query_device_state_request_t {
    fn clone(&self) -> xcb_input_query_device_state_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_query_device_state_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_query_device_state_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_classes:   u8,
    pub pad1:          [u8; 23],
}

pub const XCB_INPUT_SEND_EXTENSION_EVENT: u8 = 31;

#[repr(C)]
pub struct xcb_input_send_extension_event_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub destination:  xcb_window_t,
    pub device_id:    u8,
    pub propagate:    u8,
    pub num_classes:  u16,
    pub num_events:   u8,
    pub pad0:         [u8; 3],
}

pub const XCB_INPUT_DEVICE_BELL: u8 = 32;

#[repr(C)]
pub struct xcb_input_device_bell_request_t {
    pub major_opcode:   u8,
    pub minor_opcode:   u8,
    pub length:         u16,
    pub device_id:      u8,
    pub feedback_id:    u8,
    pub feedback_class: u8,
    pub percent:        i8,
}

impl Copy for xcb_input_device_bell_request_t {}
impl Clone for xcb_input_device_bell_request_t {
    fn clone(&self) -> xcb_input_device_bell_request_t { *self }
}

pub const XCB_INPUT_SET_DEVICE_VALUATORS: u8 = 33;

#[repr(C)]
pub struct xcb_input_set_device_valuators_request_t {
    pub major_opcode:   u8,
    pub minor_opcode:   u8,
    pub length:         u16,
    pub device_id:      u8,
    pub first_valuator: u8,
    pub num_valuators:  u8,
    pub pad0:           u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_set_device_valuators_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_set_device_valuators_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_set_device_valuators_reply_t {}
impl Clone for xcb_input_set_device_valuators_reply_t {
    fn clone(&self) -> xcb_input_set_device_valuators_reply_t { *self }
}

pub type xcb_input_device_control_t = u32;
pub const XCB_INPUT_DEVICE_CONTROL_RESOLUTION: xcb_input_device_control_t = 0x01;
pub const XCB_INPUT_DEVICE_CONTROL_ABS_CALIB : xcb_input_device_control_t = 0x02;
pub const XCB_INPUT_DEVICE_CONTROL_CORE      : xcb_input_device_control_t = 0x03;
pub const XCB_INPUT_DEVICE_CONTROL_ENABLE    : xcb_input_device_control_t = 0x04;
pub const XCB_INPUT_DEVICE_CONTROL_ABS_AREA  : xcb_input_device_control_t = 0x05;

#[repr(C)]
pub struct xcb_input_device_resolution_state_t {
    pub control_id:        u16,
    pub len:               u16,
    pub num_valuators:     u32,
}

#[repr(C)]
pub struct xcb_input_device_resolution_state_iterator_t<'a> {
    pub data:  *mut xcb_input_device_resolution_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_device_resolution_state_t>,
}

#[repr(C)]
pub struct xcb_input_device_abs_calib_state_t {
    pub control_id:       u16,
    pub len:              u16,
    pub min_x:            i32,
    pub max_x:            i32,
    pub min_y:            i32,
    pub max_y:            i32,
    pub flip_x:           u32,
    pub flip_y:           u32,
    pub rotation:         u32,
    pub button_threshold: u32,
}

impl Copy for xcb_input_device_abs_calib_state_t {}
impl Clone for xcb_input_device_abs_calib_state_t {
    fn clone(&self) -> xcb_input_device_abs_calib_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_abs_calib_state_iterator_t {
    pub data:  *mut xcb_input_device_abs_calib_state_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_abs_area_state_t {
    pub control_id: u16,
    pub len:        u16,
    pub offset_x:   u32,
    pub offset_y:   u32,
    pub width:      u32,
    pub height:     u32,
    pub screen:     u32,
    pub following:  u32,
}

impl Copy for xcb_input_device_abs_area_state_t {}
impl Clone for xcb_input_device_abs_area_state_t {
    fn clone(&self) -> xcb_input_device_abs_area_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_abs_area_state_iterator_t {
    pub data:  *mut xcb_input_device_abs_area_state_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_core_state_t {
    pub control_id: u16,
    pub len:        u16,
    pub status:     u8,
    pub iscore:     u8,
    pub pad0:       [u8; 2],
}

impl Copy for xcb_input_device_core_state_t {}
impl Clone for xcb_input_device_core_state_t {
    fn clone(&self) -> xcb_input_device_core_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_core_state_iterator_t {
    pub data:  *mut xcb_input_device_core_state_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_enable_state_t {
    pub control_id: u16,
    pub len:        u16,
    pub enable:     u8,
    pub pad0:       [u8; 3],
}

impl Copy for xcb_input_device_enable_state_t {}
impl Clone for xcb_input_device_enable_state_t {
    fn clone(&self) -> xcb_input_device_enable_state_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_enable_state_iterator_t {
    pub data:  *mut xcb_input_device_enable_state_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_state_t {
    pub control_id:         u16,
    pub len:                u16,
}

#[repr(C)]
pub struct xcb_input_device_state_iterator_t<'a> {
    pub data:  *mut xcb_input_device_state_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_device_state_t>,
}

pub const XCB_INPUT_GET_DEVICE_CONTROL: u8 = 34;

#[repr(C)]
pub struct xcb_input_get_device_control_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub control_id:   u16,
    pub device_id:    u8,
    pub pad0:         u8,
}

impl Copy for xcb_input_get_device_control_request_t {}
impl Clone for xcb_input_get_device_control_request_t {
    fn clone(&self) -> xcb_input_get_device_control_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_device_control_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_device_control_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

#[repr(C)]
pub struct xcb_input_device_resolution_ctl_t {
    pub control_id:        u16,
    pub len:               u16,
    pub first_valuator:    u8,
    pub num_valuators:     u8,
    pub pad0:              [u8; 2],
}

#[repr(C)]
pub struct xcb_input_device_resolution_ctl_iterator_t<'a> {
    pub data:  *mut xcb_input_device_resolution_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_device_resolution_ctl_t>,
}

#[repr(C)]
pub struct xcb_input_device_abs_calib_ctl_t {
    pub control_id:       u16,
    pub len:              u16,
    pub min_x:            i32,
    pub max_x:            i32,
    pub min_y:            i32,
    pub max_y:            i32,
    pub flip_x:           u32,
    pub flip_y:           u32,
    pub rotation:         u32,
    pub button_threshold: u32,
}

impl Copy for xcb_input_device_abs_calib_ctl_t {}
impl Clone for xcb_input_device_abs_calib_ctl_t {
    fn clone(&self) -> xcb_input_device_abs_calib_ctl_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_abs_calib_ctl_iterator_t {
    pub data:  *mut xcb_input_device_abs_calib_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_abs_area_ctrl_t {
    pub control_id: u16,
    pub len:        u16,
    pub offset_x:   u32,
    pub offset_y:   u32,
    pub width:      i32,
    pub height:     i32,
    pub screen:     i32,
    pub following:  u32,
}

impl Copy for xcb_input_device_abs_area_ctrl_t {}
impl Clone for xcb_input_device_abs_area_ctrl_t {
    fn clone(&self) -> xcb_input_device_abs_area_ctrl_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_abs_area_ctrl_iterator_t {
    pub data:  *mut xcb_input_device_abs_area_ctrl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_core_ctrl_t {
    pub control_id: u16,
    pub len:        u16,
    pub status:     u8,
    pub pad0:       [u8; 3],
}

impl Copy for xcb_input_device_core_ctrl_t {}
impl Clone for xcb_input_device_core_ctrl_t {
    fn clone(&self) -> xcb_input_device_core_ctrl_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_core_ctrl_iterator_t {
    pub data:  *mut xcb_input_device_core_ctrl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_enable_ctrl_t {
    pub control_id: u16,
    pub len:        u16,
    pub enable:     u8,
    pub pad0:       [u8; 3],
}

impl Copy for xcb_input_device_enable_ctrl_t {}
impl Clone for xcb_input_device_enable_ctrl_t {
    fn clone(&self) -> xcb_input_device_enable_ctrl_t { *self }
}

#[repr(C)]
pub struct xcb_input_device_enable_ctrl_iterator_t {
    pub data:  *mut xcb_input_device_enable_ctrl_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_ctl_t {
    pub control_id:         u16,
    pub len:                u16,
}

#[repr(C)]
pub struct xcb_input_device_ctl_iterator_t<'a> {
    pub data:  *mut xcb_input_device_ctl_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_device_ctl_t>,
}

pub const XCB_INPUT_CHANGE_DEVICE_CONTROL: u8 = 35;

#[repr(C)]
pub struct xcb_input_change_device_control_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub control_id:   u16,
    pub device_id:    u8,
    pub pad0:         u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_change_device_control_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_change_device_control_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_change_device_control_reply_t {}
impl Clone for xcb_input_change_device_control_reply_t {
    fn clone(&self) -> xcb_input_change_device_control_reply_t { *self }
}

pub const XCB_INPUT_LIST_DEVICE_PROPERTIES: u8 = 36;

#[repr(C)]
pub struct xcb_input_list_device_properties_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_list_device_properties_request_t {}
impl Clone for xcb_input_list_device_properties_request_t {
    fn clone(&self) -> xcb_input_list_device_properties_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_list_device_properties_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_list_device_properties_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_atoms:     u16,
    pub pad1:          [u8; 22],
}

pub type xcb_input_property_format_t = u32;
pub const XCB_INPUT_PROPERTY_FORMAT_8_BITS : xcb_input_property_format_t = 0x08;
pub const XCB_INPUT_PROPERTY_FORMAT_16_BITS: xcb_input_property_format_t = 0x10;
pub const XCB_INPUT_PROPERTY_FORMAT_32_BITS: xcb_input_property_format_t = 0x20;

#[repr(C)]
pub struct xcb_input_change_device_property_items_t {
    pub data8:  *mut u8,
    pub data16: *mut u16,
    pub data32: *mut u32,
}

pub const XCB_INPUT_CHANGE_DEVICE_PROPERTY: u8 = 37;

#[repr(C)]
pub struct xcb_input_change_device_property_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub property:     xcb_atom_t,
    pub type_:        xcb_atom_t,
    pub device_id:    u8,
    pub format:       u8,
    pub mode:         u8,
    pub pad0:         u8,
    pub num_items:    u32,
}

pub const XCB_INPUT_DELETE_DEVICE_PROPERTY: u8 = 38;

#[repr(C)]
pub struct xcb_input_delete_device_property_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub property:     xcb_atom_t,
    pub device_id:    u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_input_delete_device_property_request_t {}
impl Clone for xcb_input_delete_device_property_request_t {
    fn clone(&self) -> xcb_input_delete_device_property_request_t { *self }
}

pub const XCB_INPUT_GET_DEVICE_PROPERTY: u8 = 39;

#[repr(C)]
pub struct xcb_input_get_device_property_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub property:     xcb_atom_t,
    pub type_:        xcb_atom_t,
    pub offset:       u32,
    pub len:          u32,
    pub device_id:    u8,
    pub delete:       u8,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_get_device_property_request_t {}
impl Clone for xcb_input_get_device_property_request_t {
    fn clone(&self) -> xcb_input_get_device_property_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_get_device_property_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_get_device_property_items_t {
    pub data8:  *mut u8,
    pub data16: *mut u16,
    pub data32: *mut u32,
}

#[repr(C)]
pub struct xcb_input_get_device_property_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub type_:         xcb_atom_t,
    pub bytes_after:   u32,
    pub num_items:     u32,
    pub format:        u8,
    pub device_id:     u8,
    pub pad1:          [u8; 10],
}

pub type xcb_input_device_t = u32;
pub const XCB_INPUT_DEVICE_ALL       : xcb_input_device_t = 0x00;
pub const XCB_INPUT_DEVICE_ALL_MASTER: xcb_input_device_t = 0x01;

#[repr(C)]
pub struct xcb_input_group_info_t {
    pub base:      u8,
    pub latched:   u8,
    pub locked:    u8,
    pub effective: u8,
}

impl Copy for xcb_input_group_info_t {}
impl Clone for xcb_input_group_info_t {
    fn clone(&self) -> xcb_input_group_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_group_info_iterator_t {
    pub data:  *mut xcb_input_group_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_modifier_info_t {
    pub base:      u32,
    pub latched:   u32,
    pub locked:    u32,
    pub effective: u32,
}

impl Copy for xcb_input_modifier_info_t {}
impl Clone for xcb_input_modifier_info_t {
    fn clone(&self) -> xcb_input_modifier_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_modifier_info_iterator_t {
    pub data:  *mut xcb_input_modifier_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_INPUT_XI_QUERY_POINTER: u8 = 40;

#[repr(C)]
pub struct xcb_input_xi_query_pointer_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_query_pointer_request_t {}
impl Clone for xcb_input_xi_query_pointer_request_t {
    fn clone(&self) -> xcb_input_xi_query_pointer_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_query_pointer_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_query_pointer_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub root:          xcb_window_t,
    pub child:         xcb_window_t,
    pub root_x:        xcb_input_fp1616_t,
    pub root_y:        xcb_input_fp1616_t,
    pub win_x:         xcb_input_fp1616_t,
    pub win_y:         xcb_input_fp1616_t,
    pub same_screen:   u8,
    pub pad1:          u8,
    pub buttons_len:   u16,
    pub mods:          xcb_input_modifier_info_t,
    pub group:         xcb_input_group_info_t,
}

pub const XCB_INPUT_XI_WARP_POINTER: u8 = 41;

#[repr(C)]
pub struct xcb_input_xi_warp_pointer_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub src_win:      xcb_window_t,
    pub dst_win:      xcb_window_t,
    pub src_x:        xcb_input_fp1616_t,
    pub src_y:        xcb_input_fp1616_t,
    pub src_width:    u16,
    pub src_height:   u16,
    pub dst_x:        xcb_input_fp1616_t,
    pub dst_y:        xcb_input_fp1616_t,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_warp_pointer_request_t {}
impl Clone for xcb_input_xi_warp_pointer_request_t {
    fn clone(&self) -> xcb_input_xi_warp_pointer_request_t { *self }
}

pub const XCB_INPUT_XI_CHANGE_CURSOR: u8 = 42;

#[repr(C)]
pub struct xcb_input_xi_change_cursor_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub cursor:       xcb_cursor_t,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_change_cursor_request_t {}
impl Clone for xcb_input_xi_change_cursor_request_t {
    fn clone(&self) -> xcb_input_xi_change_cursor_request_t { *self }
}

pub type xcb_input_hierarchy_change_type_t = u32;
pub const XCB_INPUT_HIERARCHY_CHANGE_TYPE_ADD_MASTER   : xcb_input_hierarchy_change_type_t = 0x01;
pub const XCB_INPUT_HIERARCHY_CHANGE_TYPE_REMOVE_MASTER: xcb_input_hierarchy_change_type_t = 0x02;
pub const XCB_INPUT_HIERARCHY_CHANGE_TYPE_ATTACH_SLAVE : xcb_input_hierarchy_change_type_t = 0x03;
pub const XCB_INPUT_HIERARCHY_CHANGE_TYPE_DETACH_SLAVE : xcb_input_hierarchy_change_type_t = 0x04;

pub type xcb_input_change_mode_t = u32;
pub const XCB_INPUT_CHANGE_MODE_ATTACH: xcb_input_change_mode_t = 0x01;
pub const XCB_INPUT_CHANGE_MODE_FLOAT : xcb_input_change_mode_t = 0x02;

#[repr(C)]
pub struct xcb_input_add_master_t {
    pub type_:     u16,
    pub len:       u16,
    pub name_len:  u16,
    pub send_core: u8,
    pub enable:    u8,
}

#[repr(C)]
pub struct xcb_input_add_master_iterator_t<'a> {
    pub data:  *mut xcb_input_add_master_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_add_master_t>,
}

#[repr(C)]
pub struct xcb_input_remove_master_t {
    pub type_:           u16,
    pub len:             u16,
    pub deviceid:        xcb_input_device_id_t,
    pub return_mode:     u8,
    pub pad0:            u8,
    pub return_pointer:  xcb_input_device_id_t,
    pub return_keyboard: xcb_input_device_id_t,
}

impl Copy for xcb_input_remove_master_t {}
impl Clone for xcb_input_remove_master_t {
    fn clone(&self) -> xcb_input_remove_master_t { *self }
}

#[repr(C)]
pub struct xcb_input_remove_master_iterator_t {
    pub data:  *mut xcb_input_remove_master_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_attach_slave_t {
    pub type_:    u16,
    pub len:      u16,
    pub deviceid: xcb_input_device_id_t,
    pub master:   xcb_input_device_id_t,
}

impl Copy for xcb_input_attach_slave_t {}
impl Clone for xcb_input_attach_slave_t {
    fn clone(&self) -> xcb_input_attach_slave_t { *self }
}

#[repr(C)]
pub struct xcb_input_attach_slave_iterator_t {
    pub data:  *mut xcb_input_attach_slave_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_detach_slave_t {
    pub type_:    u16,
    pub len:      u16,
    pub deviceid: xcb_input_device_id_t,
    pub pad0:     [u8; 2],
}

impl Copy for xcb_input_detach_slave_t {}
impl Clone for xcb_input_detach_slave_t {
    fn clone(&self) -> xcb_input_detach_slave_t { *self }
}

#[repr(C)]
pub struct xcb_input_detach_slave_iterator_t {
    pub data:  *mut xcb_input_detach_slave_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_hierarchy_change_t {
    pub type_:              u16,
    pub len:                u16,
}

#[repr(C)]
pub struct xcb_input_hierarchy_change_iterator_t<'a> {
    pub data:  *mut xcb_input_hierarchy_change_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_hierarchy_change_t>,
}

pub const XCB_INPUT_XI_CHANGE_HIERARCHY: u8 = 43;

#[repr(C)]
pub struct xcb_input_xi_change_hierarchy_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub num_changes:  u8,
    pub pad0:         [u8; 3],
}

pub const XCB_INPUT_XI_SET_CLIENT_POINTER: u8 = 44;

#[repr(C)]
pub struct xcb_input_xi_set_client_pointer_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_set_client_pointer_request_t {}
impl Clone for xcb_input_xi_set_client_pointer_request_t {
    fn clone(&self) -> xcb_input_xi_set_client_pointer_request_t { *self }
}

pub const XCB_INPUT_XI_GET_CLIENT_POINTER: u8 = 45;

#[repr(C)]
pub struct xcb_input_xi_get_client_pointer_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_input_xi_get_client_pointer_request_t {}
impl Clone for xcb_input_xi_get_client_pointer_request_t {
    fn clone(&self) -> xcb_input_xi_get_client_pointer_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_get_client_pointer_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_get_client_pointer_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub set:           u8,
    pub pad1:          u8,
    pub deviceid:      xcb_input_device_id_t,
    pub pad2:          [u8; 20],
}

impl Copy for xcb_input_xi_get_client_pointer_reply_t {}
impl Clone for xcb_input_xi_get_client_pointer_reply_t {
    fn clone(&self) -> xcb_input_xi_get_client_pointer_reply_t { *self }
}

pub type xcb_input_xi_event_mask_t = u32;
pub const XCB_INPUT_XI_EVENT_MASK_DEVICE_CHANGED    : xcb_input_xi_event_mask_t =      0x02;
pub const XCB_INPUT_XI_EVENT_MASK_KEY_PRESS         : xcb_input_xi_event_mask_t =      0x04;
pub const XCB_INPUT_XI_EVENT_MASK_KEY_RELEASE       : xcb_input_xi_event_mask_t =      0x08;
pub const XCB_INPUT_XI_EVENT_MASK_BUTTON_PRESS      : xcb_input_xi_event_mask_t =      0x10;
pub const XCB_INPUT_XI_EVENT_MASK_BUTTON_RELEASE    : xcb_input_xi_event_mask_t =      0x20;
pub const XCB_INPUT_XI_EVENT_MASK_MOTION            : xcb_input_xi_event_mask_t =      0x40;
pub const XCB_INPUT_XI_EVENT_MASK_ENTER             : xcb_input_xi_event_mask_t =      0x80;
pub const XCB_INPUT_XI_EVENT_MASK_LEAVE             : xcb_input_xi_event_mask_t =     0x100;
pub const XCB_INPUT_XI_EVENT_MASK_FOCUS_IN          : xcb_input_xi_event_mask_t =     0x200;
pub const XCB_INPUT_XI_EVENT_MASK_FOCUS_OUT         : xcb_input_xi_event_mask_t =     0x400;
pub const XCB_INPUT_XI_EVENT_MASK_HIERARCHY         : xcb_input_xi_event_mask_t =     0x800;
pub const XCB_INPUT_XI_EVENT_MASK_PROPERTY          : xcb_input_xi_event_mask_t =    0x1000;
pub const XCB_INPUT_XI_EVENT_MASK_RAW_KEY_PRESS     : xcb_input_xi_event_mask_t =    0x2000;
pub const XCB_INPUT_XI_EVENT_MASK_RAW_KEY_RELEASE   : xcb_input_xi_event_mask_t =    0x4000;
pub const XCB_INPUT_XI_EVENT_MASK_RAW_BUTTON_PRESS  : xcb_input_xi_event_mask_t =    0x8000;
pub const XCB_INPUT_XI_EVENT_MASK_RAW_BUTTON_RELEASE: xcb_input_xi_event_mask_t =   0x10000;
pub const XCB_INPUT_XI_EVENT_MASK_RAW_MOTION        : xcb_input_xi_event_mask_t =   0x20000;
pub const XCB_INPUT_XI_EVENT_MASK_TOUCH_BEGIN       : xcb_input_xi_event_mask_t =   0x40000;
pub const XCB_INPUT_XI_EVENT_MASK_TOUCH_UPDATE      : xcb_input_xi_event_mask_t =   0x80000;
pub const XCB_INPUT_XI_EVENT_MASK_TOUCH_END         : xcb_input_xi_event_mask_t =  0x100000;
pub const XCB_INPUT_XI_EVENT_MASK_TOUCH_OWNERSHIP   : xcb_input_xi_event_mask_t =  0x200000;
pub const XCB_INPUT_XI_EVENT_MASK_RAW_TOUCH_BEGIN   : xcb_input_xi_event_mask_t =  0x400000;
pub const XCB_INPUT_XI_EVENT_MASK_RAW_TOUCH_UPDATE  : xcb_input_xi_event_mask_t =  0x800000;
pub const XCB_INPUT_XI_EVENT_MASK_RAW_TOUCH_END     : xcb_input_xi_event_mask_t = 0x1000000;
pub const XCB_INPUT_XI_EVENT_MASK_BARRIER_HIT       : xcb_input_xi_event_mask_t = 0x2000000;
pub const XCB_INPUT_XI_EVENT_MASK_BARRIER_LEAVE     : xcb_input_xi_event_mask_t = 0x4000000;

#[repr(C)]
pub struct xcb_input_event_mask_t {
    pub deviceid: xcb_input_device_id_t,
    pub mask_len: u16,
}

#[repr(C)]
pub struct xcb_input_event_mask_iterator_t<'a> {
    pub data:  *mut xcb_input_event_mask_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_event_mask_t>,
}

pub const XCB_INPUT_XI_SELECT_EVENTS: u8 = 46;

#[repr(C)]
pub struct xcb_input_xi_select_events_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub num_mask:     u16,
    pub pad0:         [u8; 2],
}

pub const XCB_INPUT_XI_QUERY_VERSION: u8 = 47;

#[repr(C)]
pub struct xcb_input_xi_query_version_request_t {
    pub major_opcode:  u8,
    pub minor_opcode:  u8,
    pub length:        u16,
    pub major_version: u16,
    pub minor_version: u16,
}

impl Copy for xcb_input_xi_query_version_request_t {}
impl Clone for xcb_input_xi_query_version_request_t {
    fn clone(&self) -> xcb_input_xi_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub pad1:          [u8; 20],
}

impl Copy for xcb_input_xi_query_version_reply_t {}
impl Clone for xcb_input_xi_query_version_reply_t {
    fn clone(&self) -> xcb_input_xi_query_version_reply_t { *self }
}

pub type xcb_input_device_class_type_t = u32;
pub const XCB_INPUT_DEVICE_CLASS_TYPE_KEY     : xcb_input_device_class_type_t = 0x00;
pub const XCB_INPUT_DEVICE_CLASS_TYPE_BUTTON  : xcb_input_device_class_type_t = 0x01;
pub const XCB_INPUT_DEVICE_CLASS_TYPE_VALUATOR: xcb_input_device_class_type_t = 0x02;
pub const XCB_INPUT_DEVICE_CLASS_TYPE_SCROLL  : xcb_input_device_class_type_t = 0x03;
pub const XCB_INPUT_DEVICE_CLASS_TYPE_TOUCH   : xcb_input_device_class_type_t = 0x08;

pub type xcb_input_device_type_t = u32;
pub const XCB_INPUT_DEVICE_TYPE_MASTER_POINTER : xcb_input_device_type_t = 0x01;
pub const XCB_INPUT_DEVICE_TYPE_MASTER_KEYBOARD: xcb_input_device_type_t = 0x02;
pub const XCB_INPUT_DEVICE_TYPE_SLAVE_POINTER  : xcb_input_device_type_t = 0x03;
pub const XCB_INPUT_DEVICE_TYPE_SLAVE_KEYBOARD : xcb_input_device_type_t = 0x04;
pub const XCB_INPUT_DEVICE_TYPE_FLOATING_SLAVE : xcb_input_device_type_t = 0x05;

pub type xcb_input_scroll_flags_t = u32;
pub const XCB_INPUT_SCROLL_FLAGS_NO_EMULATION: xcb_input_scroll_flags_t = 0x01;
pub const XCB_INPUT_SCROLL_FLAGS_PREFERRED   : xcb_input_scroll_flags_t = 0x02;

pub type xcb_input_scroll_type_t = u32;
pub const XCB_INPUT_SCROLL_TYPE_VERTICAL  : xcb_input_scroll_type_t = 0x01;
pub const XCB_INPUT_SCROLL_TYPE_HORIZONTAL: xcb_input_scroll_type_t = 0x02;

pub type xcb_input_touch_mode_t = u32;
pub const XCB_INPUT_TOUCH_MODE_DIRECT   : xcb_input_touch_mode_t = 0x01;
pub const XCB_INPUT_TOUCH_MODE_DEPENDENT: xcb_input_touch_mode_t = 0x02;

#[repr(C)]
pub struct xcb_input_button_class_t {
    pub type_:       u16,
    pub len:         u16,
    pub sourceid:    xcb_input_device_id_t,
    pub num_buttons: u16,
}

#[repr(C)]
pub struct xcb_input_button_class_iterator_t<'a> {
    pub data:  *mut xcb_input_button_class_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_button_class_t>,
}

#[repr(C)]
pub struct xcb_input_key_class_t {
    pub type_:    u16,
    pub len:      u16,
    pub sourceid: xcb_input_device_id_t,
    pub num_keys: u16,
}

#[repr(C)]
pub struct xcb_input_key_class_iterator_t<'a> {
    pub data:  *mut xcb_input_key_class_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_key_class_t>,
}

#[repr(C)]
pub struct xcb_input_scroll_class_t {
    pub type_:       u16,
    pub len:         u16,
    pub sourceid:    xcb_input_device_id_t,
    pub number:      u16,
    pub scroll_type: u16,
    pub pad0:        [u8; 2],
    pub flags:       u32,
    pub increment:   xcb_input_fp3232_t,
}

impl Copy for xcb_input_scroll_class_t {}
impl Clone for xcb_input_scroll_class_t {
    fn clone(&self) -> xcb_input_scroll_class_t { *self }
}

#[repr(C)]
pub struct xcb_input_scroll_class_iterator_t {
    pub data:  *mut xcb_input_scroll_class_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_touch_class_t {
    pub type_:       u16,
    pub len:         u16,
    pub sourceid:    xcb_input_device_id_t,
    pub mode:        u8,
    pub num_touches: u8,
}

impl Copy for xcb_input_touch_class_t {}
impl Clone for xcb_input_touch_class_t {
    fn clone(&self) -> xcb_input_touch_class_t { *self }
}

#[repr(C)]
pub struct xcb_input_touch_class_iterator_t {
    pub data:  *mut xcb_input_touch_class_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_valuator_class_t {
    pub type_:      u16,
    pub len:        u16,
    pub sourceid:   xcb_input_device_id_t,
    pub number:     u16,
    pub label:      xcb_atom_t,
    pub min:        xcb_input_fp3232_t,
    pub max:        xcb_input_fp3232_t,
    pub value:      xcb_input_fp3232_t,
    pub resolution: u32,
    pub mode:       u8,
    pub pad0:       [u8; 3],
}

impl Copy for xcb_input_valuator_class_t {}
impl Clone for xcb_input_valuator_class_t {
    fn clone(&self) -> xcb_input_valuator_class_t { *self }
}

#[repr(C)]
pub struct xcb_input_valuator_class_iterator_t {
    pub data:  *mut xcb_input_valuator_class_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_input_device_class_t {
    pub type_:              u16,
    pub len:                u16,
    pub sourceid:           xcb_input_device_id_t,
    pub pad0:               [u8; 2],
}

#[repr(C)]
pub struct xcb_input_device_class_iterator_t<'a> {
    pub data:  *mut xcb_input_device_class_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_device_class_t>,
}

#[repr(C)]
pub struct xcb_input_xi_device_info_t {
    pub deviceid:    xcb_input_device_id_t,
    pub type_:       u16,
    pub attachment:  xcb_input_device_id_t,
    pub num_classes: u16,
    pub name_len:    u16,
    pub enabled:     u8,
    pub pad0:        u8,
}

#[repr(C)]
pub struct xcb_input_xi_device_info_iterator_t<'a> {
    pub data:  *mut xcb_input_xi_device_info_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_input_xi_device_info_t>,
}

pub const XCB_INPUT_XI_QUERY_DEVICE: u8 = 48;

#[repr(C)]
pub struct xcb_input_xi_query_device_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_query_device_request_t {}
impl Clone for xcb_input_xi_query_device_request_t {
    fn clone(&self) -> xcb_input_xi_query_device_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_query_device_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_query_device_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_infos:     u16,
    pub pad1:          [u8; 22],
}

pub const XCB_INPUT_XI_SET_FOCUS: u8 = 49;

#[repr(C)]
pub struct xcb_input_xi_set_focus_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub time:         xcb_timestamp_t,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_set_focus_request_t {}
impl Clone for xcb_input_xi_set_focus_request_t {
    fn clone(&self) -> xcb_input_xi_set_focus_request_t { *self }
}

pub const XCB_INPUT_XI_GET_FOCUS: u8 = 50;

#[repr(C)]
pub struct xcb_input_xi_get_focus_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_get_focus_request_t {}
impl Clone for xcb_input_xi_get_focus_request_t {
    fn clone(&self) -> xcb_input_xi_get_focus_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_get_focus_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_get_focus_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub focus:         xcb_window_t,
    pub pad1:          [u8; 20],
}

impl Copy for xcb_input_xi_get_focus_reply_t {}
impl Clone for xcb_input_xi_get_focus_reply_t {
    fn clone(&self) -> xcb_input_xi_get_focus_reply_t { *self }
}

pub type xcb_input_grab_owner_t = u32;
pub const XCB_INPUT_GRAB_OWNER_NO_OWNER: xcb_input_grab_owner_t = 0x00;
pub const XCB_INPUT_GRAB_OWNER_OWNER   : xcb_input_grab_owner_t = 0x01;

pub const XCB_INPUT_XI_GRAB_DEVICE: u8 = 51;

#[repr(C)]
pub struct xcb_input_xi_grab_device_request_t {
    pub major_opcode:       u8,
    pub minor_opcode:       u8,
    pub length:             u16,
    pub window:             xcb_window_t,
    pub time:               xcb_timestamp_t,
    pub cursor:             xcb_cursor_t,
    pub deviceid:           xcb_input_device_id_t,
    pub mode:               u8,
    pub paired_device_mode: u8,
    pub owner_events:       u8,
    pub pad0:               u8,
    pub mask_len:           u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_grab_device_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_grab_device_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status:        u8,
    pub pad1:          [u8; 23],
}

impl Copy for xcb_input_xi_grab_device_reply_t {}
impl Clone for xcb_input_xi_grab_device_reply_t {
    fn clone(&self) -> xcb_input_xi_grab_device_reply_t { *self }
}

pub const XCB_INPUT_XI_UNGRAB_DEVICE: u8 = 52;

#[repr(C)]
pub struct xcb_input_xi_ungrab_device_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub time:         xcb_timestamp_t,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_ungrab_device_request_t {}
impl Clone for xcb_input_xi_ungrab_device_request_t {
    fn clone(&self) -> xcb_input_xi_ungrab_device_request_t { *self }
}

pub type xcb_input_event_mode_t = u32;
pub const XCB_INPUT_EVENT_MODE_ASYNC_DEVICE       : xcb_input_event_mode_t = 0x00;
pub const XCB_INPUT_EVENT_MODE_SYNC_DEVICE        : xcb_input_event_mode_t = 0x01;
pub const XCB_INPUT_EVENT_MODE_REPLAY_DEVICE      : xcb_input_event_mode_t = 0x02;
pub const XCB_INPUT_EVENT_MODE_ASYNC_PAIRED_DEVICE: xcb_input_event_mode_t = 0x03;
pub const XCB_INPUT_EVENT_MODE_ASYNC_PAIR         : xcb_input_event_mode_t = 0x04;
pub const XCB_INPUT_EVENT_MODE_SYNC_PAIR          : xcb_input_event_mode_t = 0x05;
pub const XCB_INPUT_EVENT_MODE_ACCEPT_TOUCH       : xcb_input_event_mode_t = 0x06;
pub const XCB_INPUT_EVENT_MODE_REJECT_TOUCH       : xcb_input_event_mode_t = 0x07;

pub const XCB_INPUT_XI_ALLOW_EVENTS: u8 = 53;

#[repr(C)]
pub struct xcb_input_xi_allow_events_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub time:         xcb_timestamp_t,
    pub deviceid:     xcb_input_device_id_t,
    pub event_mode:   u8,
    pub pad0:         u8,
    pub touchid:      u32,
    pub grab_window:  xcb_window_t,
}

impl Copy for xcb_input_xi_allow_events_request_t {}
impl Clone for xcb_input_xi_allow_events_request_t {
    fn clone(&self) -> xcb_input_xi_allow_events_request_t { *self }
}

pub type xcb_input_grab_mode_22_t = u32;
pub const XCB_INPUT_GRAB_MODE_22_SYNC : xcb_input_grab_mode_22_t = 0x00;
pub const XCB_INPUT_GRAB_MODE_22_ASYNC: xcb_input_grab_mode_22_t = 0x01;
pub const XCB_INPUT_GRAB_MODE_22_TOUCH: xcb_input_grab_mode_22_t = 0x02;

pub type xcb_input_grab_type_t = u32;
pub const XCB_INPUT_GRAB_TYPE_BUTTON     : xcb_input_grab_type_t = 0x00;
pub const XCB_INPUT_GRAB_TYPE_KEYCODE    : xcb_input_grab_type_t = 0x01;
pub const XCB_INPUT_GRAB_TYPE_ENTER      : xcb_input_grab_type_t = 0x02;
pub const XCB_INPUT_GRAB_TYPE_FOCUS_IN   : xcb_input_grab_type_t = 0x03;
pub const XCB_INPUT_GRAB_TYPE_TOUCH_BEGIN: xcb_input_grab_type_t = 0x04;

pub type xcb_input_modifier_mask_t = u32;
pub const XCB_INPUT_MODIFIER_MASK_ANY: xcb_input_modifier_mask_t = 0x80000000;

#[repr(C)]
pub struct xcb_input_grab_modifier_info_t {
    pub modifiers: u32,
    pub status:    u8,
    pub pad0:      [u8; 3],
}

impl Copy for xcb_input_grab_modifier_info_t {}
impl Clone for xcb_input_grab_modifier_info_t {
    fn clone(&self) -> xcb_input_grab_modifier_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_grab_modifier_info_iterator_t {
    pub data:  *mut xcb_input_grab_modifier_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_INPUT_XI_PASSIVE_GRAB_DEVICE: u8 = 54;

#[repr(C)]
pub struct xcb_input_xi_passive_grab_device_request_t {
    pub major_opcode:       u8,
    pub minor_opcode:       u8,
    pub length:             u16,
    pub time:               xcb_timestamp_t,
    pub grab_window:        xcb_window_t,
    pub cursor:             xcb_cursor_t,
    pub detail:             u32,
    pub deviceid:           xcb_input_device_id_t,
    pub num_modifiers:      u16,
    pub mask_len:           u16,
    pub grab_type:          u8,
    pub grab_mode:          u8,
    pub paired_device_mode: u8,
    pub owner_events:       u8,
    pub pad0:               [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_passive_grab_device_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_passive_grab_device_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_modifiers: u16,
    pub pad1:          [u8; 22],
}

pub const XCB_INPUT_XI_PASSIVE_UNGRAB_DEVICE: u8 = 55;

#[repr(C)]
pub struct xcb_input_xi_passive_ungrab_device_request_t {
    pub major_opcode:  u8,
    pub minor_opcode:  u8,
    pub length:        u16,
    pub grab_window:   xcb_window_t,
    pub detail:        u32,
    pub deviceid:      xcb_input_device_id_t,
    pub num_modifiers: u16,
    pub grab_type:     u8,
    pub pad0:          [u8; 3],
}

pub const XCB_INPUT_XI_LIST_PROPERTIES: u8 = 56;

#[repr(C)]
pub struct xcb_input_xi_list_properties_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_input_xi_list_properties_request_t {}
impl Clone for xcb_input_xi_list_properties_request_t {
    fn clone(&self) -> xcb_input_xi_list_properties_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_list_properties_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_list_properties_reply_t {
    pub response_type:  u8,
    pub pad0:           u8,
    pub sequence:       u16,
    pub length:         u32,
    pub num_properties: u16,
    pub pad1:           [u8; 22],
}

#[repr(C)]
pub struct xcb_input_xi_change_property_items_t {
    pub data8:  *mut u8,
    pub data16: *mut u16,
    pub data32: *mut u32,
}

pub const XCB_INPUT_XI_CHANGE_PROPERTY: u8 = 57;

#[repr(C)]
pub struct xcb_input_xi_change_property_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub deviceid:     xcb_input_device_id_t,
    pub mode:         u8,
    pub format:       u8,
    pub property:     xcb_atom_t,
    pub type_:        xcb_atom_t,
    pub num_items:    u32,
}

pub const XCB_INPUT_XI_DELETE_PROPERTY: u8 = 58;

#[repr(C)]
pub struct xcb_input_xi_delete_property_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub deviceid:     xcb_input_device_id_t,
    pub pad0:         [u8; 2],
    pub property:     xcb_atom_t,
}

impl Copy for xcb_input_xi_delete_property_request_t {}
impl Clone for xcb_input_xi_delete_property_request_t {
    fn clone(&self) -> xcb_input_xi_delete_property_request_t { *self }
}

pub const XCB_INPUT_XI_GET_PROPERTY: u8 = 59;

#[repr(C)]
pub struct xcb_input_xi_get_property_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub deviceid:     xcb_input_device_id_t,
    pub delete:       u8,
    pub pad0:         u8,
    pub property:     xcb_atom_t,
    pub type_:        xcb_atom_t,
    pub offset:       u32,
    pub len:          u32,
}

impl Copy for xcb_input_xi_get_property_request_t {}
impl Clone for xcb_input_xi_get_property_request_t {
    fn clone(&self) -> xcb_input_xi_get_property_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_get_property_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_get_property_items_t {
    pub data8:  *mut u8,
    pub data16: *mut u16,
    pub data32: *mut u32,
}

#[repr(C)]
pub struct xcb_input_xi_get_property_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub type_:         xcb_atom_t,
    pub bytes_after:   u32,
    pub num_items:     u32,
    pub format:        u8,
    pub pad1:          [u8; 11],
}

pub const XCB_INPUT_XI_GET_SELECTED_EVENTS: u8 = 60;

#[repr(C)]
pub struct xcb_input_xi_get_selected_events_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_input_xi_get_selected_events_request_t {}
impl Clone for xcb_input_xi_get_selected_events_request_t {
    fn clone(&self) -> xcb_input_xi_get_selected_events_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_input_xi_get_selected_events_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_input_xi_get_selected_events_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub num_masks:     u16,
    pub pad1:          [u8; 22],
}

#[repr(C)]
pub struct xcb_input_barrier_release_pointer_info_t {
    pub deviceid: xcb_input_device_id_t,
    pub pad0:     [u8; 2],
    pub barrier:  xcb_xfixes_barrier_t,
    pub eventid:  u32,
}

impl Copy for xcb_input_barrier_release_pointer_info_t {}
impl Clone for xcb_input_barrier_release_pointer_info_t {
    fn clone(&self) -> xcb_input_barrier_release_pointer_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_barrier_release_pointer_info_iterator_t {
    pub data:  *mut xcb_input_barrier_release_pointer_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_INPUT_XI_BARRIER_RELEASE_POINTER: u8 = 61;

#[repr(C)]
pub struct xcb_input_xi_barrier_release_pointer_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub num_barriers: u32,
}

pub const XCB_INPUT_DEVICE_VALUATOR: u8 = 0;

#[repr(C)]
pub struct xcb_input_device_valuator_event_t {
    pub response_type:  u8,
    pub device_id:      u8,
    pub sequence:       u16,
    pub device_state:   u16,
    pub num_valuators:  u8,
    pub first_valuator: u8,
    pub valuators:      [i32; 6],
}

impl Copy for xcb_input_device_valuator_event_t {}
impl Clone for xcb_input_device_valuator_event_t {
    fn clone(&self) -> xcb_input_device_valuator_event_t { *self }
}

pub const XCB_INPUT_DEVICE_KEY_PRESS: u8 = 1;

#[repr(C)]
pub struct xcb_input_device_key_press_event_t {
    pub response_type: u8,
    pub detail:        u8,
    pub sequence:      u16,
    pub time:          xcb_timestamp_t,
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    pub root_x:        i16,
    pub root_y:        i16,
    pub event_x:       i16,
    pub event_y:       i16,
    pub state:         u16,
    pub same_screen:   u8,
    pub device_id:     u8,
}

impl Copy for xcb_input_device_key_press_event_t {}
impl Clone for xcb_input_device_key_press_event_t {
    fn clone(&self) -> xcb_input_device_key_press_event_t { *self }
}

pub const XCB_INPUT_DEVICE_KEY_RELEASE: u8 = 2;

pub type xcb_input_device_key_release_event_t = xcb_input_device_key_press_event_t;

pub const XCB_INPUT_DEVICE_BUTTON_PRESS: u8 = 3;

pub type xcb_input_device_button_press_event_t = xcb_input_device_key_press_event_t;

pub const XCB_INPUT_DEVICE_BUTTON_RELEASE: u8 = 4;

pub type xcb_input_device_button_release_event_t = xcb_input_device_key_press_event_t;

pub const XCB_INPUT_DEVICE_MOTION_NOTIFY: u8 = 5;

pub type xcb_input_device_motion_notify_event_t = xcb_input_device_key_press_event_t;

pub const XCB_INPUT_DEVICE_FOCUS_IN: u8 = 6;

#[repr(C)]
pub struct xcb_input_device_focus_in_event_t {
    pub response_type: u8,
    pub detail:        u8,
    pub sequence:      u16,
    pub time:          xcb_timestamp_t,
    pub window:        xcb_window_t,
    pub mode:          u8,
    pub device_id:     u8,
    pub pad0:          [u8; 18],
}

impl Copy for xcb_input_device_focus_in_event_t {}
impl Clone for xcb_input_device_focus_in_event_t {
    fn clone(&self) -> xcb_input_device_focus_in_event_t { *self }
}

pub const XCB_INPUT_DEVICE_FOCUS_OUT: u8 = 7;

pub type xcb_input_device_focus_out_event_t = xcb_input_device_focus_in_event_t;

pub const XCB_INPUT_PROXIMITY_IN: u8 = 8;

pub type xcb_input_proximity_in_event_t = xcb_input_device_key_press_event_t;

pub const XCB_INPUT_PROXIMITY_OUT: u8 = 9;

pub type xcb_input_proximity_out_event_t = xcb_input_device_key_press_event_t;

pub const XCB_INPUT_DEVICE_STATE_NOTIFY: u8 = 10;

#[repr(C)]
pub struct xcb_input_device_state_notify_event_t {
    pub response_type:    u8,
    pub device_id:        u8,
    pub sequence:         u16,
    pub time:             xcb_timestamp_t,
    pub num_keys:         u8,
    pub num_buttons:      u8,
    pub num_valuators:    u8,
    pub classes_reported: u8,
    pub buttons:          [u8; 4],
    pub keys:             [u8; 4],
    pub valuators:        [u32; 3],
}

impl Copy for xcb_input_device_state_notify_event_t {}
impl Clone for xcb_input_device_state_notify_event_t {
    fn clone(&self) -> xcb_input_device_state_notify_event_t { *self }
}

pub const XCB_INPUT_DEVICE_MAPPING_NOTIFY: u8 = 11;

#[repr(C)]
pub struct xcb_input_device_mapping_notify_event_t {
    pub response_type: u8,
    pub device_id:     u8,
    pub sequence:      u16,
    pub request:       u8,
    pub first_keycode: xcb_input_key_code_t,
    pub count:         u8,
    pub pad0:          u8,
    pub time:          xcb_timestamp_t,
    pub pad1:          [u8; 20],
}

impl Copy for xcb_input_device_mapping_notify_event_t {}
impl Clone for xcb_input_device_mapping_notify_event_t {
    fn clone(&self) -> xcb_input_device_mapping_notify_event_t { *self }
}

pub const XCB_INPUT_CHANGE_DEVICE_NOTIFY: u8 = 12;

#[repr(C)]
pub struct xcb_input_change_device_notify_event_t {
    pub response_type: u8,
    pub device_id:     u8,
    pub sequence:      u16,
    pub time:          xcb_timestamp_t,
    pub request:       u8,
    pub pad0:          [u8; 23],
}

impl Copy for xcb_input_change_device_notify_event_t {}
impl Clone for xcb_input_change_device_notify_event_t {
    fn clone(&self) -> xcb_input_change_device_notify_event_t { *self }
}

pub const XCB_INPUT_DEVICE_KEY_STATE_NOTIFY: u8 = 13;

#[repr(C)]
pub struct xcb_input_device_key_state_notify_event_t {
    pub response_type: u8,
    pub device_id:     u8,
    pub sequence:      u16,
    pub keys:          [u8; 28],
}

impl Copy for xcb_input_device_key_state_notify_event_t {}
impl Clone for xcb_input_device_key_state_notify_event_t {
    fn clone(&self) -> xcb_input_device_key_state_notify_event_t { *self }
}

pub const XCB_INPUT_DEVICE_BUTTON_STATE_NOTIFY: u8 = 14;

#[repr(C)]
pub struct xcb_input_device_button_state_notify_event_t {
    pub response_type: u8,
    pub device_id:     u8,
    pub sequence:      u16,
    pub buttons:       [u8; 28],
}

impl Copy for xcb_input_device_button_state_notify_event_t {}
impl Clone for xcb_input_device_button_state_notify_event_t {
    fn clone(&self) -> xcb_input_device_button_state_notify_event_t { *self }
}

pub type xcb_input_device_change_t = u32;
pub const XCB_INPUT_DEVICE_CHANGE_ADDED          : xcb_input_device_change_t = 0x00;
pub const XCB_INPUT_DEVICE_CHANGE_REMOVED        : xcb_input_device_change_t = 0x01;
pub const XCB_INPUT_DEVICE_CHANGE_ENABLED        : xcb_input_device_change_t = 0x02;
pub const XCB_INPUT_DEVICE_CHANGE_DISABLED       : xcb_input_device_change_t = 0x03;
pub const XCB_INPUT_DEVICE_CHANGE_UNRECOVERABLE  : xcb_input_device_change_t = 0x04;
pub const XCB_INPUT_DEVICE_CHANGE_CONTROL_CHANGED: xcb_input_device_change_t = 0x05;

pub const XCB_INPUT_DEVICE_PRESENCE_NOTIFY: u8 = 15;

#[repr(C)]
pub struct xcb_input_device_presence_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub time:          xcb_timestamp_t,
    pub devchange:     u8,
    pub device_id:     u8,
    pub control:       u16,
    pub pad1:          [u8; 20],
}

impl Copy for xcb_input_device_presence_notify_event_t {}
impl Clone for xcb_input_device_presence_notify_event_t {
    fn clone(&self) -> xcb_input_device_presence_notify_event_t { *self }
}

pub const XCB_INPUT_DEVICE_PROPERTY_NOTIFY: u8 = 16;

#[repr(C)]
pub struct xcb_input_device_property_notify_event_t {
    pub response_type: u8,
    pub state:         u8,
    pub sequence:      u16,
    pub time:          xcb_timestamp_t,
    pub property:      xcb_atom_t,
    pub pad0:          [u8; 19],
    pub device_id:     u8,
}

impl Copy for xcb_input_device_property_notify_event_t {}
impl Clone for xcb_input_device_property_notify_event_t {
    fn clone(&self) -> xcb_input_device_property_notify_event_t { *self }
}

pub type xcb_input_change_reason_t = u32;
pub const XCB_INPUT_CHANGE_REASON_SLAVE_SWITCH : xcb_input_change_reason_t = 0x01;
pub const XCB_INPUT_CHANGE_REASON_DEVICE_CHANGE: xcb_input_change_reason_t = 0x02;

pub const XCB_INPUT_DEVICE_CHANGED: u8 = 1;

#[repr(C)]
pub struct xcb_input_device_changed_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub num_classes:   u16,
    pub sourceid:      xcb_input_device_id_t,
    pub reason:        u8,
    pub pad0:          [u8; 11],
    pub full_sequence: u32,
}

pub type xcb_input_key_event_flags_t = u32;
pub const XCB_INPUT_KEY_EVENT_FLAGS_KEY_REPEAT: xcb_input_key_event_flags_t = 0x10000;

pub const XCB_INPUT_KEY_PRESS: u8 = 2;

#[repr(C)]
pub struct xcb_input_key_press_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub detail:        u32,
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    pub full_sequence: u32,
    pub root_x:        xcb_input_fp1616_t,
    pub root_y:        xcb_input_fp1616_t,
    pub event_x:       xcb_input_fp1616_t,
    pub event_y:       xcb_input_fp1616_t,
    pub buttons_len:   u16,
    pub valuators_len: u16,
    pub sourceid:      xcb_input_device_id_t,
    pub pad0:          [u8; 2],
    pub flags:         u32,
    pub mods:          xcb_input_modifier_info_t,
    pub group:         xcb_input_group_info_t,
}

pub const XCB_INPUT_KEY_RELEASE: u8 = 3;

pub type xcb_input_key_release_event_t = xcb_input_key_press_event_t;

pub type xcb_input_pointer_event_flags_t = u32;
pub const XCB_INPUT_POINTER_EVENT_FLAGS_POINTER_EMULATED: xcb_input_pointer_event_flags_t = 0x10000;

pub const XCB_INPUT_BUTTON_PRESS: u8 = 4;

#[repr(C)]
pub struct xcb_input_button_press_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub detail:        u32,
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    pub full_sequence: u32,
    pub root_x:        xcb_input_fp1616_t,
    pub root_y:        xcb_input_fp1616_t,
    pub event_x:       xcb_input_fp1616_t,
    pub event_y:       xcb_input_fp1616_t,
    pub buttons_len:   u16,
    pub valuators_len: u16,
    pub sourceid:      xcb_input_device_id_t,
    pub pad0:          [u8; 2],
    pub flags:         u32,
    pub mods:          xcb_input_modifier_info_t,
    pub group:         xcb_input_group_info_t,
}

pub const XCB_INPUT_BUTTON_RELEASE: u8 = 5;

pub type xcb_input_button_release_event_t = xcb_input_button_press_event_t;

pub const XCB_INPUT_MOTION: u8 = 6;

pub type xcb_input_motion_event_t = xcb_input_button_press_event_t;

pub type xcb_input_notify_mode_t = u32;
pub const XCB_INPUT_NOTIFY_MODE_NORMAL        : xcb_input_notify_mode_t = 0x00;
pub const XCB_INPUT_NOTIFY_MODE_GRAB          : xcb_input_notify_mode_t = 0x01;
pub const XCB_INPUT_NOTIFY_MODE_UNGRAB        : xcb_input_notify_mode_t = 0x02;
pub const XCB_INPUT_NOTIFY_MODE_WHILE_GRABBED : xcb_input_notify_mode_t = 0x03;
pub const XCB_INPUT_NOTIFY_MODE_PASSIVE_GRAB  : xcb_input_notify_mode_t = 0x04;
pub const XCB_INPUT_NOTIFY_MODE_PASSIVE_UNGRAB: xcb_input_notify_mode_t = 0x05;

pub type xcb_input_notify_detail_t = u32;
pub const XCB_INPUT_NOTIFY_DETAIL_ANCESTOR         : xcb_input_notify_detail_t = 0x00;
pub const XCB_INPUT_NOTIFY_DETAIL_VIRTUAL          : xcb_input_notify_detail_t = 0x01;
pub const XCB_INPUT_NOTIFY_DETAIL_INFERIOR         : xcb_input_notify_detail_t = 0x02;
pub const XCB_INPUT_NOTIFY_DETAIL_NONLINEAR        : xcb_input_notify_detail_t = 0x03;
pub const XCB_INPUT_NOTIFY_DETAIL_NONLINEAR_VIRTUAL: xcb_input_notify_detail_t = 0x04;
pub const XCB_INPUT_NOTIFY_DETAIL_POINTER          : xcb_input_notify_detail_t = 0x05;
pub const XCB_INPUT_NOTIFY_DETAIL_POINTER_ROOT     : xcb_input_notify_detail_t = 0x06;
pub const XCB_INPUT_NOTIFY_DETAIL_NONE             : xcb_input_notify_detail_t = 0x07;

pub const XCB_INPUT_ENTER: u8 = 7;

#[repr(C)]
pub struct xcb_input_enter_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub sourceid:      xcb_input_device_id_t,
    pub mode:          u8,
    pub detail:        u8,
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    pub full_sequence: u32,
    pub root_x:        xcb_input_fp1616_t,
    pub root_y:        xcb_input_fp1616_t,
    pub event_x:       xcb_input_fp1616_t,
    pub event_y:       xcb_input_fp1616_t,
    pub same_screen:   u8,
    pub focus:         u8,
    pub buttons_len:   u16,
    pub mods:          xcb_input_modifier_info_t,
    pub group:         xcb_input_group_info_t,
}

pub const XCB_INPUT_LEAVE: u8 = 8;

pub type xcb_input_leave_event_t = xcb_input_enter_event_t;

pub const XCB_INPUT_FOCUS_IN: u8 = 9;

pub type xcb_input_focus_in_event_t = xcb_input_enter_event_t;

pub const XCB_INPUT_FOCUS_OUT: u8 = 10;

pub type xcb_input_focus_out_event_t = xcb_input_enter_event_t;

pub type xcb_input_hierarchy_mask_t = u32;
pub const XCB_INPUT_HIERARCHY_MASK_MASTER_ADDED   : xcb_input_hierarchy_mask_t = 0x01;
pub const XCB_INPUT_HIERARCHY_MASK_MASTER_REMOVED : xcb_input_hierarchy_mask_t = 0x02;
pub const XCB_INPUT_HIERARCHY_MASK_SLAVE_ADDED    : xcb_input_hierarchy_mask_t = 0x04;
pub const XCB_INPUT_HIERARCHY_MASK_SLAVE_REMOVED  : xcb_input_hierarchy_mask_t = 0x08;
pub const XCB_INPUT_HIERARCHY_MASK_SLAVE_ATTACHED : xcb_input_hierarchy_mask_t = 0x10;
pub const XCB_INPUT_HIERARCHY_MASK_SLAVE_DETACHED : xcb_input_hierarchy_mask_t = 0x20;
pub const XCB_INPUT_HIERARCHY_MASK_DEVICE_ENABLED : xcb_input_hierarchy_mask_t = 0x40;
pub const XCB_INPUT_HIERARCHY_MASK_DEVICE_DISABLED: xcb_input_hierarchy_mask_t = 0x80;

#[repr(C)]
pub struct xcb_input_hierarchy_info_t {
    pub deviceid:   xcb_input_device_id_t,
    pub attachment: xcb_input_device_id_t,
    pub type_:      u8,
    pub enabled:    u8,
    pub pad0:       [u8; 2],
    pub flags:      u32,
}

impl Copy for xcb_input_hierarchy_info_t {}
impl Clone for xcb_input_hierarchy_info_t {
    fn clone(&self) -> xcb_input_hierarchy_info_t { *self }
}

#[repr(C)]
pub struct xcb_input_hierarchy_info_iterator_t {
    pub data:  *mut xcb_input_hierarchy_info_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_INPUT_HIERARCHY: u8 = 11;

#[repr(C)]
pub struct xcb_input_hierarchy_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub flags:         u32,
    pub num_infos:     u16,
    pub pad0:          [u8; 10],
    pub full_sequence: u32,
}

pub type xcb_input_property_flag_t = u32;
pub const XCB_INPUT_PROPERTY_FLAG_DELETED : xcb_input_property_flag_t = 0x00;
pub const XCB_INPUT_PROPERTY_FLAG_CREATED : xcb_input_property_flag_t = 0x01;
pub const XCB_INPUT_PROPERTY_FLAG_MODIFIED: xcb_input_property_flag_t = 0x02;

pub const XCB_INPUT_PROPERTY: u8 = 12;

#[repr(C)]
pub struct xcb_input_property_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub property:      xcb_atom_t,
    pub what:          u8,
    pub pad0:          [u8; 11],
    pub full_sequence: u32,
}

impl Copy for xcb_input_property_event_t {}
impl Clone for xcb_input_property_event_t {
    fn clone(&self) -> xcb_input_property_event_t { *self }
}

pub const XCB_INPUT_RAW_KEY_PRESS: u8 = 13;

#[repr(C)]
pub struct xcb_input_raw_key_press_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub detail:        u32,
    pub sourceid:      xcb_input_device_id_t,
    pub valuators_len: u16,
    pub flags:         u32,
    pub pad0:          [u8; 4],
    pub full_sequence: u32,
}

pub const XCB_INPUT_RAW_KEY_RELEASE: u8 = 14;

pub type xcb_input_raw_key_release_event_t = xcb_input_raw_key_press_event_t;

pub const XCB_INPUT_RAW_BUTTON_PRESS: u8 = 15;

#[repr(C)]
pub struct xcb_input_raw_button_press_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub detail:        u32,
    pub sourceid:      xcb_input_device_id_t,
    pub valuators_len: u16,
    pub flags:         u32,
    pub pad0:          [u8; 4],
    pub full_sequence: u32,
}

pub const XCB_INPUT_RAW_BUTTON_RELEASE: u8 = 16;

pub type xcb_input_raw_button_release_event_t = xcb_input_raw_button_press_event_t;

pub const XCB_INPUT_RAW_MOTION: u8 = 17;

pub type xcb_input_raw_motion_event_t = xcb_input_raw_button_press_event_t;

pub type xcb_input_touch_event_flags_t = u32;
pub const XCB_INPUT_TOUCH_EVENT_FLAGS_TOUCH_PENDING_END      : xcb_input_touch_event_flags_t = 0x10000;
pub const XCB_INPUT_TOUCH_EVENT_FLAGS_TOUCH_EMULATING_POINTER: xcb_input_touch_event_flags_t = 0x20000;

pub const XCB_INPUT_TOUCH_BEGIN: u8 = 18;

#[repr(C)]
pub struct xcb_input_touch_begin_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub detail:        u32,
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    pub full_sequence: u32,
    pub root_x:        xcb_input_fp1616_t,
    pub root_y:        xcb_input_fp1616_t,
    pub event_x:       xcb_input_fp1616_t,
    pub event_y:       xcb_input_fp1616_t,
    pub buttons_len:   u16,
    pub valuators_len: u16,
    pub sourceid:      xcb_input_device_id_t,
    pub pad0:          [u8; 2],
    pub flags:         u32,
    pub mods:          xcb_input_modifier_info_t,
    pub group:         xcb_input_group_info_t,
}

pub const XCB_INPUT_TOUCH_UPDATE: u8 = 19;

pub type xcb_input_touch_update_event_t = xcb_input_touch_begin_event_t;

pub const XCB_INPUT_TOUCH_END: u8 = 20;

pub type xcb_input_touch_end_event_t = xcb_input_touch_begin_event_t;

pub type xcb_input_touch_ownership_flags_t = u32;
pub const XCB_INPUT_TOUCH_OWNERSHIP_FLAGS_NONE: xcb_input_touch_ownership_flags_t = 0x00;

pub const XCB_INPUT_TOUCH_OWNERSHIP: u8 = 21;

#[repr(C)]
pub struct xcb_input_touch_ownership_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub touchid:       u32,
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    pub full_sequence: u32,
    pub sourceid:      xcb_input_device_id_t,
    pub pad0:          [u8; 2],
    pub flags:         u32,
    pub pad1:          [u8; 8],
}

impl Copy for xcb_input_touch_ownership_event_t {}
impl Clone for xcb_input_touch_ownership_event_t {
    fn clone(&self) -> xcb_input_touch_ownership_event_t { *self }
}

pub const XCB_INPUT_RAW_TOUCH_BEGIN: u8 = 22;

#[repr(C)]
pub struct xcb_input_raw_touch_begin_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub detail:        u32,
    pub sourceid:      xcb_input_device_id_t,
    pub valuators_len: u16,
    pub flags:         u32,
    pub pad0:          [u8; 4],
    pub full_sequence: u32,
}

pub const XCB_INPUT_RAW_TOUCH_UPDATE: u8 = 23;

pub type xcb_input_raw_touch_update_event_t = xcb_input_raw_touch_begin_event_t;

pub const XCB_INPUT_RAW_TOUCH_END: u8 = 24;

pub type xcb_input_raw_touch_end_event_t = xcb_input_raw_touch_begin_event_t;

pub const XCB_INPUT_BARRIER_HIT: u8 = 25;

#[repr(C)]
pub struct xcb_input_barrier_hit_event_t {
    pub response_type: u8,
    pub extension:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pub deviceid:      xcb_input_device_id_t,
    pub time:          xcb_timestamp_t,
    pub eventid:       u32,
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub barrier:       xcb_xfixes_barrier_t,
    pub full_sequence: u32,
    pub dtime:         u32,
    pub flags:         u32,
    pub sourceid:      xcb_input_device_id_t,
    pub pad0:          [u8; 2],
    pub root_x:        xcb_input_fp1616_t,
    pub root_y:        xcb_input_fp1616_t,
    pub dx:            xcb_input_fp3232_t,
    pub dy:            xcb_input_fp3232_t,
}

impl Copy for xcb_input_barrier_hit_event_t {}
impl Clone for xcb_input_barrier_hit_event_t {
    fn clone(&self) -> xcb_input_barrier_hit_event_t { *self }
}

pub const XCB_INPUT_BARRIER_LEAVE: u8 = 26;

pub type xcb_input_barrier_leave_event_t = xcb_input_barrier_hit_event_t;

pub const XCB_INPUT_DEVICE: u8 = 0;

#[repr(C)]
pub struct xcb_input_device_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_input_device_error_t {}
impl Clone for xcb_input_device_error_t {
    fn clone(&self) -> xcb_input_device_error_t { *self }
}

pub const XCB_INPUT_EVENT: u8 = 1;

#[repr(C)]
pub struct xcb_input_event_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_input_event_error_t {}
impl Clone for xcb_input_event_error_t {
    fn clone(&self) -> xcb_input_event_error_t { *self }
}

pub const XCB_INPUT_MODE: u8 = 2;

#[repr(C)]
pub struct xcb_input_mode_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_input_mode_error_t {}
impl Clone for xcb_input_mode_error_t {
    fn clone(&self) -> xcb_input_mode_error_t { *self }
}

pub const XCB_INPUT_DEVICE_BUSY: u8 = 3;

#[repr(C)]
pub struct xcb_input_device_busy_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_input_device_busy_error_t {}
impl Clone for xcb_input_device_busy_error_t {
    fn clone(&self) -> xcb_input_device_busy_error_t { *self }
}

pub const XCB_INPUT_CLASS: u8 = 4;

#[repr(C)]
pub struct xcb_input_class_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_input_class_error_t {}
impl Clone for xcb_input_class_error_t {
    fn clone(&self) -> xcb_input_class_error_t { *self }
}


#[link(name="xcb-xinput")]
extern {

    pub static mut xcb_input_id: xcb_extension_t;

    pub fn xcb_input_event_class_next (i: *mut xcb_input_event_class_iterator_t);

    pub fn xcb_input_event_class_end (i: *mut xcb_input_event_class_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_key_code_next (i: *mut xcb_input_key_code_iterator_t);

    pub fn xcb_input_key_code_end (i: *mut xcb_input_key_code_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_id_next (i: *mut xcb_input_device_id_iterator_t);

    pub fn xcb_input_device_id_end (i: *mut xcb_input_device_id_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_fp1616_next (i: *mut xcb_input_fp1616_iterator_t);

    pub fn xcb_input_fp1616_end (i: *mut xcb_input_fp1616_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_fp3232_next (i: *mut xcb_input_fp3232_iterator_t);

    pub fn xcb_input_fp3232_end (i: *mut xcb_input_fp3232_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_extension_version_reply (c:      *mut xcb_connection_t,
                                                  cookie: xcb_input_get_extension_version_cookie_t,
                                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_extension_version_reply_t;

    pub fn xcb_input_get_extension_version (c:        *mut xcb_connection_t,
                                            name_len: u16,
                                            name:     *const c_char)
            -> xcb_input_get_extension_version_cookie_t;

    pub fn xcb_input_get_extension_version_unchecked (c:        *mut xcb_connection_t,
                                                      name_len: u16,
                                                      name:     *const c_char)
            -> xcb_input_get_extension_version_cookie_t;

    pub fn xcb_input_device_info_next (i: *mut xcb_input_device_info_iterator_t);

    pub fn xcb_input_device_info_end (i: *mut xcb_input_device_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_key_info_next (i: *mut xcb_input_key_info_iterator_t);

    pub fn xcb_input_key_info_end (i: *mut xcb_input_key_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_button_info_next (i: *mut xcb_input_button_info_iterator_t);

    pub fn xcb_input_button_info_end (i: *mut xcb_input_button_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_axis_info_next (i: *mut xcb_input_axis_info_iterator_t);

    pub fn xcb_input_axis_info_end (i: *mut xcb_input_axis_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_valuator_info_axes (R: *const xcb_input_valuator_info_t)
            -> *mut xcb_input_axis_info_t;

    pub fn xcb_input_valuator_info_axes_length (R: *const xcb_input_valuator_info_t)
            -> c_int;

    pub fn xcb_input_valuator_info_axes_iterator (R: *const xcb_input_valuator_info_t)
            -> xcb_input_axis_info_iterator_t;

    pub fn xcb_input_valuator_info_next (i: *mut xcb_input_valuator_info_iterator_t);

    pub fn xcb_input_valuator_info_end (i: *mut xcb_input_valuator_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_input_info_next (i: *mut xcb_input_input_info_iterator_t);

    pub fn xcb_input_input_info_end (i: *mut xcb_input_input_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_name_string (R: *const xcb_input_device_name_t)
            -> *mut c_char;

    pub fn xcb_input_device_name_string_length (R: *const xcb_input_device_name_t)
            -> c_int;

    pub fn xcb_input_device_name_string_end (R: *const xcb_input_device_name_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_name_next (i: *mut xcb_input_device_name_iterator_t);

    pub fn xcb_input_device_name_end (i: *mut xcb_input_device_name_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_list_input_devices_devices (R: *const xcb_input_list_input_devices_reply_t)
            -> *mut xcb_input_device_info_t;

    pub fn xcb_input_list_input_devices_devices_length (R: *const xcb_input_list_input_devices_reply_t)
            -> c_int;

    pub fn xcb_input_list_input_devices_devices_iterator (R: *const xcb_input_list_input_devices_reply_t)
            -> xcb_input_device_info_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_list_input_devices_reply (c:      *mut xcb_connection_t,
                                               cookie: xcb_input_list_input_devices_cookie_t,
                                               error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_list_input_devices_reply_t;

    pub fn xcb_input_list_input_devices (c: *mut xcb_connection_t)
            -> xcb_input_list_input_devices_cookie_t;

    pub fn xcb_input_list_input_devices_unchecked (c: *mut xcb_connection_t)
            -> xcb_input_list_input_devices_cookie_t;

    pub fn xcb_input_input_class_info_next (i: *mut xcb_input_input_class_info_iterator_t);

    pub fn xcb_input_input_class_info_end (i: *mut xcb_input_input_class_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_open_device_class_info (R: *const xcb_input_open_device_reply_t)
            -> *mut xcb_input_input_class_info_t;

    pub fn xcb_input_open_device_class_info_length (R: *const xcb_input_open_device_reply_t)
            -> c_int;

    pub fn xcb_input_open_device_class_info_iterator (R: *const xcb_input_open_device_reply_t)
            -> xcb_input_input_class_info_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_open_device_reply (c:      *mut xcb_connection_t,
                                        cookie: xcb_input_open_device_cookie_t,
                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_open_device_reply_t;

    pub fn xcb_input_open_device (c:         *mut xcb_connection_t,
                                  device_id: u8)
            -> xcb_input_open_device_cookie_t;

    pub fn xcb_input_open_device_unchecked (c:         *mut xcb_connection_t,
                                            device_id: u8)
            -> xcb_input_open_device_cookie_t;

    pub fn xcb_input_close_device (c:         *mut xcb_connection_t,
                                   device_id: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_close_device_checked (c:         *mut xcb_connection_t,
                                           device_id: u8)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_set_device_mode_reply (c:      *mut xcb_connection_t,
                                            cookie: xcb_input_set_device_mode_cookie_t,
                                            error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_set_device_mode_reply_t;

    pub fn xcb_input_set_device_mode (c:         *mut xcb_connection_t,
                                      device_id: u8,
                                      mode:      u8)
            -> xcb_input_set_device_mode_cookie_t;

    pub fn xcb_input_set_device_mode_unchecked (c:         *mut xcb_connection_t,
                                                device_id: u8,
                                                mode:      u8)
            -> xcb_input_set_device_mode_cookie_t;

    pub fn xcb_input_select_extension_event (c:           *mut xcb_connection_t,
                                             window:      xcb_window_t,
                                             num_classes: u16,
                                             classes:     *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_select_extension_event_checked (c:           *mut xcb_connection_t,
                                                     window:      xcb_window_t,
                                                     num_classes: u16,
                                                     classes:     *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_get_selected_extension_events_this_classes (R: *const xcb_input_get_selected_extension_events_reply_t)
            -> *mut xcb_input_event_class_t;

    pub fn xcb_input_get_selected_extension_events_this_classes_length (R: *const xcb_input_get_selected_extension_events_reply_t)
            -> c_int;

    pub fn xcb_input_get_selected_extension_events_this_classes_end (R: *const xcb_input_get_selected_extension_events_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_get_selected_extension_events_all_classes (R: *const xcb_input_get_selected_extension_events_reply_t)
            -> *mut xcb_input_event_class_t;

    pub fn xcb_input_get_selected_extension_events_all_classes_length (R: *const xcb_input_get_selected_extension_events_reply_t)
            -> c_int;

    pub fn xcb_input_get_selected_extension_events_all_classes_end (R: *const xcb_input_get_selected_extension_events_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_selected_extension_events_reply (c:      *mut xcb_connection_t,
                                                          cookie: xcb_input_get_selected_extension_events_cookie_t,
                                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_selected_extension_events_reply_t;

    pub fn xcb_input_get_selected_extension_events (c:      *mut xcb_connection_t,
                                                    window: xcb_window_t)
            -> xcb_input_get_selected_extension_events_cookie_t;

    pub fn xcb_input_get_selected_extension_events_unchecked (c:      *mut xcb_connection_t,
                                                              window: xcb_window_t)
            -> xcb_input_get_selected_extension_events_cookie_t;

    pub fn xcb_input_change_device_dont_propagate_list (c:           *mut xcb_connection_t,
                                                        window:      xcb_window_t,
                                                        num_classes: u16,
                                                        mode:        u8,
                                                        classes:     *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_change_device_dont_propagate_list_checked (c:           *mut xcb_connection_t,
                                                                window:      xcb_window_t,
                                                                num_classes: u16,
                                                                mode:        u8,
                                                                classes:     *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_get_device_dont_propagate_list_classes (R: *const xcb_input_get_device_dont_propagate_list_reply_t)
            -> *mut xcb_input_event_class_t;

    pub fn xcb_input_get_device_dont_propagate_list_classes_length (R: *const xcb_input_get_device_dont_propagate_list_reply_t)
            -> c_int;

    pub fn xcb_input_get_device_dont_propagate_list_classes_end (R: *const xcb_input_get_device_dont_propagate_list_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_device_dont_propagate_list_reply (c:      *mut xcb_connection_t,
                                                           cookie: xcb_input_get_device_dont_propagate_list_cookie_t,
                                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_device_dont_propagate_list_reply_t;

    pub fn xcb_input_get_device_dont_propagate_list (c:      *mut xcb_connection_t,
                                                     window: xcb_window_t)
            -> xcb_input_get_device_dont_propagate_list_cookie_t;

    pub fn xcb_input_get_device_dont_propagate_list_unchecked (c:      *mut xcb_connection_t,
                                                               window: xcb_window_t)
            -> xcb_input_get_device_dont_propagate_list_cookie_t;

    pub fn xcb_input_device_time_coord_next (i: *mut xcb_input_device_time_coord_iterator_t);

    pub fn xcb_input_device_time_coord_end (i: *mut xcb_input_device_time_coord_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_device_motion_events_reply (c:      *mut xcb_connection_t,
                                                     cookie: xcb_input_get_device_motion_events_cookie_t,
                                                     error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_device_motion_events_reply_t;

    pub fn xcb_input_get_device_motion_events (c:         *mut xcb_connection_t,
                                               start:     xcb_timestamp_t,
                                               stop:      xcb_timestamp_t,
                                               device_id: u8)
            -> xcb_input_get_device_motion_events_cookie_t;

    pub fn xcb_input_get_device_motion_events_unchecked (c:         *mut xcb_connection_t,
                                                         start:     xcb_timestamp_t,
                                                         stop:      xcb_timestamp_t,
                                                         device_id: u8)
            -> xcb_input_get_device_motion_events_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_change_keyboard_device_reply (c:      *mut xcb_connection_t,
                                                   cookie: xcb_input_change_keyboard_device_cookie_t,
                                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_change_keyboard_device_reply_t;

    pub fn xcb_input_change_keyboard_device (c:         *mut xcb_connection_t,
                                             device_id: u8)
            -> xcb_input_change_keyboard_device_cookie_t;

    pub fn xcb_input_change_keyboard_device_unchecked (c:         *mut xcb_connection_t,
                                                       device_id: u8)
            -> xcb_input_change_keyboard_device_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_change_pointer_device_reply (c:      *mut xcb_connection_t,
                                                  cookie: xcb_input_change_pointer_device_cookie_t,
                                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_change_pointer_device_reply_t;

    pub fn xcb_input_change_pointer_device (c:         *mut xcb_connection_t,
                                            x_axis:    u8,
                                            y_axis:    u8,
                                            device_id: u8)
            -> xcb_input_change_pointer_device_cookie_t;

    pub fn xcb_input_change_pointer_device_unchecked (c:         *mut xcb_connection_t,
                                                      x_axis:    u8,
                                                      y_axis:    u8,
                                                      device_id: u8)
            -> xcb_input_change_pointer_device_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_grab_device_reply (c:      *mut xcb_connection_t,
                                        cookie: xcb_input_grab_device_cookie_t,
                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_grab_device_reply_t;

    pub fn xcb_input_grab_device (c:                 *mut xcb_connection_t,
                                  grab_window:       xcb_window_t,
                                  time:              xcb_timestamp_t,
                                  num_classes:       u16,
                                  this_device_mode:  u8,
                                  other_device_mode: u8,
                                  owner_events:      u8,
                                  device_id:         u8,
                                  classes:           *const xcb_input_event_class_t)
            -> xcb_input_grab_device_cookie_t;

    pub fn xcb_input_grab_device_unchecked (c:                 *mut xcb_connection_t,
                                            grab_window:       xcb_window_t,
                                            time:              xcb_timestamp_t,
                                            num_classes:       u16,
                                            this_device_mode:  u8,
                                            other_device_mode: u8,
                                            owner_events:      u8,
                                            device_id:         u8,
                                            classes:           *const xcb_input_event_class_t)
            -> xcb_input_grab_device_cookie_t;

    pub fn xcb_input_ungrab_device (c:         *mut xcb_connection_t,
                                    time:      xcb_timestamp_t,
                                    device_id: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_ungrab_device_checked (c:         *mut xcb_connection_t,
                                            time:      xcb_timestamp_t,
                                            device_id: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_grab_device_key (c:                 *mut xcb_connection_t,
                                      grab_window:       xcb_window_t,
                                      num_classes:       u16,
                                      modifiers:         u16,
                                      modifier_device:   u8,
                                      grabbed_device:    u8,
                                      key:               u8,
                                      this_device_mode:  u8,
                                      other_device_mode: u8,
                                      owner_events:      u8,
                                      classes:           *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_grab_device_key_checked (c:                 *mut xcb_connection_t,
                                              grab_window:       xcb_window_t,
                                              num_classes:       u16,
                                              modifiers:         u16,
                                              modifier_device:   u8,
                                              grabbed_device:    u8,
                                              key:               u8,
                                              this_device_mode:  u8,
                                              other_device_mode: u8,
                                              owner_events:      u8,
                                              classes:           *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_ungrab_device_key (c:               *mut xcb_connection_t,
                                        grabWindow:      xcb_window_t,
                                        modifiers:       u16,
                                        modifier_device: u8,
                                        key:             u8,
                                        grabbed_device:  u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_ungrab_device_key_checked (c:               *mut xcb_connection_t,
                                                grabWindow:      xcb_window_t,
                                                modifiers:       u16,
                                                modifier_device: u8,
                                                key:             u8,
                                                grabbed_device:  u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_grab_device_button (c:                 *mut xcb_connection_t,
                                         grab_window:       xcb_window_t,
                                         grabbed_device:    u8,
                                         modifier_device:   u8,
                                         num_classes:       u16,
                                         modifiers:         u16,
                                         this_device_mode:  u8,
                                         other_device_mode: u8,
                                         button:            u8,
                                         owner_events:      u8,
                                         classes:           *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_grab_device_button_checked (c:                 *mut xcb_connection_t,
                                                 grab_window:       xcb_window_t,
                                                 grabbed_device:    u8,
                                                 modifier_device:   u8,
                                                 num_classes:       u16,
                                                 modifiers:         u16,
                                                 this_device_mode:  u8,
                                                 other_device_mode: u8,
                                                 button:            u8,
                                                 owner_events:      u8,
                                                 classes:           *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_ungrab_device_button (c:               *mut xcb_connection_t,
                                           grab_window:     xcb_window_t,
                                           modifiers:       u16,
                                           modifier_device: u8,
                                           button:          u8,
                                           grabbed_device:  u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_ungrab_device_button_checked (c:               *mut xcb_connection_t,
                                                   grab_window:     xcb_window_t,
                                                   modifiers:       u16,
                                                   modifier_device: u8,
                                                   button:          u8,
                                                   grabbed_device:  u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_allow_device_events (c:         *mut xcb_connection_t,
                                          time:      xcb_timestamp_t,
                                          mode:      u8,
                                          device_id: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_allow_device_events_checked (c:         *mut xcb_connection_t,
                                                  time:      xcb_timestamp_t,
                                                  mode:      u8,
                                                  device_id: u8)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_device_focus_reply (c:      *mut xcb_connection_t,
                                             cookie: xcb_input_get_device_focus_cookie_t,
                                             error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_device_focus_reply_t;

    pub fn xcb_input_get_device_focus (c:         *mut xcb_connection_t,
                                       device_id: u8)
            -> xcb_input_get_device_focus_cookie_t;

    pub fn xcb_input_get_device_focus_unchecked (c:         *mut xcb_connection_t,
                                                 device_id: u8)
            -> xcb_input_get_device_focus_cookie_t;

    pub fn xcb_input_set_device_focus (c:         *mut xcb_connection_t,
                                       focus:     xcb_window_t,
                                       time:      xcb_timestamp_t,
                                       revert_to: u8,
                                       device_id: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_set_device_focus_checked (c:         *mut xcb_connection_t,
                                               focus:     xcb_window_t,
                                               time:      xcb_timestamp_t,
                                               revert_to: u8,
                                               device_id: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_kbd_feedback_state_next (i: *mut xcb_input_kbd_feedback_state_iterator_t);

    pub fn xcb_input_kbd_feedback_state_end (i: *mut xcb_input_kbd_feedback_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_ptr_feedback_state_next (i: *mut xcb_input_ptr_feedback_state_iterator_t);

    pub fn xcb_input_ptr_feedback_state_end (i: *mut xcb_input_ptr_feedback_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_integer_feedback_state_next (i: *mut xcb_input_integer_feedback_state_iterator_t);

    pub fn xcb_input_integer_feedback_state_end (i: *mut xcb_input_integer_feedback_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_string_feedback_state_keysyms (R: *const xcb_input_string_feedback_state_t)
            -> *mut xcb_keysym_t;

    pub fn xcb_input_string_feedback_state_keysyms_length (R: *const xcb_input_string_feedback_state_t)
            -> c_int;

    pub fn xcb_input_string_feedback_state_keysyms_end (R: *const xcb_input_string_feedback_state_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_string_feedback_state_next (i: *mut xcb_input_string_feedback_state_iterator_t);

    pub fn xcb_input_string_feedback_state_end (i: *mut xcb_input_string_feedback_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_bell_feedback_state_next (i: *mut xcb_input_bell_feedback_state_iterator_t);

    pub fn xcb_input_bell_feedback_state_end (i: *mut xcb_input_bell_feedback_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_led_feedback_state_next (i: *mut xcb_input_led_feedback_state_iterator_t);

    pub fn xcb_input_led_feedback_state_end (i: *mut xcb_input_led_feedback_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_feedback_state_uninterpreted_data (R: *const xcb_input_feedback_state_t)
            -> *mut u8;

    pub fn xcb_input_feedback_state_uninterpreted_data_length (R: *const xcb_input_feedback_state_t)
            -> c_int;

    pub fn xcb_input_feedback_state_uninterpreted_data_end (R: *const xcb_input_feedback_state_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_feedback_state_next (i: *mut xcb_input_feedback_state_iterator_t);

    pub fn xcb_input_feedback_state_end (i: *mut xcb_input_feedback_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_get_feedback_control_feedbacks_length (R: *const xcb_input_get_feedback_control_reply_t)
            -> c_int;

    pub fn xcb_input_get_feedback_control_feedbacks_iterator<'a> (R: *const xcb_input_get_feedback_control_reply_t)
            -> xcb_input_feedback_state_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_feedback_control_reply (c:      *mut xcb_connection_t,
                                                 cookie: xcb_input_get_feedback_control_cookie_t,
                                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_feedback_control_reply_t;

    pub fn xcb_input_get_feedback_control (c:         *mut xcb_connection_t,
                                           device_id: u8)
            -> xcb_input_get_feedback_control_cookie_t;

    pub fn xcb_input_get_feedback_control_unchecked (c:         *mut xcb_connection_t,
                                                     device_id: u8)
            -> xcb_input_get_feedback_control_cookie_t;

    pub fn xcb_input_kbd_feedback_ctl_next (i: *mut xcb_input_kbd_feedback_ctl_iterator_t);

    pub fn xcb_input_kbd_feedback_ctl_end (i: *mut xcb_input_kbd_feedback_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_ptr_feedback_ctl_next (i: *mut xcb_input_ptr_feedback_ctl_iterator_t);

    pub fn xcb_input_ptr_feedback_ctl_end (i: *mut xcb_input_ptr_feedback_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_integer_feedback_ctl_next (i: *mut xcb_input_integer_feedback_ctl_iterator_t);

    pub fn xcb_input_integer_feedback_ctl_end (i: *mut xcb_input_integer_feedback_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_string_feedback_ctl_keysyms (R: *const xcb_input_string_feedback_ctl_t)
            -> *mut xcb_keysym_t;

    pub fn xcb_input_string_feedback_ctl_keysyms_length (R: *const xcb_input_string_feedback_ctl_t)
            -> c_int;

    pub fn xcb_input_string_feedback_ctl_keysyms_end (R: *const xcb_input_string_feedback_ctl_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_string_feedback_ctl_next (i: *mut xcb_input_string_feedback_ctl_iterator_t);

    pub fn xcb_input_string_feedback_ctl_end (i: *mut xcb_input_string_feedback_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_bell_feedback_ctl_next (i: *mut xcb_input_bell_feedback_ctl_iterator_t);

    pub fn xcb_input_bell_feedback_ctl_end (i: *mut xcb_input_bell_feedback_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_led_feedback_ctl_next (i: *mut xcb_input_led_feedback_ctl_iterator_t);

    pub fn xcb_input_led_feedback_ctl_end (i: *mut xcb_input_led_feedback_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_feedback_ctl_uninterpreted_data (R: *const xcb_input_feedback_ctl_t)
            -> *mut u8;

    pub fn xcb_input_feedback_ctl_uninterpreted_data_length (R: *const xcb_input_feedback_ctl_t)
            -> c_int;

    pub fn xcb_input_feedback_ctl_uninterpreted_data_end (R: *const xcb_input_feedback_ctl_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_feedback_ctl_next (i: *mut xcb_input_feedback_ctl_iterator_t);

    pub fn xcb_input_feedback_ctl_end (i: *mut xcb_input_feedback_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_change_feedback_control (c:           *mut xcb_connection_t,
                                              mask:        u32,
                                              device_id:   u8,
                                              feedback_id: u8,
                                              feedback:    *mut xcb_input_feedback_ctl_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_change_feedback_control_checked (c:           *mut xcb_connection_t,
                                                      mask:        u32,
                                                      device_id:   u8,
                                                      feedback_id: u8,
                                                      feedback:    *mut xcb_input_feedback_ctl_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_get_device_key_mapping_keysyms (R: *const xcb_input_get_device_key_mapping_reply_t)
            -> *mut xcb_keysym_t;

    pub fn xcb_input_get_device_key_mapping_keysyms_length (R: *const xcb_input_get_device_key_mapping_reply_t)
            -> c_int;

    pub fn xcb_input_get_device_key_mapping_keysyms_end (R: *const xcb_input_get_device_key_mapping_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_device_key_mapping_reply (c:      *mut xcb_connection_t,
                                                   cookie: xcb_input_get_device_key_mapping_cookie_t,
                                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_device_key_mapping_reply_t;

    pub fn xcb_input_get_device_key_mapping (c:             *mut xcb_connection_t,
                                             device_id:     u8,
                                             first_keycode: xcb_input_key_code_t,
                                             count:         u8)
            -> xcb_input_get_device_key_mapping_cookie_t;

    pub fn xcb_input_get_device_key_mapping_unchecked (c:             *mut xcb_connection_t,
                                                       device_id:     u8,
                                                       first_keycode: xcb_input_key_code_t,
                                                       count:         u8)
            -> xcb_input_get_device_key_mapping_cookie_t;

    pub fn xcb_input_change_device_key_mapping (c:                   *mut xcb_connection_t,
                                                device_id:           u8,
                                                first_keycode:       xcb_input_key_code_t,
                                                keysyms_per_keycode: u8,
                                                keycode_count:       u8,
                                                keysyms:             *const xcb_keysym_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_change_device_key_mapping_checked (c:                   *mut xcb_connection_t,
                                                        device_id:           u8,
                                                        first_keycode:       xcb_input_key_code_t,
                                                        keysyms_per_keycode: u8,
                                                        keycode_count:       u8,
                                                        keysyms:             *const xcb_keysym_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_get_device_modifier_mapping_keymaps (R: *const xcb_input_get_device_modifier_mapping_reply_t)
            -> *mut u8;

    pub fn xcb_input_get_device_modifier_mapping_keymaps_length (R: *const xcb_input_get_device_modifier_mapping_reply_t)
            -> c_int;

    pub fn xcb_input_get_device_modifier_mapping_keymaps_end (R: *const xcb_input_get_device_modifier_mapping_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_device_modifier_mapping_reply (c:      *mut xcb_connection_t,
                                                        cookie: xcb_input_get_device_modifier_mapping_cookie_t,
                                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_device_modifier_mapping_reply_t;

    pub fn xcb_input_get_device_modifier_mapping (c:         *mut xcb_connection_t,
                                                  device_id: u8)
            -> xcb_input_get_device_modifier_mapping_cookie_t;

    pub fn xcb_input_get_device_modifier_mapping_unchecked (c:         *mut xcb_connection_t,
                                                            device_id: u8)
            -> xcb_input_get_device_modifier_mapping_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_set_device_modifier_mapping_reply (c:      *mut xcb_connection_t,
                                                        cookie: xcb_input_set_device_modifier_mapping_cookie_t,
                                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_set_device_modifier_mapping_reply_t;

    pub fn xcb_input_set_device_modifier_mapping (c:                     *mut xcb_connection_t,
                                                  device_id:             u8,
                                                  keycodes_per_modifier: u8,
                                                  keymaps:               *const u8)
            -> xcb_input_set_device_modifier_mapping_cookie_t;

    pub fn xcb_input_set_device_modifier_mapping_unchecked (c:                     *mut xcb_connection_t,
                                                            device_id:             u8,
                                                            keycodes_per_modifier: u8,
                                                            keymaps:               *const u8)
            -> xcb_input_set_device_modifier_mapping_cookie_t;

    pub fn xcb_input_get_device_button_mapping_map (R: *const xcb_input_get_device_button_mapping_reply_t)
            -> *mut u8;

    pub fn xcb_input_get_device_button_mapping_map_length (R: *const xcb_input_get_device_button_mapping_reply_t)
            -> c_int;

    pub fn xcb_input_get_device_button_mapping_map_end (R: *const xcb_input_get_device_button_mapping_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_device_button_mapping_reply (c:      *mut xcb_connection_t,
                                                      cookie: xcb_input_get_device_button_mapping_cookie_t,
                                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_device_button_mapping_reply_t;

    pub fn xcb_input_get_device_button_mapping (c:         *mut xcb_connection_t,
                                                device_id: u8)
            -> xcb_input_get_device_button_mapping_cookie_t;

    pub fn xcb_input_get_device_button_mapping_unchecked (c:         *mut xcb_connection_t,
                                                          device_id: u8)
            -> xcb_input_get_device_button_mapping_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_set_device_button_mapping_reply (c:      *mut xcb_connection_t,
                                                      cookie: xcb_input_set_device_button_mapping_cookie_t,
                                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_set_device_button_mapping_reply_t;

    pub fn xcb_input_set_device_button_mapping (c:         *mut xcb_connection_t,
                                                device_id: u8,
                                                map_size:  u8,
                                                map:       *const u8)
            -> xcb_input_set_device_button_mapping_cookie_t;

    pub fn xcb_input_set_device_button_mapping_unchecked (c:         *mut xcb_connection_t,
                                                          device_id: u8,
                                                          map_size:  u8,
                                                          map:       *const u8)
            -> xcb_input_set_device_button_mapping_cookie_t;

    pub fn xcb_input_key_state_next (i: *mut xcb_input_key_state_iterator_t);

    pub fn xcb_input_key_state_end (i: *mut xcb_input_key_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_button_state_next (i: *mut xcb_input_button_state_iterator_t);

    pub fn xcb_input_button_state_end (i: *mut xcb_input_button_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_valuator_state_valuators (R: *const xcb_input_valuator_state_t)
            -> *mut u32;

    pub fn xcb_input_valuator_state_valuators_length (R: *const xcb_input_valuator_state_t)
            -> c_int;

    pub fn xcb_input_valuator_state_valuators_end (R: *const xcb_input_valuator_state_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_valuator_state_next (i: *mut xcb_input_valuator_state_iterator_t);

    pub fn xcb_input_valuator_state_end (i: *mut xcb_input_valuator_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_input_state_uninterpreted_data (R: *const xcb_input_input_state_t)
            -> *mut u8;

    pub fn xcb_input_input_state_uninterpreted_data_length (R: *const xcb_input_input_state_t)
            -> c_int;

    pub fn xcb_input_input_state_uninterpreted_data_end (R: *const xcb_input_input_state_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_input_state_next (i: *mut xcb_input_input_state_iterator_t);

    pub fn xcb_input_input_state_end (i: *mut xcb_input_input_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_query_device_state_classes_length (R: *const xcb_input_query_device_state_reply_t)
            -> c_int;

    pub fn xcb_input_query_device_state_classes_iterator<'a> (R: *const xcb_input_query_device_state_reply_t)
            -> xcb_input_input_state_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_query_device_state_reply (c:      *mut xcb_connection_t,
                                               cookie: xcb_input_query_device_state_cookie_t,
                                               error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_query_device_state_reply_t;

    pub fn xcb_input_query_device_state (c:         *mut xcb_connection_t,
                                         device_id: u8)
            -> xcb_input_query_device_state_cookie_t;

    pub fn xcb_input_query_device_state_unchecked (c:         *mut xcb_connection_t,
                                                   device_id: u8)
            -> xcb_input_query_device_state_cookie_t;

    pub fn xcb_input_send_extension_event (c:           *mut xcb_connection_t,
                                           destination: xcb_window_t,
                                           device_id:   u8,
                                           propagate:   u8,
                                           num_classes: u16,
                                           num_events:  u8,
                                           events:      *const u8,
                                           classes:     *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_send_extension_event_checked (c:           *mut xcb_connection_t,
                                                   destination: xcb_window_t,
                                                   device_id:   u8,
                                                   propagate:   u8,
                                                   num_classes: u16,
                                                   num_events:  u8,
                                                   events:      *const u8,
                                                   classes:     *const xcb_input_event_class_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_device_bell (c:              *mut xcb_connection_t,
                                  device_id:      u8,
                                  feedback_id:    u8,
                                  feedback_class: u8,
                                  percent:        i8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_device_bell_checked (c:              *mut xcb_connection_t,
                                          device_id:      u8,
                                          feedback_id:    u8,
                                          feedback_class: u8,
                                          percent:        i8)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_set_device_valuators_reply (c:      *mut xcb_connection_t,
                                                 cookie: xcb_input_set_device_valuators_cookie_t,
                                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_set_device_valuators_reply_t;

    pub fn xcb_input_set_device_valuators (c:              *mut xcb_connection_t,
                                           device_id:      u8,
                                           first_valuator: u8,
                                           num_valuators:  u8,
                                           valuators:      *const i32)
            -> xcb_input_set_device_valuators_cookie_t;

    pub fn xcb_input_set_device_valuators_unchecked (c:              *mut xcb_connection_t,
                                                     device_id:      u8,
                                                     first_valuator: u8,
                                                     num_valuators:  u8,
                                                     valuators:      *const i32)
            -> xcb_input_set_device_valuators_cookie_t;

    pub fn xcb_input_device_resolution_state_resolution_values (R: *const xcb_input_device_resolution_state_t)
            -> *mut u32;

    pub fn xcb_input_device_resolution_state_resolution_values_length (R: *const xcb_input_device_resolution_state_t)
            -> c_int;

    pub fn xcb_input_device_resolution_state_resolution_values_end (R: *const xcb_input_device_resolution_state_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_resolution_state_resolution_min (R: *const xcb_input_device_resolution_state_t)
            -> *mut u32;

    pub fn xcb_input_device_resolution_state_resolution_min_length (R: *const xcb_input_device_resolution_state_t)
            -> c_int;

    pub fn xcb_input_device_resolution_state_resolution_min_end (R: *const xcb_input_device_resolution_state_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_resolution_state_resolution_max (R: *const xcb_input_device_resolution_state_t)
            -> *mut u32;

    pub fn xcb_input_device_resolution_state_resolution_max_length (R: *const xcb_input_device_resolution_state_t)
            -> c_int;

    pub fn xcb_input_device_resolution_state_resolution_max_end (R: *const xcb_input_device_resolution_state_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_resolution_state_next (i: *mut xcb_input_device_resolution_state_iterator_t);

    pub fn xcb_input_device_resolution_state_end (i: *mut xcb_input_device_resolution_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_abs_calib_state_next (i: *mut xcb_input_device_abs_calib_state_iterator_t);

    pub fn xcb_input_device_abs_calib_state_end (i: *mut xcb_input_device_abs_calib_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_abs_area_state_next (i: *mut xcb_input_device_abs_area_state_iterator_t);

    pub fn xcb_input_device_abs_area_state_end (i: *mut xcb_input_device_abs_area_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_core_state_next (i: *mut xcb_input_device_core_state_iterator_t);

    pub fn xcb_input_device_core_state_end (i: *mut xcb_input_device_core_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_enable_state_next (i: *mut xcb_input_device_enable_state_iterator_t);

    pub fn xcb_input_device_enable_state_end (i: *mut xcb_input_device_enable_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_state_uninterpreted_data (R: *const xcb_input_device_state_t)
            -> *mut u8;

    pub fn xcb_input_device_state_uninterpreted_data_length (R: *const xcb_input_device_state_t)
            -> c_int;

    pub fn xcb_input_device_state_uninterpreted_data_end (R: *const xcb_input_device_state_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_state_next (i: *mut xcb_input_device_state_iterator_t);

    pub fn xcb_input_device_state_end (i: *mut xcb_input_device_state_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_get_device_control_control (R: *const xcb_input_get_device_control_reply_t)
            -> *mut xcb_input_device_state_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_device_control_reply (c:      *mut xcb_connection_t,
                                               cookie: xcb_input_get_device_control_cookie_t,
                                               error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_device_control_reply_t;

    pub fn xcb_input_get_device_control (c:          *mut xcb_connection_t,
                                         control_id: u16,
                                         device_id:  u8)
            -> xcb_input_get_device_control_cookie_t;

    pub fn xcb_input_get_device_control_unchecked (c:          *mut xcb_connection_t,
                                                   control_id: u16,
                                                   device_id:  u8)
            -> xcb_input_get_device_control_cookie_t;

    pub fn xcb_input_device_resolution_ctl_resolution_values (R: *const xcb_input_device_resolution_ctl_t)
            -> *mut u32;

    pub fn xcb_input_device_resolution_ctl_resolution_values_length (R: *const xcb_input_device_resolution_ctl_t)
            -> c_int;

    pub fn xcb_input_device_resolution_ctl_resolution_values_end (R: *const xcb_input_device_resolution_ctl_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_resolution_ctl_next (i: *mut xcb_input_device_resolution_ctl_iterator_t);

    pub fn xcb_input_device_resolution_ctl_end (i: *mut xcb_input_device_resolution_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_abs_calib_ctl_next (i: *mut xcb_input_device_abs_calib_ctl_iterator_t);

    pub fn xcb_input_device_abs_calib_ctl_end (i: *mut xcb_input_device_abs_calib_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_abs_area_ctrl_next (i: *mut xcb_input_device_abs_area_ctrl_iterator_t);

    pub fn xcb_input_device_abs_area_ctrl_end (i: *mut xcb_input_device_abs_area_ctrl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_core_ctrl_next (i: *mut xcb_input_device_core_ctrl_iterator_t);

    pub fn xcb_input_device_core_ctrl_end (i: *mut xcb_input_device_core_ctrl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_enable_ctrl_next (i: *mut xcb_input_device_enable_ctrl_iterator_t);

    pub fn xcb_input_device_enable_ctrl_end (i: *mut xcb_input_device_enable_ctrl_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_ctl_uninterpreted_data (R: *const xcb_input_device_ctl_t)
            -> *mut u8;

    pub fn xcb_input_device_ctl_uninterpreted_data_length (R: *const xcb_input_device_ctl_t)
            -> c_int;

    pub fn xcb_input_device_ctl_uninterpreted_data_end (R: *const xcb_input_device_ctl_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_ctl_next (i: *mut xcb_input_device_ctl_iterator_t);

    pub fn xcb_input_device_ctl_end (i: *mut xcb_input_device_ctl_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_change_device_control_reply (c:      *mut xcb_connection_t,
                                                  cookie: xcb_input_change_device_control_cookie_t,
                                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_change_device_control_reply_t;

    pub fn xcb_input_change_device_control (c:          *mut xcb_connection_t,
                                            control_id: u16,
                                            device_id:  u8,
                                            control:    *mut xcb_input_device_ctl_t)
            -> xcb_input_change_device_control_cookie_t;

    pub fn xcb_input_change_device_control_unchecked (c:          *mut xcb_connection_t,
                                                      control_id: u16,
                                                      device_id:  u8,
                                                      control:    *mut xcb_input_device_ctl_t)
            -> xcb_input_change_device_control_cookie_t;

    pub fn xcb_input_list_device_properties_atoms (R: *const xcb_input_list_device_properties_reply_t)
            -> *mut xcb_atom_t;

    pub fn xcb_input_list_device_properties_atoms_length (R: *const xcb_input_list_device_properties_reply_t)
            -> c_int;

    pub fn xcb_input_list_device_properties_atoms_end (R: *const xcb_input_list_device_properties_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_list_device_properties_reply (c:      *mut xcb_connection_t,
                                                   cookie: xcb_input_list_device_properties_cookie_t,
                                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_list_device_properties_reply_t;

    pub fn xcb_input_list_device_properties (c:         *mut xcb_connection_t,
                                             device_id: u8)
            -> xcb_input_list_device_properties_cookie_t;

    pub fn xcb_input_list_device_properties_unchecked (c:         *mut xcb_connection_t,
                                                       device_id: u8)
            -> xcb_input_list_device_properties_cookie_t;

    pub fn xcb_input_change_device_property_items_data_8 (S: *const xcb_input_change_device_property_items_t)
            -> *mut u8;

    pub fn xcb_input_change_device_property_items_data_8_length (R: *const xcb_input_change_device_property_request_t,
                                                                 S: *const xcb_input_change_device_property_items_t)
            -> c_int;

    pub fn xcb_input_change_device_property_items_data_8_end (R: *const xcb_input_change_device_property_request_t,
                                                              S: *const xcb_input_change_device_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_change_device_property_items_data_16 (S: *const xcb_input_change_device_property_items_t)
            -> *mut u16;

    pub fn xcb_input_change_device_property_items_data_16_length (R: *const xcb_input_change_device_property_request_t,
                                                                  S: *const xcb_input_change_device_property_items_t)
            -> c_int;

    pub fn xcb_input_change_device_property_items_data_16_end (R: *const xcb_input_change_device_property_request_t,
                                                               S: *const xcb_input_change_device_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_change_device_property_items_data_32 (S: *const xcb_input_change_device_property_items_t)
            -> *mut u32;

    pub fn xcb_input_change_device_property_items_data_32_length (R: *const xcb_input_change_device_property_request_t,
                                                                  S: *const xcb_input_change_device_property_items_t)
            -> c_int;

    pub fn xcb_input_change_device_property_items_data_32_end (R: *const xcb_input_change_device_property_request_t,
                                                               S: *const xcb_input_change_device_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_change_device_property (c:         *mut xcb_connection_t,
                                             property:  xcb_atom_t,
                                             type_:     xcb_atom_t,
                                             device_id: u8,
                                             format:    u8,
                                             mode:      u8,
                                             num_items: u32,
                                             items:     *const xcb_input_change_device_property_items_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_change_device_property_checked (c:         *mut xcb_connection_t,
                                                     property:  xcb_atom_t,
                                                     type_:     xcb_atom_t,
                                                     device_id: u8,
                                                     format:    u8,
                                                     mode:      u8,
                                                     num_items: u32,
                                                     items:     *const xcb_input_change_device_property_items_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_delete_device_property (c:         *mut xcb_connection_t,
                                             property:  xcb_atom_t,
                                             device_id: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_delete_device_property_checked (c:         *mut xcb_connection_t,
                                                     property:  xcb_atom_t,
                                                     device_id: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_input_get_device_property_items_data_8 (S: *const xcb_input_get_device_property_items_t)
            -> *mut u8;

    pub fn xcb_input_get_device_property_items_data_8_length (R: *const xcb_input_get_device_property_reply_t,
                                                              S: *const xcb_input_get_device_property_items_t)
            -> c_int;

    pub fn xcb_input_get_device_property_items_data_8_end (R: *const xcb_input_get_device_property_reply_t,
                                                           S: *const xcb_input_get_device_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_get_device_property_items_data_16 (S: *const xcb_input_get_device_property_items_t)
            -> *mut u16;

    pub fn xcb_input_get_device_property_items_data_16_length (R: *const xcb_input_get_device_property_reply_t,
                                                               S: *const xcb_input_get_device_property_items_t)
            -> c_int;

    pub fn xcb_input_get_device_property_items_data_16_end (R: *const xcb_input_get_device_property_reply_t,
                                                            S: *const xcb_input_get_device_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_get_device_property_items_data_32 (S: *const xcb_input_get_device_property_items_t)
            -> *mut u32;

    pub fn xcb_input_get_device_property_items_data_32_length (R: *const xcb_input_get_device_property_reply_t,
                                                               S: *const xcb_input_get_device_property_items_t)
            -> c_int;

    pub fn xcb_input_get_device_property_items_data_32_end (R: *const xcb_input_get_device_property_reply_t,
                                                            S: *const xcb_input_get_device_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_get_device_property_items (R: *const xcb_input_get_device_property_reply_t)
            -> *mut c_void;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_get_device_property_reply (c:      *mut xcb_connection_t,
                                                cookie: xcb_input_get_device_property_cookie_t,
                                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_get_device_property_reply_t;

    pub fn xcb_input_get_device_property (c:         *mut xcb_connection_t,
                                          property:  xcb_atom_t,
                                          type_:     xcb_atom_t,
                                          offset:    u32,
                                          len:       u32,
                                          device_id: u8,
                                          delete:    u8)
            -> xcb_input_get_device_property_cookie_t;

    pub fn xcb_input_get_device_property_unchecked (c:         *mut xcb_connection_t,
                                                    property:  xcb_atom_t,
                                                    type_:     xcb_atom_t,
                                                    offset:    u32,
                                                    len:       u32,
                                                    device_id: u8,
                                                    delete:    u8)
            -> xcb_input_get_device_property_cookie_t;

    pub fn xcb_input_group_info_next (i: *mut xcb_input_group_info_iterator_t);

    pub fn xcb_input_group_info_end (i: *mut xcb_input_group_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_modifier_info_next (i: *mut xcb_input_modifier_info_iterator_t);

    pub fn xcb_input_modifier_info_end (i: *mut xcb_input_modifier_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_query_pointer_buttons (R: *const xcb_input_xi_query_pointer_reply_t)
            -> *mut u32;

    pub fn xcb_input_xi_query_pointer_buttons_length (R: *const xcb_input_xi_query_pointer_reply_t)
            -> c_int;

    pub fn xcb_input_xi_query_pointer_buttons_end (R: *const xcb_input_xi_query_pointer_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_query_pointer_reply (c:      *mut xcb_connection_t,
                                             cookie: xcb_input_xi_query_pointer_cookie_t,
                                             error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_query_pointer_reply_t;

    pub fn xcb_input_xi_query_pointer (c:        *mut xcb_connection_t,
                                       window:   xcb_window_t,
                                       deviceid: xcb_input_device_id_t)
            -> xcb_input_xi_query_pointer_cookie_t;

    pub fn xcb_input_xi_query_pointer_unchecked (c:        *mut xcb_connection_t,
                                                 window:   xcb_window_t,
                                                 deviceid: xcb_input_device_id_t)
            -> xcb_input_xi_query_pointer_cookie_t;

    pub fn xcb_input_xi_warp_pointer (c:          *mut xcb_connection_t,
                                      src_win:    xcb_window_t,
                                      dst_win:    xcb_window_t,
                                      src_x:      xcb_input_fp1616_t,
                                      src_y:      xcb_input_fp1616_t,
                                      src_width:  u16,
                                      src_height: u16,
                                      dst_x:      xcb_input_fp1616_t,
                                      dst_y:      xcb_input_fp1616_t,
                                      deviceid:   xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_warp_pointer_checked (c:          *mut xcb_connection_t,
                                              src_win:    xcb_window_t,
                                              dst_win:    xcb_window_t,
                                              src_x:      xcb_input_fp1616_t,
                                              src_y:      xcb_input_fp1616_t,
                                              src_width:  u16,
                                              src_height: u16,
                                              dst_x:      xcb_input_fp1616_t,
                                              dst_y:      xcb_input_fp1616_t,
                                              deviceid:   xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_change_cursor (c:        *mut xcb_connection_t,
                                       window:   xcb_window_t,
                                       cursor:   xcb_cursor_t,
                                       deviceid: xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_change_cursor_checked (c:        *mut xcb_connection_t,
                                               window:   xcb_window_t,
                                               cursor:   xcb_cursor_t,
                                               deviceid: xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_add_master_name (R: *const xcb_input_add_master_t)
            -> *mut c_char;

    pub fn xcb_input_add_master_name_length (R: *const xcb_input_add_master_t)
            -> c_int;

    pub fn xcb_input_add_master_name_end (R: *const xcb_input_add_master_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_add_master_next (i: *mut xcb_input_add_master_iterator_t);

    pub fn xcb_input_add_master_end (i: *mut xcb_input_add_master_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_remove_master_next (i: *mut xcb_input_remove_master_iterator_t);

    pub fn xcb_input_remove_master_end (i: *mut xcb_input_remove_master_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_attach_slave_next (i: *mut xcb_input_attach_slave_iterator_t);

    pub fn xcb_input_attach_slave_end (i: *mut xcb_input_attach_slave_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_detach_slave_next (i: *mut xcb_input_detach_slave_iterator_t);

    pub fn xcb_input_detach_slave_end (i: *mut xcb_input_detach_slave_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_hierarchy_change_uninterpreted_data (R: *const xcb_input_hierarchy_change_t)
            -> *mut u8;

    pub fn xcb_input_hierarchy_change_uninterpreted_data_length (R: *const xcb_input_hierarchy_change_t)
            -> c_int;

    pub fn xcb_input_hierarchy_change_uninterpreted_data_end (R: *const xcb_input_hierarchy_change_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_hierarchy_change_next (i: *mut xcb_input_hierarchy_change_iterator_t);

    pub fn xcb_input_hierarchy_change_end (i: *mut xcb_input_hierarchy_change_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_change_hierarchy (c:           *mut xcb_connection_t,
                                          num_changes: u8,
                                          changes:     *const xcb_input_hierarchy_change_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_change_hierarchy_checked (c:           *mut xcb_connection_t,
                                                  num_changes: u8,
                                                  changes:     *const xcb_input_hierarchy_change_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_set_client_pointer (c:        *mut xcb_connection_t,
                                            window:   xcb_window_t,
                                            deviceid: xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_set_client_pointer_checked (c:        *mut xcb_connection_t,
                                                    window:   xcb_window_t,
                                                    deviceid: xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_get_client_pointer_reply (c:      *mut xcb_connection_t,
                                                  cookie: xcb_input_xi_get_client_pointer_cookie_t,
                                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_get_client_pointer_reply_t;

    pub fn xcb_input_xi_get_client_pointer (c:      *mut xcb_connection_t,
                                            window: xcb_window_t)
            -> xcb_input_xi_get_client_pointer_cookie_t;

    pub fn xcb_input_xi_get_client_pointer_unchecked (c:      *mut xcb_connection_t,
                                                      window: xcb_window_t)
            -> xcb_input_xi_get_client_pointer_cookie_t;

    pub fn xcb_input_event_mask_mask (R: *const xcb_input_event_mask_t)
            -> *mut u32;

    pub fn xcb_input_event_mask_mask_length (R: *const xcb_input_event_mask_t)
            -> c_int;

    pub fn xcb_input_event_mask_mask_end (R: *const xcb_input_event_mask_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_event_mask_next (i: *mut xcb_input_event_mask_iterator_t);

    pub fn xcb_input_event_mask_end (i: *mut xcb_input_event_mask_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_select_events (c:        *mut xcb_connection_t,
                                       window:   xcb_window_t,
                                       num_mask: u16,
                                       masks:    *const xcb_input_event_mask_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_select_events_checked (c:        *mut xcb_connection_t,
                                               window:   xcb_window_t,
                                               num_mask: u16,
                                               masks:    *const xcb_input_event_mask_t)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_query_version_reply (c:      *mut xcb_connection_t,
                                             cookie: xcb_input_xi_query_version_cookie_t,
                                             error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_query_version_reply_t;

    pub fn xcb_input_xi_query_version (c:             *mut xcb_connection_t,
                                       major_version: u16,
                                       minor_version: u16)
            -> xcb_input_xi_query_version_cookie_t;

    pub fn xcb_input_xi_query_version_unchecked (c:             *mut xcb_connection_t,
                                                 major_version: u16,
                                                 minor_version: u16)
            -> xcb_input_xi_query_version_cookie_t;

    pub fn xcb_input_button_class_state (R: *const xcb_input_button_class_t)
            -> *mut u32;

    pub fn xcb_input_button_class_state_length (R: *const xcb_input_button_class_t)
            -> c_int;

    pub fn xcb_input_button_class_state_end (R: *const xcb_input_button_class_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_button_class_labels (R: *const xcb_input_button_class_t)
            -> *mut xcb_atom_t;

    pub fn xcb_input_button_class_labels_length (R: *const xcb_input_button_class_t)
            -> c_int;

    pub fn xcb_input_button_class_labels_end (R: *const xcb_input_button_class_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_button_class_next (i: *mut xcb_input_button_class_iterator_t);

    pub fn xcb_input_button_class_end (i: *mut xcb_input_button_class_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_key_class_keys (R: *const xcb_input_key_class_t)
            -> *mut u32;

    pub fn xcb_input_key_class_keys_length (R: *const xcb_input_key_class_t)
            -> c_int;

    pub fn xcb_input_key_class_keys_end (R: *const xcb_input_key_class_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_key_class_next (i: *mut xcb_input_key_class_iterator_t);

    pub fn xcb_input_key_class_end (i: *mut xcb_input_key_class_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_scroll_class_next (i: *mut xcb_input_scroll_class_iterator_t);

    pub fn xcb_input_scroll_class_end (i: *mut xcb_input_scroll_class_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_touch_class_next (i: *mut xcb_input_touch_class_iterator_t);

    pub fn xcb_input_touch_class_end (i: *mut xcb_input_touch_class_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_valuator_class_next (i: *mut xcb_input_valuator_class_iterator_t);

    pub fn xcb_input_valuator_class_end (i: *mut xcb_input_valuator_class_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_class_uninterpreted_data (R: *const xcb_input_device_class_t)
            -> *mut u8;

    pub fn xcb_input_device_class_uninterpreted_data_length (R: *const xcb_input_device_class_t)
            -> c_int;

    pub fn xcb_input_device_class_uninterpreted_data_end (R: *const xcb_input_device_class_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_device_class_next (i: *mut xcb_input_device_class_iterator_t);

    pub fn xcb_input_device_class_end (i: *mut xcb_input_device_class_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_device_info_name (R: *const xcb_input_xi_device_info_t)
            -> *mut c_char;

    pub fn xcb_input_xi_device_info_name_length (R: *const xcb_input_xi_device_info_t)
            -> c_int;

    pub fn xcb_input_xi_device_info_name_end (R: *const xcb_input_xi_device_info_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_device_info_classes_length (R: *const xcb_input_xi_device_info_t)
            -> c_int;

    pub fn xcb_input_xi_device_info_classes_iterator<'a> (R: *const xcb_input_xi_device_info_t)
            -> xcb_input_device_class_iterator_t<'a>;

    pub fn xcb_input_xi_device_info_next (i: *mut xcb_input_xi_device_info_iterator_t);

    pub fn xcb_input_xi_device_info_end (i: *mut xcb_input_xi_device_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_query_device_infos_length (R: *const xcb_input_xi_query_device_reply_t)
            -> c_int;

    pub fn xcb_input_xi_query_device_infos_iterator<'a> (R: *const xcb_input_xi_query_device_reply_t)
            -> xcb_input_xi_device_info_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_query_device_reply (c:      *mut xcb_connection_t,
                                            cookie: xcb_input_xi_query_device_cookie_t,
                                            error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_query_device_reply_t;

    pub fn xcb_input_xi_query_device (c:        *mut xcb_connection_t,
                                      deviceid: xcb_input_device_id_t)
            -> xcb_input_xi_query_device_cookie_t;

    pub fn xcb_input_xi_query_device_unchecked (c:        *mut xcb_connection_t,
                                                deviceid: xcb_input_device_id_t)
            -> xcb_input_xi_query_device_cookie_t;

    pub fn xcb_input_xi_set_focus (c:        *mut xcb_connection_t,
                                   window:   xcb_window_t,
                                   time:     xcb_timestamp_t,
                                   deviceid: xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_set_focus_checked (c:        *mut xcb_connection_t,
                                           window:   xcb_window_t,
                                           time:     xcb_timestamp_t,
                                           deviceid: xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_get_focus_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_input_xi_get_focus_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_get_focus_reply_t;

    pub fn xcb_input_xi_get_focus (c:        *mut xcb_connection_t,
                                   deviceid: xcb_input_device_id_t)
            -> xcb_input_xi_get_focus_cookie_t;

    pub fn xcb_input_xi_get_focus_unchecked (c:        *mut xcb_connection_t,
                                             deviceid: xcb_input_device_id_t)
            -> xcb_input_xi_get_focus_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_grab_device_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_input_xi_grab_device_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_grab_device_reply_t;

    pub fn xcb_input_xi_grab_device (c:                  *mut xcb_connection_t,
                                     window:             xcb_window_t,
                                     time:               xcb_timestamp_t,
                                     cursor:             xcb_cursor_t,
                                     deviceid:           xcb_input_device_id_t,
                                     mode:               u8,
                                     paired_device_mode: u8,
                                     owner_events:       u8,
                                     mask_len:           u16,
                                     mask:               *const u32)
            -> xcb_input_xi_grab_device_cookie_t;

    pub fn xcb_input_xi_grab_device_unchecked (c:                  *mut xcb_connection_t,
                                               window:             xcb_window_t,
                                               time:               xcb_timestamp_t,
                                               cursor:             xcb_cursor_t,
                                               deviceid:           xcb_input_device_id_t,
                                               mode:               u8,
                                               paired_device_mode: u8,
                                               owner_events:       u8,
                                               mask_len:           u16,
                                               mask:               *const u32)
            -> xcb_input_xi_grab_device_cookie_t;

    pub fn xcb_input_xi_ungrab_device (c:        *mut xcb_connection_t,
                                       time:     xcb_timestamp_t,
                                       deviceid: xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_ungrab_device_checked (c:        *mut xcb_connection_t,
                                               time:     xcb_timestamp_t,
                                               deviceid: xcb_input_device_id_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_allow_events (c:           *mut xcb_connection_t,
                                      time:        xcb_timestamp_t,
                                      deviceid:    xcb_input_device_id_t,
                                      event_mode:  u8,
                                      touchid:     u32,
                                      grab_window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_allow_events_checked (c:           *mut xcb_connection_t,
                                              time:        xcb_timestamp_t,
                                              deviceid:    xcb_input_device_id_t,
                                              event_mode:  u8,
                                              touchid:     u32,
                                              grab_window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_grab_modifier_info_next (i: *mut xcb_input_grab_modifier_info_iterator_t);

    pub fn xcb_input_grab_modifier_info_end (i: *mut xcb_input_grab_modifier_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_passive_grab_device_modifiers (R: *const xcb_input_xi_passive_grab_device_reply_t)
            -> *mut xcb_input_grab_modifier_info_t;

    pub fn xcb_input_xi_passive_grab_device_modifiers_length (R: *const xcb_input_xi_passive_grab_device_reply_t)
            -> c_int;

    pub fn xcb_input_xi_passive_grab_device_modifiers_iterator (R: *const xcb_input_xi_passive_grab_device_reply_t)
            -> xcb_input_grab_modifier_info_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_passive_grab_device_reply (c:      *mut xcb_connection_t,
                                                   cookie: xcb_input_xi_passive_grab_device_cookie_t,
                                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_passive_grab_device_reply_t;

    pub fn xcb_input_xi_passive_grab_device (c:                  *mut xcb_connection_t,
                                             time:               xcb_timestamp_t,
                                             grab_window:        xcb_window_t,
                                             cursor:             xcb_cursor_t,
                                             detail:             u32,
                                             deviceid:           xcb_input_device_id_t,
                                             num_modifiers:      u16,
                                             mask_len:           u16,
                                             grab_type:          u8,
                                             grab_mode:          u8,
                                             paired_device_mode: u8,
                                             owner_events:       u8,
                                             mask:               *const u32,
                                             modifiers:          *const u32)
            -> xcb_input_xi_passive_grab_device_cookie_t;

    pub fn xcb_input_xi_passive_grab_device_unchecked (c:                  *mut xcb_connection_t,
                                                       time:               xcb_timestamp_t,
                                                       grab_window:        xcb_window_t,
                                                       cursor:             xcb_cursor_t,
                                                       detail:             u32,
                                                       deviceid:           xcb_input_device_id_t,
                                                       num_modifiers:      u16,
                                                       mask_len:           u16,
                                                       grab_type:          u8,
                                                       grab_mode:          u8,
                                                       paired_device_mode: u8,
                                                       owner_events:       u8,
                                                       mask:               *const u32,
                                                       modifiers:          *const u32)
            -> xcb_input_xi_passive_grab_device_cookie_t;

    pub fn xcb_input_xi_passive_ungrab_device (c:             *mut xcb_connection_t,
                                               grab_window:   xcb_window_t,
                                               detail:        u32,
                                               deviceid:      xcb_input_device_id_t,
                                               num_modifiers: u16,
                                               grab_type:     u8,
                                               modifiers:     *const u32)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_passive_ungrab_device_checked (c:             *mut xcb_connection_t,
                                                       grab_window:   xcb_window_t,
                                                       detail:        u32,
                                                       deviceid:      xcb_input_device_id_t,
                                                       num_modifiers: u16,
                                                       grab_type:     u8,
                                                       modifiers:     *const u32)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_list_properties_properties (R: *const xcb_input_xi_list_properties_reply_t)
            -> *mut xcb_atom_t;

    pub fn xcb_input_xi_list_properties_properties_length (R: *const xcb_input_xi_list_properties_reply_t)
            -> c_int;

    pub fn xcb_input_xi_list_properties_properties_end (R: *const xcb_input_xi_list_properties_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_list_properties_reply (c:      *mut xcb_connection_t,
                                               cookie: xcb_input_xi_list_properties_cookie_t,
                                               error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_list_properties_reply_t;

    pub fn xcb_input_xi_list_properties (c:        *mut xcb_connection_t,
                                         deviceid: xcb_input_device_id_t)
            -> xcb_input_xi_list_properties_cookie_t;

    pub fn xcb_input_xi_list_properties_unchecked (c:        *mut xcb_connection_t,
                                                   deviceid: xcb_input_device_id_t)
            -> xcb_input_xi_list_properties_cookie_t;

    pub fn xcb_input_xi_change_property_items_data_8 (S: *const xcb_input_xi_change_property_items_t)
            -> *mut u8;

    pub fn xcb_input_xi_change_property_items_data_8_length (R: *const xcb_input_xi_change_property_request_t,
                                                             S: *const xcb_input_xi_change_property_items_t)
            -> c_int;

    pub fn xcb_input_xi_change_property_items_data_8_end (R: *const xcb_input_xi_change_property_request_t,
                                                          S: *const xcb_input_xi_change_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_change_property_items_data_16 (S: *const xcb_input_xi_change_property_items_t)
            -> *mut u16;

    pub fn xcb_input_xi_change_property_items_data_16_length (R: *const xcb_input_xi_change_property_request_t,
                                                              S: *const xcb_input_xi_change_property_items_t)
            -> c_int;

    pub fn xcb_input_xi_change_property_items_data_16_end (R: *const xcb_input_xi_change_property_request_t,
                                                           S: *const xcb_input_xi_change_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_change_property_items_data_32 (S: *const xcb_input_xi_change_property_items_t)
            -> *mut u32;

    pub fn xcb_input_xi_change_property_items_data_32_length (R: *const xcb_input_xi_change_property_request_t,
                                                              S: *const xcb_input_xi_change_property_items_t)
            -> c_int;

    pub fn xcb_input_xi_change_property_items_data_32_end (R: *const xcb_input_xi_change_property_request_t,
                                                           S: *const xcb_input_xi_change_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_change_property (c:         *mut xcb_connection_t,
                                         deviceid:  xcb_input_device_id_t,
                                         mode:      u8,
                                         format:    u8,
                                         property:  xcb_atom_t,
                                         type_:     xcb_atom_t,
                                         num_items: u32,
                                         items:     *const xcb_input_xi_change_property_items_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_change_property_checked (c:         *mut xcb_connection_t,
                                                 deviceid:  xcb_input_device_id_t,
                                                 mode:      u8,
                                                 format:    u8,
                                                 property:  xcb_atom_t,
                                                 type_:     xcb_atom_t,
                                                 num_items: u32,
                                                 items:     *const xcb_input_xi_change_property_items_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_delete_property (c:        *mut xcb_connection_t,
                                         deviceid: xcb_input_device_id_t,
                                         property: xcb_atom_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_delete_property_checked (c:        *mut xcb_connection_t,
                                                 deviceid: xcb_input_device_id_t,
                                                 property: xcb_atom_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_get_property_items_data_8 (S: *const xcb_input_xi_get_property_items_t)
            -> *mut u8;

    pub fn xcb_input_xi_get_property_items_data_8_length (R: *const xcb_input_xi_get_property_reply_t,
                                                          S: *const xcb_input_xi_get_property_items_t)
            -> c_int;

    pub fn xcb_input_xi_get_property_items_data_8_end (R: *const xcb_input_xi_get_property_reply_t,
                                                       S: *const xcb_input_xi_get_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_get_property_items_data_16 (S: *const xcb_input_xi_get_property_items_t)
            -> *mut u16;

    pub fn xcb_input_xi_get_property_items_data_16_length (R: *const xcb_input_xi_get_property_reply_t,
                                                           S: *const xcb_input_xi_get_property_items_t)
            -> c_int;

    pub fn xcb_input_xi_get_property_items_data_16_end (R: *const xcb_input_xi_get_property_reply_t,
                                                        S: *const xcb_input_xi_get_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_get_property_items_data_32 (S: *const xcb_input_xi_get_property_items_t)
            -> *mut u32;

    pub fn xcb_input_xi_get_property_items_data_32_length (R: *const xcb_input_xi_get_property_reply_t,
                                                           S: *const xcb_input_xi_get_property_items_t)
            -> c_int;

    pub fn xcb_input_xi_get_property_items_data_32_end (R: *const xcb_input_xi_get_property_reply_t,
                                                        S: *const xcb_input_xi_get_property_items_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_get_property_items (R: *const xcb_input_xi_get_property_reply_t)
            -> *mut c_void;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_get_property_reply (c:      *mut xcb_connection_t,
                                            cookie: xcb_input_xi_get_property_cookie_t,
                                            error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_get_property_reply_t;

    pub fn xcb_input_xi_get_property (c:        *mut xcb_connection_t,
                                      deviceid: xcb_input_device_id_t,
                                      delete:   u8,
                                      property: xcb_atom_t,
                                      type_:    xcb_atom_t,
                                      offset:   u32,
                                      len:      u32)
            -> xcb_input_xi_get_property_cookie_t;

    pub fn xcb_input_xi_get_property_unchecked (c:        *mut xcb_connection_t,
                                                deviceid: xcb_input_device_id_t,
                                                delete:   u8,
                                                property: xcb_atom_t,
                                                type_:    xcb_atom_t,
                                                offset:   u32,
                                                len:      u32)
            -> xcb_input_xi_get_property_cookie_t;

    pub fn xcb_input_xi_get_selected_events_masks_length (R: *const xcb_input_xi_get_selected_events_reply_t)
            -> c_int;

    pub fn xcb_input_xi_get_selected_events_masks_iterator<'a> (R: *const xcb_input_xi_get_selected_events_reply_t)
            -> xcb_input_event_mask_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_input_xi_get_selected_events_reply (c:      *mut xcb_connection_t,
                                                   cookie: xcb_input_xi_get_selected_events_cookie_t,
                                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_input_xi_get_selected_events_reply_t;

    pub fn xcb_input_xi_get_selected_events (c:      *mut xcb_connection_t,
                                             window: xcb_window_t)
            -> xcb_input_xi_get_selected_events_cookie_t;

    pub fn xcb_input_xi_get_selected_events_unchecked (c:      *mut xcb_connection_t,
                                                       window: xcb_window_t)
            -> xcb_input_xi_get_selected_events_cookie_t;

    pub fn xcb_input_barrier_release_pointer_info_next (i: *mut xcb_input_barrier_release_pointer_info_iterator_t);

    pub fn xcb_input_barrier_release_pointer_info_end (i: *mut xcb_input_barrier_release_pointer_info_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_input_xi_barrier_release_pointer (c:            *mut xcb_connection_t,
                                                 num_barriers: u32,
                                                 barriers:     *const xcb_input_barrier_release_pointer_info_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_xi_barrier_release_pointer_checked (c:            *mut xcb_connection_t,
                                                         num_barriers: u32,
                                                         barriers:     *const xcb_input_barrier_release_pointer_info_t)
            -> xcb_void_cookie_t;

    pub fn xcb_input_hierarchy_info_next (i: *mut xcb_input_hierarchy_info_iterator_t);

    pub fn xcb_input_hierarchy_info_end (i: *mut xcb_input_hierarchy_info_iterator_t)
            -> xcb_generic_iterator_t;

} // extern
