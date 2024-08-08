// Generated automatically from xproto.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use libc::{c_char, c_int, c_uint, c_void};
use std;


#[repr(C)]
pub struct xcb_char2b_t {
    pub byte1: u8,
    pub byte2: u8,
}

impl Copy for xcb_char2b_t {}
impl Clone for xcb_char2b_t {
    fn clone(&self) -> xcb_char2b_t { *self }
}

#[repr(C)]
pub struct xcb_char2b_iterator_t {
    pub data:  *mut xcb_char2b_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_window_t = u32;

#[repr(C)]
pub struct xcb_window_iterator_t {
    pub data:  *mut xcb_window_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_pixmap_t = u32;

#[repr(C)]
pub struct xcb_pixmap_iterator_t {
    pub data:  *mut xcb_pixmap_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_cursor_t = u32;

#[repr(C)]
pub struct xcb_cursor_iterator_t {
    pub data:  *mut xcb_cursor_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_font_t = u32;

#[repr(C)]
pub struct xcb_font_iterator_t {
    pub data:  *mut xcb_font_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_gcontext_t = u32;

#[repr(C)]
pub struct xcb_gcontext_iterator_t {
    pub data:  *mut xcb_gcontext_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_colormap_t = u32;

#[repr(C)]
pub struct xcb_colormap_iterator_t {
    pub data:  *mut xcb_colormap_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_atom_t = u32;

#[repr(C)]
pub struct xcb_atom_iterator_t {
    pub data:  *mut xcb_atom_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_drawable_t = u32;

#[repr(C)]
pub struct xcb_drawable_iterator_t {
    pub data:  *mut xcb_drawable_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_fontable_t = u32;

#[repr(C)]
pub struct xcb_fontable_iterator_t {
    pub data:  *mut xcb_fontable_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_visualid_t = u32;

#[repr(C)]
pub struct xcb_visualid_iterator_t {
    pub data:  *mut xcb_visualid_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_timestamp_t = u32;

#[repr(C)]
pub struct xcb_timestamp_iterator_t {
    pub data:  *mut xcb_timestamp_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_keysym_t = u32;

#[repr(C)]
pub struct xcb_keysym_iterator_t {
    pub data:  *mut xcb_keysym_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_keycode_t = u8;

#[repr(C)]
pub struct xcb_keycode_iterator_t {
    pub data:  *mut xcb_keycode_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_button_t = u8;

#[repr(C)]
pub struct xcb_button_iterator_t {
    pub data:  *mut xcb_button_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_point_t {
    pub x: i16,
    pub y: i16,
}

impl Copy for xcb_point_t {}
impl Clone for xcb_point_t {
    fn clone(&self) -> xcb_point_t { *self }
}

#[repr(C)]
pub struct xcb_point_iterator_t {
    pub data:  *mut xcb_point_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_rectangle_t {
    pub x:      i16,
    pub y:      i16,
    pub width:  u16,
    pub height: u16,
}

impl Copy for xcb_rectangle_t {}
impl Clone for xcb_rectangle_t {
    fn clone(&self) -> xcb_rectangle_t { *self }
}

#[repr(C)]
pub struct xcb_rectangle_iterator_t {
    pub data:  *mut xcb_rectangle_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_arc_t {
    pub x:      i16,
    pub y:      i16,
    pub width:  u16,
    pub height: u16,
    pub angle1: i16,
    pub angle2: i16,
}

impl Copy for xcb_arc_t {}
impl Clone for xcb_arc_t {
    fn clone(&self) -> xcb_arc_t { *self }
}

#[repr(C)]
pub struct xcb_arc_iterator_t {
    pub data:  *mut xcb_arc_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_format_t {
    pub depth:          u8,
    pub bits_per_pixel: u8,
    pub scanline_pad:   u8,
    pub pad0:           [u8; 5],
}

impl Copy for xcb_format_t {}
impl Clone for xcb_format_t {
    fn clone(&self) -> xcb_format_t { *self }
}

#[repr(C)]
pub struct xcb_format_iterator_t {
    pub data:  *mut xcb_format_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_visual_class_t = u32;
pub const XCB_VISUAL_CLASS_STATIC_GRAY : xcb_visual_class_t = 0x00;
pub const XCB_VISUAL_CLASS_GRAY_SCALE  : xcb_visual_class_t = 0x01;
pub const XCB_VISUAL_CLASS_STATIC_COLOR: xcb_visual_class_t = 0x02;
pub const XCB_VISUAL_CLASS_PSEUDO_COLOR: xcb_visual_class_t = 0x03;
pub const XCB_VISUAL_CLASS_TRUE_COLOR  : xcb_visual_class_t = 0x04;
pub const XCB_VISUAL_CLASS_DIRECT_COLOR: xcb_visual_class_t = 0x05;

#[repr(C)]
pub struct xcb_visualtype_t {
    pub visual_id:          xcb_visualid_t,
    pub class:              u8,
    pub bits_per_rgb_value: u8,
    pub colormap_entries:   u16,
    pub red_mask:           u32,
    pub green_mask:         u32,
    pub blue_mask:          u32,
    pub pad0:               [u8; 4],
}

impl Copy for xcb_visualtype_t {}
impl Clone for xcb_visualtype_t {
    fn clone(&self) -> xcb_visualtype_t { *self }
}

#[repr(C)]
pub struct xcb_visualtype_iterator_t {
    pub data:  *mut xcb_visualtype_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_depth_t {
    pub depth:       u8,
    pub pad0:        u8,
    pub visuals_len: u16,
    pub pad1:        [u8; 4],
}

#[repr(C)]
pub struct xcb_depth_iterator_t<'a> {
    pub data:  *mut xcb_depth_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_depth_t>,
}

pub type xcb_event_mask_t = u32;
pub const XCB_EVENT_MASK_NO_EVENT             : xcb_event_mask_t =      0x00;
pub const XCB_EVENT_MASK_KEY_PRESS            : xcb_event_mask_t =      0x01;
pub const XCB_EVENT_MASK_KEY_RELEASE          : xcb_event_mask_t =      0x02;
pub const XCB_EVENT_MASK_BUTTON_PRESS         : xcb_event_mask_t =      0x04;
pub const XCB_EVENT_MASK_BUTTON_RELEASE       : xcb_event_mask_t =      0x08;
pub const XCB_EVENT_MASK_ENTER_WINDOW         : xcb_event_mask_t =      0x10;
pub const XCB_EVENT_MASK_LEAVE_WINDOW         : xcb_event_mask_t =      0x20;
pub const XCB_EVENT_MASK_POINTER_MOTION       : xcb_event_mask_t =      0x40;
pub const XCB_EVENT_MASK_POINTER_MOTION_HINT  : xcb_event_mask_t =      0x80;
pub const XCB_EVENT_MASK_BUTTON_1_MOTION      : xcb_event_mask_t =     0x100;
pub const XCB_EVENT_MASK_BUTTON_2_MOTION      : xcb_event_mask_t =     0x200;
pub const XCB_EVENT_MASK_BUTTON_3_MOTION      : xcb_event_mask_t =     0x400;
pub const XCB_EVENT_MASK_BUTTON_4_MOTION      : xcb_event_mask_t =     0x800;
pub const XCB_EVENT_MASK_BUTTON_5_MOTION      : xcb_event_mask_t =    0x1000;
pub const XCB_EVENT_MASK_BUTTON_MOTION        : xcb_event_mask_t =    0x2000;
pub const XCB_EVENT_MASK_KEYMAP_STATE         : xcb_event_mask_t =    0x4000;
pub const XCB_EVENT_MASK_EXPOSURE             : xcb_event_mask_t =    0x8000;
pub const XCB_EVENT_MASK_VISIBILITY_CHANGE    : xcb_event_mask_t =   0x10000;
pub const XCB_EVENT_MASK_STRUCTURE_NOTIFY     : xcb_event_mask_t =   0x20000;
pub const XCB_EVENT_MASK_RESIZE_REDIRECT      : xcb_event_mask_t =   0x40000;
pub const XCB_EVENT_MASK_SUBSTRUCTURE_NOTIFY  : xcb_event_mask_t =   0x80000;
pub const XCB_EVENT_MASK_SUBSTRUCTURE_REDIRECT: xcb_event_mask_t =  0x100000;
pub const XCB_EVENT_MASK_FOCUS_CHANGE         : xcb_event_mask_t =  0x200000;
pub const XCB_EVENT_MASK_PROPERTY_CHANGE      : xcb_event_mask_t =  0x400000;
pub const XCB_EVENT_MASK_COLOR_MAP_CHANGE     : xcb_event_mask_t =  0x800000;
pub const XCB_EVENT_MASK_OWNER_GRAB_BUTTON    : xcb_event_mask_t = 0x1000000;

pub type xcb_backing_store_t = u32;
pub const XCB_BACKING_STORE_NOT_USEFUL : xcb_backing_store_t = 0x00;
pub const XCB_BACKING_STORE_WHEN_MAPPED: xcb_backing_store_t = 0x01;
pub const XCB_BACKING_STORE_ALWAYS     : xcb_backing_store_t = 0x02;

#[repr(C)]
pub struct xcb_screen_t {
    pub root:                  xcb_window_t,
    pub default_colormap:      xcb_colormap_t,
    pub white_pixel:           u32,
    pub black_pixel:           u32,
    pub current_input_masks:   u32,
    pub width_in_pixels:       u16,
    pub height_in_pixels:      u16,
    pub width_in_millimeters:  u16,
    pub height_in_millimeters: u16,
    pub min_installed_maps:    u16,
    pub max_installed_maps:    u16,
    pub root_visual:           xcb_visualid_t,
    pub backing_stores:        u8,
    pub save_unders:           u8,
    pub root_depth:            u8,
    pub allowed_depths_len:    u8,
}

#[repr(C)]
pub struct xcb_screen_iterator_t<'a> {
    pub data:  *mut xcb_screen_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_screen_t>,
}

#[repr(C)]
pub struct xcb_setup_request_t {
    pub byte_order:                      u8,
    pub pad0:                            u8,
    pub protocol_major_version:          u16,
    pub protocol_minor_version:          u16,
    pub authorization_protocol_name_len: u16,
    pub authorization_protocol_data_len: u16,
    pub pad1:                            [u8; 2],
}

#[repr(C)]
pub struct xcb_setup_request_iterator_t<'a> {
    pub data:  *mut xcb_setup_request_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_setup_request_t>,
}

#[repr(C)]
pub struct xcb_setup_failed_t {
    pub status:                 u8,
    pub reason_len:             u8,
    pub protocol_major_version: u16,
    pub protocol_minor_version: u16,
    pub length:                 u16,
}

#[repr(C)]
pub struct xcb_setup_failed_iterator_t<'a> {
    pub data:  *mut xcb_setup_failed_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_setup_failed_t>,
}

#[repr(C)]
pub struct xcb_setup_authenticate_t {
    pub status: u8,
    pub pad0:   [u8; 5],
    pub length: u16,
}

#[repr(C)]
pub struct xcb_setup_authenticate_iterator_t<'a> {
    pub data:  *mut xcb_setup_authenticate_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_setup_authenticate_t>,
}

pub type xcb_image_order_t = u32;
pub const XCB_IMAGE_ORDER_LSB_FIRST: xcb_image_order_t = 0x00;
pub const XCB_IMAGE_ORDER_MSB_FIRST: xcb_image_order_t = 0x01;

#[repr(C)]
pub struct xcb_setup_t {
    pub status:                      u8,
    pub pad0:                        u8,
    pub protocol_major_version:      u16,
    pub protocol_minor_version:      u16,
    pub length:                      u16,
    pub release_number:              u32,
    pub resource_id_base:            u32,
    pub resource_id_mask:            u32,
    pub motion_buffer_size:          u32,
    pub vendor_len:                  u16,
    pub maximum_request_length:      u16,
    pub roots_len:                   u8,
    pub pixmap_formats_len:          u8,
    pub image_byte_order:            u8,
    pub bitmap_format_bit_order:     u8,
    pub bitmap_format_scanline_unit: u8,
    pub bitmap_format_scanline_pad:  u8,
    pub min_keycode:                 xcb_keycode_t,
    pub max_keycode:                 xcb_keycode_t,
    pub pad1:                        [u8; 4],
}

#[repr(C)]
pub struct xcb_setup_iterator_t<'a> {
    pub data:  *mut xcb_setup_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_setup_t>,
}

pub type xcb_mod_mask_t = u32;
pub const XCB_MOD_MASK_SHIFT  : xcb_mod_mask_t =   0x01;
pub const XCB_MOD_MASK_LOCK   : xcb_mod_mask_t =   0x02;
pub const XCB_MOD_MASK_CONTROL: xcb_mod_mask_t =   0x04;
pub const XCB_MOD_MASK_1      : xcb_mod_mask_t =   0x08;
pub const XCB_MOD_MASK_2      : xcb_mod_mask_t =   0x10;
pub const XCB_MOD_MASK_3      : xcb_mod_mask_t =   0x20;
pub const XCB_MOD_MASK_4      : xcb_mod_mask_t =   0x40;
pub const XCB_MOD_MASK_5      : xcb_mod_mask_t =   0x80;
pub const XCB_MOD_MASK_ANY    : xcb_mod_mask_t = 0x8000;

pub type xcb_key_but_mask_t = u32;
pub const XCB_KEY_BUT_MASK_SHIFT   : xcb_key_but_mask_t =   0x01;
pub const XCB_KEY_BUT_MASK_LOCK    : xcb_key_but_mask_t =   0x02;
pub const XCB_KEY_BUT_MASK_CONTROL : xcb_key_but_mask_t =   0x04;
pub const XCB_KEY_BUT_MASK_MOD_1   : xcb_key_but_mask_t =   0x08;
pub const XCB_KEY_BUT_MASK_MOD_2   : xcb_key_but_mask_t =   0x10;
pub const XCB_KEY_BUT_MASK_MOD_3   : xcb_key_but_mask_t =   0x20;
pub const XCB_KEY_BUT_MASK_MOD_4   : xcb_key_but_mask_t =   0x40;
pub const XCB_KEY_BUT_MASK_MOD_5   : xcb_key_but_mask_t =   0x80;
pub const XCB_KEY_BUT_MASK_BUTTON_1: xcb_key_but_mask_t =  0x100;
pub const XCB_KEY_BUT_MASK_BUTTON_2: xcb_key_but_mask_t =  0x200;
pub const XCB_KEY_BUT_MASK_BUTTON_3: xcb_key_but_mask_t =  0x400;
pub const XCB_KEY_BUT_MASK_BUTTON_4: xcb_key_but_mask_t =  0x800;
pub const XCB_KEY_BUT_MASK_BUTTON_5: xcb_key_but_mask_t = 0x1000;

pub type xcb_window_enum_t = u32;
pub const XCB_WINDOW_NONE: xcb_window_enum_t = 0x00;

pub const XCB_KEY_PRESS: u8 = 2;

/// a key was pressed/released
#[repr(C)]
pub struct xcb_key_press_event_t {
    pub response_type: u8,
    /// The keycode (a number representing a physical key on the keyboard) of the key
    /// which was pressed.
    pub detail:        xcb_keycode_t,
    pub sequence:      u16,
    /// Time when the event was generated (in milliseconds).
    pub time:          xcb_timestamp_t,
    /// The root window of `child`.
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    /// The X coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub root_x:        i16,
    /// The Y coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub root_y:        i16,
    /// If `same_screen` is true, this is the X coordinate relative to the `event`
    /// window's origin. Otherwise, `event_x` will be set to zero.
    pub event_x:       i16,
    /// If `same_screen` is true, this is the Y coordinate relative to the `event`
    /// window's origin. Otherwise, `event_y` will be set to zero.
    pub event_y:       i16,
    /// The logical state of the pointer buttons and modifier keys just prior to the
    /// event.
    pub state:         u16,
    /// Whether the `event` window is on the same screen as the `root` window.
    pub same_screen:   u8,
    pub pad0:          u8,
}

impl Copy for xcb_key_press_event_t {}
impl Clone for xcb_key_press_event_t {
    fn clone(&self) -> xcb_key_press_event_t { *self }
}

pub const XCB_KEY_RELEASE: u8 = 3;

pub type xcb_key_release_event_t = xcb_key_press_event_t;

pub type xcb_button_mask_t = u32;
pub const XCB_BUTTON_MASK_1  : xcb_button_mask_t =  0x100;
pub const XCB_BUTTON_MASK_2  : xcb_button_mask_t =  0x200;
pub const XCB_BUTTON_MASK_3  : xcb_button_mask_t =  0x400;
pub const XCB_BUTTON_MASK_4  : xcb_button_mask_t =  0x800;
pub const XCB_BUTTON_MASK_5  : xcb_button_mask_t = 0x1000;
pub const XCB_BUTTON_MASK_ANY: xcb_button_mask_t = 0x8000;

pub const XCB_BUTTON_PRESS: u8 = 4;

/// a mouse button was pressed/released
#[repr(C)]
pub struct xcb_button_press_event_t {
    pub response_type: u8,
    /// The keycode (a number representing a physical key on the keyboard) of the key
    /// which was pressed.
    pub detail:        xcb_button_t,
    pub sequence:      u16,
    /// Time when the event was generated (in milliseconds).
    pub time:          xcb_timestamp_t,
    /// The root window of `child`.
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    /// The X coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub root_x:        i16,
    /// The Y coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub root_y:        i16,
    /// If `same_screen` is true, this is the X coordinate relative to the `event`
    /// window's origin. Otherwise, `event_x` will be set to zero.
    pub event_x:       i16,
    /// If `same_screen` is true, this is the Y coordinate relative to the `event`
    /// window's origin. Otherwise, `event_y` will be set to zero.
    pub event_y:       i16,
    /// The logical state of the pointer buttons and modifier keys just prior to the
    /// event.
    pub state:         u16,
    /// Whether the `event` window is on the same screen as the `root` window.
    pub same_screen:   u8,
    pub pad0:          u8,
}

impl Copy for xcb_button_press_event_t {}
impl Clone for xcb_button_press_event_t {
    fn clone(&self) -> xcb_button_press_event_t { *self }
}

pub const XCB_BUTTON_RELEASE: u8 = 5;

pub type xcb_button_release_event_t = xcb_button_press_event_t;

pub type xcb_motion_t = u32;
pub const XCB_MOTION_NORMAL: xcb_motion_t = 0x00;
pub const XCB_MOTION_HINT  : xcb_motion_t = 0x01;

pub const XCB_MOTION_NOTIFY: u8 = 6;

/// a key was pressed
#[repr(C)]
pub struct xcb_motion_notify_event_t {
    pub response_type: u8,
    /// The keycode (a number representing a physical key on the keyboard) of the key
    /// which was pressed.
    pub detail:        u8,
    pub sequence:      u16,
    /// Time when the event was generated (in milliseconds).
    pub time:          xcb_timestamp_t,
    /// The root window of `child`.
    pub root:          xcb_window_t,
    pub event:         xcb_window_t,
    pub child:         xcb_window_t,
    /// The X coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub root_x:        i16,
    /// The Y coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub root_y:        i16,
    /// If `same_screen` is true, this is the X coordinate relative to the `event`
    /// window's origin. Otherwise, `event_x` will be set to zero.
    pub event_x:       i16,
    /// If `same_screen` is true, this is the Y coordinate relative to the `event`
    /// window's origin. Otherwise, `event_y` will be set to zero.
    pub event_y:       i16,
    /// The logical state of the pointer buttons and modifier keys just prior to the
    /// event.
    pub state:         u16,
    /// Whether the `event` window is on the same screen as the `root` window.
    pub same_screen:   u8,
    pub pad0:          u8,
}

impl Copy for xcb_motion_notify_event_t {}
impl Clone for xcb_motion_notify_event_t {
    fn clone(&self) -> xcb_motion_notify_event_t { *self }
}

pub type xcb_notify_detail_t = u32;
pub const XCB_NOTIFY_DETAIL_ANCESTOR         : xcb_notify_detail_t = 0x00;
pub const XCB_NOTIFY_DETAIL_VIRTUAL          : xcb_notify_detail_t = 0x01;
pub const XCB_NOTIFY_DETAIL_INFERIOR         : xcb_notify_detail_t = 0x02;
pub const XCB_NOTIFY_DETAIL_NONLINEAR        : xcb_notify_detail_t = 0x03;
pub const XCB_NOTIFY_DETAIL_NONLINEAR_VIRTUAL: xcb_notify_detail_t = 0x04;
pub const XCB_NOTIFY_DETAIL_POINTER          : xcb_notify_detail_t = 0x05;
pub const XCB_NOTIFY_DETAIL_POINTER_ROOT     : xcb_notify_detail_t = 0x06;
pub const XCB_NOTIFY_DETAIL_NONE             : xcb_notify_detail_t = 0x07;

pub type xcb_notify_mode_t = u32;
pub const XCB_NOTIFY_MODE_NORMAL       : xcb_notify_mode_t = 0x00;
pub const XCB_NOTIFY_MODE_GRAB         : xcb_notify_mode_t = 0x01;
pub const XCB_NOTIFY_MODE_UNGRAB       : xcb_notify_mode_t = 0x02;
pub const XCB_NOTIFY_MODE_WHILE_GRABBED: xcb_notify_mode_t = 0x03;

pub const XCB_ENTER_NOTIFY: u8 = 7;

/// the pointer is in a different window
#[repr(C)]
pub struct xcb_enter_notify_event_t {
    pub response_type:     u8,
    pub detail:            u8,
    pub sequence:          u16,
    pub time:              xcb_timestamp_t,
    /// The root window for the final cursor position.
    pub root:              xcb_window_t,
    /// The window on which the event was generated.
    pub event:             xcb_window_t,
    /// If the `event` window has subwindows and the final pointer position is in one
    /// of them, then `child` is set to that subwindow, `XCB_WINDOW_NONE` otherwise.
    pub child:             xcb_window_t,
    /// The pointer X coordinate relative to `root`'s origin at the time of the event.
    pub root_x:            i16,
    /// The pointer Y coordinate relative to `root`'s origin at the time of the event.
    pub root_y:            i16,
    /// If `event` is on the same screen as `root`, this is the pointer X coordinate
    /// relative to the event window's origin.
    pub event_x:           i16,
    /// If `event` is on the same screen as `root`, this is the pointer Y coordinate
    /// relative to the event window's origin.
    pub event_y:           i16,
    pub state:             u16,
    ///
    pub mode:              u8,
    pub same_screen_focus: u8,
}

impl Copy for xcb_enter_notify_event_t {}
impl Clone for xcb_enter_notify_event_t {
    fn clone(&self) -> xcb_enter_notify_event_t { *self }
}

pub const XCB_LEAVE_NOTIFY: u8 = 8;

pub type xcb_leave_notify_event_t = xcb_enter_notify_event_t;

pub const XCB_FOCUS_IN: u8 = 9;

/// NOT YET DOCUMENTED
#[repr(C)]
pub struct xcb_focus_in_event_t {
    pub response_type: u8,
    ///
    pub detail:        u8,
    pub sequence:      u16,
    /// The window on which the focus event was generated. This is the window used by
    /// the X server to report the event.
    pub event:         xcb_window_t,
    ///
    pub mode:          u8,
    pub pad0:          [u8; 3],
}

impl Copy for xcb_focus_in_event_t {}
impl Clone for xcb_focus_in_event_t {
    fn clone(&self) -> xcb_focus_in_event_t { *self }
}

pub const XCB_FOCUS_OUT: u8 = 10;

pub type xcb_focus_out_event_t = xcb_focus_in_event_t;

pub const XCB_KEYMAP_NOTIFY: u8 = 11;

#[repr(C)]
pub struct xcb_keymap_notify_event_t {
    pub response_type: u8,
    pub keys:          [u8; 31],
}

impl Copy for xcb_keymap_notify_event_t {}
impl Clone for xcb_keymap_notify_event_t {
    fn clone(&self) -> xcb_keymap_notify_event_t { *self }
}

pub const XCB_EXPOSE: u8 = 12;

/// NOT YET DOCUMENTED
#[repr(C)]
pub struct xcb_expose_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    /// The exposed (damaged) window.
    pub window:        xcb_window_t,
    /// The X coordinate of the left-upper corner of the exposed rectangle, relative to
    /// the `window`'s origin.
    pub x:             u16,
    /// The Y coordinate of the left-upper corner of the exposed rectangle, relative to
    /// the `window`'s origin.
    pub y:             u16,
    /// The width of the exposed rectangle.
    pub width:         u16,
    /// The height of the exposed rectangle.
    pub height:        u16,
    /// The amount of `Expose` events following this one. Simple applications that do
    /// not want to optimize redisplay by distinguishing between subareas of its window
    /// can just ignore all Expose events with nonzero counts and perform full
    /// redisplays on events with zero counts.
    pub count:         u16,
    pub pad1:          [u8; 2],
}

impl Copy for xcb_expose_event_t {}
impl Clone for xcb_expose_event_t {
    fn clone(&self) -> xcb_expose_event_t { *self }
}

pub const XCB_GRAPHICS_EXPOSURE: u8 = 13;

#[repr(C)]
pub struct xcb_graphics_exposure_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub drawable:      xcb_drawable_t,
    pub x:             u16,
    pub y:             u16,
    pub width:         u16,
    pub height:        u16,
    pub minor_opcode:  u16,
    pub count:         u16,
    pub major_opcode:  u8,
    pub pad1:          [u8; 3],
}

impl Copy for xcb_graphics_exposure_event_t {}
impl Clone for xcb_graphics_exposure_event_t {
    fn clone(&self) -> xcb_graphics_exposure_event_t { *self }
}

pub const XCB_NO_EXPOSURE: u8 = 14;

#[repr(C)]
pub struct xcb_no_exposure_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub drawable:      xcb_drawable_t,
    pub minor_opcode:  u16,
    pub major_opcode:  u8,
    pub pad1:          u8,
}

impl Copy for xcb_no_exposure_event_t {}
impl Clone for xcb_no_exposure_event_t {
    fn clone(&self) -> xcb_no_exposure_event_t { *self }
}

pub type xcb_visibility_t = u32;
pub const XCB_VISIBILITY_UNOBSCURED        : xcb_visibility_t = 0x00;
pub const XCB_VISIBILITY_PARTIALLY_OBSCURED: xcb_visibility_t = 0x01;
pub const XCB_VISIBILITY_FULLY_OBSCURED    : xcb_visibility_t = 0x02;

pub const XCB_VISIBILITY_NOTIFY: u8 = 15;

#[repr(C)]
pub struct xcb_visibility_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub window:        xcb_window_t,
    pub state:         u8,
    pub pad1:          [u8; 3],
}

impl Copy for xcb_visibility_notify_event_t {}
impl Clone for xcb_visibility_notify_event_t {
    fn clone(&self) -> xcb_visibility_notify_event_t { *self }
}

pub const XCB_CREATE_NOTIFY: u8 = 16;

#[repr(C)]
pub struct xcb_create_notify_event_t {
    pub response_type:     u8,
    pub pad0:              u8,
    pub sequence:          u16,
    pub parent:            xcb_window_t,
    pub window:            xcb_window_t,
    pub x:                 i16,
    pub y:                 i16,
    pub width:             u16,
    pub height:            u16,
    pub border_width:      u16,
    pub override_redirect: u8,
    pub pad1:              u8,
}

impl Copy for xcb_create_notify_event_t {}
impl Clone for xcb_create_notify_event_t {
    fn clone(&self) -> xcb_create_notify_event_t { *self }
}

pub const XCB_DESTROY_NOTIFY: u8 = 17;

/// a window is destroyed
#[repr(C)]
pub struct xcb_destroy_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    /// The reconfigured window or its parent, depending on whether `StructureNotify`
    /// or `SubstructureNotify` was selected.
    pub event:         xcb_window_t,
    /// The window that is destroyed.
    pub window:        xcb_window_t,
}

impl Copy for xcb_destroy_notify_event_t {}
impl Clone for xcb_destroy_notify_event_t {
    fn clone(&self) -> xcb_destroy_notify_event_t { *self }
}

pub const XCB_UNMAP_NOTIFY: u8 = 18;

/// a window is unmapped
#[repr(C)]
pub struct xcb_unmap_notify_event_t {
    pub response_type:  u8,
    pub pad0:           u8,
    pub sequence:       u16,
    /// The reconfigured window or its parent, depending on whether `StructureNotify`
    /// or `SubstructureNotify` was selected.
    pub event:          xcb_window_t,
    /// The window that was unmapped.
    pub window:         xcb_window_t,
    /// Set to 1 if the event was generated as a result of a resizing of the window's
    /// parent when `window` had a win_gravity of `UnmapGravity`.
    pub from_configure: u8,
    pub pad1:           [u8; 3],
}

impl Copy for xcb_unmap_notify_event_t {}
impl Clone for xcb_unmap_notify_event_t {
    fn clone(&self) -> xcb_unmap_notify_event_t { *self }
}

pub const XCB_MAP_NOTIFY: u8 = 19;

/// a window was mapped
#[repr(C)]
pub struct xcb_map_notify_event_t {
    pub response_type:     u8,
    pub pad0:              u8,
    pub sequence:          u16,
    /// The window which was mapped or its parent, depending on whether
    /// `StructureNotify` or `SubstructureNotify` was selected.
    pub event:             xcb_window_t,
    /// The window that was mapped.
    pub window:            xcb_window_t,
    /// Window managers should ignore this window if `override_redirect` is 1.
    pub override_redirect: u8,
    pub pad1:              [u8; 3],
}

impl Copy for xcb_map_notify_event_t {}
impl Clone for xcb_map_notify_event_t {
    fn clone(&self) -> xcb_map_notify_event_t { *self }
}

pub const XCB_MAP_REQUEST: u8 = 20;

/// window wants to be mapped
#[repr(C)]
pub struct xcb_map_request_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    /// The parent of `window`.
    pub parent:        xcb_window_t,
    /// The window to be mapped.
    pub window:        xcb_window_t,
}

impl Copy for xcb_map_request_event_t {}
impl Clone for xcb_map_request_event_t {
    fn clone(&self) -> xcb_map_request_event_t { *self }
}

pub const XCB_REPARENT_NOTIFY: u8 = 21;

#[repr(C)]
pub struct xcb_reparent_notify_event_t {
    pub response_type:     u8,
    pub pad0:              u8,
    pub sequence:          u16,
    pub event:             xcb_window_t,
    pub window:            xcb_window_t,
    pub parent:            xcb_window_t,
    pub x:                 i16,
    pub y:                 i16,
    pub override_redirect: u8,
    pub pad1:              [u8; 3],
}

impl Copy for xcb_reparent_notify_event_t {}
impl Clone for xcb_reparent_notify_event_t {
    fn clone(&self) -> xcb_reparent_notify_event_t { *self }
}

pub const XCB_CONFIGURE_NOTIFY: u8 = 22;

/// NOT YET DOCUMENTED
#[repr(C)]
pub struct xcb_configure_notify_event_t {
    pub response_type:     u8,
    pub pad0:              u8,
    pub sequence:          u16,
    /// The reconfigured window or its parent, depending on whether `StructureNotify`
    /// or `SubstructureNotify` was selected.
    pub event:             xcb_window_t,
    /// The window whose size, position, border, and/or stacking order was changed.
    pub window:            xcb_window_t,
    /// If `XCB_NONE`, the `window` is on the bottom of the stack with respect to
    /// sibling windows. However, if set to a sibling window, the `window` is placed on
    /// top of this sibling window.
    pub above_sibling:     xcb_window_t,
    /// The X coordinate of the upper-left outside corner of `window`, relative to the
    /// parent window's origin.
    pub x:                 i16,
    /// The Y coordinate of the upper-left outside corner of `window`, relative to the
    /// parent window's origin.
    pub y:                 i16,
    /// The inside width of `window`, not including the border.
    pub width:             u16,
    /// The inside height of `window`, not including the border.
    pub height:            u16,
    /// The border width of `window`.
    pub border_width:      u16,
    /// Window managers should ignore this window if `override_redirect` is 1.
    pub override_redirect: u8,
    pub pad1:              u8,
}

impl Copy for xcb_configure_notify_event_t {}
impl Clone for xcb_configure_notify_event_t {
    fn clone(&self) -> xcb_configure_notify_event_t { *self }
}

pub const XCB_CONFIGURE_REQUEST: u8 = 23;

#[repr(C)]
pub struct xcb_configure_request_event_t {
    pub response_type: u8,
    pub stack_mode:    u8,
    pub sequence:      u16,
    pub parent:        xcb_window_t,
    pub window:        xcb_window_t,
    pub sibling:       xcb_window_t,
    pub x:             i16,
    pub y:             i16,
    pub width:         u16,
    pub height:        u16,
    pub border_width:  u16,
    pub value_mask:    u16,
}

impl Copy for xcb_configure_request_event_t {}
impl Clone for xcb_configure_request_event_t {
    fn clone(&self) -> xcb_configure_request_event_t { *self }
}

pub const XCB_GRAVITY_NOTIFY: u8 = 24;

#[repr(C)]
pub struct xcb_gravity_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub event:         xcb_window_t,
    pub window:        xcb_window_t,
    pub x:             i16,
    pub y:             i16,
}

impl Copy for xcb_gravity_notify_event_t {}
impl Clone for xcb_gravity_notify_event_t {
    fn clone(&self) -> xcb_gravity_notify_event_t { *self }
}

pub const XCB_RESIZE_REQUEST: u8 = 25;

#[repr(C)]
pub struct xcb_resize_request_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub window:        xcb_window_t,
    pub width:         u16,
    pub height:        u16,
}

impl Copy for xcb_resize_request_event_t {}
impl Clone for xcb_resize_request_event_t {
    fn clone(&self) -> xcb_resize_request_event_t { *self }
}

pub type xcb_place_t = u32;
/// The window is now on top of all siblings.
pub const XCB_PLACE_ON_TOP   : xcb_place_t = 0x00;
/// The window is now below all siblings.
pub const XCB_PLACE_ON_BOTTOM: xcb_place_t = 0x01;

pub const XCB_CIRCULATE_NOTIFY: u8 = 26;

/// NOT YET DOCUMENTED
#[repr(C)]
pub struct xcb_circulate_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    /// Either the restacked window or its parent, depending on whether
    /// `StructureNotify` or `SubstructureNotify` was selected.
    pub event:         xcb_window_t,
    /// The restacked window.
    pub window:        xcb_window_t,
    pub pad1:          [u8; 4],
    ///
    pub place:         u8,
    pub pad2:          [u8; 3],
}

impl Copy for xcb_circulate_notify_event_t {}
impl Clone for xcb_circulate_notify_event_t {
    fn clone(&self) -> xcb_circulate_notify_event_t { *self }
}

pub const XCB_CIRCULATE_REQUEST: u8 = 27;

pub type xcb_circulate_request_event_t = xcb_circulate_notify_event_t;

pub type xcb_property_t = u32;
pub const XCB_PROPERTY_NEW_VALUE: xcb_property_t = 0x00;
pub const XCB_PROPERTY_DELETE   : xcb_property_t = 0x01;

pub const XCB_PROPERTY_NOTIFY: u8 = 28;

/// a window property changed
#[repr(C)]
pub struct xcb_property_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    /// The window whose associated property was changed.
    pub window:        xcb_window_t,
    /// The property's atom, to indicate which property was changed.
    pub atom:          xcb_atom_t,
    /// A timestamp of the server time when the property was changed.
    pub time:          xcb_timestamp_t,
    ///
    pub state:         u8,
    pub pad1:          [u8; 3],
}

impl Copy for xcb_property_notify_event_t {}
impl Clone for xcb_property_notify_event_t {
    fn clone(&self) -> xcb_property_notify_event_t { *self }
}

pub const XCB_SELECTION_CLEAR: u8 = 29;

#[repr(C)]
pub struct xcb_selection_clear_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub time:          xcb_timestamp_t,
    pub owner:         xcb_window_t,
    pub selection:     xcb_atom_t,
}

impl Copy for xcb_selection_clear_event_t {}
impl Clone for xcb_selection_clear_event_t {
    fn clone(&self) -> xcb_selection_clear_event_t { *self }
}

pub type xcb_time_t = u32;
pub const XCB_TIME_CURRENT_TIME: xcb_time_t = 0x00;

pub type xcb_atom_enum_t = u32;
pub const XCB_ATOM_NONE               : xcb_atom_enum_t = 0x00;
pub const XCB_ATOM_ANY                : xcb_atom_enum_t = 0x00;
pub const XCB_ATOM_PRIMARY            : xcb_atom_enum_t = 0x01;
pub const XCB_ATOM_SECONDARY          : xcb_atom_enum_t = 0x02;
pub const XCB_ATOM_ARC                : xcb_atom_enum_t = 0x03;
pub const XCB_ATOM_ATOM               : xcb_atom_enum_t = 0x04;
pub const XCB_ATOM_BITMAP             : xcb_atom_enum_t = 0x05;
pub const XCB_ATOM_CARDINAL           : xcb_atom_enum_t = 0x06;
pub const XCB_ATOM_COLORMAP           : xcb_atom_enum_t = 0x07;
pub const XCB_ATOM_CURSOR             : xcb_atom_enum_t = 0x08;
pub const XCB_ATOM_CUT_BUFFER0        : xcb_atom_enum_t = 0x09;
pub const XCB_ATOM_CUT_BUFFER1        : xcb_atom_enum_t = 0x0a;
pub const XCB_ATOM_CUT_BUFFER2        : xcb_atom_enum_t = 0x0b;
pub const XCB_ATOM_CUT_BUFFER3        : xcb_atom_enum_t = 0x0c;
pub const XCB_ATOM_CUT_BUFFER4        : xcb_atom_enum_t = 0x0d;
pub const XCB_ATOM_CUT_BUFFER5        : xcb_atom_enum_t = 0x0e;
pub const XCB_ATOM_CUT_BUFFER6        : xcb_atom_enum_t = 0x0f;
pub const XCB_ATOM_CUT_BUFFER7        : xcb_atom_enum_t = 0x10;
pub const XCB_ATOM_DRAWABLE           : xcb_atom_enum_t = 0x11;
pub const XCB_ATOM_FONT               : xcb_atom_enum_t = 0x12;
pub const XCB_ATOM_INTEGER            : xcb_atom_enum_t = 0x13;
pub const XCB_ATOM_PIXMAP             : xcb_atom_enum_t = 0x14;
pub const XCB_ATOM_POINT              : xcb_atom_enum_t = 0x15;
pub const XCB_ATOM_RECTANGLE          : xcb_atom_enum_t = 0x16;
pub const XCB_ATOM_RESOURCE_MANAGER   : xcb_atom_enum_t = 0x17;
pub const XCB_ATOM_RGB_COLOR_MAP      : xcb_atom_enum_t = 0x18;
pub const XCB_ATOM_RGB_BEST_MAP       : xcb_atom_enum_t = 0x19;
pub const XCB_ATOM_RGB_BLUE_MAP       : xcb_atom_enum_t = 0x1a;
pub const XCB_ATOM_RGB_DEFAULT_MAP    : xcb_atom_enum_t = 0x1b;
pub const XCB_ATOM_RGB_GRAY_MAP       : xcb_atom_enum_t = 0x1c;
pub const XCB_ATOM_RGB_GREEN_MAP      : xcb_atom_enum_t = 0x1d;
pub const XCB_ATOM_RGB_RED_MAP        : xcb_atom_enum_t = 0x1e;
pub const XCB_ATOM_STRING             : xcb_atom_enum_t = 0x1f;
pub const XCB_ATOM_VISUALID           : xcb_atom_enum_t = 0x20;
pub const XCB_ATOM_WINDOW             : xcb_atom_enum_t = 0x21;
pub const XCB_ATOM_WM_COMMAND         : xcb_atom_enum_t = 0x22;
pub const XCB_ATOM_WM_HINTS           : xcb_atom_enum_t = 0x23;
pub const XCB_ATOM_WM_CLIENT_MACHINE  : xcb_atom_enum_t = 0x24;
pub const XCB_ATOM_WM_ICON_NAME       : xcb_atom_enum_t = 0x25;
pub const XCB_ATOM_WM_ICON_SIZE       : xcb_atom_enum_t = 0x26;
pub const XCB_ATOM_WM_NAME            : xcb_atom_enum_t = 0x27;
pub const XCB_ATOM_WM_NORMAL_HINTS    : xcb_atom_enum_t = 0x28;
pub const XCB_ATOM_WM_SIZE_HINTS      : xcb_atom_enum_t = 0x29;
pub const XCB_ATOM_WM_ZOOM_HINTS      : xcb_atom_enum_t = 0x2a;
pub const XCB_ATOM_MIN_SPACE          : xcb_atom_enum_t = 0x2b;
pub const XCB_ATOM_NORM_SPACE         : xcb_atom_enum_t = 0x2c;
pub const XCB_ATOM_MAX_SPACE          : xcb_atom_enum_t = 0x2d;
pub const XCB_ATOM_END_SPACE          : xcb_atom_enum_t = 0x2e;
pub const XCB_ATOM_SUPERSCRIPT_X      : xcb_atom_enum_t = 0x2f;
pub const XCB_ATOM_SUPERSCRIPT_Y      : xcb_atom_enum_t = 0x30;
pub const XCB_ATOM_SUBSCRIPT_X        : xcb_atom_enum_t = 0x31;
pub const XCB_ATOM_SUBSCRIPT_Y        : xcb_atom_enum_t = 0x32;
pub const XCB_ATOM_UNDERLINE_POSITION : xcb_atom_enum_t = 0x33;
pub const XCB_ATOM_UNDERLINE_THICKNESS: xcb_atom_enum_t = 0x34;
pub const XCB_ATOM_STRIKEOUT_ASCENT   : xcb_atom_enum_t = 0x35;
pub const XCB_ATOM_STRIKEOUT_DESCENT  : xcb_atom_enum_t = 0x36;
pub const XCB_ATOM_ITALIC_ANGLE       : xcb_atom_enum_t = 0x37;
pub const XCB_ATOM_X_HEIGHT           : xcb_atom_enum_t = 0x38;
pub const XCB_ATOM_QUAD_WIDTH         : xcb_atom_enum_t = 0x39;
pub const XCB_ATOM_WEIGHT             : xcb_atom_enum_t = 0x3a;
pub const XCB_ATOM_POINT_SIZE         : xcb_atom_enum_t = 0x3b;
pub const XCB_ATOM_RESOLUTION         : xcb_atom_enum_t = 0x3c;
pub const XCB_ATOM_COPYRIGHT          : xcb_atom_enum_t = 0x3d;
pub const XCB_ATOM_NOTICE             : xcb_atom_enum_t = 0x3e;
pub const XCB_ATOM_FONT_NAME          : xcb_atom_enum_t = 0x3f;
pub const XCB_ATOM_FAMILY_NAME        : xcb_atom_enum_t = 0x40;
pub const XCB_ATOM_FULL_NAME          : xcb_atom_enum_t = 0x41;
pub const XCB_ATOM_CAP_HEIGHT         : xcb_atom_enum_t = 0x42;
pub const XCB_ATOM_WM_CLASS           : xcb_atom_enum_t = 0x43;
pub const XCB_ATOM_WM_TRANSIENT_FOR   : xcb_atom_enum_t = 0x44;

pub const XCB_SELECTION_REQUEST: u8 = 30;

#[repr(C)]
pub struct xcb_selection_request_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub time:          xcb_timestamp_t,
    pub owner:         xcb_window_t,
    pub requestor:     xcb_window_t,
    pub selection:     xcb_atom_t,
    pub target:        xcb_atom_t,
    pub property:      xcb_atom_t,
}

impl Copy for xcb_selection_request_event_t {}
impl Clone for xcb_selection_request_event_t {
    fn clone(&self) -> xcb_selection_request_event_t { *self }
}

pub const XCB_SELECTION_NOTIFY: u8 = 31;

#[repr(C)]
pub struct xcb_selection_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub time:          xcb_timestamp_t,
    pub requestor:     xcb_window_t,
    pub selection:     xcb_atom_t,
    pub target:        xcb_atom_t,
    pub property:      xcb_atom_t,
}

impl Copy for xcb_selection_notify_event_t {}
impl Clone for xcb_selection_notify_event_t {
    fn clone(&self) -> xcb_selection_notify_event_t { *self }
}

pub type xcb_colormap_state_t = u32;
/// The colormap was uninstalled.
pub const XCB_COLORMAP_STATE_UNINSTALLED: xcb_colormap_state_t = 0x00;
/// The colormap was installed.
pub const XCB_COLORMAP_STATE_INSTALLED  : xcb_colormap_state_t = 0x01;

pub type xcb_colormap_enum_t = u32;
pub const XCB_COLORMAP_NONE: xcb_colormap_enum_t = 0x00;

pub const XCB_COLORMAP_NOTIFY: u8 = 32;

/// the colormap for some window changed
#[repr(C)]
pub struct xcb_colormap_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    /// The window whose associated colormap is changed, installed or uninstalled.
    pub window:        xcb_window_t,
    /// The colormap which is changed, installed or uninstalled. This is `XCB_NONE`
    /// when the colormap is changed by a call to `FreeColormap`.
    pub colormap:      xcb_colormap_t,
    pub new_:          u8,
    ///
    pub state:         u8,
    pub pad1:          [u8; 2],
}

impl Copy for xcb_colormap_notify_event_t {}
impl Clone for xcb_colormap_notify_event_t {
    fn clone(&self) -> xcb_colormap_notify_event_t { *self }
}

// union
#[repr(C)]
pub struct xcb_client_message_data_t {
    pub data: [u8; 20]
}

impl Copy for xcb_client_message_data_t {}
impl Clone for xcb_client_message_data_t {
    fn clone(&self) -> xcb_client_message_data_t { *self }
}

#[repr(C)]
pub struct xcb_client_message_data_iterator_t {
    pub data:  *mut xcb_client_message_data_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_CLIENT_MESSAGE: u8 = 33;

/// NOT YET DOCUMENTED
///
/// This event represents a ClientMessage, sent by another X11 client. An example
/// is a client sending the `_NET_WM_STATE` ClientMessage to the root window
/// to indicate the fullscreen window state, effectively requesting that the window
/// manager puts it into fullscreen mode.
#[repr(C)]
pub struct xcb_client_message_event_t {
    pub response_type: u8,
    /// Specifies how to interpret `data`. Can be either 8, 16 or 32.
    pub format:        u8,
    pub sequence:      u16,
    pub window:        xcb_window_t,
    /// An atom which indicates how the data should be interpreted by the receiving
    /// client.
    pub type_:         xcb_atom_t,
    /// The data itself (20 bytes max).
    pub data:          xcb_client_message_data_t,
}

impl Copy for xcb_client_message_event_t {}
impl Clone for xcb_client_message_event_t {
    fn clone(&self) -> xcb_client_message_event_t { *self }
}

pub type xcb_mapping_t = u32;
pub const XCB_MAPPING_MODIFIER: xcb_mapping_t = 0x00;
pub const XCB_MAPPING_KEYBOARD: xcb_mapping_t = 0x01;
pub const XCB_MAPPING_POINTER : xcb_mapping_t = 0x02;

pub const XCB_MAPPING_NOTIFY: u8 = 34;

/// keyboard mapping changed
#[repr(C)]
pub struct xcb_mapping_notify_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    ///
    pub request:       u8,
    /// The first number in the range of the altered mapping.
    pub first_keycode: xcb_keycode_t,
    /// The number of keycodes altered.
    pub count:         u8,
    pub pad1:          u8,
}

impl Copy for xcb_mapping_notify_event_t {}
impl Clone for xcb_mapping_notify_event_t {
    fn clone(&self) -> xcb_mapping_notify_event_t { *self }
}

pub const XCB_GE_GENERIC: u8 = 35;

/// generic event (with length)
#[repr(C)]
pub struct xcb_ge_generic_event_t {
    pub response_type: u8,
    /// The major opcode of the extension creating this event
    pub extension:     u8,
    pub sequence:      u16,
    /// The amount (in 4-byte units) of data beyond 32 bytes
    pub length:        u32,
    pub event_type:    u16,
    pub pad0:          [u8; 22],
    pub full_sequence: u32,
}

impl Copy for xcb_ge_generic_event_t {}
impl Clone for xcb_ge_generic_event_t {
    fn clone(&self) -> xcb_ge_generic_event_t { *self }
}

pub const XCB_REQUEST: u8 = 1;

#[repr(C)]
pub struct xcb_request_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
    pub bad_value:     u32,
    pub minor_opcode:  u16,
    pub major_opcode:  u8,
    pub pad0:          u8,
}

impl Copy for xcb_request_error_t {}
impl Clone for xcb_request_error_t {
    fn clone(&self) -> xcb_request_error_t { *self }
}

pub const XCB_VALUE: u8 = 2;

#[repr(C)]
pub struct xcb_value_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
    pub bad_value:     u32,
    pub minor_opcode:  u16,
    pub major_opcode:  u8,
    pub pad0:          u8,
}

impl Copy for xcb_value_error_t {}
impl Clone for xcb_value_error_t {
    fn clone(&self) -> xcb_value_error_t { *self }
}

pub const XCB_WINDOW: u8 = 3;

pub type xcb_window_error_t = xcb_value_error_t;

pub const XCB_PIXMAP: u8 = 4;

pub type xcb_pixmap_error_t = xcb_value_error_t;

pub const XCB_ATOM: u8 = 5;

pub type xcb_atom_error_t = xcb_value_error_t;

pub const XCB_CURSOR: u8 = 6;

pub type xcb_cursor_error_t = xcb_value_error_t;

pub const XCB_FONT: u8 = 7;

pub type xcb_font_error_t = xcb_value_error_t;

pub const XCB_MATCH: u8 = 8;

pub type xcb_match_error_t = xcb_request_error_t;

pub const XCB_DRAWABLE: u8 = 9;

pub type xcb_drawable_error_t = xcb_value_error_t;

pub const XCB_ACCESS: u8 = 10;

pub type xcb_access_error_t = xcb_request_error_t;

pub const XCB_ALLOC: u8 = 11;

pub type xcb_alloc_error_t = xcb_request_error_t;

pub const XCB_COLORMAP: u8 = 12;

pub type xcb_colormap_error_t = xcb_value_error_t;

pub const XCB_G_CONTEXT: u8 = 13;

pub type xcb_g_context_error_t = xcb_value_error_t;

pub const XCB_ID_CHOICE: u8 = 14;

pub type xcb_id_choice_error_t = xcb_value_error_t;

pub const XCB_NAME: u8 = 15;

pub type xcb_name_error_t = xcb_request_error_t;

pub const XCB_LENGTH: u8 = 16;

pub type xcb_length_error_t = xcb_request_error_t;

pub const XCB_IMPLEMENTATION: u8 = 17;

pub type xcb_implementation_error_t = xcb_request_error_t;

pub type xcb_window_class_t = u32;
pub const XCB_WINDOW_CLASS_COPY_FROM_PARENT: xcb_window_class_t = 0x00;
pub const XCB_WINDOW_CLASS_INPUT_OUTPUT    : xcb_window_class_t = 0x01;
pub const XCB_WINDOW_CLASS_INPUT_ONLY      : xcb_window_class_t = 0x02;

pub type xcb_cw_t = u32;
/// Overrides the default background-pixmap. The background pixmap and window must
/// have the same root and same depth. Any size pixmap can be used, although some
/// sizes may be faster than others.
///
/// If `XCB_BACK_PIXMAP_NONE` is specified, the window has no defined background.
/// The server may fill the contents with the previous screen contents or with
/// contents of its own choosing.
///
/// If `XCB_BACK_PIXMAP_PARENT_RELATIVE` is specified, the parent's background is
/// used, but the window must have the same depth as the parent (or a Match error
/// results).   The parent's background is tracked, and the current version is
/// used each time the window background is required.
pub const XCB_CW_BACK_PIXMAP      : xcb_cw_t =   0x01;
/// Overrides `BackPixmap`. A pixmap of undefined size filled with the specified
/// background pixel is used for the background. Range-checking is not performed,
/// the background pixel is truncated to the appropriate number of bits.
pub const XCB_CW_BACK_PIXEL       : xcb_cw_t =   0x02;
/// Overrides the default border-pixmap. The border pixmap and window must have the
/// same root and the same depth. Any size pixmap can be used, although some sizes
/// may be faster than others.
///
/// The special value `XCB_COPY_FROM_PARENT` means the parent's border pixmap is
/// copied (subsequent changes to the parent's border attribute do not affect the
/// child), but the window must have the same depth as the parent.
pub const XCB_CW_BORDER_PIXMAP    : xcb_cw_t =   0x04;
/// Overrides `BorderPixmap`. A pixmap of undefined size filled with the specified
/// border pixel is used for the border. Range checking is not performed on the
/// border-pixel value, it is truncated to the appropriate number of bits.
pub const XCB_CW_BORDER_PIXEL     : xcb_cw_t =   0x08;
/// Defines which region of the window should be retained if the window is resized.
pub const XCB_CW_BIT_GRAVITY      : xcb_cw_t =   0x10;
/// Defines how the window should be repositioned if the parent is resized (see
/// `ConfigureWindow`).
pub const XCB_CW_WIN_GRAVITY      : xcb_cw_t =   0x20;
/// A backing-store of `WhenMapped` advises the server that maintaining contents of
/// obscured regions when the window is mapped would be beneficial. A backing-store
/// of `Always` advises the server that maintaining contents even when the window
/// is unmapped would be beneficial. In this case, the server may generate an
/// exposure event when the window is created. A value of `NotUseful` advises the
/// server that maintaining contents is unnecessary, although a server may still
/// choose to maintain contents while the window is mapped. Note that if the server
/// maintains contents, then the server should maintain complete contents not just
/// the region within the parent boundaries, even if the window is larger than its
/// parent. While the server maintains contents, exposure events will not normally
/// be generated, but the server may stop maintaining contents at any time.
pub const XCB_CW_BACKING_STORE    : xcb_cw_t =   0x40;
/// The backing-planes indicates (with bits set to 1) which bit planes of the
/// window hold dynamic data that must be preserved in backing-stores and during
/// save-unders.
pub const XCB_CW_BACKING_PLANES   : xcb_cw_t =   0x80;
/// The backing-pixel specifies what value to use in planes not covered by
/// backing-planes. The server is free to save only the specified bit planes in the
/// backing-store or save-under and regenerate the remaining planes with the
/// specified pixel value. Any bits beyond the specified depth of the window in
/// these values are simply ignored.
pub const XCB_CW_BACKING_PIXEL    : xcb_cw_t =  0x100;
/// The override-redirect specifies whether map and configure requests on this
/// window should override a SubstructureRedirect on the parent, typically to
/// inform a window manager not to tamper with the window.
pub const XCB_CW_OVERRIDE_REDIRECT: xcb_cw_t =  0x200;
/// If 1, the server is advised that when this window is mapped, saving the
/// contents of windows it obscures would be beneficial.
pub const XCB_CW_SAVE_UNDER       : xcb_cw_t =  0x400;
/// The event-mask defines which events the client is interested in for this window
/// (or for some event types, inferiors of the window).
pub const XCB_CW_EVENT_MASK       : xcb_cw_t =  0x800;
/// The do-not-propagate-mask defines which events should not be propagated to
/// ancestor windows when no client has the event type selected in this window.
pub const XCB_CW_DONT_PROPAGATE   : xcb_cw_t = 0x1000;
/// The colormap specifies the colormap that best reflects the true colors of the window. Servers
/// capable of supporting multiple hardware colormaps may use this information, and window man-
/// agers may use it for InstallColormap requests. The colormap must have the same visual type
/// and root as the window (or a Match error results). If CopyFromParent is specified, the parent's
/// colormap is copied (subsequent changes to the parent's colormap attribute do not affect the child).
/// However, the window must have the same visual type as the parent (or a Match error results),
/// and the parent must not have a colormap of None (or a Match error results). For an explanation
/// of None, see FreeColormap request. The colormap is copied by sharing the colormap object
/// between the child and the parent, not by making a complete copy of the colormap contents.
pub const XCB_CW_COLORMAP         : xcb_cw_t = 0x2000;
/// If a cursor is specified, it will be used whenever the pointer is in the window. If None is speci-
/// fied, the parent's cursor will be used when the pointer is in the window, and any change in the
/// parent's cursor will cause an immediate change in the displayed cursor.
pub const XCB_CW_CURSOR           : xcb_cw_t = 0x4000;

pub type xcb_back_pixmap_t = u32;
pub const XCB_BACK_PIXMAP_NONE           : xcb_back_pixmap_t = 0x00;
pub const XCB_BACK_PIXMAP_PARENT_RELATIVE: xcb_back_pixmap_t = 0x01;

pub type xcb_gravity_t = u32;
pub const XCB_GRAVITY_BIT_FORGET: xcb_gravity_t = 0x00;
pub const XCB_GRAVITY_WIN_UNMAP : xcb_gravity_t = 0x00;
pub const XCB_GRAVITY_NORTH_WEST: xcb_gravity_t = 0x01;
pub const XCB_GRAVITY_NORTH     : xcb_gravity_t = 0x02;
pub const XCB_GRAVITY_NORTH_EAST: xcb_gravity_t = 0x03;
pub const XCB_GRAVITY_WEST      : xcb_gravity_t = 0x04;
pub const XCB_GRAVITY_CENTER    : xcb_gravity_t = 0x05;
pub const XCB_GRAVITY_EAST      : xcb_gravity_t = 0x06;
pub const XCB_GRAVITY_SOUTH_WEST: xcb_gravity_t = 0x07;
pub const XCB_GRAVITY_SOUTH     : xcb_gravity_t = 0x08;
pub const XCB_GRAVITY_SOUTH_EAST: xcb_gravity_t = 0x09;
pub const XCB_GRAVITY_STATIC    : xcb_gravity_t = 0x0a;

pub const XCB_CREATE_WINDOW: u8 = 1;

/// Creates a window
///
/// Creates an unmapped window as child of the specified `parent` window. A
/// CreateNotify event will be generated. The new window is placed on top in the
/// stacking order with respect to siblings.
///
/// The coordinate system has the X axis horizontal and the Y axis vertical with
/// the origin [0, 0] at the upper-left corner. Coordinates are integral, in terms
/// of pixels, and coincide with pixel centers. Each window and pixmap has its own
/// coordinate system. For a window, the origin is inside the border at the inside,
/// upper-left corner.
///
/// The created window is not yet displayed (mapped), call `xcb_map_window` to
/// display it.
///
/// The created window will initially use the same cursor as its parent.
#[repr(C)]
pub struct xcb_create_window_request_t {
    pub major_opcode: u8,
    /// Specifies the new window's depth (TODO: what unit?).
    ///
    /// The special value `XCB_COPY_FROM_PARENT` means the depth is taken from the
    /// `parent` window.
    pub depth:        u8,
    pub length:       u16,
    /// The ID with which you will refer to the new window, created by
    /// `xcb_generate_id`.
    pub wid:          xcb_window_t,
    /// The parent window of the new window.
    pub parent:       xcb_window_t,
    /// The X coordinate of the new window.
    pub x:            i16,
    /// The Y coordinate of the new window.
    pub y:            i16,
    /// The width of the new window.
    pub width:        u16,
    /// The height of the new window.
    pub height:       u16,
    /// TODO:
    ///
    /// Must be zero if the `class` is `InputOnly` or a `xcb_match_error_t` occurs.
    pub border_width: u16,
    ///
    pub class:        u16,
    /// Specifies the id for the new window's visual.
    ///
    /// The special value `XCB_COPY_FROM_PARENT` means the visual is taken from the
    /// `parent` window.
    pub visual:       xcb_visualid_t,
    pub value_mask:   u32,
}

pub const XCB_CHANGE_WINDOW_ATTRIBUTES: u8 = 2;

/// change window attributes
///
/// Changes the attributes specified by `value_mask` for the specified `window`.
#[repr(C)]
pub struct xcb_change_window_attributes_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The window to change.
    pub window:       xcb_window_t,
    ///
    pub value_mask:   u32,
}

pub type xcb_map_state_t = u32;
pub const XCB_MAP_STATE_UNMAPPED  : xcb_map_state_t = 0x00;
pub const XCB_MAP_STATE_UNVIEWABLE: xcb_map_state_t = 0x01;
pub const XCB_MAP_STATE_VIEWABLE  : xcb_map_state_t = 0x02;

pub const XCB_GET_WINDOW_ATTRIBUTES: u8 = 3;

/// Gets window attributes
///
/// Gets the current attributes for the specified `window`.
#[repr(C)]
pub struct xcb_get_window_attributes_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The window to get the attributes from.
    pub window:       xcb_window_t,
}

impl Copy for xcb_get_window_attributes_request_t {}
impl Clone for xcb_get_window_attributes_request_t {
    fn clone(&self) -> xcb_get_window_attributes_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_window_attributes_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_window_attributes_reply_t {
    pub response_type:         u8,
    ///
    pub backing_store:         u8,
    pub sequence:              u16,
    pub length:                u32,
    /// The associated visual structure of `window`.
    pub visual:                xcb_visualid_t,
    ///
    pub class:                 u16,
    ///
    pub bit_gravity:           u8,
    ///
    pub win_gravity:           u8,
    /// Planes to be preserved if possible.
    pub backing_planes:        u32,
    /// Value to be used when restoring planes.
    pub backing_pixel:         u32,
    /// Boolean, should bits under be saved?
    pub save_under:            u8,
    pub map_is_installed:      u8,
    ///
    pub map_state:             u8,
    /// Window managers should ignore this window if `override_redirect` is 1.
    pub override_redirect:     u8,
    /// Color map to be associated with window.
    pub colormap:              xcb_colormap_t,
    /// Set of events all people have interest in.
    pub all_event_masks:       u32,
    /// My event mask.
    pub your_event_mask:       u32,
    /// Set of events that should not propagate.
    pub do_not_propagate_mask: u16,
    pub pad0:                  [u8; 2],
}

impl Copy for xcb_get_window_attributes_reply_t {}
impl Clone for xcb_get_window_attributes_reply_t {
    fn clone(&self) -> xcb_get_window_attributes_reply_t { *self }
}

pub const XCB_DESTROY_WINDOW: u8 = 4;

/// Destroys a window
///
/// Destroys the specified window and all of its subwindows. A DestroyNotify event
/// is generated for each destroyed window (a DestroyNotify event is first generated
/// for any given window's inferiors). If the window was mapped, it will be
/// automatically unmapped before destroying.
///
/// Calling DestroyWindow on the root window will do nothing.
#[repr(C)]
pub struct xcb_destroy_window_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The window to destroy.
    pub window:       xcb_window_t,
}

impl Copy for xcb_destroy_window_request_t {}
impl Clone for xcb_destroy_window_request_t {
    fn clone(&self) -> xcb_destroy_window_request_t { *self }
}

pub const XCB_DESTROY_SUBWINDOWS: u8 = 5;

#[repr(C)]
pub struct xcb_destroy_subwindows_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_destroy_subwindows_request_t {}
impl Clone for xcb_destroy_subwindows_request_t {
    fn clone(&self) -> xcb_destroy_subwindows_request_t { *self }
}

pub type xcb_set_mode_t = u32;
pub const XCB_SET_MODE_INSERT: xcb_set_mode_t = 0x00;
pub const XCB_SET_MODE_DELETE: xcb_set_mode_t = 0x01;

pub const XCB_CHANGE_SAVE_SET: u8 = 6;

/// Changes a client's save set
///
/// TODO: explain what the save set is for.
///
/// This function either adds or removes the specified window to the client's (your
/// application's) save set.
#[repr(C)]
pub struct xcb_change_save_set_request_t {
    pub major_opcode: u8,
    /// Insert to add the specified window to the save set or Delete to delete it from the save set.
    pub mode:         u8,
    pub length:       u16,
    /// The window to add or delete to/from your save set.
    pub window:       xcb_window_t,
}

impl Copy for xcb_change_save_set_request_t {}
impl Clone for xcb_change_save_set_request_t {
    fn clone(&self) -> xcb_change_save_set_request_t { *self }
}

pub const XCB_REPARENT_WINDOW: u8 = 7;

/// Reparents a window
///
/// Makes the specified window a child of the specified parent window. If the
/// window is mapped, it will automatically be unmapped before reparenting and
/// re-mapped after reparenting. The window is placed in the stacking order on top
/// with respect to sibling windows.
///
/// After reparenting, a ReparentNotify event is generated.
#[repr(C)]
pub struct xcb_reparent_window_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The window to reparent.
    pub window:       xcb_window_t,
    /// The new parent of the window.
    pub parent:       xcb_window_t,
    /// The X position of the window within its new parent.
    pub x:            i16,
    /// The Y position of the window within its new parent.
    pub y:            i16,
}

impl Copy for xcb_reparent_window_request_t {}
impl Clone for xcb_reparent_window_request_t {
    fn clone(&self) -> xcb_reparent_window_request_t { *self }
}

pub const XCB_MAP_WINDOW: u8 = 8;

/// Makes a window visible
///
/// Maps the specified window. This means making the window visible (as long as its
/// parent is visible).
///
/// This MapWindow request will be translated to a MapRequest request if a window
/// manager is running. The window manager then decides to either map the window or
/// not. Set the override-redirect window attribute to true if you want to bypass
/// this mechanism.
///
/// If the window manager decides to map the window (or if no window manager is
/// running), a MapNotify event is generated.
///
/// If the window becomes viewable and no earlier contents for it are remembered,
/// the X server tiles the window with its background. If the window's background
/// is undefined, the existing screen contents are not altered, and the X server
/// generates zero or more Expose events.
///
/// If the window type is InputOutput, an Expose event will be generated when the
/// window becomes visible. The normal response to an Expose event should be to
/// repaint the window.
#[repr(C)]
pub struct xcb_map_window_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The window to make visible.
    pub window:       xcb_window_t,
}

impl Copy for xcb_map_window_request_t {}
impl Clone for xcb_map_window_request_t {
    fn clone(&self) -> xcb_map_window_request_t { *self }
}

pub const XCB_MAP_SUBWINDOWS: u8 = 9;

#[repr(C)]
pub struct xcb_map_subwindows_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_map_subwindows_request_t {}
impl Clone for xcb_map_subwindows_request_t {
    fn clone(&self) -> xcb_map_subwindows_request_t { *self }
}

pub const XCB_UNMAP_WINDOW: u8 = 10;

/// Makes a window invisible
///
/// Unmaps the specified window. This means making the window invisible (and all
/// its child windows).
///
/// Unmapping a window leads to the `UnmapNotify` event being generated. Also,
/// `Expose` events are generated for formerly obscured windows.
#[repr(C)]
pub struct xcb_unmap_window_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The window to make invisible.
    pub window:       xcb_window_t,
}

impl Copy for xcb_unmap_window_request_t {}
impl Clone for xcb_unmap_window_request_t {
    fn clone(&self) -> xcb_unmap_window_request_t { *self }
}

pub const XCB_UNMAP_SUBWINDOWS: u8 = 11;

#[repr(C)]
pub struct xcb_unmap_subwindows_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_unmap_subwindows_request_t {}
impl Clone for xcb_unmap_subwindows_request_t {
    fn clone(&self) -> xcb_unmap_subwindows_request_t { *self }
}

pub type xcb_config_window_t = u32;
pub const XCB_CONFIG_WINDOW_X           : xcb_config_window_t = 0x01;
pub const XCB_CONFIG_WINDOW_Y           : xcb_config_window_t = 0x02;
pub const XCB_CONFIG_WINDOW_WIDTH       : xcb_config_window_t = 0x04;
pub const XCB_CONFIG_WINDOW_HEIGHT      : xcb_config_window_t = 0x08;
pub const XCB_CONFIG_WINDOW_BORDER_WIDTH: xcb_config_window_t = 0x10;
pub const XCB_CONFIG_WINDOW_SIBLING     : xcb_config_window_t = 0x20;
pub const XCB_CONFIG_WINDOW_STACK_MODE  : xcb_config_window_t = 0x40;

pub type xcb_stack_mode_t = u32;
pub const XCB_STACK_MODE_ABOVE    : xcb_stack_mode_t = 0x00;
pub const XCB_STACK_MODE_BELOW    : xcb_stack_mode_t = 0x01;
pub const XCB_STACK_MODE_TOP_IF   : xcb_stack_mode_t = 0x02;
pub const XCB_STACK_MODE_BOTTOM_IF: xcb_stack_mode_t = 0x03;
pub const XCB_STACK_MODE_OPPOSITE : xcb_stack_mode_t = 0x04;

pub const XCB_CONFIGURE_WINDOW: u8 = 12;

/// Configures window attributes
///
/// Configures a window's size, position, border width and stacking order.
#[repr(C)]
pub struct xcb_configure_window_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The window to configure.
    pub window:       xcb_window_t,
    /// Bitmask of attributes to change.
    pub value_mask:   u16,
    pub pad1:         [u8; 2],
}

pub type xcb_circulate_t = u32;
pub const XCB_CIRCULATE_RAISE_LOWEST : xcb_circulate_t = 0x00;
pub const XCB_CIRCULATE_LOWER_HIGHEST: xcb_circulate_t = 0x01;

pub const XCB_CIRCULATE_WINDOW: u8 = 13;

/// Change window stacking order
///
/// If `direction` is `XCB_CIRCULATE_RAISE_LOWEST`, the lowest mapped child (if
/// any) will be raised to the top of the stack.
///
/// If `direction` is `XCB_CIRCULATE_LOWER_HIGHEST`, the highest mapped child will
/// be lowered to the bottom of the stack.
#[repr(C)]
pub struct xcb_circulate_window_request_t {
    pub major_opcode: u8,
    ///
    pub direction:    u8,
    pub length:       u16,
    /// The window to raise/lower (depending on `direction`).
    pub window:       xcb_window_t,
}

impl Copy for xcb_circulate_window_request_t {}
impl Clone for xcb_circulate_window_request_t {
    fn clone(&self) -> xcb_circulate_window_request_t { *self }
}

pub const XCB_GET_GEOMETRY: u8 = 14;

/// Get current window geometry
///
/// Gets the current geometry of the specified drawable (either `Window` or `Pixmap`).
#[repr(C)]
pub struct xcb_get_geometry_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The drawable (`Window` or `Pixmap`) of which the geometry will be received.
    pub drawable:     xcb_drawable_t,
}

impl Copy for xcb_get_geometry_request_t {}
impl Clone for xcb_get_geometry_request_t {
    fn clone(&self) -> xcb_get_geometry_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_geometry_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_geometry_reply_t {
    pub response_type: u8,
    /// The depth of the drawable (bits per pixel for the object).
    pub depth:         u8,
    pub sequence:      u16,
    pub length:        u32,
    /// Root window of the screen containing `drawable`.
    pub root:          xcb_window_t,
    /// The X coordinate of `drawable`. If `drawable` is a window, the coordinate
    /// specifies the upper-left outer corner relative to its parent's origin. If
    /// `drawable` is a pixmap, the X coordinate is always 0.
    pub x:             i16,
    /// The Y coordinate of `drawable`. If `drawable` is a window, the coordinate
    /// specifies the upper-left outer corner relative to its parent's origin. If
    /// `drawable` is a pixmap, the Y coordinate is always 0.
    pub y:             i16,
    /// The width of `drawable`.
    pub width:         u16,
    /// The height of `drawable`.
    pub height:        u16,
    /// The border width (in pixels).
    pub border_width:  u16,
    pub pad0:          [u8; 2],
}

impl Copy for xcb_get_geometry_reply_t {}
impl Clone for xcb_get_geometry_reply_t {
    fn clone(&self) -> xcb_get_geometry_reply_t { *self }
}

pub const XCB_QUERY_TREE: u8 = 15;

/// query the window tree
///
/// Gets the root window ID, parent window ID and list of children windows for the
/// specified `window`. The children are listed in bottom-to-top stacking order.
#[repr(C)]
pub struct xcb_query_tree_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The `window` to query.
    pub window:       xcb_window_t,
}

impl Copy for xcb_query_tree_request_t {}
impl Clone for xcb_query_tree_request_t {
    fn clone(&self) -> xcb_query_tree_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_query_tree_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_query_tree_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    /// The root window of `window`.
    pub root:          xcb_window_t,
    /// The parent window of `window`.
    pub parent:        xcb_window_t,
    /// The number of child windows.
    pub children_len:  u16,
    pub pad1:          [u8; 14],
}

pub const XCB_INTERN_ATOM: u8 = 16;

/// Get atom identifier by name
///
/// Retrieves the identifier (xcb_atom_t TODO) for the atom with the specified
/// name. Atoms are used in protocols like EWMH, for example to store window titles
/// (`_NET_WM_NAME` atom) as property of a window.
///
/// If `only_if_exists` is 0, the atom will be created if it does not already exist.
/// If `only_if_exists` is 1, `XCB_ATOM_NONE` will be returned if the atom does
/// not yet exist.
#[repr(C)]
pub struct xcb_intern_atom_request_t {
    pub major_opcode:   u8,
    /// Return a valid atom id only if the atom already exists.
    pub only_if_exists: u8,
    pub length:         u16,
    /// The length of the following `name`.
    pub name_len:       u16,
    pub pad0:           [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_intern_atom_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_intern_atom_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub atom:          xcb_atom_t,
}

impl Copy for xcb_intern_atom_reply_t {}
impl Clone for xcb_intern_atom_reply_t {
    fn clone(&self) -> xcb_intern_atom_reply_t { *self }
}

pub const XCB_GET_ATOM_NAME: u8 = 17;

#[repr(C)]
pub struct xcb_get_atom_name_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub atom:         xcb_atom_t,
}

impl Copy for xcb_get_atom_name_request_t {}
impl Clone for xcb_get_atom_name_request_t {
    fn clone(&self) -> xcb_get_atom_name_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_atom_name_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_atom_name_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub name_len:      u16,
    pub pad1:          [u8; 22],
}

pub type xcb_prop_mode_t = u32;
/// Discard the previous property value and store the new data.
pub const XCB_PROP_MODE_REPLACE: xcb_prop_mode_t = 0x00;
/// Insert the new data before the beginning of existing data. The `format` must
/// match existing property value. If the property is undefined, it is treated as
/// defined with the correct type and format with zero-length data.
pub const XCB_PROP_MODE_PREPEND: xcb_prop_mode_t = 0x01;
/// Insert the new data after the beginning of existing data. The `format` must
/// match existing property value. If the property is undefined, it is treated as
/// defined with the correct type and format with zero-length data.
pub const XCB_PROP_MODE_APPEND : xcb_prop_mode_t = 0x02;

pub const XCB_CHANGE_PROPERTY: u8 = 18;

/// Changes a window property
///
/// Sets or updates a property on the specified `window`. Properties are for
/// example the window title (`WM_NAME`) or its minimum size (`WM_NORMAL_HINTS`).
/// Protocols such as EWMH also use properties - for example EWMH defines the
/// window title, encoded as UTF-8 string, in the `_NET_WM_NAME` property.
#[repr(C)]
pub struct xcb_change_property_request_t {
    pub major_opcode: u8,
    ///
    pub mode:         u8,
    pub length:       u16,
    /// The window whose property you want to change.
    pub window:       xcb_window_t,
    /// The property you want to change (an atom).
    pub property:     xcb_atom_t,
    /// The type of the property you want to change (an atom).
    pub type_:        xcb_atom_t,
    /// Specifies whether the data should be viewed as a list of 8-bit, 16-bit or
    /// 32-bit quantities. Possible values are 8, 16 and 32. This information allows
    /// the X server to correctly perform byte-swap operations as necessary.
    pub format:       u8,
    pub pad0:         [u8; 3],
    /// Specifies the number of elements (see `format`).
    pub data_len:     u32,
}

pub const XCB_DELETE_PROPERTY: u8 = 19;

#[repr(C)]
pub struct xcb_delete_property_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub property:     xcb_atom_t,
}

impl Copy for xcb_delete_property_request_t {}
impl Clone for xcb_delete_property_request_t {
    fn clone(&self) -> xcb_delete_property_request_t { *self }
}

pub type xcb_get_property_type_t = u32;
pub const XCB_GET_PROPERTY_TYPE_ANY: xcb_get_property_type_t = 0x00;

pub const XCB_GET_PROPERTY: u8 = 20;

/// Gets a window property
///
/// Gets the specified `property` from the specified `window`. Properties are for
/// example the window title (`WM_NAME`) or its minimum size (`WM_NORMAL_HINTS`).
/// Protocols such as EWMH also use properties - for example EWMH defines the
/// window title, encoded as UTF-8 string, in the `_NET_WM_NAME` property.
///
/// TODO: talk about `type`
///
/// TODO: talk about `delete`
///
/// TODO: talk about the offset/length thing. what's a valid use case?
#[repr(C)]
pub struct xcb_get_property_request_t {
    pub major_opcode: u8,
    /// Whether the property should actually be deleted. For deleting a property, the
    /// specified `type` has to match the actual property type.
    pub delete:       u8,
    pub length:       u16,
    /// The window whose property you want to get.
    pub window:       xcb_window_t,
    /// The property you want to get (an atom).
    pub property:     xcb_atom_t,
    /// The type of the property you want to get (an atom).
    pub type_:        xcb_atom_t,
    /// Specifies the offset (in 32-bit multiples) in the specified property where the
    /// data is to be retrieved.
    pub long_offset:  u32,
    /// Specifies how many 32-bit multiples of data should be retrieved (e.g. if you
    /// set `long_length` to 4, you will receive 16 bytes of data).
    pub long_length:  u32,
}

impl Copy for xcb_get_property_request_t {}
impl Clone for xcb_get_property_request_t {
    fn clone(&self) -> xcb_get_property_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_property_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_property_reply_t {
    pub response_type: u8,
    /// Specifies whether the data should be viewed as a list of 8-bit, 16-bit, or
    /// 32-bit quantities. Possible values are 8, 16, and 32. This information allows
    /// the X server to correctly perform byte-swap operations as necessary.
    pub format:        u8,
    pub sequence:      u16,
    pub length:        u32,
    /// The actual type of the property (an atom).
    pub type_:         xcb_atom_t,
    /// The number of bytes remaining to be read in the property if a partial read was
    /// performed.
    pub bytes_after:   u32,
    /// The length of value. You should use the corresponding accessor instead of this
    /// field.
    pub value_len:     u32,
    pub pad0:          [u8; 12],
}

pub const XCB_LIST_PROPERTIES: u8 = 21;

#[repr(C)]
pub struct xcb_list_properties_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_list_properties_request_t {}
impl Clone for xcb_list_properties_request_t {
    fn clone(&self) -> xcb_list_properties_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_list_properties_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_list_properties_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub atoms_len:     u16,
    pub pad1:          [u8; 22],
}

pub const XCB_SET_SELECTION_OWNER: u8 = 22;

/// Sets the owner of a selection
///
/// Makes `window` the owner of the selection `selection` and updates the
/// last-change time of the specified selection.
///
/// TODO: briefly explain what a selection is.
#[repr(C)]
pub struct xcb_set_selection_owner_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The new owner of the selection.
    ///
    /// The special value `XCB_NONE` means that the selection will have no owner.
    pub owner:        xcb_window_t,
    /// The selection.
    pub selection:    xcb_atom_t,
    /// Timestamp to avoid race conditions when running X over the network.
    ///
    /// The selection will not be changed if `time` is earlier than the current
    /// last-change time of the `selection` or is later than the current X server time.
    /// Otherwise, the last-change time is set to the specified time.
    ///
    /// The special value `XCB_CURRENT_TIME` will be replaced with the current server
    /// time.
    pub time:         xcb_timestamp_t,
}

impl Copy for xcb_set_selection_owner_request_t {}
impl Clone for xcb_set_selection_owner_request_t {
    fn clone(&self) -> xcb_set_selection_owner_request_t { *self }
}

pub const XCB_GET_SELECTION_OWNER: u8 = 23;

/// Gets the owner of a selection
///
/// Gets the owner of the specified selection.
///
/// TODO: briefly explain what a selection is.
#[repr(C)]
pub struct xcb_get_selection_owner_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The selection.
    pub selection:    xcb_atom_t,
}

impl Copy for xcb_get_selection_owner_request_t {}
impl Clone for xcb_get_selection_owner_request_t {
    fn clone(&self) -> xcb_get_selection_owner_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_selection_owner_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_selection_owner_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    /// The current selection owner window.
    pub owner:         xcb_window_t,
}

impl Copy for xcb_get_selection_owner_reply_t {}
impl Clone for xcb_get_selection_owner_reply_t {
    fn clone(&self) -> xcb_get_selection_owner_reply_t { *self }
}

pub const XCB_CONVERT_SELECTION: u8 = 24;

#[repr(C)]
pub struct xcb_convert_selection_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub requestor:    xcb_window_t,
    pub selection:    xcb_atom_t,
    pub target:       xcb_atom_t,
    pub property:     xcb_atom_t,
    pub time:         xcb_timestamp_t,
}

impl Copy for xcb_convert_selection_request_t {}
impl Clone for xcb_convert_selection_request_t {
    fn clone(&self) -> xcb_convert_selection_request_t { *self }
}

pub type xcb_send_event_dest_t = u32;
pub const XCB_SEND_EVENT_DEST_POINTER_WINDOW: xcb_send_event_dest_t = 0x00;
pub const XCB_SEND_EVENT_DEST_ITEM_FOCUS    : xcb_send_event_dest_t = 0x01;

pub const XCB_SEND_EVENT: u8 = 25;

/// send an event
///
/// Identifies the `destination` window, determines which clients should receive
/// the specified event and ignores any active grabs.
///
/// The `event` must be one of the core events or an event defined by an extension,
/// so that the X server can correctly byte-swap the contents as necessary. The
/// contents of `event` are otherwise unaltered and unchecked except for the
/// `send_event` field which is forced to 'true'.
#[repr(C)]
pub struct xcb_send_event_request_t {
    pub major_opcode: u8,
    /// If `propagate` is true and no clients have selected any event on `destination`,
    /// the destination is replaced with the closest ancestor of `destination` for
    /// which some client has selected a type in `event_mask` and for which no
    /// intervening window has that type in its do-not-propagate-mask. If no such
    /// window exists or if the window is an ancestor of the focus window and
    /// `InputFocus` was originally specified as the destination, the event is not sent
    /// to any clients. Otherwise, the event is reported to every client selecting on
    /// the final destination any of the types specified in `event_mask`.
    pub propagate:    u8,
    pub length:       u16,
    /// The window to send this event to. Every client which selects any event within
    /// `event_mask` on `destination` will get the event.
    ///
    /// The special value `XCB_SEND_EVENT_DEST_POINTER_WINDOW` refers to the window
    /// that contains the mouse pointer.
    ///
    /// The special value `XCB_SEND_EVENT_DEST_ITEM_FOCUS` refers to the window which
    /// has the keyboard focus.
    pub destination:  xcb_window_t,
    /// Event_mask for determining which clients should receive the specified event.
    /// See `destination` and `propagate`.
    pub event_mask:   u32,
    /// The event to send to the specified `destination`.
    pub event:        [c_char; 32],
}

impl Copy for xcb_send_event_request_t {}
impl Clone for xcb_send_event_request_t {
    fn clone(&self) -> xcb_send_event_request_t { *self }
}

pub type xcb_grab_mode_t = u32;
/// The state of the keyboard appears to freeze: No further keyboard events are
/// generated by the server until the grabbing client issues a releasing
/// `AllowEvents` request or until the keyboard grab is released.
pub const XCB_GRAB_MODE_SYNC : xcb_grab_mode_t = 0x00;
/// Keyboard event processing continues normally.
pub const XCB_GRAB_MODE_ASYNC: xcb_grab_mode_t = 0x01;

pub type xcb_grab_status_t = u32;
pub const XCB_GRAB_STATUS_SUCCESS        : xcb_grab_status_t = 0x00;
pub const XCB_GRAB_STATUS_ALREADY_GRABBED: xcb_grab_status_t = 0x01;
pub const XCB_GRAB_STATUS_INVALID_TIME   : xcb_grab_status_t = 0x02;
pub const XCB_GRAB_STATUS_NOT_VIEWABLE   : xcb_grab_status_t = 0x03;
pub const XCB_GRAB_STATUS_FROZEN         : xcb_grab_status_t = 0x04;

pub type xcb_cursor_enum_t = u32;
pub const XCB_CURSOR_NONE: xcb_cursor_enum_t = 0x00;

pub const XCB_GRAB_POINTER: u8 = 26;

/// Grab the pointer
///
/// Actively grabs control of the pointer. Further pointer events are reported only to the grabbing client. Overrides any active pointer grab by this client.
#[repr(C)]
pub struct xcb_grab_pointer_request_t {
    pub major_opcode:  u8,
    /// If 1, the `grab_window` will still get the pointer events. If 0, events are not
    /// reported to the `grab_window`.
    pub owner_events:  u8,
    pub length:        u16,
    /// Specifies the window on which the pointer should be grabbed.
    pub grab_window:   xcb_window_t,
    /// Specifies which pointer events are reported to the client.
    ///
    /// TODO: which values?
    pub event_mask:    u16,
    ///
    pub pointer_mode:  u8,
    ///
    pub keyboard_mode: u8,
    /// Specifies the window to confine the pointer in (the user will not be able to
    /// move the pointer out of that window).
    ///
    /// The special value `XCB_NONE` means don't confine the pointer.
    pub confine_to:    xcb_window_t,
    /// Specifies the cursor that should be displayed or `XCB_NONE` to not change the
    /// cursor.
    pub cursor:        xcb_cursor_t,
    /// The time argument allows you to avoid certain circumstances that come up if
    /// applications take a long time to respond or if there are long network delays.
    /// Consider a situation where you have two applications, both of which normally
    /// grab the pointer when clicked on. If both applications specify the timestamp
    /// from the event, the second application may wake up faster and successfully grab
    /// the pointer before the first application. The first application then will get
    /// an indication that the other application grabbed the pointer before its request
    /// was processed.
    ///
    /// The special value `XCB_CURRENT_TIME` will be replaced with the current server
    /// time.
    pub time:          xcb_timestamp_t,
}

impl Copy for xcb_grab_pointer_request_t {}
impl Clone for xcb_grab_pointer_request_t {
    fn clone(&self) -> xcb_grab_pointer_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_grab_pointer_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_grab_pointer_reply_t {
    pub response_type: u8,
    pub status:        u8,
    pub sequence:      u16,
    pub length:        u32,
}

impl Copy for xcb_grab_pointer_reply_t {}
impl Clone for xcb_grab_pointer_reply_t {
    fn clone(&self) -> xcb_grab_pointer_reply_t { *self }
}

pub const XCB_UNGRAB_POINTER: u8 = 27;

/// release the pointer
///
/// Releases the pointer and any queued events if you actively grabbed the pointer
/// before using `xcb_grab_pointer`, `xcb_grab_button` or within a normal button
/// press.
///
/// EnterNotify and LeaveNotify events are generated.
#[repr(C)]
pub struct xcb_ungrab_pointer_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// Timestamp to avoid race conditions when running X over the network.
    ///
    /// The pointer will not be released if `time` is earlier than the
    /// last-pointer-grab time or later than the current X server time.
    pub time:         xcb_timestamp_t,
}

impl Copy for xcb_ungrab_pointer_request_t {}
impl Clone for xcb_ungrab_pointer_request_t {
    fn clone(&self) -> xcb_ungrab_pointer_request_t { *self }
}

pub type xcb_button_index_t = u32;
/// Any of the following (or none):
pub const XCB_BUTTON_INDEX_ANY: xcb_button_index_t = 0x00;
/// The left mouse button.
pub const XCB_BUTTON_INDEX_1  : xcb_button_index_t = 0x01;
/// The right mouse button.
pub const XCB_BUTTON_INDEX_2  : xcb_button_index_t = 0x02;
/// The middle mouse button.
pub const XCB_BUTTON_INDEX_3  : xcb_button_index_t = 0x03;
/// Scroll wheel. TODO: direction?
pub const XCB_BUTTON_INDEX_4  : xcb_button_index_t = 0x04;
/// Scroll wheel. TODO: direction?
pub const XCB_BUTTON_INDEX_5  : xcb_button_index_t = 0x05;

pub const XCB_GRAB_BUTTON: u8 = 28;

/// Grab pointer button(s)
///
/// This request establishes a passive grab. The pointer is actively grabbed as
/// described in GrabPointer, the last-pointer-grab time is set to the time at
/// which the button was pressed (as transmitted in the ButtonPress event), and the
/// ButtonPress event is reported if all of the following conditions are true:
///
/// The pointer is not grabbed and the specified button is logically pressed when
/// the specified modifier keys are logically down, and no other buttons or
/// modifier keys are logically down.
///
/// The grab-window contains the pointer.
///
/// The confine-to window (if any) is viewable.
///
/// A passive grab on the same button/key combination does not exist on any
/// ancestor of grab-window.
///
/// The interpretation of the remaining arguments is the same as for GrabPointer.
/// The active grab is terminated automatically when the logical state of the
/// pointer has all buttons released, independent of the logical state of modifier
/// keys. Note that the logical state of a device (as seen by means of the
/// protocol) may lag the physical state if device event processing is frozen. This
/// request overrides all previous passive grabs by the same client on the same
/// button/key combinations on the same window. A modifier of AnyModifier is
/// equivalent to issuing the request for all possible modifier combinations
/// (including the combination of no modifiers). It is not required that all
/// specified modifiers have currently assigned keycodes. A button of AnyButton is
/// equivalent to issuing the request for all possible buttons. Otherwise, it is
/// not required that the button specified currently be assigned to a physical
/// button.
///
/// An Access error is generated if some other client has already issued a
/// GrabButton request with the same button/key combination on the same window.
/// When using AnyModifier or AnyButton, the request fails completely (no grabs are
/// established), and an Access error is generated if there is a conflicting grab
/// for any combination. The request has no effect on an active grab.
#[repr(C)]
pub struct xcb_grab_button_request_t {
    pub major_opcode:  u8,
    /// If 1, the `grab_window` will still get the pointer events. If 0, events are not
    /// reported to the `grab_window`.
    pub owner_events:  u8,
    pub length:        u16,
    /// Specifies the window on which the pointer should be grabbed.
    pub grab_window:   xcb_window_t,
    /// Specifies which pointer events are reported to the client.
    ///
    /// TODO: which values?
    pub event_mask:    u16,
    ///
    pub pointer_mode:  u8,
    ///
    pub keyboard_mode: u8,
    /// Specifies the window to confine the pointer in (the user will not be able to
    /// move the pointer out of that window).
    ///
    /// The special value `XCB_NONE` means don't confine the pointer.
    pub confine_to:    xcb_window_t,
    /// Specifies the cursor that should be displayed or `XCB_NONE` to not change the
    /// cursor.
    pub cursor:        xcb_cursor_t,
    ///
    pub button:        u8,
    pub pad0:          u8,
    /// The modifiers to grab.
    ///
    /// Using the special value `XCB_MOD_MASK_ANY` means grab the pointer with all
    /// possible modifier combinations.
    pub modifiers:     u16,
}

impl Copy for xcb_grab_button_request_t {}
impl Clone for xcb_grab_button_request_t {
    fn clone(&self) -> xcb_grab_button_request_t { *self }
}

pub const XCB_UNGRAB_BUTTON: u8 = 29;

#[repr(C)]
pub struct xcb_ungrab_button_request_t {
    pub major_opcode: u8,
    pub button:       u8,
    pub length:       u16,
    pub grab_window:  xcb_window_t,
    pub modifiers:    u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_ungrab_button_request_t {}
impl Clone for xcb_ungrab_button_request_t {
    fn clone(&self) -> xcb_ungrab_button_request_t { *self }
}

pub const XCB_CHANGE_ACTIVE_POINTER_GRAB: u8 = 30;

#[repr(C)]
pub struct xcb_change_active_pointer_grab_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cursor:       xcb_cursor_t,
    pub time:         xcb_timestamp_t,
    pub event_mask:   u16,
    pub pad1:         [u8; 2],
}

impl Copy for xcb_change_active_pointer_grab_request_t {}
impl Clone for xcb_change_active_pointer_grab_request_t {
    fn clone(&self) -> xcb_change_active_pointer_grab_request_t { *self }
}

pub const XCB_GRAB_KEYBOARD: u8 = 31;

/// Grab the keyboard
///
/// Actively grabs control of the keyboard and generates FocusIn and FocusOut
/// events. Further key events are reported only to the grabbing client.
///
/// Any active keyboard grab by this client is overridden. If the keyboard is
/// actively grabbed by some other client, `AlreadyGrabbed` is returned. If
/// `grab_window` is not viewable, `GrabNotViewable` is returned. If the keyboard
/// is frozen by an active grab of another client, `GrabFrozen` is returned. If the
/// specified `time` is earlier than the last-keyboard-grab time or later than the
/// current X server time, `GrabInvalidTime` is returned. Otherwise, the
/// last-keyboard-grab time is set to the specified time.
#[repr(C)]
pub struct xcb_grab_keyboard_request_t {
    pub major_opcode:  u8,
    /// If 1, the `grab_window` will still get the pointer events. If 0, events are not
    /// reported to the `grab_window`.
    pub owner_events:  u8,
    pub length:        u16,
    /// Specifies the window on which the pointer should be grabbed.
    pub grab_window:   xcb_window_t,
    /// Timestamp to avoid race conditions when running X over the network.
    ///
    /// The special value `XCB_CURRENT_TIME` will be replaced with the current server
    /// time.
    pub time:          xcb_timestamp_t,
    ///
    pub pointer_mode:  u8,
    ///
    pub keyboard_mode: u8,
    pub pad0:          [u8; 2],
}

impl Copy for xcb_grab_keyboard_request_t {}
impl Clone for xcb_grab_keyboard_request_t {
    fn clone(&self) -> xcb_grab_keyboard_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_grab_keyboard_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_grab_keyboard_reply_t {
    pub response_type: u8,
    pub status:        u8,
    pub sequence:      u16,
    pub length:        u32,
}

impl Copy for xcb_grab_keyboard_reply_t {}
impl Clone for xcb_grab_keyboard_reply_t {
    fn clone(&self) -> xcb_grab_keyboard_reply_t { *self }
}

pub const XCB_UNGRAB_KEYBOARD: u8 = 32;

#[repr(C)]
pub struct xcb_ungrab_keyboard_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub time:         xcb_timestamp_t,
}

impl Copy for xcb_ungrab_keyboard_request_t {}
impl Clone for xcb_ungrab_keyboard_request_t {
    fn clone(&self) -> xcb_ungrab_keyboard_request_t { *self }
}

pub type xcb_grab_t = u32;
pub const XCB_GRAB_ANY: xcb_grab_t = 0x00;

pub const XCB_GRAB_KEY: u8 = 33;

/// Grab keyboard key(s)
///
/// Establishes a passive grab on the keyboard. In the future, the keyboard is
/// actively grabbed (as for `GrabKeyboard`), the last-keyboard-grab time is set to
/// the time at which the key was pressed (as transmitted in the KeyPress event),
/// and the KeyPress event is reported if all of the following conditions are true:
///
/// The keyboard is not grabbed and the specified key (which can itself be a
/// modifier key) is logically pressed when the specified modifier keys are
/// logically down, and no other modifier keys are logically down.
///
/// Either the grab_window is an ancestor of (or is) the focus window, or the
/// grab_window is a descendant of the focus window and contains the pointer.
///
/// A passive grab on the same key combination does not exist on any ancestor of
/// grab_window.
///
/// The interpretation of the remaining arguments is as for XGrabKeyboard.  The active grab is terminated
/// automatically when the logical state of the keyboard has the specified key released (independent of the
/// logical state of the modifier keys), at which point a KeyRelease event is reported to the grabbing window.
///
/// Note that the logical state of a device (as seen by client applications) may lag the physical state if
/// device event processing is frozen.
///
/// A modifiers argument of AnyModifier is equivalent to issuing the request for all possible modifier combinations (including the combination of no modifiers).  It is not required that all modifiers specified
/// have currently assigned KeyCodes.  A keycode argument of AnyKey is equivalent to issuing the request for
/// all possible KeyCodes.  Otherwise, the specified keycode must be in the range specified by min_keycode
/// and max_keycode in the connection setup, or a BadValue error results.
///
/// If some other client has issued a XGrabKey with the same key combination on the same window, a BadAccess
/// error results.  When using AnyModifier or AnyKey, the request fails completely, and a BadAccess error
/// results (no grabs are established) if there is a conflicting grab for any combination.
#[repr(C)]
pub struct xcb_grab_key_request_t {
    pub major_opcode:  u8,
    /// If 1, the `grab_window` will still get the pointer events. If 0, events are not
    /// reported to the `grab_window`.
    pub owner_events:  u8,
    pub length:        u16,
    /// Specifies the window on which the pointer should be grabbed.
    pub grab_window:   xcb_window_t,
    /// The modifiers to grab.
    ///
    /// Using the special value `XCB_MOD_MASK_ANY` means grab the pointer with all
    /// possible modifier combinations.
    pub modifiers:     u16,
    /// The keycode of the key to grab.
    ///
    /// The special value `XCB_GRAB_ANY` means grab any key.
    pub key:           xcb_keycode_t,
    ///
    pub pointer_mode:  u8,
    ///
    pub keyboard_mode: u8,
    pub pad0:          [u8; 3],
}

impl Copy for xcb_grab_key_request_t {}
impl Clone for xcb_grab_key_request_t {
    fn clone(&self) -> xcb_grab_key_request_t { *self }
}

pub const XCB_UNGRAB_KEY: u8 = 34;

/// release a key combination
///
/// Releases the key combination on `grab_window` if you grabbed it using
/// `xcb_grab_key` before.
#[repr(C)]
pub struct xcb_ungrab_key_request_t {
    pub major_opcode: u8,
    /// The keycode of the specified key combination.
    ///
    /// Using the special value `XCB_GRAB_ANY` means releasing all possible key codes.
    pub key:          xcb_keycode_t,
    pub length:       u16,
    /// The window on which the grabbed key combination will be released.
    pub grab_window:  xcb_window_t,
    /// The modifiers of the specified key combination.
    ///
    /// Using the special value `XCB_MOD_MASK_ANY` means releasing the key combination
    /// with every possible modifier combination.
    pub modifiers:    u16,
    pub pad0:         [u8; 2],
}

impl Copy for xcb_ungrab_key_request_t {}
impl Clone for xcb_ungrab_key_request_t {
    fn clone(&self) -> xcb_ungrab_key_request_t { *self }
}

pub type xcb_allow_t = u32;
/// For AsyncPointer, if the pointer is frozen by the client, pointer event
/// processing continues normally. If the pointer is frozen twice by the client on
/// behalf of two separate grabs, AsyncPointer thaws for both. AsyncPointer has no
/// effect if the pointer is not frozen by the client, but the pointer need not be
/// grabbed by the client.
///
/// TODO: rewrite this in more understandable terms.
pub const XCB_ALLOW_ASYNC_POINTER  : xcb_allow_t = 0x00;
/// For SyncPointer, if the pointer is frozen and actively grabbed by the client,
/// pointer event processing continues normally until the next ButtonPress or
/// ButtonRelease event is reported to the client, at which time the pointer again
/// appears to freeze. However, if the reported event causes the pointer grab to be
/// released, then the pointer does not freeze. SyncPointer has no effect if the
/// pointer is not frozen by the client or if the pointer is not grabbed by the
/// client.
pub const XCB_ALLOW_SYNC_POINTER   : xcb_allow_t = 0x01;
/// For ReplayPointer, if the pointer is actively grabbed by the client and is
/// frozen as the result of an event having been sent to the client (either from
/// the activation of a GrabButton or from a previous AllowEvents with mode
/// SyncPointer but not from a GrabPointer), then the pointer grab is released and
/// that event is completely reprocessed, this time ignoring any passive grabs at
/// or above (towards the root) the grab-window of the grab just released. The
/// request has no effect if the pointer is not grabbed by the client or if the
/// pointer is not frozen as the result of an event.
pub const XCB_ALLOW_REPLAY_POINTER : xcb_allow_t = 0x02;
/// For AsyncKeyboard, if the keyboard is frozen by the client, keyboard event
/// processing continues normally. If the keyboard is frozen twice by the client on
/// behalf of two separate grabs, AsyncKeyboard thaws for both. AsyncKeyboard has
/// no effect if the keyboard is not frozen by the client, but the keyboard need
/// not be grabbed by the client.
pub const XCB_ALLOW_ASYNC_KEYBOARD : xcb_allow_t = 0x03;
/// For SyncKeyboard, if the keyboard is frozen and actively grabbed by the client,
/// keyboard event processing continues normally until the next KeyPress or
/// KeyRelease event is reported to the client, at which time the keyboard again
/// appears to freeze. However, if the reported event causes the keyboard grab to
/// be released, then the keyboard does not freeze. SyncKeyboard has no effect if
/// the keyboard is not frozen by the client or if the keyboard is not grabbed by
/// the client.
pub const XCB_ALLOW_SYNC_KEYBOARD  : xcb_allow_t = 0x04;
/// For ReplayKeyboard, if the keyboard is actively grabbed by the client and is
/// frozen as the result of an event having been sent to the client (either from
/// the activation of a GrabKey or from a previous AllowEvents with mode
/// SyncKeyboard but not from a GrabKeyboard), then the keyboard grab is released
/// and that event is completely reprocessed, this time ignoring any passive grabs
/// at or above (towards the root) the grab-window of the grab just released. The
/// request has no effect if the keyboard is not grabbed by the client or if the
/// keyboard is not frozen as the result of an event.
pub const XCB_ALLOW_REPLAY_KEYBOARD: xcb_allow_t = 0x05;
/// For AsyncBoth, if the pointer and the keyboard are frozen by the client, event
/// processing for both devices continues normally. If a device is frozen twice by
/// the client on behalf of two separate grabs, AsyncBoth thaws for both. AsyncBoth
/// has no effect unless both pointer and keyboard are frozen by the client.
pub const XCB_ALLOW_ASYNC_BOTH     : xcb_allow_t = 0x06;
/// For SyncBoth, if both pointer and keyboard are frozen by the client, event
/// processing (for both devices) continues normally until the next ButtonPress,
/// ButtonRelease, KeyPress, or KeyRelease event is reported to the client for a
/// grabbed device (button event for the pointer, key event for the keyboard), at
/// which time the devices again appear to freeze. However, if the reported event
/// causes the grab to be released, then the devices do not freeze (but if the
/// other device is still grabbed, then a subsequent event for it will still cause
/// both devices to freeze). SyncBoth has no effect unless both pointer and
/// keyboard are frozen by the client. If the pointer or keyboard is frozen twice
/// by the client on behalf of two separate grabs, SyncBoth thaws for both (but a
/// subsequent freeze for SyncBoth will only freeze each device once).
pub const XCB_ALLOW_SYNC_BOTH      : xcb_allow_t = 0x07;

pub const XCB_ALLOW_EVENTS: u8 = 35;

/// release queued events
///
/// Releases queued events if the client has caused a device (pointer/keyboard) to
/// freeze due to grabbing it actively. This request has no effect if `time` is
/// earlier than the last-grab time of the most recent active grab for this client
/// or if `time` is later than the current X server time.
#[repr(C)]
pub struct xcb_allow_events_request_t {
    pub major_opcode: u8,
    ///
    pub mode:         u8,
    pub length:       u16,
    /// Timestamp to avoid race conditions when running X over the network.
    ///
    /// The special value `XCB_CURRENT_TIME` will be replaced with the current server
    /// time.
    pub time:         xcb_timestamp_t,
}

impl Copy for xcb_allow_events_request_t {}
impl Clone for xcb_allow_events_request_t {
    fn clone(&self) -> xcb_allow_events_request_t { *self }
}

pub const XCB_GRAB_SERVER: u8 = 36;

#[repr(C)]
pub struct xcb_grab_server_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_grab_server_request_t {}
impl Clone for xcb_grab_server_request_t {
    fn clone(&self) -> xcb_grab_server_request_t { *self }
}

pub const XCB_UNGRAB_SERVER: u8 = 37;

#[repr(C)]
pub struct xcb_ungrab_server_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_ungrab_server_request_t {}
impl Clone for xcb_ungrab_server_request_t {
    fn clone(&self) -> xcb_ungrab_server_request_t { *self }
}

pub const XCB_QUERY_POINTER: u8 = 38;

/// get pointer coordinates
///
/// Gets the root window the pointer is logically on and the pointer coordinates
/// relative to the root window's origin.
#[repr(C)]
pub struct xcb_query_pointer_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// A window to check if the pointer is on the same screen as `window` (see the
    /// `same_screen` field in the reply).
    pub window:       xcb_window_t,
}

impl Copy for xcb_query_pointer_request_t {}
impl Clone for xcb_query_pointer_request_t {
    fn clone(&self) -> xcb_query_pointer_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_query_pointer_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_query_pointer_reply_t {
    pub response_type: u8,
    /// If `same_screen` is False, then the pointer is not on the same screen as the
    /// argument window, `child` is None, and `win_x` and `win_y` are zero. If
    /// `same_screen` is True, then `win_x` and `win_y` are the pointer coordinates
    /// relative to the argument window's origin, and child is the child containing the
    /// pointer, if any.
    pub same_screen:   u8,
    pub sequence:      u16,
    pub length:        u32,
    /// The root window the pointer is logically on.
    pub root:          xcb_window_t,
    /// The child window containing the pointer, if any, if `same_screen` is true. If
    /// `same_screen` is false, `XCB_NONE` is returned.
    pub child:         xcb_window_t,
    /// The pointer X position, relative to `root`.
    pub root_x:        i16,
    /// The pointer Y position, relative to `root`.
    pub root_y:        i16,
    /// The pointer X coordinate, relative to `child`, if `same_screen` is true. Zero
    /// otherwise.
    pub win_x:         i16,
    /// The pointer Y coordinate, relative to `child`, if `same_screen` is true. Zero
    /// otherwise.
    pub win_y:         i16,
    /// The current logical state of the modifier keys and the buttons. Note that the
    /// logical state of a device (as seen by means of the protocol) may lag the
    /// physical state if device event processing is frozen.
    pub mask:          u16,
    pub pad0:          [u8; 2],
}

impl Copy for xcb_query_pointer_reply_t {}
impl Clone for xcb_query_pointer_reply_t {
    fn clone(&self) -> xcb_query_pointer_reply_t { *self }
}

#[repr(C)]
pub struct xcb_timecoord_t {
    pub time: xcb_timestamp_t,
    pub x:    i16,
    pub y:    i16,
}

impl Copy for xcb_timecoord_t {}
impl Clone for xcb_timecoord_t {
    fn clone(&self) -> xcb_timecoord_t { *self }
}

#[repr(C)]
pub struct xcb_timecoord_iterator_t {
    pub data:  *mut xcb_timecoord_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_GET_MOTION_EVENTS: u8 = 39;

#[repr(C)]
pub struct xcb_get_motion_events_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub start:        xcb_timestamp_t,
    pub stop:         xcb_timestamp_t,
}

impl Copy for xcb_get_motion_events_request_t {}
impl Clone for xcb_get_motion_events_request_t {
    fn clone(&self) -> xcb_get_motion_events_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_motion_events_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_motion_events_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub events_len:    u32,
    pub pad1:          [u8; 20],
}

pub const XCB_TRANSLATE_COORDINATES: u8 = 40;

#[repr(C)]
pub struct xcb_translate_coordinates_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub src_window:   xcb_window_t,
    pub dst_window:   xcb_window_t,
    pub src_x:        i16,
    pub src_y:        i16,
}

impl Copy for xcb_translate_coordinates_request_t {}
impl Clone for xcb_translate_coordinates_request_t {
    fn clone(&self) -> xcb_translate_coordinates_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_translate_coordinates_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_translate_coordinates_reply_t {
    pub response_type: u8,
    pub same_screen:   u8,
    pub sequence:      u16,
    pub length:        u32,
    pub child:         xcb_window_t,
    pub dst_x:         i16,
    pub dst_y:         i16,
}

impl Copy for xcb_translate_coordinates_reply_t {}
impl Clone for xcb_translate_coordinates_reply_t {
    fn clone(&self) -> xcb_translate_coordinates_reply_t { *self }
}

pub const XCB_WARP_POINTER: u8 = 41;

/// move mouse pointer
///
/// Moves the mouse pointer to the specified position.
///
/// If `src_window` is not `XCB_NONE` (TODO), the move will only take place if the
/// pointer is inside `src_window` and within the rectangle specified by (`src_x`,
/// `src_y`, `src_width`, `src_height`). The rectangle coordinates are relative to
/// `src_window`.
///
/// If `dst_window` is not `XCB_NONE` (TODO), the pointer will be moved to the
/// offsets (`dst_x`, `dst_y`) relative to `dst_window`. If `dst_window` is
/// `XCB_NONE` (TODO), the pointer will be moved by the offsets (`dst_x`, `dst_y`)
/// relative to the current position of the pointer.
#[repr(C)]
pub struct xcb_warp_pointer_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// If `src_window` is not `XCB_NONE` (TODO), the move will only take place if the
    /// pointer is inside `src_window` and within the rectangle specified by (`src_x`,
    /// `src_y`, `src_width`, `src_height`). The rectangle coordinates are relative to
    /// `src_window`.
    pub src_window:   xcb_window_t,
    /// If `dst_window` is not `XCB_NONE` (TODO), the pointer will be moved to the
    /// offsets (`dst_x`, `dst_y`) relative to `dst_window`. If `dst_window` is
    /// `XCB_NONE` (TODO), the pointer will be moved by the offsets (`dst_x`, `dst_y`)
    /// relative to the current position of the pointer.
    pub dst_window:   xcb_window_t,
    pub src_x:        i16,
    pub src_y:        i16,
    pub src_width:    u16,
    pub src_height:   u16,
    pub dst_x:        i16,
    pub dst_y:        i16,
}

impl Copy for xcb_warp_pointer_request_t {}
impl Clone for xcb_warp_pointer_request_t {
    fn clone(&self) -> xcb_warp_pointer_request_t { *self }
}

pub type xcb_input_focus_t = u32;
/// The focus reverts to `XCB_NONE`, so no window will have the input focus.
pub const XCB_INPUT_FOCUS_NONE           : xcb_input_focus_t = 0x00;
/// The focus reverts to `XCB_POINTER_ROOT` respectively. When the focus reverts,
/// FocusIn and FocusOut events are generated, but the last-focus-change time is
/// not changed.
pub const XCB_INPUT_FOCUS_POINTER_ROOT   : xcb_input_focus_t = 0x01;
/// The focus reverts to the parent (or closest viewable ancestor) and the new
/// revert_to value is `XCB_INPUT_FOCUS_NONE`.
pub const XCB_INPUT_FOCUS_PARENT         : xcb_input_focus_t = 0x02;
/// NOT YET DOCUMENTED. Only relevant for the xinput extension.
pub const XCB_INPUT_FOCUS_FOLLOW_KEYBOARD: xcb_input_focus_t = 0x03;

pub const XCB_SET_INPUT_FOCUS: u8 = 42;

/// Sets input focus
///
/// Changes the input focus and the last-focus-change time. If the specified `time`
/// is earlier than the current last-focus-change time, the request is ignored (to
/// avoid race conditions when running X over the network).
///
/// A FocusIn and FocusOut event is generated when focus is changed.
#[repr(C)]
pub struct xcb_set_input_focus_request_t {
    pub major_opcode: u8,
    /// Specifies what happens when the `focus` window becomes unviewable (if `focus`
    /// is neither `XCB_NONE` nor `XCB_POINTER_ROOT`).
    pub revert_to:    u8,
    pub length:       u16,
    /// The window to focus. All keyboard events will be reported to this window. The
    /// window must be viewable (TODO), or a `xcb_match_error_t` occurs (TODO).
    ///
    /// If `focus` is `XCB_NONE` (TODO), all keyboard events are
    /// discarded until a new focus window is set.
    ///
    /// If `focus` is `XCB_POINTER_ROOT` (TODO), focus is on the root window of the
    /// screen on which the pointer is on currently.
    pub focus:        xcb_window_t,
    /// Timestamp to avoid race conditions when running X over the network.
    ///
    /// The special value `XCB_CURRENT_TIME` will be replaced with the current server
    /// time.
    pub time:         xcb_timestamp_t,
}

impl Copy for xcb_set_input_focus_request_t {}
impl Clone for xcb_set_input_focus_request_t {
    fn clone(&self) -> xcb_set_input_focus_request_t { *self }
}

pub const XCB_GET_INPUT_FOCUS: u8 = 43;

#[repr(C)]
pub struct xcb_get_input_focus_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_get_input_focus_request_t {}
impl Clone for xcb_get_input_focus_request_t {
    fn clone(&self) -> xcb_get_input_focus_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_input_focus_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_input_focus_reply_t {
    pub response_type: u8,
    pub revert_to:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub focus:         xcb_window_t,
}

impl Copy for xcb_get_input_focus_reply_t {}
impl Clone for xcb_get_input_focus_reply_t {
    fn clone(&self) -> xcb_get_input_focus_reply_t { *self }
}

pub const XCB_QUERY_KEYMAP: u8 = 44;

#[repr(C)]
pub struct xcb_query_keymap_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_query_keymap_request_t {}
impl Clone for xcb_query_keymap_request_t {
    fn clone(&self) -> xcb_query_keymap_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_query_keymap_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_query_keymap_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub keys:          [u8; 32],
}

impl Copy for xcb_query_keymap_reply_t {}
impl Clone for xcb_query_keymap_reply_t {
    fn clone(&self) -> xcb_query_keymap_reply_t { *self }
}

pub const XCB_OPEN_FONT: u8 = 45;

/// opens a font
///
/// Opens any X core font matching the given `name` (for example "-misc-fixed-*").
///
/// Note that X core fonts are deprecated (but still supported) in favor of
/// client-side rendering using Xft.
#[repr(C)]
pub struct xcb_open_font_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The ID with which you will refer to the font, created by `xcb_generate_id`.
    pub fid:          xcb_font_t,
    /// Length (in bytes) of `name`.
    pub name_len:     u16,
    pub pad1:         [u8; 2],
}

pub const XCB_CLOSE_FONT: u8 = 46;

#[repr(C)]
pub struct xcb_close_font_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub font:         xcb_font_t,
}

impl Copy for xcb_close_font_request_t {}
impl Clone for xcb_close_font_request_t {
    fn clone(&self) -> xcb_close_font_request_t { *self }
}

pub type xcb_font_draw_t = u32;
pub const XCB_FONT_DRAW_LEFT_TO_RIGHT: xcb_font_draw_t = 0x00;
pub const XCB_FONT_DRAW_RIGHT_TO_LEFT: xcb_font_draw_t = 0x01;

#[repr(C)]
pub struct xcb_fontprop_t {
    pub name:  xcb_atom_t,
    pub value: u32,
}

impl Copy for xcb_fontprop_t {}
impl Clone for xcb_fontprop_t {
    fn clone(&self) -> xcb_fontprop_t { *self }
}

#[repr(C)]
pub struct xcb_fontprop_iterator_t {
    pub data:  *mut xcb_fontprop_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_charinfo_t {
    pub left_side_bearing:  i16,
    pub right_side_bearing: i16,
    pub character_width:    i16,
    pub ascent:             i16,
    pub descent:            i16,
    pub attributes:         u16,
}

impl Copy for xcb_charinfo_t {}
impl Clone for xcb_charinfo_t {
    fn clone(&self) -> xcb_charinfo_t { *self }
}

#[repr(C)]
pub struct xcb_charinfo_iterator_t {
    pub data:  *mut xcb_charinfo_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_QUERY_FONT: u8 = 47;

/// query font metrics
///
/// Queries information associated with the font.
#[repr(C)]
pub struct xcb_query_font_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The fontable (Font or Graphics Context) to query.
    pub font:         xcb_fontable_t,
}

impl Copy for xcb_query_font_request_t {}
impl Clone for xcb_query_font_request_t {
    fn clone(&self) -> xcb_query_font_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_query_font_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_query_font_reply_t {
    pub response_type:     u8,
    pub pad0:              u8,
    pub sequence:          u16,
    pub length:            u32,
    /// minimum bounds over all existing char
    pub min_bounds:        xcb_charinfo_t,
    pub pad1:              [u8; 4],
    /// maximum bounds over all existing char
    pub max_bounds:        xcb_charinfo_t,
    pub pad2:              [u8; 4],
    /// first character
    pub min_char_or_byte2: u16,
    /// last character
    pub max_char_or_byte2: u16,
    /// char to print for undefined character
    pub default_char:      u16,
    /// how many properties there are
    pub properties_len:    u16,
    ///
    pub draw_direction:    u8,
    pub min_byte1:         u8,
    pub max_byte1:         u8,
    /// flag if all characters have nonzero size
    pub all_chars_exist:   u8,
    /// baseline to top edge of raster
    pub font_ascent:       i16,
    /// baseline to bottom edge of raster
    pub font_descent:      i16,
    pub char_infos_len:    u32,
}

pub const XCB_QUERY_TEXT_EXTENTS: u8 = 48;

/// get text extents
///
/// Query text extents from the X11 server. This request returns the bounding box
/// of the specified 16-bit character string in the specified `font` or the font
/// contained in the specified graphics context.
///
/// `font_ascent` is set to the maximum of the ascent metrics of all characters in
/// the string. `font_descent` is set to the maximum of the descent metrics.
/// `overall_width` is set to the sum of the character-width metrics of all
/// characters in the string. For each character in the string, let W be the sum of
/// the character-width metrics of all characters preceding it in the string. Let L
/// be the left-side-bearing metric of the character plus W. Let R be the
/// right-side-bearing metric of the character plus W. The lbearing member is set
/// to the minimum L of all characters in the string. The rbearing member is set to
/// the maximum R.
///
/// For fonts defined with linear indexing rather than 2-byte matrix indexing, each
/// `xcb_char2b_t` structure is interpreted as a 16-bit number with byte1 as the
/// most significant byte. If the font has no defined default character, undefined
/// characters in the string are taken to have all zero metrics.
///
/// Characters with all zero metrics are ignored. If the font has no defined
/// default_char, the undefined characters in the string are also ignored.
#[repr(C)]
pub struct xcb_query_text_extents_request_t {
    pub major_opcode: u8,
    pub odd_length:   u8,
    pub length:       u16,
    /// The `font` to calculate text extents in. You can also pass a graphics context.
    pub font:         xcb_fontable_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_query_text_extents_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_query_text_extents_reply_t {
    pub response_type:   u8,
    pub draw_direction:  u8,
    pub sequence:        u16,
    pub length:          u32,
    pub font_ascent:     i16,
    pub font_descent:    i16,
    pub overall_ascent:  i16,
    pub overall_descent: i16,
    pub overall_width:   i32,
    pub overall_left:    i32,
    pub overall_right:   i32,
}

impl Copy for xcb_query_text_extents_reply_t {}
impl Clone for xcb_query_text_extents_reply_t {
    fn clone(&self) -> xcb_query_text_extents_reply_t { *self }
}

#[repr(C)]
pub struct xcb_str_t {
    pub name_len: u8,
}

#[repr(C)]
pub struct xcb_str_iterator_t<'a> {
    pub data:  *mut xcb_str_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_str_t>,
}

pub const XCB_LIST_FONTS: u8 = 49;

/// get matching font names
///
/// Gets a list of available font names which match the given `pattern`.
#[repr(C)]
pub struct xcb_list_fonts_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The maximum number of fonts to be returned.
    pub max_names:    u16,
    /// The length (in bytes) of `pattern`.
    pub pattern_len:  u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_list_fonts_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_list_fonts_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    /// The number of font names.
    pub names_len:     u16,
    pub pad1:          [u8; 22],
}

pub const XCB_LIST_FONTS_WITH_INFO: u8 = 50;

/// get matching font names and information
///
/// Gets a list of available font names which match the given `pattern`.
#[repr(C)]
pub struct xcb_list_fonts_with_info_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The maximum number of fonts to be returned.
    pub max_names:    u16,
    /// The length (in bytes) of `pattern`.
    pub pattern_len:  u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_list_fonts_with_info_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_list_fonts_with_info_reply_t {
    pub response_type:     u8,
    /// The number of matched font names.
    pub name_len:          u8,
    pub sequence:          u16,
    pub length:            u32,
    /// minimum bounds over all existing char
    pub min_bounds:        xcb_charinfo_t,
    pub pad0:              [u8; 4],
    /// maximum bounds over all existing char
    pub max_bounds:        xcb_charinfo_t,
    pub pad1:              [u8; 4],
    /// first character
    pub min_char_or_byte2: u16,
    /// last character
    pub max_char_or_byte2: u16,
    /// char to print for undefined character
    pub default_char:      u16,
    /// how many properties there are
    pub properties_len:    u16,
    ///
    pub draw_direction:    u8,
    pub min_byte1:         u8,
    pub max_byte1:         u8,
    /// flag if all characters have nonzero size
    pub all_chars_exist:   u8,
    /// baseline to top edge of raster
    pub font_ascent:       i16,
    /// baseline to bottom edge of raster
    pub font_descent:      i16,
    /// An indication of how many more fonts will be returned. This is only a hint and
    /// may be larger or smaller than the number of fonts actually returned. A zero
    /// value does not guarantee that no more fonts will be returned.
    pub replies_hint:      u32,
}

pub const XCB_SET_FONT_PATH: u8 = 51;

#[repr(C)]
pub struct xcb_set_font_path_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub font_qty:     u16,
    pub pad1:         [u8; 2],
}

pub const XCB_GET_FONT_PATH: u8 = 52;

#[repr(C)]
pub struct xcb_get_font_path_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_get_font_path_request_t {}
impl Clone for xcb_get_font_path_request_t {
    fn clone(&self) -> xcb_get_font_path_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_font_path_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_font_path_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub path_len:      u16,
    pub pad1:          [u8; 22],
}

pub const XCB_CREATE_PIXMAP: u8 = 53;

/// Creates a pixmap
///
/// Creates a pixmap. The pixmap can only be used on the same screen as `drawable`
/// is on and only with drawables of the same `depth`.
#[repr(C)]
pub struct xcb_create_pixmap_request_t {
    pub major_opcode: u8,
    /// TODO
    pub depth:        u8,
    pub length:       u16,
    /// The ID with which you will refer to the new pixmap, created by
    /// `xcb_generate_id`.
    pub pid:          xcb_pixmap_t,
    /// Drawable to get the screen from.
    pub drawable:     xcb_drawable_t,
    /// The width of the new pixmap.
    pub width:        u16,
    /// The height of the new pixmap.
    pub height:       u16,
}

impl Copy for xcb_create_pixmap_request_t {}
impl Clone for xcb_create_pixmap_request_t {
    fn clone(&self) -> xcb_create_pixmap_request_t { *self }
}

pub const XCB_FREE_PIXMAP: u8 = 54;

/// Destroys a pixmap
///
/// Deletes the association between the pixmap ID and the pixmap. The pixmap
/// storage will be freed when there are no more references to it.
#[repr(C)]
pub struct xcb_free_pixmap_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The pixmap to destroy.
    pub pixmap:       xcb_pixmap_t,
}

impl Copy for xcb_free_pixmap_request_t {}
impl Clone for xcb_free_pixmap_request_t {
    fn clone(&self) -> xcb_free_pixmap_request_t { *self }
}

pub type xcb_gc_t = u32;
/// TODO: Refer to GX
pub const XCB_GC_FUNCTION             : xcb_gc_t =     0x01;
/// In graphics operations, given a source and destination pixel, the result is
/// computed bitwise on corresponding bits of the pixels; that is, a Boolean
/// operation is performed in each bit plane. The plane-mask restricts the
/// operation to a subset of planes, so the result is:
///
///         ((src FUNC dst) AND plane-mask) OR (dst AND (NOT plane-mask))
pub const XCB_GC_PLANE_MASK           : xcb_gc_t =     0x02;
/// Foreground colorpixel.
pub const XCB_GC_FOREGROUND           : xcb_gc_t =     0x04;
/// Background colorpixel.
pub const XCB_GC_BACKGROUND           : xcb_gc_t =     0x08;
/// The line-width is measured in pixels and can be greater than or equal to one, a wide line, or the
/// special value zero, a thin line.
pub const XCB_GC_LINE_WIDTH           : xcb_gc_t =     0x10;
/// The line-style defines which sections of a line are drawn:
/// Solid                The full path of the line is drawn.
/// DoubleDash           The full path of the line is drawn, but the even dashes are filled differently
///                      than the odd dashes (see fill-style), with Butt cap-style used where even and
///                      odd dashes meet.
/// OnOffDash            Only the even dashes are drawn, and cap-style applies to all internal ends of
///                      the individual dashes (except NotLast is treated as Butt).
pub const XCB_GC_LINE_STYLE           : xcb_gc_t =     0x20;
/// The cap-style defines how the endpoints of a path are drawn:
/// NotLast    The result is equivalent to Butt, except that for a line-width of zero the final
///            endpoint is not drawn.
/// Butt       The result is square at the endpoint (perpendicular to the slope of the line)
///            with no projection beyond.
/// Round      The result is a circular arc with its diameter equal to the line-width, centered
///            on the endpoint; it is equivalent to Butt for line-width zero.
/// Projecting The result is square at the end, but the path continues beyond the endpoint for
///            a distance equal to half the line-width; it is equivalent to Butt for line-width
///            zero.
pub const XCB_GC_CAP_STYLE            : xcb_gc_t =     0x40;
/// The join-style defines how corners are drawn for wide lines:
/// Miter               The outer edges of the two lines extend to meet at an angle. However, if the
///                     angle is less than 11 degrees, a Bevel join-style is used instead.
/// Round               The result is a circular arc with a diameter equal to the line-width, centered
///                     on the joinpoint.
/// Bevel               The result is Butt endpoint styles, and then the triangular notch is filled.
pub const XCB_GC_JOIN_STYLE           : xcb_gc_t =     0x80;
/// The fill-style defines the contents of the source for line, text, and fill requests. For all text and fill
/// requests (for example, PolyText8, PolyText16, PolyFillRectangle, FillPoly, and PolyFillArc)
/// as well as for line requests with line-style Solid, (for example, PolyLine, PolySegment,
/// PolyRectangle, PolyArc) and for the even dashes for line requests with line-style OnOffDash
/// or DoubleDash:
/// Solid                     Foreground
/// Tiled                     Tile
/// OpaqueStippled            A tile with the same width and height as stipple but with background
///                           everywhere stipple has a zero and with foreground everywhere stipple
///                           has a one
/// Stippled                  Foreground masked by stipple
/// For the odd dashes for line requests with line-style DoubleDash:
/// Solid                     Background
/// Tiled                     Same as for even dashes
/// OpaqueStippled            Same as for even dashes
/// Stippled                  Background masked by stipple
pub const XCB_GC_FILL_STYLE           : xcb_gc_t =    0x100;
pub const XCB_GC_FILL_RULE            : xcb_gc_t =    0x200;
/// The tile/stipple represents an infinite two-dimensional plane with the tile/stipple replicated in all
/// dimensions. When that plane is superimposed on the drawable for use in a graphics operation,
/// the upper-left corner of some instance of the tile/stipple is at the coordinates within the drawable
/// specified by the tile/stipple origin. The tile/stipple and clip origins are interpreted relative to the
/// origin of whatever destination drawable is specified in a graphics request.
/// The tile pixmap must have the same root and depth as the gcontext (or a Match error results).
/// The stipple pixmap must have depth one and must have the same root as the gcontext (or a
/// Match error results). For fill-style Stippled (but not fill-style
/// OpaqueStippled), the stipple pattern is tiled in a single plane and acts as an
/// additional clip mask to be ANDed with the clip-mask.
/// Any size pixmap can be used for tiling or stippling, although some sizes may be faster to use than
/// others.
pub const XCB_GC_TILE                 : xcb_gc_t =    0x400;
/// The tile/stipple represents an infinite two-dimensional plane with the tile/stipple replicated in all
/// dimensions. When that plane is superimposed on the drawable for use in a graphics operation,
/// the upper-left corner of some instance of the tile/stipple is at the coordinates within the drawable
/// specified by the tile/stipple origin. The tile/stipple and clip origins are interpreted relative to the
/// origin of whatever destination drawable is specified in a graphics request.
/// The tile pixmap must have the same root and depth as the gcontext (or a Match error results).
/// The stipple pixmap must have depth one and must have the same root as the gcontext (or a
/// Match error results). For fill-style Stippled (but not fill-style
/// OpaqueStippled), the stipple pattern is tiled in a single plane and acts as an
/// additional clip mask to be ANDed with the clip-mask.
/// Any size pixmap can be used for tiling or stippling, although some sizes may be faster to use than
/// others.
pub const XCB_GC_STIPPLE              : xcb_gc_t =    0x800;
/// TODO
pub const XCB_GC_TILE_STIPPLE_ORIGIN_X: xcb_gc_t =   0x1000;
/// TODO
pub const XCB_GC_TILE_STIPPLE_ORIGIN_Y: xcb_gc_t =   0x2000;
/// Which font to use for the `ImageText8` and `ImageText16` requests.
pub const XCB_GC_FONT                 : xcb_gc_t =   0x4000;
/// For ClipByChildren, both source and destination windows are additionally
/// clipped by all viewable InputOutput children. For IncludeInferiors, neither
/// source nor destination window is
/// clipped by inferiors. This will result in including subwindow contents in the source and drawing
/// through subwindow boundaries of the destination. The use of IncludeInferiors with a source or
/// destination window of one depth with mapped inferiors of differing depth is not illegal, but the
/// semantics is undefined by the core protocol.
pub const XCB_GC_SUBWINDOW_MODE       : xcb_gc_t =   0x8000;
/// Whether ExposureEvents should be generated (1) or not (0).
///
/// The default is 1.
pub const XCB_GC_GRAPHICS_EXPOSURES   : xcb_gc_t =  0x10000;
/// TODO
pub const XCB_GC_CLIP_ORIGIN_X        : xcb_gc_t =  0x20000;
/// TODO
pub const XCB_GC_CLIP_ORIGIN_Y        : xcb_gc_t =  0x40000;
/// The clip-mask restricts writes to the destination drawable. Only pixels where the clip-mask has
/// bits set to 1 are drawn. Pixels are not drawn outside the area covered by the clip-mask or where
/// the clip-mask has bits set to 0. The clip-mask affects all graphics requests, but it does not clip
/// sources. The clip-mask origin is interpreted relative to the origin of whatever destination drawable is specified in a graphics request. If a pixmap is specified as the clip-mask, it must have
/// depth 1 and have the same root as the gcontext (or a Match error results). If clip-mask is None,
/// then pixels are always drawn, regardless of the clip origin. The clip-mask can also be set with the
/// SetClipRectangles request.
pub const XCB_GC_CLIP_MASK            : xcb_gc_t =  0x80000;
/// TODO
pub const XCB_GC_DASH_OFFSET          : xcb_gc_t = 0x100000;
/// TODO
pub const XCB_GC_DASH_LIST            : xcb_gc_t = 0x200000;
/// TODO
pub const XCB_GC_ARC_MODE             : xcb_gc_t = 0x400000;

pub type xcb_gx_t = u32;
pub const XCB_GX_CLEAR        : xcb_gx_t = 0x00;
pub const XCB_GX_AND          : xcb_gx_t = 0x01;
pub const XCB_GX_AND_REVERSE  : xcb_gx_t = 0x02;
pub const XCB_GX_COPY         : xcb_gx_t = 0x03;
pub const XCB_GX_AND_INVERTED : xcb_gx_t = 0x04;
pub const XCB_GX_NOOP         : xcb_gx_t = 0x05;
pub const XCB_GX_XOR          : xcb_gx_t = 0x06;
pub const XCB_GX_OR           : xcb_gx_t = 0x07;
pub const XCB_GX_NOR          : xcb_gx_t = 0x08;
pub const XCB_GX_EQUIV        : xcb_gx_t = 0x09;
pub const XCB_GX_INVERT       : xcb_gx_t = 0x0a;
pub const XCB_GX_OR_REVERSE   : xcb_gx_t = 0x0b;
pub const XCB_GX_COPY_INVERTED: xcb_gx_t = 0x0c;
pub const XCB_GX_OR_INVERTED  : xcb_gx_t = 0x0d;
pub const XCB_GX_NAND         : xcb_gx_t = 0x0e;
pub const XCB_GX_SET          : xcb_gx_t = 0x0f;

pub type xcb_line_style_t = u32;
pub const XCB_LINE_STYLE_SOLID      : xcb_line_style_t = 0x00;
pub const XCB_LINE_STYLE_ON_OFF_DASH: xcb_line_style_t = 0x01;
pub const XCB_LINE_STYLE_DOUBLE_DASH: xcb_line_style_t = 0x02;

pub type xcb_cap_style_t = u32;
pub const XCB_CAP_STYLE_NOT_LAST  : xcb_cap_style_t = 0x00;
pub const XCB_CAP_STYLE_BUTT      : xcb_cap_style_t = 0x01;
pub const XCB_CAP_STYLE_ROUND     : xcb_cap_style_t = 0x02;
pub const XCB_CAP_STYLE_PROJECTING: xcb_cap_style_t = 0x03;

pub type xcb_join_style_t = u32;
pub const XCB_JOIN_STYLE_MITER: xcb_join_style_t = 0x00;
pub const XCB_JOIN_STYLE_ROUND: xcb_join_style_t = 0x01;
pub const XCB_JOIN_STYLE_BEVEL: xcb_join_style_t = 0x02;

pub type xcb_fill_style_t = u32;
pub const XCB_FILL_STYLE_SOLID          : xcb_fill_style_t = 0x00;
pub const XCB_FILL_STYLE_TILED          : xcb_fill_style_t = 0x01;
pub const XCB_FILL_STYLE_STIPPLED       : xcb_fill_style_t = 0x02;
pub const XCB_FILL_STYLE_OPAQUE_STIPPLED: xcb_fill_style_t = 0x03;

pub type xcb_fill_rule_t = u32;
pub const XCB_FILL_RULE_EVEN_ODD: xcb_fill_rule_t = 0x00;
pub const XCB_FILL_RULE_WINDING : xcb_fill_rule_t = 0x01;

pub type xcb_subwindow_mode_t = u32;
pub const XCB_SUBWINDOW_MODE_CLIP_BY_CHILDREN : xcb_subwindow_mode_t = 0x00;
pub const XCB_SUBWINDOW_MODE_INCLUDE_INFERIORS: xcb_subwindow_mode_t = 0x01;

pub type xcb_arc_mode_t = u32;
pub const XCB_ARC_MODE_CHORD    : xcb_arc_mode_t = 0x00;
pub const XCB_ARC_MODE_PIE_SLICE: xcb_arc_mode_t = 0x01;

pub const XCB_CREATE_GC: u8 = 55;

/// Creates a graphics context
///
/// Creates a graphics context. The graphics context can be used with any drawable
/// that has the same root and depth as the specified drawable.
#[repr(C)]
pub struct xcb_create_gc_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The ID with which you will refer to the graphics context, created by
    /// `xcb_generate_id`.
    pub cid:          xcb_gcontext_t,
    /// Drawable to get the root/depth from.
    pub drawable:     xcb_drawable_t,
    pub value_mask:   u32,
}

pub const XCB_CHANGE_GC: u8 = 56;

/// change graphics context components
///
/// Changes the components specified by `value_mask` for the specified graphics context.
#[repr(C)]
pub struct xcb_change_gc_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The graphics context to change.
    pub gc:           xcb_gcontext_t,
    ///
    pub value_mask:   u32,
}

pub const XCB_COPY_GC: u8 = 57;

#[repr(C)]
pub struct xcb_copy_gc_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub src_gc:       xcb_gcontext_t,
    pub dst_gc:       xcb_gcontext_t,
    pub value_mask:   u32,
}

impl Copy for xcb_copy_gc_request_t {}
impl Clone for xcb_copy_gc_request_t {
    fn clone(&self) -> xcb_copy_gc_request_t { *self }
}

pub const XCB_SET_DASHES: u8 = 58;

#[repr(C)]
pub struct xcb_set_dashes_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub gc:           xcb_gcontext_t,
    pub dash_offset:  u16,
    pub dashes_len:   u16,
}

pub type xcb_clip_ordering_t = u32;
pub const XCB_CLIP_ORDERING_UNSORTED : xcb_clip_ordering_t = 0x00;
pub const XCB_CLIP_ORDERING_Y_SORTED : xcb_clip_ordering_t = 0x01;
pub const XCB_CLIP_ORDERING_YX_SORTED: xcb_clip_ordering_t = 0x02;
pub const XCB_CLIP_ORDERING_YX_BANDED: xcb_clip_ordering_t = 0x03;

pub const XCB_SET_CLIP_RECTANGLES: u8 = 59;

#[repr(C)]
pub struct xcb_set_clip_rectangles_request_t {
    pub major_opcode:   u8,
    pub ordering:       u8,
    pub length:         u16,
    pub gc:             xcb_gcontext_t,
    pub clip_x_origin:  i16,
    pub clip_y_origin:  i16,
}

pub const XCB_FREE_GC: u8 = 60;

/// Destroys a graphics context
///
/// Destroys the specified `gc` and all associated storage.
#[repr(C)]
pub struct xcb_free_gc_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The graphics context to destroy.
    pub gc:           xcb_gcontext_t,
}

impl Copy for xcb_free_gc_request_t {}
impl Clone for xcb_free_gc_request_t {
    fn clone(&self) -> xcb_free_gc_request_t { *self }
}

pub const XCB_CLEAR_AREA: u8 = 61;

#[repr(C)]
pub struct xcb_clear_area_request_t {
    pub major_opcode: u8,
    pub exposures:    u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub x:            i16,
    pub y:            i16,
    pub width:        u16,
    pub height:       u16,
}

impl Copy for xcb_clear_area_request_t {}
impl Clone for xcb_clear_area_request_t {
    fn clone(&self) -> xcb_clear_area_request_t { *self }
}

pub const XCB_COPY_AREA: u8 = 62;

/// copy areas
///
/// Copies the specified rectangle from `src_drawable` to `dst_drawable`.
#[repr(C)]
pub struct xcb_copy_area_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The source drawable (Window or Pixmap).
    pub src_drawable: xcb_drawable_t,
    /// The destination drawable (Window or Pixmap).
    pub dst_drawable: xcb_drawable_t,
    /// The graphics context to use.
    pub gc:           xcb_gcontext_t,
    /// The source X coordinate.
    pub src_x:        i16,
    /// The source Y coordinate.
    pub src_y:        i16,
    /// The destination X coordinate.
    pub dst_x:        i16,
    /// The destination Y coordinate.
    pub dst_y:        i16,
    /// The width of the area to copy (in pixels).
    pub width:        u16,
    /// The height of the area to copy (in pixels).
    pub height:       u16,
}

impl Copy for xcb_copy_area_request_t {}
impl Clone for xcb_copy_area_request_t {
    fn clone(&self) -> xcb_copy_area_request_t { *self }
}

pub const XCB_COPY_PLANE: u8 = 63;

#[repr(C)]
pub struct xcb_copy_plane_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub src_drawable: xcb_drawable_t,
    pub dst_drawable: xcb_drawable_t,
    pub gc:           xcb_gcontext_t,
    pub src_x:        i16,
    pub src_y:        i16,
    pub dst_x:        i16,
    pub dst_y:        i16,
    pub width:        u16,
    pub height:       u16,
    pub bit_plane:    u32,
}

impl Copy for xcb_copy_plane_request_t {}
impl Clone for xcb_copy_plane_request_t {
    fn clone(&self) -> xcb_copy_plane_request_t { *self }
}

pub type xcb_coord_mode_t = u32;
/// Treats all coordinates as relative to the origin.
pub const XCB_COORD_MODE_ORIGIN  : xcb_coord_mode_t = 0x00;
/// Treats all coordinates after the first as relative to the previous coordinate.
pub const XCB_COORD_MODE_PREVIOUS: xcb_coord_mode_t = 0x01;

pub const XCB_POLY_POINT: u8 = 64;

#[repr(C)]
pub struct xcb_poly_point_request_t {
    pub major_opcode:    u8,
    pub coordinate_mode: u8,
    pub length:          u16,
    pub drawable:        xcb_drawable_t,
    pub gc:              xcb_gcontext_t,
}

pub const XCB_POLY_LINE: u8 = 65;

/// draw lines
///
/// Draws `points_len`-1 lines between each pair of points (point[i], point[i+1])
/// in the `points` array. The lines are drawn in the order listed in the array.
/// They join correctly at all intermediate points, and if the first and last
/// points coincide, the first and last lines also join correctly. For any given
/// line, a pixel is not drawn more than once. If thin (zero line-width) lines
/// intersect, the intersecting pixels are drawn multiple times. If wide lines
/// intersect, the intersecting pixels are drawn only once, as though the entire
/// request were a single, filled shape.
#[repr(C)]
pub struct xcb_poly_line_request_t {
    pub major_opcode:    u8,
    ///
    pub coordinate_mode: u8,
    pub length:          u16,
    /// The drawable to draw the line(s) on.
    pub drawable:        xcb_drawable_t,
    /// The graphics context to use.
    pub gc:              xcb_gcontext_t,
}

#[repr(C)]
pub struct xcb_segment_t {
    pub x1: i16,
    pub y1: i16,
    pub x2: i16,
    pub y2: i16,
}

impl Copy for xcb_segment_t {}
impl Clone for xcb_segment_t {
    fn clone(&self) -> xcb_segment_t { *self }
}

#[repr(C)]
pub struct xcb_segment_iterator_t {
    pub data:  *mut xcb_segment_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_POLY_SEGMENT: u8 = 66;

/// draw lines
///
/// Draws multiple, unconnected lines. For each segment, a line is drawn between
/// (x1, y1) and (x2, y2). The lines are drawn in the order listed in the array of
/// `xcb_segment_t` structures and does not perform joining at coincident
/// endpoints. For any given line, a pixel is not drawn more than once. If lines
/// intersect, the intersecting pixels are drawn multiple times.
///
/// TODO: include the xcb_segment_t data structure
///
/// TODO: an example
#[repr(C)]
pub struct xcb_poly_segment_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// A drawable (Window or Pixmap) to draw on.
    pub drawable:     xcb_drawable_t,
    /// The graphics context to use.
    ///
    /// TODO: document which attributes of a gc are used
    pub gc:           xcb_gcontext_t,
}

pub const XCB_POLY_RECTANGLE: u8 = 67;

#[repr(C)]
pub struct xcb_poly_rectangle_request_t {
    pub major_opcode:   u8,
    pub pad0:           u8,
    pub length:         u16,
    pub drawable:       xcb_drawable_t,
    pub gc:             xcb_gcontext_t,
}

pub const XCB_POLY_ARC: u8 = 68;

#[repr(C)]
pub struct xcb_poly_arc_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub gc:           xcb_gcontext_t,
}

pub type xcb_poly_shape_t = u32;
pub const XCB_POLY_SHAPE_COMPLEX  : xcb_poly_shape_t = 0x00;
pub const XCB_POLY_SHAPE_NONCONVEX: xcb_poly_shape_t = 0x01;
pub const XCB_POLY_SHAPE_CONVEX   : xcb_poly_shape_t = 0x02;

pub const XCB_FILL_POLY: u8 = 69;

#[repr(C)]
pub struct xcb_fill_poly_request_t {
    pub major_opcode:    u8,
    pub pad0:            u8,
    pub length:          u16,
    pub drawable:        xcb_drawable_t,
    pub gc:              xcb_gcontext_t,
    pub shape:           u8,
    pub coordinate_mode: u8,
    pub pad1:            [u8; 2],
}

pub const XCB_POLY_FILL_RECTANGLE: u8 = 70;

/// Fills rectangles
///
/// Fills the specified rectangle(s) in the order listed in the array. For any
/// given rectangle, each pixel is not drawn more than once. If rectangles
/// intersect, the intersecting pixels are drawn multiple times.
#[repr(C)]
pub struct xcb_poly_fill_rectangle_request_t {
    pub major_opcode:   u8,
    pub pad0:           u8,
    pub length:         u16,
    /// The drawable (Window or Pixmap) to draw on.
    pub drawable:       xcb_drawable_t,
    /// The graphics context to use.
    ///
    /// The following graphics context components are used: function, plane-mask,
    /// fill-style, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
    ///
    /// The following graphics context mode-dependent components are used:
    /// foreground, background, tile, stipple, tile-stipple-x-origin, and
    /// tile-stipple-y-origin.
    pub gc:             xcb_gcontext_t,
}

pub const XCB_POLY_FILL_ARC: u8 = 71;

#[repr(C)]
pub struct xcb_poly_fill_arc_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub gc:           xcb_gcontext_t,
}

pub type xcb_image_format_t = u32;
pub const XCB_IMAGE_FORMAT_XY_BITMAP: xcb_image_format_t = 0x00;
pub const XCB_IMAGE_FORMAT_XY_PIXMAP: xcb_image_format_t = 0x01;
pub const XCB_IMAGE_FORMAT_Z_PIXMAP : xcb_image_format_t = 0x02;

pub const XCB_PUT_IMAGE: u8 = 72;

#[repr(C)]
pub struct xcb_put_image_request_t {
    pub major_opcode: u8,
    pub format:       u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub gc:           xcb_gcontext_t,
    pub width:        u16,
    pub height:       u16,
    pub dst_x:        i16,
    pub dst_y:        i16,
    pub left_pad:     u8,
    pub depth:        u8,
    pub pad0:         [u8; 2],
}

pub const XCB_GET_IMAGE: u8 = 73;

#[repr(C)]
pub struct xcb_get_image_request_t {
    pub major_opcode: u8,
    pub format:       u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub x:            i16,
    pub y:            i16,
    pub width:        u16,
    pub height:       u16,
    pub plane_mask:   u32,
}

impl Copy for xcb_get_image_request_t {}
impl Clone for xcb_get_image_request_t {
    fn clone(&self) -> xcb_get_image_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_image_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_image_reply_t {
    pub response_type: u8,
    pub depth:         u8,
    pub sequence:      u16,
    pub length:        u32,
    pub visual:        xcb_visualid_t,
    pub pad0:          [u8; 20],
}

pub const XCB_POLY_TEXT_8: u8 = 74;

#[repr(C)]
pub struct xcb_poly_text_8_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub gc:           xcb_gcontext_t,
    pub x:            i16,
    pub y:            i16,
}

pub const XCB_POLY_TEXT_16: u8 = 75;

#[repr(C)]
pub struct xcb_poly_text_16_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub gc:           xcb_gcontext_t,
    pub x:            i16,
    pub y:            i16,
}

pub const XCB_IMAGE_TEXT_8: u8 = 76;

/// Draws text
///
/// Fills the destination rectangle with the background pixel from `gc`, then
/// paints the text with the foreground pixel from `gc`. The upper-left corner of
/// the filled rectangle is at [x, y - font-ascent]. The width is overall-width,
/// the height is font-ascent + font-descent. The overall-width, font-ascent and
/// font-descent are as returned by `xcb_query_text_extents` (TODO).
///
/// Note that using X core fonts is deprecated (but still supported) in favor of
/// client-side rendering using Xft.
#[repr(C)]
pub struct xcb_image_text_8_request_t {
    pub major_opcode: u8,
    /// The length of the `string`. Note that this parameter limited by 255 due to
    /// using 8 bits!
    pub string_len:   u8,
    pub length:       u16,
    /// The drawable (Window or Pixmap) to draw text on.
    pub drawable:     xcb_drawable_t,
    /// The graphics context to use.
    ///
    /// The following graphics context components are used: plane-mask, foreground,
    /// background, font, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
    pub gc:           xcb_gcontext_t,
    /// The x coordinate of the first character, relative to the origin of `drawable`.
    pub x:            i16,
    /// The y coordinate of the first character, relative to the origin of `drawable`.
    pub y:            i16,
}

pub const XCB_IMAGE_TEXT_16: u8 = 77;

/// Draws text
///
/// Fills the destination rectangle with the background pixel from `gc`, then
/// paints the text with the foreground pixel from `gc`. The upper-left corner of
/// the filled rectangle is at [x, y - font-ascent]. The width is overall-width,
/// the height is font-ascent + font-descent. The overall-width, font-ascent and
/// font-descent are as returned by `xcb_query_text_extents` (TODO).
///
/// Note that using X core fonts is deprecated (but still supported) in favor of
/// client-side rendering using Xft.
#[repr(C)]
pub struct xcb_image_text_16_request_t {
    pub major_opcode: u8,
    /// The length of the `string` in characters. Note that this parameter limited by
    /// 255 due to using 8 bits!
    pub string_len:   u8,
    pub length:       u16,
    /// The drawable (Window or Pixmap) to draw text on.
    pub drawable:     xcb_drawable_t,
    /// The graphics context to use.
    ///
    /// The following graphics context components are used: plane-mask, foreground,
    /// background, font, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
    pub gc:           xcb_gcontext_t,
    /// The x coordinate of the first character, relative to the origin of `drawable`.
    pub x:            i16,
    /// The y coordinate of the first character, relative to the origin of `drawable`.
    pub y:            i16,
}

pub type xcb_colormap_alloc_t = u32;
pub const XCB_COLORMAP_ALLOC_NONE: xcb_colormap_alloc_t = 0x00;
pub const XCB_COLORMAP_ALLOC_ALL : xcb_colormap_alloc_t = 0x01;

pub const XCB_CREATE_COLORMAP: u8 = 78;

#[repr(C)]
pub struct xcb_create_colormap_request_t {
    pub major_opcode: u8,
    pub alloc:        u8,
    pub length:       u16,
    pub mid:          xcb_colormap_t,
    pub window:       xcb_window_t,
    pub visual:       xcb_visualid_t,
}

impl Copy for xcb_create_colormap_request_t {}
impl Clone for xcb_create_colormap_request_t {
    fn clone(&self) -> xcb_create_colormap_request_t { *self }
}

pub const XCB_FREE_COLORMAP: u8 = 79;

#[repr(C)]
pub struct xcb_free_colormap_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
}

impl Copy for xcb_free_colormap_request_t {}
impl Clone for xcb_free_colormap_request_t {
    fn clone(&self) -> xcb_free_colormap_request_t { *self }
}

pub const XCB_COPY_COLORMAP_AND_FREE: u8 = 80;

#[repr(C)]
pub struct xcb_copy_colormap_and_free_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub mid:          xcb_colormap_t,
    pub src_cmap:     xcb_colormap_t,
}

impl Copy for xcb_copy_colormap_and_free_request_t {}
impl Clone for xcb_copy_colormap_and_free_request_t {
    fn clone(&self) -> xcb_copy_colormap_and_free_request_t { *self }
}

pub const XCB_INSTALL_COLORMAP: u8 = 81;

#[repr(C)]
pub struct xcb_install_colormap_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
}

impl Copy for xcb_install_colormap_request_t {}
impl Clone for xcb_install_colormap_request_t {
    fn clone(&self) -> xcb_install_colormap_request_t { *self }
}

pub const XCB_UNINSTALL_COLORMAP: u8 = 82;

#[repr(C)]
pub struct xcb_uninstall_colormap_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
}

impl Copy for xcb_uninstall_colormap_request_t {}
impl Clone for xcb_uninstall_colormap_request_t {
    fn clone(&self) -> xcb_uninstall_colormap_request_t { *self }
}

pub const XCB_LIST_INSTALLED_COLORMAPS: u8 = 83;

#[repr(C)]
pub struct xcb_list_installed_colormaps_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_list_installed_colormaps_request_t {}
impl Clone for xcb_list_installed_colormaps_request_t {
    fn clone(&self) -> xcb_list_installed_colormaps_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_list_installed_colormaps_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_list_installed_colormaps_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub cmaps_len:     u16,
    pub pad1:          [u8; 22],
}

pub const XCB_ALLOC_COLOR: u8 = 84;

/// Allocate a color
///
/// Allocates a read-only colormap entry corresponding to the closest RGB value
/// supported by the hardware. If you are using TrueColor, you can take a shortcut
/// and directly calculate the color pixel value to avoid the round trip. But, for
/// example, on 16-bit color setups (VNC), you can easily get the closest supported
/// RGB value to the RGB value you are specifying.
#[repr(C)]
pub struct xcb_alloc_color_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// TODO
    pub cmap:         xcb_colormap_t,
    /// The red value of your color.
    pub red:          u16,
    /// The green value of your color.
    pub green:        u16,
    /// The blue value of your color.
    pub blue:         u16,
    pub pad1:         [u8; 2],
}

impl Copy for xcb_alloc_color_request_t {}
impl Clone for xcb_alloc_color_request_t {
    fn clone(&self) -> xcb_alloc_color_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_alloc_color_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_alloc_color_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub red:           u16,
    pub green:         u16,
    pub blue:          u16,
    pub pad1:          [u8; 2],
    pub pixel:         u32,
}

impl Copy for xcb_alloc_color_reply_t {}
impl Clone for xcb_alloc_color_reply_t {
    fn clone(&self) -> xcb_alloc_color_reply_t { *self }
}

pub const XCB_ALLOC_NAMED_COLOR: u8 = 85;

#[repr(C)]
pub struct xcb_alloc_named_color_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
    pub name_len:     u16,
    pub pad1:         [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_alloc_named_color_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_alloc_named_color_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pixel:         u32,
    pub exact_red:     u16,
    pub exact_green:   u16,
    pub exact_blue:    u16,
    pub visual_red:    u16,
    pub visual_green:  u16,
    pub visual_blue:   u16,
}

impl Copy for xcb_alloc_named_color_reply_t {}
impl Clone for xcb_alloc_named_color_reply_t {
    fn clone(&self) -> xcb_alloc_named_color_reply_t { *self }
}

pub const XCB_ALLOC_COLOR_CELLS: u8 = 86;

#[repr(C)]
pub struct xcb_alloc_color_cells_request_t {
    pub major_opcode: u8,
    pub contiguous:   u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
    pub colors:       u16,
    pub planes:       u16,
}

impl Copy for xcb_alloc_color_cells_request_t {}
impl Clone for xcb_alloc_color_cells_request_t {
    fn clone(&self) -> xcb_alloc_color_cells_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_alloc_color_cells_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_alloc_color_cells_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pixels_len:    u16,
    pub masks_len:     u16,
    pub pad1:          [u8; 20],
}

pub const XCB_ALLOC_COLOR_PLANES: u8 = 87;

#[repr(C)]
pub struct xcb_alloc_color_planes_request_t {
    pub major_opcode: u8,
    pub contiguous:   u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
    pub colors:       u16,
    pub reds:         u16,
    pub greens:       u16,
    pub blues:        u16,
}

impl Copy for xcb_alloc_color_planes_request_t {}
impl Clone for xcb_alloc_color_planes_request_t {
    fn clone(&self) -> xcb_alloc_color_planes_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_alloc_color_planes_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_alloc_color_planes_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pixels_len:    u16,
    pub pad1:          [u8; 2],
    pub red_mask:      u32,
    pub green_mask:    u32,
    pub blue_mask:     u32,
    pub pad2:          [u8; 8],
}

pub const XCB_FREE_COLORS: u8 = 88;

#[repr(C)]
pub struct xcb_free_colors_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
    pub plane_mask:   u32,
}

pub type xcb_color_flag_t = u32;
pub const XCB_COLOR_FLAG_RED  : xcb_color_flag_t = 0x01;
pub const XCB_COLOR_FLAG_GREEN: xcb_color_flag_t = 0x02;
pub const XCB_COLOR_FLAG_BLUE : xcb_color_flag_t = 0x04;

#[repr(C)]
pub struct xcb_coloritem_t {
    pub pixel: u32,
    pub red:   u16,
    pub green: u16,
    pub blue:  u16,
    pub flags: u8,
    pub pad0:  u8,
}

impl Copy for xcb_coloritem_t {}
impl Clone for xcb_coloritem_t {
    fn clone(&self) -> xcb_coloritem_t { *self }
}

#[repr(C)]
pub struct xcb_coloritem_iterator_t {
    pub data:  *mut xcb_coloritem_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_STORE_COLORS: u8 = 89;

#[repr(C)]
pub struct xcb_store_colors_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
}

pub const XCB_STORE_NAMED_COLOR: u8 = 90;

#[repr(C)]
pub struct xcb_store_named_color_request_t {
    pub major_opcode: u8,
    pub flags:        u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
    pub pixel:        u32,
    pub name_len:     u16,
    pub pad0:         [u8; 2],
}

#[repr(C)]
pub struct xcb_rgb_t {
    pub red:   u16,
    pub green: u16,
    pub blue:  u16,
    pub pad0:  [u8; 2],
}

impl Copy for xcb_rgb_t {}
impl Clone for xcb_rgb_t {
    fn clone(&self) -> xcb_rgb_t { *self }
}

#[repr(C)]
pub struct xcb_rgb_iterator_t {
    pub data:  *mut xcb_rgb_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub const XCB_QUERY_COLORS: u8 = 91;

#[repr(C)]
pub struct xcb_query_colors_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_query_colors_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_query_colors_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub colors_len:    u16,
    pub pad1:          [u8; 22],
}

pub const XCB_LOOKUP_COLOR: u8 = 92;

#[repr(C)]
pub struct xcb_lookup_color_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cmap:         xcb_colormap_t,
    pub name_len:     u16,
    pub pad1:         [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_lookup_color_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_lookup_color_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub exact_red:     u16,
    pub exact_green:   u16,
    pub exact_blue:    u16,
    pub visual_red:    u16,
    pub visual_green:  u16,
    pub visual_blue:   u16,
}

impl Copy for xcb_lookup_color_reply_t {}
impl Clone for xcb_lookup_color_reply_t {
    fn clone(&self) -> xcb_lookup_color_reply_t { *self }
}

pub type xcb_pixmap_enum_t = u32;
pub const XCB_PIXMAP_NONE: xcb_pixmap_enum_t = 0x00;

pub const XCB_CREATE_CURSOR: u8 = 93;

#[repr(C)]
pub struct xcb_create_cursor_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cid:          xcb_cursor_t,
    pub source:       xcb_pixmap_t,
    pub mask:         xcb_pixmap_t,
    pub fore_red:     u16,
    pub fore_green:   u16,
    pub fore_blue:    u16,
    pub back_red:     u16,
    pub back_green:   u16,
    pub back_blue:    u16,
    pub x:            u16,
    pub y:            u16,
}

impl Copy for xcb_create_cursor_request_t {}
impl Clone for xcb_create_cursor_request_t {
    fn clone(&self) -> xcb_create_cursor_request_t { *self }
}

pub type xcb_font_enum_t = u32;
pub const XCB_FONT_NONE: xcb_font_enum_t = 0x00;

pub const XCB_CREATE_GLYPH_CURSOR: u8 = 94;

/// create cursor
///
/// Creates a cursor from a font glyph. X provides a set of standard cursor shapes
/// in a special font named cursor. Applications are encouraged to use this
/// interface for their cursors because the font can be customized for the
/// individual display type.
///
/// All pixels which are set to 1 in the source will use the foreground color (as
/// specified by `fore_red`, `fore_green` and `fore_blue`). All pixels set to 0
/// will use the background color (as specified by `back_red`, `back_green` and
/// `back_blue`).
#[repr(C)]
pub struct xcb_create_glyph_cursor_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The ID with which you will refer to the cursor, created by `xcb_generate_id`.
    pub cid:          xcb_cursor_t,
    /// In which font to look for the cursor glyph.
    pub source_font:  xcb_font_t,
    /// In which font to look for the mask glyph.
    pub mask_font:    xcb_font_t,
    /// The glyph of `source_font` to use.
    pub source_char:  u16,
    /// The glyph of `mask_font` to use as a mask: Pixels which are set to 1 define
    /// which source pixels are displayed. All pixels which are set to 0 are not
    /// displayed.
    pub mask_char:    u16,
    /// The red value of the foreground color.
    pub fore_red:     u16,
    /// The green value of the foreground color.
    pub fore_green:   u16,
    /// The blue value of the foreground color.
    pub fore_blue:    u16,
    /// The red value of the background color.
    pub back_red:     u16,
    /// The green value of the background color.
    pub back_green:   u16,
    /// The blue value of the background color.
    pub back_blue:    u16,
}

impl Copy for xcb_create_glyph_cursor_request_t {}
impl Clone for xcb_create_glyph_cursor_request_t {
    fn clone(&self) -> xcb_create_glyph_cursor_request_t { *self }
}

pub const XCB_FREE_CURSOR: u8 = 95;

/// Deletes a cursor
///
/// Deletes the association between the cursor resource ID and the specified
/// cursor. The cursor is freed when no other resource references it.
#[repr(C)]
pub struct xcb_free_cursor_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The cursor to destroy.
    pub cursor:       xcb_cursor_t,
}

impl Copy for xcb_free_cursor_request_t {}
impl Clone for xcb_free_cursor_request_t {
    fn clone(&self) -> xcb_free_cursor_request_t { *self }
}

pub const XCB_RECOLOR_CURSOR: u8 = 96;

#[repr(C)]
pub struct xcb_recolor_cursor_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub cursor:       xcb_cursor_t,
    pub fore_red:     u16,
    pub fore_green:   u16,
    pub fore_blue:    u16,
    pub back_red:     u16,
    pub back_green:   u16,
    pub back_blue:    u16,
}

impl Copy for xcb_recolor_cursor_request_t {}
impl Clone for xcb_recolor_cursor_request_t {
    fn clone(&self) -> xcb_recolor_cursor_request_t { *self }
}

pub type xcb_query_shape_of_t = u32;
pub const XCB_QUERY_SHAPE_OF_LARGEST_CURSOR : xcb_query_shape_of_t = 0x00;
pub const XCB_QUERY_SHAPE_OF_FASTEST_TILE   : xcb_query_shape_of_t = 0x01;
pub const XCB_QUERY_SHAPE_OF_FASTEST_STIPPLE: xcb_query_shape_of_t = 0x02;

pub const XCB_QUERY_BEST_SIZE: u8 = 97;

#[repr(C)]
pub struct xcb_query_best_size_request_t {
    pub major_opcode: u8,
    pub class:        u8,
    pub length:       u16,
    pub drawable:     xcb_drawable_t,
    pub width:        u16,
    pub height:       u16,
}

impl Copy for xcb_query_best_size_request_t {}
impl Clone for xcb_query_best_size_request_t {
    fn clone(&self) -> xcb_query_best_size_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_query_best_size_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_query_best_size_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub width:         u16,
    pub height:        u16,
}

impl Copy for xcb_query_best_size_reply_t {}
impl Clone for xcb_query_best_size_reply_t {
    fn clone(&self) -> xcb_query_best_size_reply_t { *self }
}

pub const XCB_QUERY_EXTENSION: u8 = 98;

/// check if extension is present
///
/// Determines if the specified extension is present on this X11 server.
///
/// Every extension has a unique `major_opcode` to identify requests, the minor
/// opcodes and request formats are extension-specific. If the extension provides
/// events and errors, the `first_event` and `first_error` fields in the reply are
/// set accordingly.
///
/// There should rarely be a need to use this request directly, XCB provides the
/// `xcb_get_extension_data` function instead.
#[repr(C)]
pub struct xcb_query_extension_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// The length of `name` in bytes.
    pub name_len:     u16,
    pub pad1:         [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_query_extension_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_query_extension_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    /// Whether the extension is present on this X11 server.
    pub present:       u8,
    /// The major opcode for requests.
    pub major_opcode:  u8,
    /// The first event code, if any.
    pub first_event:   u8,
    /// The first error code, if any.
    pub first_error:   u8,
}

impl Copy for xcb_query_extension_reply_t {}
impl Clone for xcb_query_extension_reply_t {
    fn clone(&self) -> xcb_query_extension_reply_t { *self }
}

pub const XCB_LIST_EXTENSIONS: u8 = 99;

#[repr(C)]
pub struct xcb_list_extensions_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_list_extensions_request_t {}
impl Clone for xcb_list_extensions_request_t {
    fn clone(&self) -> xcb_list_extensions_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_list_extensions_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_list_extensions_reply_t {
    pub response_type: u8,
    pub names_len:     u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad0:          [u8; 24],
}

pub const XCB_CHANGE_KEYBOARD_MAPPING: u8 = 100;

#[repr(C)]
pub struct xcb_change_keyboard_mapping_request_t {
    pub major_opcode:        u8,
    pub keycode_count:       u8,
    pub length:              u16,
    pub first_keycode:       xcb_keycode_t,
    pub keysyms_per_keycode: u8,
    pub pad0:                [u8; 2],
}

pub const XCB_GET_KEYBOARD_MAPPING: u8 = 101;

#[repr(C)]
pub struct xcb_get_keyboard_mapping_request_t {
    pub major_opcode:  u8,
    pub pad0:          u8,
    pub length:        u16,
    pub first_keycode: xcb_keycode_t,
    pub count:         u8,
}

impl Copy for xcb_get_keyboard_mapping_request_t {}
impl Clone for xcb_get_keyboard_mapping_request_t {
    fn clone(&self) -> xcb_get_keyboard_mapping_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_keyboard_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_keyboard_mapping_reply_t {
    pub response_type:       u8,
    pub keysyms_per_keycode: u8,
    pub sequence:            u16,
    pub length:              u32,
    pub pad0:                [u8; 24],
}

pub type xcb_kb_t = u32;
pub const XCB_KB_KEY_CLICK_PERCENT: xcb_kb_t = 0x01;
pub const XCB_KB_BELL_PERCENT     : xcb_kb_t = 0x02;
pub const XCB_KB_BELL_PITCH       : xcb_kb_t = 0x04;
pub const XCB_KB_BELL_DURATION    : xcb_kb_t = 0x08;
pub const XCB_KB_LED              : xcb_kb_t = 0x10;
pub const XCB_KB_LED_MODE         : xcb_kb_t = 0x20;
pub const XCB_KB_KEY              : xcb_kb_t = 0x40;
pub const XCB_KB_AUTO_REPEAT_MODE : xcb_kb_t = 0x80;

pub type xcb_led_mode_t = u32;
pub const XCB_LED_MODE_OFF: xcb_led_mode_t = 0x00;
pub const XCB_LED_MODE_ON : xcb_led_mode_t = 0x01;

pub type xcb_auto_repeat_mode_t = u32;
pub const XCB_AUTO_REPEAT_MODE_OFF    : xcb_auto_repeat_mode_t = 0x00;
pub const XCB_AUTO_REPEAT_MODE_ON     : xcb_auto_repeat_mode_t = 0x01;
pub const XCB_AUTO_REPEAT_MODE_DEFAULT: xcb_auto_repeat_mode_t = 0x02;

pub const XCB_CHANGE_KEYBOARD_CONTROL: u8 = 102;

#[repr(C)]
pub struct xcb_change_keyboard_control_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub value_mask:   u32,
}

pub const XCB_GET_KEYBOARD_CONTROL: u8 = 103;

#[repr(C)]
pub struct xcb_get_keyboard_control_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_get_keyboard_control_request_t {}
impl Clone for xcb_get_keyboard_control_request_t {
    fn clone(&self) -> xcb_get_keyboard_control_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_keyboard_control_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_keyboard_control_reply_t {
    pub response_type:      u8,
    pub global_auto_repeat: u8,
    pub sequence:           u16,
    pub length:             u32,
    pub led_mask:           u32,
    pub key_click_percent:  u8,
    pub bell_percent:       u8,
    pub bell_pitch:         u16,
    pub bell_duration:      u16,
    pub pad0:               [u8; 2],
    pub auto_repeats:       [u8; 32],
}

impl Copy for xcb_get_keyboard_control_reply_t {}
impl Clone for xcb_get_keyboard_control_reply_t {
    fn clone(&self) -> xcb_get_keyboard_control_reply_t { *self }
}

pub const XCB_BELL: u8 = 104;

#[repr(C)]
pub struct xcb_bell_request_t {
    pub major_opcode: u8,
    pub percent:      i8,
    pub length:       u16,
}

impl Copy for xcb_bell_request_t {}
impl Clone for xcb_bell_request_t {
    fn clone(&self) -> xcb_bell_request_t { *self }
}

pub const XCB_CHANGE_POINTER_CONTROL: u8 = 105;

#[repr(C)]
pub struct xcb_change_pointer_control_request_t {
    pub major_opcode:             u8,
    pub pad0:                     u8,
    pub length:                   u16,
    pub acceleration_numerator:   i16,
    pub acceleration_denominator: i16,
    pub threshold:                i16,
    pub do_acceleration:          u8,
    pub do_threshold:             u8,
}

impl Copy for xcb_change_pointer_control_request_t {}
impl Clone for xcb_change_pointer_control_request_t {
    fn clone(&self) -> xcb_change_pointer_control_request_t { *self }
}

pub const XCB_GET_POINTER_CONTROL: u8 = 106;

#[repr(C)]
pub struct xcb_get_pointer_control_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_get_pointer_control_request_t {}
impl Clone for xcb_get_pointer_control_request_t {
    fn clone(&self) -> xcb_get_pointer_control_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_pointer_control_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_pointer_control_reply_t {
    pub response_type:            u8,
    pub pad0:                     u8,
    pub sequence:                 u16,
    pub length:                   u32,
    pub acceleration_numerator:   u16,
    pub acceleration_denominator: u16,
    pub threshold:                u16,
    pub pad1:                     [u8; 18],
}

impl Copy for xcb_get_pointer_control_reply_t {}
impl Clone for xcb_get_pointer_control_reply_t {
    fn clone(&self) -> xcb_get_pointer_control_reply_t { *self }
}

pub type xcb_blanking_t = u32;
pub const XCB_BLANKING_NOT_PREFERRED: xcb_blanking_t = 0x00;
pub const XCB_BLANKING_PREFERRED    : xcb_blanking_t = 0x01;
pub const XCB_BLANKING_DEFAULT      : xcb_blanking_t = 0x02;

pub type xcb_exposures_t = u32;
pub const XCB_EXPOSURES_NOT_ALLOWED: xcb_exposures_t = 0x00;
pub const XCB_EXPOSURES_ALLOWED    : xcb_exposures_t = 0x01;
pub const XCB_EXPOSURES_DEFAULT    : xcb_exposures_t = 0x02;

pub const XCB_SET_SCREEN_SAVER: u8 = 107;

#[repr(C)]
pub struct xcb_set_screen_saver_request_t {
    pub major_opcode:    u8,
    pub pad0:            u8,
    pub length:          u16,
    pub timeout:         i16,
    pub interval:        i16,
    pub prefer_blanking: u8,
    pub allow_exposures: u8,
}

impl Copy for xcb_set_screen_saver_request_t {}
impl Clone for xcb_set_screen_saver_request_t {
    fn clone(&self) -> xcb_set_screen_saver_request_t { *self }
}

pub const XCB_GET_SCREEN_SAVER: u8 = 108;

#[repr(C)]
pub struct xcb_get_screen_saver_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_get_screen_saver_request_t {}
impl Clone for xcb_get_screen_saver_request_t {
    fn clone(&self) -> xcb_get_screen_saver_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_screen_saver_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_screen_saver_reply_t {
    pub response_type:   u8,
    pub pad0:            u8,
    pub sequence:        u16,
    pub length:          u32,
    pub timeout:         u16,
    pub interval:        u16,
    pub prefer_blanking: u8,
    pub allow_exposures: u8,
    pub pad1:            [u8; 18],
}

impl Copy for xcb_get_screen_saver_reply_t {}
impl Clone for xcb_get_screen_saver_reply_t {
    fn clone(&self) -> xcb_get_screen_saver_reply_t { *self }
}

pub type xcb_host_mode_t = u32;
pub const XCB_HOST_MODE_INSERT: xcb_host_mode_t = 0x00;
pub const XCB_HOST_MODE_DELETE: xcb_host_mode_t = 0x01;

pub type xcb_family_t = u32;
pub const XCB_FAMILY_INTERNET          : xcb_family_t = 0x00;
pub const XCB_FAMILY_DE_CNET           : xcb_family_t = 0x01;
pub const XCB_FAMILY_CHAOS             : xcb_family_t = 0x02;
pub const XCB_FAMILY_SERVER_INTERPRETED: xcb_family_t = 0x05;
pub const XCB_FAMILY_INTERNET_6        : xcb_family_t = 0x06;

pub const XCB_CHANGE_HOSTS: u8 = 109;

#[repr(C)]
pub struct xcb_change_hosts_request_t {
    pub major_opcode: u8,
    pub mode:         u8,
    pub length:       u16,
    pub family:       u8,
    pub pad0:         u8,
    pub address_len:  u16,
}

#[repr(C)]
pub struct xcb_host_t {
    pub family:      u8,
    pub pad0:        u8,
    pub address_len: u16,
}

#[repr(C)]
pub struct xcb_host_iterator_t<'a> {
    pub data:  *mut xcb_host_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_host_t>,
}

pub const XCB_LIST_HOSTS: u8 = 110;

#[repr(C)]
pub struct xcb_list_hosts_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_list_hosts_request_t {}
impl Clone for xcb_list_hosts_request_t {
    fn clone(&self) -> xcb_list_hosts_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_list_hosts_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_list_hosts_reply_t {
    pub response_type: u8,
    pub mode:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub hosts_len:     u16,
    pub pad0:          [u8; 22],
}

pub type xcb_access_control_t = u32;
pub const XCB_ACCESS_CONTROL_DISABLE: xcb_access_control_t = 0x00;
pub const XCB_ACCESS_CONTROL_ENABLE : xcb_access_control_t = 0x01;

pub const XCB_SET_ACCESS_CONTROL: u8 = 111;

#[repr(C)]
pub struct xcb_set_access_control_request_t {
    pub major_opcode: u8,
    pub mode:         u8,
    pub length:       u16,
}

impl Copy for xcb_set_access_control_request_t {}
impl Clone for xcb_set_access_control_request_t {
    fn clone(&self) -> xcb_set_access_control_request_t { *self }
}

pub type xcb_close_down_t = u32;
pub const XCB_CLOSE_DOWN_DESTROY_ALL     : xcb_close_down_t = 0x00;
pub const XCB_CLOSE_DOWN_RETAIN_PERMANENT: xcb_close_down_t = 0x01;
pub const XCB_CLOSE_DOWN_RETAIN_TEMPORARY: xcb_close_down_t = 0x02;

pub const XCB_SET_CLOSE_DOWN_MODE: u8 = 112;

#[repr(C)]
pub struct xcb_set_close_down_mode_request_t {
    pub major_opcode: u8,
    pub mode:         u8,
    pub length:       u16,
}

impl Copy for xcb_set_close_down_mode_request_t {}
impl Clone for xcb_set_close_down_mode_request_t {
    fn clone(&self) -> xcb_set_close_down_mode_request_t { *self }
}

pub type xcb_kill_t = u32;
pub const XCB_KILL_ALL_TEMPORARY: xcb_kill_t = 0x00;

pub const XCB_KILL_CLIENT: u8 = 113;

/// kills a client
///
/// Forces a close down of the client that created the specified `resource`.
#[repr(C)]
pub struct xcb_kill_client_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    /// Any resource belonging to the client (for example a Window), used to identify
    /// the client connection.
    ///
    /// The special value of `XCB_KILL_ALL_TEMPORARY`, the resources of all clients
    /// that have terminated in `RetainTemporary` (TODO) are destroyed.
    pub resource:     u32,
}

impl Copy for xcb_kill_client_request_t {}
impl Clone for xcb_kill_client_request_t {
    fn clone(&self) -> xcb_kill_client_request_t { *self }
}

pub const XCB_ROTATE_PROPERTIES: u8 = 114;

#[repr(C)]
pub struct xcb_rotate_properties_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
    pub window:       xcb_window_t,
    pub atoms_len:    u16,
    pub delta:        i16,
}

pub type xcb_screen_saver_t = u32;
pub const XCB_SCREEN_SAVER_RESET : xcb_screen_saver_t = 0x00;
pub const XCB_SCREEN_SAVER_ACTIVE: xcb_screen_saver_t = 0x01;

pub const XCB_FORCE_SCREEN_SAVER: u8 = 115;

#[repr(C)]
pub struct xcb_force_screen_saver_request_t {
    pub major_opcode: u8,
    pub mode:         u8,
    pub length:       u16,
}

impl Copy for xcb_force_screen_saver_request_t {}
impl Clone for xcb_force_screen_saver_request_t {
    fn clone(&self) -> xcb_force_screen_saver_request_t { *self }
}

pub type xcb_mapping_status_t = u32;
pub const XCB_MAPPING_STATUS_SUCCESS: xcb_mapping_status_t = 0x00;
pub const XCB_MAPPING_STATUS_BUSY   : xcb_mapping_status_t = 0x01;
pub const XCB_MAPPING_STATUS_FAILURE: xcb_mapping_status_t = 0x02;

pub const XCB_SET_POINTER_MAPPING: u8 = 116;

#[repr(C)]
pub struct xcb_set_pointer_mapping_request_t {
    pub major_opcode: u8,
    pub map_len:      u8,
    pub length:       u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_set_pointer_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_set_pointer_mapping_reply_t {
    pub response_type: u8,
    pub status:        u8,
    pub sequence:      u16,
    pub length:        u32,
}

impl Copy for xcb_set_pointer_mapping_reply_t {}
impl Clone for xcb_set_pointer_mapping_reply_t {
    fn clone(&self) -> xcb_set_pointer_mapping_reply_t { *self }
}

pub const XCB_GET_POINTER_MAPPING: u8 = 117;

#[repr(C)]
pub struct xcb_get_pointer_mapping_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_get_pointer_mapping_request_t {}
impl Clone for xcb_get_pointer_mapping_request_t {
    fn clone(&self) -> xcb_get_pointer_mapping_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_pointer_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_pointer_mapping_reply_t {
    pub response_type: u8,
    pub map_len:       u8,
    pub sequence:      u16,
    pub length:        u32,
    pub pad0:          [u8; 24],
}

pub type xcb_map_index_t = u32;
pub const XCB_MAP_INDEX_SHIFT  : xcb_map_index_t = 0x00;
pub const XCB_MAP_INDEX_LOCK   : xcb_map_index_t = 0x01;
pub const XCB_MAP_INDEX_CONTROL: xcb_map_index_t = 0x02;
pub const XCB_MAP_INDEX_1      : xcb_map_index_t = 0x03;
pub const XCB_MAP_INDEX_2      : xcb_map_index_t = 0x04;
pub const XCB_MAP_INDEX_3      : xcb_map_index_t = 0x05;
pub const XCB_MAP_INDEX_4      : xcb_map_index_t = 0x06;
pub const XCB_MAP_INDEX_5      : xcb_map_index_t = 0x07;

pub const XCB_SET_MODIFIER_MAPPING: u8 = 118;

#[repr(C)]
pub struct xcb_set_modifier_mapping_request_t {
    pub major_opcode:          u8,
    pub keycodes_per_modifier: u8,
    pub length:                u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_set_modifier_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_set_modifier_mapping_reply_t {
    pub response_type: u8,
    pub status:        u8,
    pub sequence:      u16,
    pub length:        u32,
}

impl Copy for xcb_set_modifier_mapping_reply_t {}
impl Clone for xcb_set_modifier_mapping_reply_t {
    fn clone(&self) -> xcb_set_modifier_mapping_reply_t { *self }
}

pub const XCB_GET_MODIFIER_MAPPING: u8 = 119;

#[repr(C)]
pub struct xcb_get_modifier_mapping_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_get_modifier_mapping_request_t {}
impl Clone for xcb_get_modifier_mapping_request_t {
    fn clone(&self) -> xcb_get_modifier_mapping_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_get_modifier_mapping_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_get_modifier_mapping_reply_t {
    pub response_type:         u8,
    pub keycodes_per_modifier: u8,
    pub sequence:              u16,
    pub length:                u32,
    pub pad0:                  [u8; 24],
}

pub const XCB_NO_OPERATION: u8 = 127;

#[repr(C)]
pub struct xcb_no_operation_request_t {
    pub major_opcode: u8,
    pub pad0:         u8,
    pub length:       u16,
}

impl Copy for xcb_no_operation_request_t {}
impl Clone for xcb_no_operation_request_t {
    fn clone(&self) -> xcb_no_operation_request_t { *self }
}


#[link(name="xcb")]
extern {

    pub fn xcb_char2b_next (i: *mut xcb_char2b_iterator_t);

    pub fn xcb_char2b_end (i: *mut xcb_char2b_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_window_next (i: *mut xcb_window_iterator_t);

    pub fn xcb_window_end (i: *mut xcb_window_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_pixmap_next (i: *mut xcb_pixmap_iterator_t);

    pub fn xcb_pixmap_end (i: *mut xcb_pixmap_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_cursor_next (i: *mut xcb_cursor_iterator_t);

    pub fn xcb_cursor_end (i: *mut xcb_cursor_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_font_next (i: *mut xcb_font_iterator_t);

    pub fn xcb_font_end (i: *mut xcb_font_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_gcontext_next (i: *mut xcb_gcontext_iterator_t);

    pub fn xcb_gcontext_end (i: *mut xcb_gcontext_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_colormap_next (i: *mut xcb_colormap_iterator_t);

    pub fn xcb_colormap_end (i: *mut xcb_colormap_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_atom_next (i: *mut xcb_atom_iterator_t);

    pub fn xcb_atom_end (i: *mut xcb_atom_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_drawable_next (i: *mut xcb_drawable_iterator_t);

    pub fn xcb_drawable_end (i: *mut xcb_drawable_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_fontable_next (i: *mut xcb_fontable_iterator_t);

    pub fn xcb_fontable_end (i: *mut xcb_fontable_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_visualid_next (i: *mut xcb_visualid_iterator_t);

    pub fn xcb_visualid_end (i: *mut xcb_visualid_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_timestamp_next (i: *mut xcb_timestamp_iterator_t);

    pub fn xcb_timestamp_end (i: *mut xcb_timestamp_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_keysym_next (i: *mut xcb_keysym_iterator_t);

    pub fn xcb_keysym_end (i: *mut xcb_keysym_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_keycode_next (i: *mut xcb_keycode_iterator_t);

    pub fn xcb_keycode_end (i: *mut xcb_keycode_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_button_next (i: *mut xcb_button_iterator_t);

    pub fn xcb_button_end (i: *mut xcb_button_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_point_next (i: *mut xcb_point_iterator_t);

    pub fn xcb_point_end (i: *mut xcb_point_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_rectangle_next (i: *mut xcb_rectangle_iterator_t);

    pub fn xcb_rectangle_end (i: *mut xcb_rectangle_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_arc_next (i: *mut xcb_arc_iterator_t);

    pub fn xcb_arc_end (i: *mut xcb_arc_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_format_next (i: *mut xcb_format_iterator_t);

    pub fn xcb_format_end (i: *mut xcb_format_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_visualtype_next (i: *mut xcb_visualtype_iterator_t);

    pub fn xcb_visualtype_end (i: *mut xcb_visualtype_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_depth_visuals (R: *const xcb_depth_t)
            -> *mut xcb_visualtype_t;

    pub fn xcb_depth_visuals_length (R: *const xcb_depth_t)
            -> c_int;

    pub fn xcb_depth_visuals_iterator (R: *const xcb_depth_t)
            -> xcb_visualtype_iterator_t;

    pub fn xcb_depth_next (i: *mut xcb_depth_iterator_t);

    pub fn xcb_depth_end (i: *mut xcb_depth_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_screen_allowed_depths_length (R: *const xcb_screen_t)
            -> c_int;

    pub fn xcb_screen_allowed_depths_iterator<'a> (R: *const xcb_screen_t)
            -> xcb_depth_iterator_t<'a>;

    pub fn xcb_screen_next (i: *mut xcb_screen_iterator_t);

    pub fn xcb_screen_end (i: *mut xcb_screen_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_request_authorization_protocol_name (R: *const xcb_setup_request_t)
            -> *mut c_char;

    pub fn xcb_setup_request_authorization_protocol_name_length (R: *const xcb_setup_request_t)
            -> c_int;

    pub fn xcb_setup_request_authorization_protocol_name_end (R: *const xcb_setup_request_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_request_authorization_protocol_data (R: *const xcb_setup_request_t)
            -> *mut c_char;

    pub fn xcb_setup_request_authorization_protocol_data_length (R: *const xcb_setup_request_t)
            -> c_int;

    pub fn xcb_setup_request_authorization_protocol_data_end (R: *const xcb_setup_request_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_request_next (i: *mut xcb_setup_request_iterator_t);

    pub fn xcb_setup_request_end (i: *mut xcb_setup_request_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_failed_reason (R: *const xcb_setup_failed_t)
            -> *mut c_char;

    pub fn xcb_setup_failed_reason_length (R: *const xcb_setup_failed_t)
            -> c_int;

    pub fn xcb_setup_failed_reason_end (R: *const xcb_setup_failed_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_failed_next (i: *mut xcb_setup_failed_iterator_t);

    pub fn xcb_setup_failed_end (i: *mut xcb_setup_failed_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_authenticate_reason (R: *const xcb_setup_authenticate_t)
            -> *mut c_char;

    pub fn xcb_setup_authenticate_reason_length (R: *const xcb_setup_authenticate_t)
            -> c_int;

    pub fn xcb_setup_authenticate_reason_end (R: *const xcb_setup_authenticate_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_authenticate_next (i: *mut xcb_setup_authenticate_iterator_t);

    pub fn xcb_setup_authenticate_end (i: *mut xcb_setup_authenticate_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_vendor (R: *const xcb_setup_t)
            -> *mut c_char;

    pub fn xcb_setup_vendor_length (R: *const xcb_setup_t)
            -> c_int;

    pub fn xcb_setup_vendor_end (R: *const xcb_setup_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_setup_pixmap_formats (R: *const xcb_setup_t)
            -> *mut xcb_format_t;

    pub fn xcb_setup_pixmap_formats_length (R: *const xcb_setup_t)
            -> c_int;

    pub fn xcb_setup_pixmap_formats_iterator (R: *const xcb_setup_t)
            -> xcb_format_iterator_t;

    pub fn xcb_setup_roots_length (R: *const xcb_setup_t)
            -> c_int;

    pub fn xcb_setup_roots_iterator<'a> (R: *const xcb_setup_t)
            -> xcb_screen_iterator_t<'a>;

    pub fn xcb_setup_next (i: *mut xcb_setup_iterator_t);

    pub fn xcb_setup_end (i: *mut xcb_setup_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_client_message_data_next (i: *mut xcb_client_message_data_iterator_t);

    pub fn xcb_client_message_data_end (i: *mut xcb_client_message_data_iterator_t)
            -> xcb_generic_iterator_t;

    /// Creates a window
    ///
    /// Creates an unmapped window as child of the specified `parent` window. A
    /// CreateNotify event will be generated. The new window is placed on top in the
    /// stacking order with respect to siblings.
    ///
    /// The coordinate system has the X axis horizontal and the Y axis vertical with
    /// the origin [0, 0] at the upper-left corner. Coordinates are integral, in terms
    /// of pixels, and coincide with pixel centers. Each window and pixmap has its own
    /// coordinate system. For a window, the origin is inside the border at the inside,
    /// upper-left corner.
    ///
    /// The created window is not yet displayed (mapped), call `xcb_map_window` to
    /// display it.
    ///
    /// The created window will initially use the same cursor as its parent.
    pub fn xcb_create_window (c:            *mut xcb_connection_t,
                              depth:        u8,
                              wid:          xcb_window_t,
                              parent:       xcb_window_t,
                              x:            i16,
                              y:            i16,
                              width:        u16,
                              height:       u16,
                              border_width: u16,
                              class:        u16,
                              visual:       xcb_visualid_t,
                              value_mask:   u32,
                              value_list:   *const u32)
            -> xcb_void_cookie_t;

    /// Creates a window
    ///
    /// Creates an unmapped window as child of the specified `parent` window. A
    /// CreateNotify event will be generated. The new window is placed on top in the
    /// stacking order with respect to siblings.
    ///
    /// The coordinate system has the X axis horizontal and the Y axis vertical with
    /// the origin [0, 0] at the upper-left corner. Coordinates are integral, in terms
    /// of pixels, and coincide with pixel centers. Each window and pixmap has its own
    /// coordinate system. For a window, the origin is inside the border at the inside,
    /// upper-left corner.
    ///
    /// The created window is not yet displayed (mapped), call `xcb_map_window` to
    /// display it.
    ///
    /// The created window will initially use the same cursor as its parent.
    pub fn xcb_create_window_checked (c:            *mut xcb_connection_t,
                                      depth:        u8,
                                      wid:          xcb_window_t,
                                      parent:       xcb_window_t,
                                      x:            i16,
                                      y:            i16,
                                      width:        u16,
                                      height:       u16,
                                      border_width: u16,
                                      class:        u16,
                                      visual:       xcb_visualid_t,
                                      value_mask:   u32,
                                      value_list:   *const u32)
            -> xcb_void_cookie_t;

    /// change window attributes
    ///
    /// Changes the attributes specified by `value_mask` for the specified `window`.
    pub fn xcb_change_window_attributes (c:          *mut xcb_connection_t,
                                         window:     xcb_window_t,
                                         value_mask: u32,
                                         value_list: *const u32)
            -> xcb_void_cookie_t;

    /// change window attributes
    ///
    /// Changes the attributes specified by `value_mask` for the specified `window`.
    pub fn xcb_change_window_attributes_checked (c:          *mut xcb_connection_t,
                                                 window:     xcb_window_t,
                                                 value_mask: u32,
                                                 value_list: *const u32)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_window_attributes_reply (c:      *mut xcb_connection_t,
                                            cookie: xcb_get_window_attributes_cookie_t,
                                            error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_window_attributes_reply_t;

    /// Gets window attributes
    ///
    /// Gets the current attributes for the specified `window`.
    pub fn xcb_get_window_attributes (c:      *mut xcb_connection_t,
                                      window: xcb_window_t)
            -> xcb_get_window_attributes_cookie_t;

    /// Gets window attributes
    ///
    /// Gets the current attributes for the specified `window`.
    pub fn xcb_get_window_attributes_unchecked (c:      *mut xcb_connection_t,
                                                window: xcb_window_t)
            -> xcb_get_window_attributes_cookie_t;

    /// Destroys a window
    ///
    /// Destroys the specified window and all of its subwindows. A DestroyNotify event
    /// is generated for each destroyed window (a DestroyNotify event is first generated
    /// for any given window's inferiors). If the window was mapped, it will be
    /// automatically unmapped before destroying.
    ///
    /// Calling DestroyWindow on the root window will do nothing.
    pub fn xcb_destroy_window (c:      *mut xcb_connection_t,
                               window: xcb_window_t)
            -> xcb_void_cookie_t;

    /// Destroys a window
    ///
    /// Destroys the specified window and all of its subwindows. A DestroyNotify event
    /// is generated for each destroyed window (a DestroyNotify event is first generated
    /// for any given window's inferiors). If the window was mapped, it will be
    /// automatically unmapped before destroying.
    ///
    /// Calling DestroyWindow on the root window will do nothing.
    pub fn xcb_destroy_window_checked (c:      *mut xcb_connection_t,
                                       window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_destroy_subwindows (c:      *mut xcb_connection_t,
                                   window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_destroy_subwindows_checked (c:      *mut xcb_connection_t,
                                           window: xcb_window_t)
            -> xcb_void_cookie_t;

    /// Changes a client's save set
    ///
    /// TODO: explain what the save set is for.
    ///
    /// This function either adds or removes the specified window to the client's (your
    /// application's) save set.
    pub fn xcb_change_save_set (c:      *mut xcb_connection_t,
                                mode:   u8,
                                window: xcb_window_t)
            -> xcb_void_cookie_t;

    /// Changes a client's save set
    ///
    /// TODO: explain what the save set is for.
    ///
    /// This function either adds or removes the specified window to the client's (your
    /// application's) save set.
    pub fn xcb_change_save_set_checked (c:      *mut xcb_connection_t,
                                        mode:   u8,
                                        window: xcb_window_t)
            -> xcb_void_cookie_t;

    /// Reparents a window
    ///
    /// Makes the specified window a child of the specified parent window. If the
    /// window is mapped, it will automatically be unmapped before reparenting and
    /// re-mapped after reparenting. The window is placed in the stacking order on top
    /// with respect to sibling windows.
    ///
    /// After reparenting, a ReparentNotify event is generated.
    pub fn xcb_reparent_window (c:      *mut xcb_connection_t,
                                window: xcb_window_t,
                                parent: xcb_window_t,
                                x:      i16,
                                y:      i16)
            -> xcb_void_cookie_t;

    /// Reparents a window
    ///
    /// Makes the specified window a child of the specified parent window. If the
    /// window is mapped, it will automatically be unmapped before reparenting and
    /// re-mapped after reparenting. The window is placed in the stacking order on top
    /// with respect to sibling windows.
    ///
    /// After reparenting, a ReparentNotify event is generated.
    pub fn xcb_reparent_window_checked (c:      *mut xcb_connection_t,
                                        window: xcb_window_t,
                                        parent: xcb_window_t,
                                        x:      i16,
                                        y:      i16)
            -> xcb_void_cookie_t;

    /// Makes a window visible
    ///
    /// Maps the specified window. This means making the window visible (as long as its
    /// parent is visible).
    ///
    /// This MapWindow request will be translated to a MapRequest request if a window
    /// manager is running. The window manager then decides to either map the window or
    /// not. Set the override-redirect window attribute to true if you want to bypass
    /// this mechanism.
    ///
    /// If the window manager decides to map the window (or if no window manager is
    /// running), a MapNotify event is generated.
    ///
    /// If the window becomes viewable and no earlier contents for it are remembered,
    /// the X server tiles the window with its background. If the window's background
    /// is undefined, the existing screen contents are not altered, and the X server
    /// generates zero or more Expose events.
    ///
    /// If the window type is InputOutput, an Expose event will be generated when the
    /// window becomes visible. The normal response to an Expose event should be to
    /// repaint the window.
    pub fn xcb_map_window (c:      *mut xcb_connection_t,
                           window: xcb_window_t)
            -> xcb_void_cookie_t;

    /// Makes a window visible
    ///
    /// Maps the specified window. This means making the window visible (as long as its
    /// parent is visible).
    ///
    /// This MapWindow request will be translated to a MapRequest request if a window
    /// manager is running. The window manager then decides to either map the window or
    /// not. Set the override-redirect window attribute to true if you want to bypass
    /// this mechanism.
    ///
    /// If the window manager decides to map the window (or if no window manager is
    /// running), a MapNotify event is generated.
    ///
    /// If the window becomes viewable and no earlier contents for it are remembered,
    /// the X server tiles the window with its background. If the window's background
    /// is undefined, the existing screen contents are not altered, and the X server
    /// generates zero or more Expose events.
    ///
    /// If the window type is InputOutput, an Expose event will be generated when the
    /// window becomes visible. The normal response to an Expose event should be to
    /// repaint the window.
    pub fn xcb_map_window_checked (c:      *mut xcb_connection_t,
                                   window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_map_subwindows (c:      *mut xcb_connection_t,
                               window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_map_subwindows_checked (c:      *mut xcb_connection_t,
                                       window: xcb_window_t)
            -> xcb_void_cookie_t;

    /// Makes a window invisible
    ///
    /// Unmaps the specified window. This means making the window invisible (and all
    /// its child windows).
    ///
    /// Unmapping a window leads to the `UnmapNotify` event being generated. Also,
    /// `Expose` events are generated for formerly obscured windows.
    pub fn xcb_unmap_window (c:      *mut xcb_connection_t,
                             window: xcb_window_t)
            -> xcb_void_cookie_t;

    /// Makes a window invisible
    ///
    /// Unmaps the specified window. This means making the window invisible (and all
    /// its child windows).
    ///
    /// Unmapping a window leads to the `UnmapNotify` event being generated. Also,
    /// `Expose` events are generated for formerly obscured windows.
    pub fn xcb_unmap_window_checked (c:      *mut xcb_connection_t,
                                     window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_unmap_subwindows (c:      *mut xcb_connection_t,
                                 window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_unmap_subwindows_checked (c:      *mut xcb_connection_t,
                                         window: xcb_window_t)
            -> xcb_void_cookie_t;

    /// Configures window attributes
    ///
    /// Configures a window's size, position, border width and stacking order.
    pub fn xcb_configure_window (c:          *mut xcb_connection_t,
                                 window:     xcb_window_t,
                                 value_mask: u16,
                                 value_list: *const u32)
            -> xcb_void_cookie_t;

    /// Configures window attributes
    ///
    /// Configures a window's size, position, border width and stacking order.
    pub fn xcb_configure_window_checked (c:          *mut xcb_connection_t,
                                         window:     xcb_window_t,
                                         value_mask: u16,
                                         value_list: *const u32)
            -> xcb_void_cookie_t;

    /// Change window stacking order
    ///
    /// If `direction` is `XCB_CIRCULATE_RAISE_LOWEST`, the lowest mapped child (if
    /// any) will be raised to the top of the stack.
    ///
    /// If `direction` is `XCB_CIRCULATE_LOWER_HIGHEST`, the highest mapped child will
    /// be lowered to the bottom of the stack.
    pub fn xcb_circulate_window (c:         *mut xcb_connection_t,
                                 direction: u8,
                                 window:    xcb_window_t)
            -> xcb_void_cookie_t;

    /// Change window stacking order
    ///
    /// If `direction` is `XCB_CIRCULATE_RAISE_LOWEST`, the lowest mapped child (if
    /// any) will be raised to the top of the stack.
    ///
    /// If `direction` is `XCB_CIRCULATE_LOWER_HIGHEST`, the highest mapped child will
    /// be lowered to the bottom of the stack.
    pub fn xcb_circulate_window_checked (c:         *mut xcb_connection_t,
                                         direction: u8,
                                         window:    xcb_window_t)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_geometry_reply (c:      *mut xcb_connection_t,
                                   cookie: xcb_get_geometry_cookie_t,
                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_geometry_reply_t;

    /// Get current window geometry
    ///
    /// Gets the current geometry of the specified drawable (either `Window` or `Pixmap`).
    pub fn xcb_get_geometry (c:        *mut xcb_connection_t,
                             drawable: xcb_drawable_t)
            -> xcb_get_geometry_cookie_t;

    /// Get current window geometry
    ///
    /// Gets the current geometry of the specified drawable (either `Window` or `Pixmap`).
    pub fn xcb_get_geometry_unchecked (c:        *mut xcb_connection_t,
                                       drawable: xcb_drawable_t)
            -> xcb_get_geometry_cookie_t;

    pub fn xcb_query_tree_children (R: *const xcb_query_tree_reply_t)
            -> *mut xcb_window_t;

    pub fn xcb_query_tree_children_length (R: *const xcb_query_tree_reply_t)
            -> c_int;

    pub fn xcb_query_tree_children_end (R: *const xcb_query_tree_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_query_tree_reply (c:      *mut xcb_connection_t,
                                 cookie: xcb_query_tree_cookie_t,
                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_query_tree_reply_t;

    /// query the window tree
    ///
    /// Gets the root window ID, parent window ID and list of children windows for the
    /// specified `window`. The children are listed in bottom-to-top stacking order.
    pub fn xcb_query_tree (c:      *mut xcb_connection_t,
                           window: xcb_window_t)
            -> xcb_query_tree_cookie_t;

    /// query the window tree
    ///
    /// Gets the root window ID, parent window ID and list of children windows for the
    /// specified `window`. The children are listed in bottom-to-top stacking order.
    pub fn xcb_query_tree_unchecked (c:      *mut xcb_connection_t,
                                     window: xcb_window_t)
            -> xcb_query_tree_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_intern_atom_reply (c:      *mut xcb_connection_t,
                                  cookie: xcb_intern_atom_cookie_t,
                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_intern_atom_reply_t;

    /// Get atom identifier by name
    ///
    /// Retrieves the identifier (xcb_atom_t TODO) for the atom with the specified
    /// name. Atoms are used in protocols like EWMH, for example to store window titles
    /// (`_NET_WM_NAME` atom) as property of a window.
    ///
    /// If `only_if_exists` is 0, the atom will be created if it does not already exist.
    /// If `only_if_exists` is 1, `XCB_ATOM_NONE` will be returned if the atom does
    /// not yet exist.
    pub fn xcb_intern_atom (c:              *mut xcb_connection_t,
                            only_if_exists: u8,
                            name_len:       u16,
                            name:           *const c_char)
            -> xcb_intern_atom_cookie_t;

    /// Get atom identifier by name
    ///
    /// Retrieves the identifier (xcb_atom_t TODO) for the atom with the specified
    /// name. Atoms are used in protocols like EWMH, for example to store window titles
    /// (`_NET_WM_NAME` atom) as property of a window.
    ///
    /// If `only_if_exists` is 0, the atom will be created if it does not already exist.
    /// If `only_if_exists` is 1, `XCB_ATOM_NONE` will be returned if the atom does
    /// not yet exist.
    pub fn xcb_intern_atom_unchecked (c:              *mut xcb_connection_t,
                                      only_if_exists: u8,
                                      name_len:       u16,
                                      name:           *const c_char)
            -> xcb_intern_atom_cookie_t;

    pub fn xcb_get_atom_name_name (R: *const xcb_get_atom_name_reply_t)
            -> *mut c_char;

    pub fn xcb_get_atom_name_name_length (R: *const xcb_get_atom_name_reply_t)
            -> c_int;

    pub fn xcb_get_atom_name_name_end (R: *const xcb_get_atom_name_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_atom_name_reply (c:      *mut xcb_connection_t,
                                    cookie: xcb_get_atom_name_cookie_t,
                                    error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_atom_name_reply_t;

    pub fn xcb_get_atom_name (c:    *mut xcb_connection_t,
                              atom: xcb_atom_t)
            -> xcb_get_atom_name_cookie_t;

    pub fn xcb_get_atom_name_unchecked (c:    *mut xcb_connection_t,
                                        atom: xcb_atom_t)
            -> xcb_get_atom_name_cookie_t;

    /// Changes a window property
    ///
    /// Sets or updates a property on the specified `window`. Properties are for
    /// example the window title (`WM_NAME`) or its minimum size (`WM_NORMAL_HINTS`).
    /// Protocols such as EWMH also use properties - for example EWMH defines the
    /// window title, encoded as UTF-8 string, in the `_NET_WM_NAME` property.
    pub fn xcb_change_property (c:        *mut xcb_connection_t,
                                mode:     u8,
                                window:   xcb_window_t,
                                property: xcb_atom_t,
                                type_:    xcb_atom_t,
                                format:   u8,
                                data_len: u32,
                                data:     *const c_void)
            -> xcb_void_cookie_t;

    /// Changes a window property
    ///
    /// Sets or updates a property on the specified `window`. Properties are for
    /// example the window title (`WM_NAME`) or its minimum size (`WM_NORMAL_HINTS`).
    /// Protocols such as EWMH also use properties - for example EWMH defines the
    /// window title, encoded as UTF-8 string, in the `_NET_WM_NAME` property.
    pub fn xcb_change_property_checked (c:        *mut xcb_connection_t,
                                        mode:     u8,
                                        window:   xcb_window_t,
                                        property: xcb_atom_t,
                                        type_:    xcb_atom_t,
                                        format:   u8,
                                        data_len: u32,
                                        data:     *const c_void)
            -> xcb_void_cookie_t;

    pub fn xcb_delete_property (c:        *mut xcb_connection_t,
                                window:   xcb_window_t,
                                property: xcb_atom_t)
            -> xcb_void_cookie_t;

    pub fn xcb_delete_property_checked (c:        *mut xcb_connection_t,
                                        window:   xcb_window_t,
                                        property: xcb_atom_t)
            -> xcb_void_cookie_t;

    pub fn xcb_get_property_value (R: *const xcb_get_property_reply_t)
            -> *mut c_void;

    pub fn xcb_get_property_value_length (R: *const xcb_get_property_reply_t)
            -> c_int;

    pub fn xcb_get_property_value_end (R: *const xcb_get_property_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_property_reply (c:      *mut xcb_connection_t,
                                   cookie: xcb_get_property_cookie_t,
                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_property_reply_t;

    /// Gets a window property
    ///
    /// Gets the specified `property` from the specified `window`. Properties are for
    /// example the window title (`WM_NAME`) or its minimum size (`WM_NORMAL_HINTS`).
    /// Protocols such as EWMH also use properties - for example EWMH defines the
    /// window title, encoded as UTF-8 string, in the `_NET_WM_NAME` property.
    ///
    /// TODO: talk about `type`
    ///
    /// TODO: talk about `delete`
    ///
    /// TODO: talk about the offset/length thing. what's a valid use case?
    pub fn xcb_get_property (c:           *mut xcb_connection_t,
                             delete:      u8,
                             window:      xcb_window_t,
                             property:    xcb_atom_t,
                             type_:       xcb_atom_t,
                             long_offset: u32,
                             long_length: u32)
            -> xcb_get_property_cookie_t;

    /// Gets a window property
    ///
    /// Gets the specified `property` from the specified `window`. Properties are for
    /// example the window title (`WM_NAME`) or its minimum size (`WM_NORMAL_HINTS`).
    /// Protocols such as EWMH also use properties - for example EWMH defines the
    /// window title, encoded as UTF-8 string, in the `_NET_WM_NAME` property.
    ///
    /// TODO: talk about `type`
    ///
    /// TODO: talk about `delete`
    ///
    /// TODO: talk about the offset/length thing. what's a valid use case?
    pub fn xcb_get_property_unchecked (c:           *mut xcb_connection_t,
                                       delete:      u8,
                                       window:      xcb_window_t,
                                       property:    xcb_atom_t,
                                       type_:       xcb_atom_t,
                                       long_offset: u32,
                                       long_length: u32)
            -> xcb_get_property_cookie_t;

    pub fn xcb_list_properties_atoms (R: *const xcb_list_properties_reply_t)
            -> *mut xcb_atom_t;

    pub fn xcb_list_properties_atoms_length (R: *const xcb_list_properties_reply_t)
            -> c_int;

    pub fn xcb_list_properties_atoms_end (R: *const xcb_list_properties_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_list_properties_reply (c:      *mut xcb_connection_t,
                                      cookie: xcb_list_properties_cookie_t,
                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_list_properties_reply_t;

    pub fn xcb_list_properties (c:      *mut xcb_connection_t,
                                window: xcb_window_t)
            -> xcb_list_properties_cookie_t;

    pub fn xcb_list_properties_unchecked (c:      *mut xcb_connection_t,
                                          window: xcb_window_t)
            -> xcb_list_properties_cookie_t;

    /// Sets the owner of a selection
    ///
    /// Makes `window` the owner of the selection `selection` and updates the
    /// last-change time of the specified selection.
    ///
    /// TODO: briefly explain what a selection is.
    pub fn xcb_set_selection_owner (c:         *mut xcb_connection_t,
                                    owner:     xcb_window_t,
                                    selection: xcb_atom_t,
                                    time:      xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// Sets the owner of a selection
    ///
    /// Makes `window` the owner of the selection `selection` and updates the
    /// last-change time of the specified selection.
    ///
    /// TODO: briefly explain what a selection is.
    pub fn xcb_set_selection_owner_checked (c:         *mut xcb_connection_t,
                                            owner:     xcb_window_t,
                                            selection: xcb_atom_t,
                                            time:      xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_selection_owner_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_get_selection_owner_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_selection_owner_reply_t;

    /// Gets the owner of a selection
    ///
    /// Gets the owner of the specified selection.
    ///
    /// TODO: briefly explain what a selection is.
    pub fn xcb_get_selection_owner (c:         *mut xcb_connection_t,
                                    selection: xcb_atom_t)
            -> xcb_get_selection_owner_cookie_t;

    /// Gets the owner of a selection
    ///
    /// Gets the owner of the specified selection.
    ///
    /// TODO: briefly explain what a selection is.
    pub fn xcb_get_selection_owner_unchecked (c:         *mut xcb_connection_t,
                                              selection: xcb_atom_t)
            -> xcb_get_selection_owner_cookie_t;

    pub fn xcb_convert_selection (c:         *mut xcb_connection_t,
                                  requestor: xcb_window_t,
                                  selection: xcb_atom_t,
                                  target:    xcb_atom_t,
                                  property:  xcb_atom_t,
                                  time:      xcb_timestamp_t)
            -> xcb_void_cookie_t;

    pub fn xcb_convert_selection_checked (c:         *mut xcb_connection_t,
                                          requestor: xcb_window_t,
                                          selection: xcb_atom_t,
                                          target:    xcb_atom_t,
                                          property:  xcb_atom_t,
                                          time:      xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// send an event
    ///
    /// Identifies the `destination` window, determines which clients should receive
    /// the specified event and ignores any active grabs.
    ///
    /// The `event` must be one of the core events or an event defined by an extension,
    /// so that the X server can correctly byte-swap the contents as necessary. The
    /// contents of `event` are otherwise unaltered and unchecked except for the
    /// `send_event` field which is forced to 'true'.
    pub fn xcb_send_event (c:           *mut xcb_connection_t,
                           propagate:   u8,
                           destination: xcb_window_t,
                           event_mask:  u32,
                           event:       *const c_char)
            -> xcb_void_cookie_t;

    /// send an event
    ///
    /// Identifies the `destination` window, determines which clients should receive
    /// the specified event and ignores any active grabs.
    ///
    /// The `event` must be one of the core events or an event defined by an extension,
    /// so that the X server can correctly byte-swap the contents as necessary. The
    /// contents of `event` are otherwise unaltered and unchecked except for the
    /// `send_event` field which is forced to 'true'.
    pub fn xcb_send_event_checked (c:           *mut xcb_connection_t,
                                   propagate:   u8,
                                   destination: xcb_window_t,
                                   event_mask:  u32,
                                   event:       *const c_char)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_grab_pointer_reply (c:      *mut xcb_connection_t,
                                   cookie: xcb_grab_pointer_cookie_t,
                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_grab_pointer_reply_t;

    /// Grab the pointer
    ///
    /// Actively grabs control of the pointer. Further pointer events are reported only to the grabbing client. Overrides any active pointer grab by this client.
    pub fn xcb_grab_pointer (c:             *mut xcb_connection_t,
                             owner_events:  u8,
                             grab_window:   xcb_window_t,
                             event_mask:    u16,
                             pointer_mode:  u8,
                             keyboard_mode: u8,
                             confine_to:    xcb_window_t,
                             cursor:        xcb_cursor_t,
                             time:          xcb_timestamp_t)
            -> xcb_grab_pointer_cookie_t;

    /// Grab the pointer
    ///
    /// Actively grabs control of the pointer. Further pointer events are reported only to the grabbing client. Overrides any active pointer grab by this client.
    pub fn xcb_grab_pointer_unchecked (c:             *mut xcb_connection_t,
                                       owner_events:  u8,
                                       grab_window:   xcb_window_t,
                                       event_mask:    u16,
                                       pointer_mode:  u8,
                                       keyboard_mode: u8,
                                       confine_to:    xcb_window_t,
                                       cursor:        xcb_cursor_t,
                                       time:          xcb_timestamp_t)
            -> xcb_grab_pointer_cookie_t;

    /// release the pointer
    ///
    /// Releases the pointer and any queued events if you actively grabbed the pointer
    /// before using `xcb_grab_pointer`, `xcb_grab_button` or within a normal button
    /// press.
    ///
    /// EnterNotify and LeaveNotify events are generated.
    pub fn xcb_ungrab_pointer (c:    *mut xcb_connection_t,
                               time: xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// release the pointer
    ///
    /// Releases the pointer and any queued events if you actively grabbed the pointer
    /// before using `xcb_grab_pointer`, `xcb_grab_button` or within a normal button
    /// press.
    ///
    /// EnterNotify and LeaveNotify events are generated.
    pub fn xcb_ungrab_pointer_checked (c:    *mut xcb_connection_t,
                                       time: xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// Grab pointer button(s)
    ///
    /// This request establishes a passive grab. The pointer is actively grabbed as
    /// described in GrabPointer, the last-pointer-grab time is set to the time at
    /// which the button was pressed (as transmitted in the ButtonPress event), and the
    /// ButtonPress event is reported if all of the following conditions are true:
    ///
    /// The pointer is not grabbed and the specified button is logically pressed when
    /// the specified modifier keys are logically down, and no other buttons or
    /// modifier keys are logically down.
    ///
    /// The grab-window contains the pointer.
    ///
    /// The confine-to window (if any) is viewable.
    ///
    /// A passive grab on the same button/key combination does not exist on any
    /// ancestor of grab-window.
    ///
    /// The interpretation of the remaining arguments is the same as for GrabPointer.
    /// The active grab is terminated automatically when the logical state of the
    /// pointer has all buttons released, independent of the logical state of modifier
    /// keys. Note that the logical state of a device (as seen by means of the
    /// protocol) may lag the physical state if device event processing is frozen. This
    /// request overrides all previous passive grabs by the same client on the same
    /// button/key combinations on the same window. A modifier of AnyModifier is
    /// equivalent to issuing the request for all possible modifier combinations
    /// (including the combination of no modifiers). It is not required that all
    /// specified modifiers have currently assigned keycodes. A button of AnyButton is
    /// equivalent to issuing the request for all possible buttons. Otherwise, it is
    /// not required that the button specified currently be assigned to a physical
    /// button.
    ///
    /// An Access error is generated if some other client has already issued a
    /// GrabButton request with the same button/key combination on the same window.
    /// When using AnyModifier or AnyButton, the request fails completely (no grabs are
    /// established), and an Access error is generated if there is a conflicting grab
    /// for any combination. The request has no effect on an active grab.
    pub fn xcb_grab_button (c:             *mut xcb_connection_t,
                            owner_events:  u8,
                            grab_window:   xcb_window_t,
                            event_mask:    u16,
                            pointer_mode:  u8,
                            keyboard_mode: u8,
                            confine_to:    xcb_window_t,
                            cursor:        xcb_cursor_t,
                            button:        u8,
                            modifiers:     u16)
            -> xcb_void_cookie_t;

    /// Grab pointer button(s)
    ///
    /// This request establishes a passive grab. The pointer is actively grabbed as
    /// described in GrabPointer, the last-pointer-grab time is set to the time at
    /// which the button was pressed (as transmitted in the ButtonPress event), and the
    /// ButtonPress event is reported if all of the following conditions are true:
    ///
    /// The pointer is not grabbed and the specified button is logically pressed when
    /// the specified modifier keys are logically down, and no other buttons or
    /// modifier keys are logically down.
    ///
    /// The grab-window contains the pointer.
    ///
    /// The confine-to window (if any) is viewable.
    ///
    /// A passive grab on the same button/key combination does not exist on any
    /// ancestor of grab-window.
    ///
    /// The interpretation of the remaining arguments is the same as for GrabPointer.
    /// The active grab is terminated automatically when the logical state of the
    /// pointer has all buttons released, independent of the logical state of modifier
    /// keys. Note that the logical state of a device (as seen by means of the
    /// protocol) may lag the physical state if device event processing is frozen. This
    /// request overrides all previous passive grabs by the same client on the same
    /// button/key combinations on the same window. A modifier of AnyModifier is
    /// equivalent to issuing the request for all possible modifier combinations
    /// (including the combination of no modifiers). It is not required that all
    /// specified modifiers have currently assigned keycodes. A button of AnyButton is
    /// equivalent to issuing the request for all possible buttons. Otherwise, it is
    /// not required that the button specified currently be assigned to a physical
    /// button.
    ///
    /// An Access error is generated if some other client has already issued a
    /// GrabButton request with the same button/key combination on the same window.
    /// When using AnyModifier or AnyButton, the request fails completely (no grabs are
    /// established), and an Access error is generated if there is a conflicting grab
    /// for any combination. The request has no effect on an active grab.
    pub fn xcb_grab_button_checked (c:             *mut xcb_connection_t,
                                    owner_events:  u8,
                                    grab_window:   xcb_window_t,
                                    event_mask:    u16,
                                    pointer_mode:  u8,
                                    keyboard_mode: u8,
                                    confine_to:    xcb_window_t,
                                    cursor:        xcb_cursor_t,
                                    button:        u8,
                                    modifiers:     u16)
            -> xcb_void_cookie_t;

    pub fn xcb_ungrab_button (c:           *mut xcb_connection_t,
                              button:      u8,
                              grab_window: xcb_window_t,
                              modifiers:   u16)
            -> xcb_void_cookie_t;

    pub fn xcb_ungrab_button_checked (c:           *mut xcb_connection_t,
                                      button:      u8,
                                      grab_window: xcb_window_t,
                                      modifiers:   u16)
            -> xcb_void_cookie_t;

    pub fn xcb_change_active_pointer_grab (c:          *mut xcb_connection_t,
                                           cursor:     xcb_cursor_t,
                                           time:       xcb_timestamp_t,
                                           event_mask: u16)
            -> xcb_void_cookie_t;

    pub fn xcb_change_active_pointer_grab_checked (c:          *mut xcb_connection_t,
                                                   cursor:     xcb_cursor_t,
                                                   time:       xcb_timestamp_t,
                                                   event_mask: u16)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_grab_keyboard_reply (c:      *mut xcb_connection_t,
                                    cookie: xcb_grab_keyboard_cookie_t,
                                    error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_grab_keyboard_reply_t;

    /// Grab the keyboard
    ///
    /// Actively grabs control of the keyboard and generates FocusIn and FocusOut
    /// events. Further key events are reported only to the grabbing client.
    ///
    /// Any active keyboard grab by this client is overridden. If the keyboard is
    /// actively grabbed by some other client, `AlreadyGrabbed` is returned. If
    /// `grab_window` is not viewable, `GrabNotViewable` is returned. If the keyboard
    /// is frozen by an active grab of another client, `GrabFrozen` is returned. If the
    /// specified `time` is earlier than the last-keyboard-grab time or later than the
    /// current X server time, `GrabInvalidTime` is returned. Otherwise, the
    /// last-keyboard-grab time is set to the specified time.
    pub fn xcb_grab_keyboard (c:             *mut xcb_connection_t,
                              owner_events:  u8,
                              grab_window:   xcb_window_t,
                              time:          xcb_timestamp_t,
                              pointer_mode:  u8,
                              keyboard_mode: u8)
            -> xcb_grab_keyboard_cookie_t;

    /// Grab the keyboard
    ///
    /// Actively grabs control of the keyboard and generates FocusIn and FocusOut
    /// events. Further key events are reported only to the grabbing client.
    ///
    /// Any active keyboard grab by this client is overridden. If the keyboard is
    /// actively grabbed by some other client, `AlreadyGrabbed` is returned. If
    /// `grab_window` is not viewable, `GrabNotViewable` is returned. If the keyboard
    /// is frozen by an active grab of another client, `GrabFrozen` is returned. If the
    /// specified `time` is earlier than the last-keyboard-grab time or later than the
    /// current X server time, `GrabInvalidTime` is returned. Otherwise, the
    /// last-keyboard-grab time is set to the specified time.
    pub fn xcb_grab_keyboard_unchecked (c:             *mut xcb_connection_t,
                                        owner_events:  u8,
                                        grab_window:   xcb_window_t,
                                        time:          xcb_timestamp_t,
                                        pointer_mode:  u8,
                                        keyboard_mode: u8)
            -> xcb_grab_keyboard_cookie_t;

    pub fn xcb_ungrab_keyboard (c:    *mut xcb_connection_t,
                                time: xcb_timestamp_t)
            -> xcb_void_cookie_t;

    pub fn xcb_ungrab_keyboard_checked (c:    *mut xcb_connection_t,
                                        time: xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// Grab keyboard key(s)
    ///
    /// Establishes a passive grab on the keyboard. In the future, the keyboard is
    /// actively grabbed (as for `GrabKeyboard`), the last-keyboard-grab time is set to
    /// the time at which the key was pressed (as transmitted in the KeyPress event),
    /// and the KeyPress event is reported if all of the following conditions are true:
    ///
    /// The keyboard is not grabbed and the specified key (which can itself be a
    /// modifier key) is logically pressed when the specified modifier keys are
    /// logically down, and no other modifier keys are logically down.
    ///
    /// Either the grab_window is an ancestor of (or is) the focus window, or the
    /// grab_window is a descendant of the focus window and contains the pointer.
    ///
    /// A passive grab on the same key combination does not exist on any ancestor of
    /// grab_window.
    ///
    /// The interpretation of the remaining arguments is as for XGrabKeyboard.  The active grab is terminated
    /// automatically when the logical state of the keyboard has the specified key released (independent of the
    /// logical state of the modifier keys), at which point a KeyRelease event is reported to the grabbing window.
    ///
    /// Note that the logical state of a device (as seen by client applications) may lag the physical state if
    /// device event processing is frozen.
    ///
    /// A modifiers argument of AnyModifier is equivalent to issuing the request for all possible modifier combinations (including the combination of no modifiers).  It is not required that all modifiers specified
    /// have currently assigned KeyCodes.  A keycode argument of AnyKey is equivalent to issuing the request for
    /// all possible KeyCodes.  Otherwise, the specified keycode must be in the range specified by min_keycode
    /// and max_keycode in the connection setup, or a BadValue error results.
    ///
    /// If some other client has issued a XGrabKey with the same key combination on the same window, a BadAccess
    /// error results.  When using AnyModifier or AnyKey, the request fails completely, and a BadAccess error
    /// results (no grabs are established) if there is a conflicting grab for any combination.
    pub fn xcb_grab_key (c:             *mut xcb_connection_t,
                         owner_events:  u8,
                         grab_window:   xcb_window_t,
                         modifiers:     u16,
                         key:           xcb_keycode_t,
                         pointer_mode:  u8,
                         keyboard_mode: u8)
            -> xcb_void_cookie_t;

    /// Grab keyboard key(s)
    ///
    /// Establishes a passive grab on the keyboard. In the future, the keyboard is
    /// actively grabbed (as for `GrabKeyboard`), the last-keyboard-grab time is set to
    /// the time at which the key was pressed (as transmitted in the KeyPress event),
    /// and the KeyPress event is reported if all of the following conditions are true:
    ///
    /// The keyboard is not grabbed and the specified key (which can itself be a
    /// modifier key) is logically pressed when the specified modifier keys are
    /// logically down, and no other modifier keys are logically down.
    ///
    /// Either the grab_window is an ancestor of (or is) the focus window, or the
    /// grab_window is a descendant of the focus window and contains the pointer.
    ///
    /// A passive grab on the same key combination does not exist on any ancestor of
    /// grab_window.
    ///
    /// The interpretation of the remaining arguments is as for XGrabKeyboard.  The active grab is terminated
    /// automatically when the logical state of the keyboard has the specified key released (independent of the
    /// logical state of the modifier keys), at which point a KeyRelease event is reported to the grabbing window.
    ///
    /// Note that the logical state of a device (as seen by client applications) may lag the physical state if
    /// device event processing is frozen.
    ///
    /// A modifiers argument of AnyModifier is equivalent to issuing the request for all possible modifier combinations (including the combination of no modifiers).  It is not required that all modifiers specified
    /// have currently assigned KeyCodes.  A keycode argument of AnyKey is equivalent to issuing the request for
    /// all possible KeyCodes.  Otherwise, the specified keycode must be in the range specified by min_keycode
    /// and max_keycode in the connection setup, or a BadValue error results.
    ///
    /// If some other client has issued a XGrabKey with the same key combination on the same window, a BadAccess
    /// error results.  When using AnyModifier or AnyKey, the request fails completely, and a BadAccess error
    /// results (no grabs are established) if there is a conflicting grab for any combination.
    pub fn xcb_grab_key_checked (c:             *mut xcb_connection_t,
                                 owner_events:  u8,
                                 grab_window:   xcb_window_t,
                                 modifiers:     u16,
                                 key:           xcb_keycode_t,
                                 pointer_mode:  u8,
                                 keyboard_mode: u8)
            -> xcb_void_cookie_t;

    /// release a key combination
    ///
    /// Releases the key combination on `grab_window` if you grabbed it using
    /// `xcb_grab_key` before.
    pub fn xcb_ungrab_key (c:           *mut xcb_connection_t,
                           key:         xcb_keycode_t,
                           grab_window: xcb_window_t,
                           modifiers:   u16)
            -> xcb_void_cookie_t;

    /// release a key combination
    ///
    /// Releases the key combination on `grab_window` if you grabbed it using
    /// `xcb_grab_key` before.
    pub fn xcb_ungrab_key_checked (c:           *mut xcb_connection_t,
                                   key:         xcb_keycode_t,
                                   grab_window: xcb_window_t,
                                   modifiers:   u16)
            -> xcb_void_cookie_t;

    /// release queued events
    ///
    /// Releases queued events if the client has caused a device (pointer/keyboard) to
    /// freeze due to grabbing it actively. This request has no effect if `time` is
    /// earlier than the last-grab time of the most recent active grab for this client
    /// or if `time` is later than the current X server time.
    pub fn xcb_allow_events (c:    *mut xcb_connection_t,
                             mode: u8,
                             time: xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// release queued events
    ///
    /// Releases queued events if the client has caused a device (pointer/keyboard) to
    /// freeze due to grabbing it actively. This request has no effect if `time` is
    /// earlier than the last-grab time of the most recent active grab for this client
    /// or if `time` is later than the current X server time.
    pub fn xcb_allow_events_checked (c:    *mut xcb_connection_t,
                                     mode: u8,
                                     time: xcb_timestamp_t)
            -> xcb_void_cookie_t;

    pub fn xcb_grab_server (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_grab_server_checked (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_ungrab_server (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_ungrab_server_checked (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_query_pointer_reply (c:      *mut xcb_connection_t,
                                    cookie: xcb_query_pointer_cookie_t,
                                    error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_query_pointer_reply_t;

    /// get pointer coordinates
    ///
    /// Gets the root window the pointer is logically on and the pointer coordinates
    /// relative to the root window's origin.
    pub fn xcb_query_pointer (c:      *mut xcb_connection_t,
                              window: xcb_window_t)
            -> xcb_query_pointer_cookie_t;

    /// get pointer coordinates
    ///
    /// Gets the root window the pointer is logically on and the pointer coordinates
    /// relative to the root window's origin.
    pub fn xcb_query_pointer_unchecked (c:      *mut xcb_connection_t,
                                        window: xcb_window_t)
            -> xcb_query_pointer_cookie_t;

    pub fn xcb_timecoord_next (i: *mut xcb_timecoord_iterator_t);

    pub fn xcb_timecoord_end (i: *mut xcb_timecoord_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_get_motion_events_events (R: *const xcb_get_motion_events_reply_t)
            -> *mut xcb_timecoord_t;

    pub fn xcb_get_motion_events_events_length (R: *const xcb_get_motion_events_reply_t)
            -> c_int;

    pub fn xcb_get_motion_events_events_iterator (R: *const xcb_get_motion_events_reply_t)
            -> xcb_timecoord_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_motion_events_reply (c:      *mut xcb_connection_t,
                                        cookie: xcb_get_motion_events_cookie_t,
                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_motion_events_reply_t;

    pub fn xcb_get_motion_events (c:      *mut xcb_connection_t,
                                  window: xcb_window_t,
                                  start:  xcb_timestamp_t,
                                  stop:   xcb_timestamp_t)
            -> xcb_get_motion_events_cookie_t;

    pub fn xcb_get_motion_events_unchecked (c:      *mut xcb_connection_t,
                                            window: xcb_window_t,
                                            start:  xcb_timestamp_t,
                                            stop:   xcb_timestamp_t)
            -> xcb_get_motion_events_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_translate_coordinates_reply (c:      *mut xcb_connection_t,
                                            cookie: xcb_translate_coordinates_cookie_t,
                                            error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_translate_coordinates_reply_t;

    pub fn xcb_translate_coordinates (c:          *mut xcb_connection_t,
                                      src_window: xcb_window_t,
                                      dst_window: xcb_window_t,
                                      src_x:      i16,
                                      src_y:      i16)
            -> xcb_translate_coordinates_cookie_t;

    pub fn xcb_translate_coordinates_unchecked (c:          *mut xcb_connection_t,
                                                src_window: xcb_window_t,
                                                dst_window: xcb_window_t,
                                                src_x:      i16,
                                                src_y:      i16)
            -> xcb_translate_coordinates_cookie_t;

    /// move mouse pointer
    ///
    /// Moves the mouse pointer to the specified position.
    ///
    /// If `src_window` is not `XCB_NONE` (TODO), the move will only take place if the
    /// pointer is inside `src_window` and within the rectangle specified by (`src_x`,
    /// `src_y`, `src_width`, `src_height`). The rectangle coordinates are relative to
    /// `src_window`.
    ///
    /// If `dst_window` is not `XCB_NONE` (TODO), the pointer will be moved to the
    /// offsets (`dst_x`, `dst_y`) relative to `dst_window`. If `dst_window` is
    /// `XCB_NONE` (TODO), the pointer will be moved by the offsets (`dst_x`, `dst_y`)
    /// relative to the current position of the pointer.
    pub fn xcb_warp_pointer (c:          *mut xcb_connection_t,
                             src_window: xcb_window_t,
                             dst_window: xcb_window_t,
                             src_x:      i16,
                             src_y:      i16,
                             src_width:  u16,
                             src_height: u16,
                             dst_x:      i16,
                             dst_y:      i16)
            -> xcb_void_cookie_t;

    /// move mouse pointer
    ///
    /// Moves the mouse pointer to the specified position.
    ///
    /// If `src_window` is not `XCB_NONE` (TODO), the move will only take place if the
    /// pointer is inside `src_window` and within the rectangle specified by (`src_x`,
    /// `src_y`, `src_width`, `src_height`). The rectangle coordinates are relative to
    /// `src_window`.
    ///
    /// If `dst_window` is not `XCB_NONE` (TODO), the pointer will be moved to the
    /// offsets (`dst_x`, `dst_y`) relative to `dst_window`. If `dst_window` is
    /// `XCB_NONE` (TODO), the pointer will be moved by the offsets (`dst_x`, `dst_y`)
    /// relative to the current position of the pointer.
    pub fn xcb_warp_pointer_checked (c:          *mut xcb_connection_t,
                                     src_window: xcb_window_t,
                                     dst_window: xcb_window_t,
                                     src_x:      i16,
                                     src_y:      i16,
                                     src_width:  u16,
                                     src_height: u16,
                                     dst_x:      i16,
                                     dst_y:      i16)
            -> xcb_void_cookie_t;

    /// Sets input focus
    ///
    /// Changes the input focus and the last-focus-change time. If the specified `time`
    /// is earlier than the current last-focus-change time, the request is ignored (to
    /// avoid race conditions when running X over the network).
    ///
    /// A FocusIn and FocusOut event is generated when focus is changed.
    pub fn xcb_set_input_focus (c:         *mut xcb_connection_t,
                                revert_to: u8,
                                focus:     xcb_window_t,
                                time:      xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// Sets input focus
    ///
    /// Changes the input focus and the last-focus-change time. If the specified `time`
    /// is earlier than the current last-focus-change time, the request is ignored (to
    /// avoid race conditions when running X over the network).
    ///
    /// A FocusIn and FocusOut event is generated when focus is changed.
    pub fn xcb_set_input_focus_checked (c:         *mut xcb_connection_t,
                                        revert_to: u8,
                                        focus:     xcb_window_t,
                                        time:      xcb_timestamp_t)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_input_focus_reply (c:      *mut xcb_connection_t,
                                      cookie: xcb_get_input_focus_cookie_t,
                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_input_focus_reply_t;

    pub fn xcb_get_input_focus (c: *mut xcb_connection_t)
            -> xcb_get_input_focus_cookie_t;

    pub fn xcb_get_input_focus_unchecked (c: *mut xcb_connection_t)
            -> xcb_get_input_focus_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_query_keymap_reply (c:      *mut xcb_connection_t,
                                   cookie: xcb_query_keymap_cookie_t,
                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_query_keymap_reply_t;

    pub fn xcb_query_keymap (c: *mut xcb_connection_t)
            -> xcb_query_keymap_cookie_t;

    pub fn xcb_query_keymap_unchecked (c: *mut xcb_connection_t)
            -> xcb_query_keymap_cookie_t;

    /// opens a font
    ///
    /// Opens any X core font matching the given `name` (for example "-misc-fixed-*").
    ///
    /// Note that X core fonts are deprecated (but still supported) in favor of
    /// client-side rendering using Xft.
    pub fn xcb_open_font (c:        *mut xcb_connection_t,
                          fid:      xcb_font_t,
                          name_len: u16,
                          name:     *const c_char)
            -> xcb_void_cookie_t;

    /// opens a font
    ///
    /// Opens any X core font matching the given `name` (for example "-misc-fixed-*").
    ///
    /// Note that X core fonts are deprecated (but still supported) in favor of
    /// client-side rendering using Xft.
    pub fn xcb_open_font_checked (c:        *mut xcb_connection_t,
                                  fid:      xcb_font_t,
                                  name_len: u16,
                                  name:     *const c_char)
            -> xcb_void_cookie_t;

    pub fn xcb_close_font (c:    *mut xcb_connection_t,
                           font: xcb_font_t)
            -> xcb_void_cookie_t;

    pub fn xcb_close_font_checked (c:    *mut xcb_connection_t,
                                   font: xcb_font_t)
            -> xcb_void_cookie_t;

    pub fn xcb_fontprop_next (i: *mut xcb_fontprop_iterator_t);

    pub fn xcb_fontprop_end (i: *mut xcb_fontprop_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_charinfo_next (i: *mut xcb_charinfo_iterator_t);

    pub fn xcb_charinfo_end (i: *mut xcb_charinfo_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_query_font_properties (R: *const xcb_query_font_reply_t)
            -> *mut xcb_fontprop_t;

    pub fn xcb_query_font_properties_length (R: *const xcb_query_font_reply_t)
            -> c_int;

    pub fn xcb_query_font_properties_iterator (R: *const xcb_query_font_reply_t)
            -> xcb_fontprop_iterator_t;

    pub fn xcb_query_font_char_infos (R: *const xcb_query_font_reply_t)
            -> *mut xcb_charinfo_t;

    pub fn xcb_query_font_char_infos_length (R: *const xcb_query_font_reply_t)
            -> c_int;

    pub fn xcb_query_font_char_infos_iterator (R: *const xcb_query_font_reply_t)
            -> xcb_charinfo_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_query_font_reply (c:      *mut xcb_connection_t,
                                 cookie: xcb_query_font_cookie_t,
                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_query_font_reply_t;

    /// query font metrics
    ///
    /// Queries information associated with the font.
    pub fn xcb_query_font (c:    *mut xcb_connection_t,
                           font: xcb_fontable_t)
            -> xcb_query_font_cookie_t;

    /// query font metrics
    ///
    /// Queries information associated with the font.
    pub fn xcb_query_font_unchecked (c:    *mut xcb_connection_t,
                                     font: xcb_fontable_t)
            -> xcb_query_font_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_query_text_extents_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_query_text_extents_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_query_text_extents_reply_t;

    /// get text extents
    ///
    /// Query text extents from the X11 server. This request returns the bounding box
    /// of the specified 16-bit character string in the specified `font` or the font
    /// contained in the specified graphics context.
    ///
    /// `font_ascent` is set to the maximum of the ascent metrics of all characters in
    /// the string. `font_descent` is set to the maximum of the descent metrics.
    /// `overall_width` is set to the sum of the character-width metrics of all
    /// characters in the string. For each character in the string, let W be the sum of
    /// the character-width metrics of all characters preceding it in the string. Let L
    /// be the left-side-bearing metric of the character plus W. Let R be the
    /// right-side-bearing metric of the character plus W. The lbearing member is set
    /// to the minimum L of all characters in the string. The rbearing member is set to
    /// the maximum R.
    ///
    /// For fonts defined with linear indexing rather than 2-byte matrix indexing, each
    /// `xcb_char2b_t` structure is interpreted as a 16-bit number with byte1 as the
    /// most significant byte. If the font has no defined default character, undefined
    /// characters in the string are taken to have all zero metrics.
    ///
    /// Characters with all zero metrics are ignored. If the font has no defined
    /// default_char, the undefined characters in the string are also ignored.
    pub fn xcb_query_text_extents (c:          *mut xcb_connection_t,
                                   font:       xcb_fontable_t,
                                   string_len: u32,
                                   string:     *const xcb_char2b_t)
            -> xcb_query_text_extents_cookie_t;

    /// get text extents
    ///
    /// Query text extents from the X11 server. This request returns the bounding box
    /// of the specified 16-bit character string in the specified `font` or the font
    /// contained in the specified graphics context.
    ///
    /// `font_ascent` is set to the maximum of the ascent metrics of all characters in
    /// the string. `font_descent` is set to the maximum of the descent metrics.
    /// `overall_width` is set to the sum of the character-width metrics of all
    /// characters in the string. For each character in the string, let W be the sum of
    /// the character-width metrics of all characters preceding it in the string. Let L
    /// be the left-side-bearing metric of the character plus W. Let R be the
    /// right-side-bearing metric of the character plus W. The lbearing member is set
    /// to the minimum L of all characters in the string. The rbearing member is set to
    /// the maximum R.
    ///
    /// For fonts defined with linear indexing rather than 2-byte matrix indexing, each
    /// `xcb_char2b_t` structure is interpreted as a 16-bit number with byte1 as the
    /// most significant byte. If the font has no defined default character, undefined
    /// characters in the string are taken to have all zero metrics.
    ///
    /// Characters with all zero metrics are ignored. If the font has no defined
    /// default_char, the undefined characters in the string are also ignored.
    pub fn xcb_query_text_extents_unchecked (c:          *mut xcb_connection_t,
                                             font:       xcb_fontable_t,
                                             string_len: u32,
                                             string:     *const xcb_char2b_t)
            -> xcb_query_text_extents_cookie_t;

    pub fn xcb_str_name (R: *const xcb_str_t)
            -> *mut c_char;

    pub fn xcb_str_name_length (R: *const xcb_str_t)
            -> c_int;

    pub fn xcb_str_name_end (R: *const xcb_str_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_str_next (i: *mut xcb_str_iterator_t);

    pub fn xcb_str_end (i: *mut xcb_str_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_list_fonts_names_length (R: *const xcb_list_fonts_reply_t)
            -> c_int;

    pub fn xcb_list_fonts_names_iterator<'a> (R: *const xcb_list_fonts_reply_t)
            -> xcb_str_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_list_fonts_reply (c:      *mut xcb_connection_t,
                                 cookie: xcb_list_fonts_cookie_t,
                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_list_fonts_reply_t;

    /// get matching font names
    ///
    /// Gets a list of available font names which match the given `pattern`.
    pub fn xcb_list_fonts (c:           *mut xcb_connection_t,
                           max_names:   u16,
                           pattern_len: u16,
                           pattern:     *const c_char)
            -> xcb_list_fonts_cookie_t;

    /// get matching font names
    ///
    /// Gets a list of available font names which match the given `pattern`.
    pub fn xcb_list_fonts_unchecked (c:           *mut xcb_connection_t,
                                     max_names:   u16,
                                     pattern_len: u16,
                                     pattern:     *const c_char)
            -> xcb_list_fonts_cookie_t;

    pub fn xcb_list_fonts_with_info_properties (R: *const xcb_list_fonts_with_info_reply_t)
            -> *mut xcb_fontprop_t;

    pub fn xcb_list_fonts_with_info_properties_length (R: *const xcb_list_fonts_with_info_reply_t)
            -> c_int;

    pub fn xcb_list_fonts_with_info_properties_iterator (R: *const xcb_list_fonts_with_info_reply_t)
            -> xcb_fontprop_iterator_t;

    pub fn xcb_list_fonts_with_info_name (R: *const xcb_list_fonts_with_info_reply_t)
            -> *mut c_char;

    pub fn xcb_list_fonts_with_info_name_length (R: *const xcb_list_fonts_with_info_reply_t)
            -> c_int;

    pub fn xcb_list_fonts_with_info_name_end (R: *const xcb_list_fonts_with_info_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_list_fonts_with_info_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_list_fonts_with_info_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_list_fonts_with_info_reply_t;

    /// get matching font names and information
    ///
    /// Gets a list of available font names which match the given `pattern`.
    pub fn xcb_list_fonts_with_info (c:           *mut xcb_connection_t,
                                     max_names:   u16,
                                     pattern_len: u16,
                                     pattern:     *const c_char)
            -> xcb_list_fonts_with_info_cookie_t;

    /// get matching font names and information
    ///
    /// Gets a list of available font names which match the given `pattern`.
    pub fn xcb_list_fonts_with_info_unchecked (c:           *mut xcb_connection_t,
                                               max_names:   u16,
                                               pattern_len: u16,
                                               pattern:     *const c_char)
            -> xcb_list_fonts_with_info_cookie_t;

    pub fn xcb_set_font_path (c:        *mut xcb_connection_t,
                              font_qty: u16,
                              font:     *const xcb_str_t)
            -> xcb_void_cookie_t;

    pub fn xcb_set_font_path_checked (c:        *mut xcb_connection_t,
                                      font_qty: u16,
                                      font:     *const xcb_str_t)
            -> xcb_void_cookie_t;

    pub fn xcb_get_font_path_path_length (R: *const xcb_get_font_path_reply_t)
            -> c_int;

    pub fn xcb_get_font_path_path_iterator<'a> (R: *const xcb_get_font_path_reply_t)
            -> xcb_str_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_font_path_reply (c:      *mut xcb_connection_t,
                                    cookie: xcb_get_font_path_cookie_t,
                                    error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_font_path_reply_t;

    pub fn xcb_get_font_path (c: *mut xcb_connection_t)
            -> xcb_get_font_path_cookie_t;

    pub fn xcb_get_font_path_unchecked (c: *mut xcb_connection_t)
            -> xcb_get_font_path_cookie_t;

    /// Creates a pixmap
    ///
    /// Creates a pixmap. The pixmap can only be used on the same screen as `drawable`
    /// is on and only with drawables of the same `depth`.
    pub fn xcb_create_pixmap (c:        *mut xcb_connection_t,
                              depth:    u8,
                              pid:      xcb_pixmap_t,
                              drawable: xcb_drawable_t,
                              width:    u16,
                              height:   u16)
            -> xcb_void_cookie_t;

    /// Creates a pixmap
    ///
    /// Creates a pixmap. The pixmap can only be used on the same screen as `drawable`
    /// is on and only with drawables of the same `depth`.
    pub fn xcb_create_pixmap_checked (c:        *mut xcb_connection_t,
                                      depth:    u8,
                                      pid:      xcb_pixmap_t,
                                      drawable: xcb_drawable_t,
                                      width:    u16,
                                      height:   u16)
            -> xcb_void_cookie_t;

    /// Destroys a pixmap
    ///
    /// Deletes the association between the pixmap ID and the pixmap. The pixmap
    /// storage will be freed when there are no more references to it.
    pub fn xcb_free_pixmap (c:      *mut xcb_connection_t,
                            pixmap: xcb_pixmap_t)
            -> xcb_void_cookie_t;

    /// Destroys a pixmap
    ///
    /// Deletes the association between the pixmap ID and the pixmap. The pixmap
    /// storage will be freed when there are no more references to it.
    pub fn xcb_free_pixmap_checked (c:      *mut xcb_connection_t,
                                    pixmap: xcb_pixmap_t)
            -> xcb_void_cookie_t;

    /// Creates a graphics context
    ///
    /// Creates a graphics context. The graphics context can be used with any drawable
    /// that has the same root and depth as the specified drawable.
    pub fn xcb_create_gc (c:          *mut xcb_connection_t,
                          cid:        xcb_gcontext_t,
                          drawable:   xcb_drawable_t,
                          value_mask: u32,
                          value_list: *const u32)
            -> xcb_void_cookie_t;

    /// Creates a graphics context
    ///
    /// Creates a graphics context. The graphics context can be used with any drawable
    /// that has the same root and depth as the specified drawable.
    pub fn xcb_create_gc_checked (c:          *mut xcb_connection_t,
                                  cid:        xcb_gcontext_t,
                                  drawable:   xcb_drawable_t,
                                  value_mask: u32,
                                  value_list: *const u32)
            -> xcb_void_cookie_t;

    /// change graphics context components
    ///
    /// Changes the components specified by `value_mask` for the specified graphics context.
    pub fn xcb_change_gc (c:          *mut xcb_connection_t,
                          gc:         xcb_gcontext_t,
                          value_mask: u32,
                          value_list: *const u32)
            -> xcb_void_cookie_t;

    /// change graphics context components
    ///
    /// Changes the components specified by `value_mask` for the specified graphics context.
    pub fn xcb_change_gc_checked (c:          *mut xcb_connection_t,
                                  gc:         xcb_gcontext_t,
                                  value_mask: u32,
                                  value_list: *const u32)
            -> xcb_void_cookie_t;

    pub fn xcb_copy_gc (c:          *mut xcb_connection_t,
                        src_gc:     xcb_gcontext_t,
                        dst_gc:     xcb_gcontext_t,
                        value_mask: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_copy_gc_checked (c:          *mut xcb_connection_t,
                                src_gc:     xcb_gcontext_t,
                                dst_gc:     xcb_gcontext_t,
                                value_mask: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_set_dashes (c:           *mut xcb_connection_t,
                           gc:          xcb_gcontext_t,
                           dash_offset: u16,
                           dashes_len:  u16,
                           dashes:      *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_set_dashes_checked (c:           *mut xcb_connection_t,
                                   gc:          xcb_gcontext_t,
                                   dash_offset: u16,
                                   dashes_len:  u16,
                                   dashes:      *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_set_clip_rectangles (c:              *mut xcb_connection_t,
                                    ordering:       u8,
                                    gc:             xcb_gcontext_t,
                                    clip_x_origin:  i16,
                                    clip_y_origin:  i16,
                                    rectangles_len: u32,
                                    rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    pub fn xcb_set_clip_rectangles_checked (c:              *mut xcb_connection_t,
                                            ordering:       u8,
                                            gc:             xcb_gcontext_t,
                                            clip_x_origin:  i16,
                                            clip_y_origin:  i16,
                                            rectangles_len: u32,
                                            rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    /// Destroys a graphics context
    ///
    /// Destroys the specified `gc` and all associated storage.
    pub fn xcb_free_gc (c:  *mut xcb_connection_t,
                        gc: xcb_gcontext_t)
            -> xcb_void_cookie_t;

    /// Destroys a graphics context
    ///
    /// Destroys the specified `gc` and all associated storage.
    pub fn xcb_free_gc_checked (c:  *mut xcb_connection_t,
                                gc: xcb_gcontext_t)
            -> xcb_void_cookie_t;

    pub fn xcb_clear_area (c:         *mut xcb_connection_t,
                           exposures: u8,
                           window:    xcb_window_t,
                           x:         i16,
                           y:         i16,
                           width:     u16,
                           height:    u16)
            -> xcb_void_cookie_t;

    pub fn xcb_clear_area_checked (c:         *mut xcb_connection_t,
                                   exposures: u8,
                                   window:    xcb_window_t,
                                   x:         i16,
                                   y:         i16,
                                   width:     u16,
                                   height:    u16)
            -> xcb_void_cookie_t;

    /// copy areas
    ///
    /// Copies the specified rectangle from `src_drawable` to `dst_drawable`.
    pub fn xcb_copy_area (c:            *mut xcb_connection_t,
                          src_drawable: xcb_drawable_t,
                          dst_drawable: xcb_drawable_t,
                          gc:           xcb_gcontext_t,
                          src_x:        i16,
                          src_y:        i16,
                          dst_x:        i16,
                          dst_y:        i16,
                          width:        u16,
                          height:       u16)
            -> xcb_void_cookie_t;

    /// copy areas
    ///
    /// Copies the specified rectangle from `src_drawable` to `dst_drawable`.
    pub fn xcb_copy_area_checked (c:            *mut xcb_connection_t,
                                  src_drawable: xcb_drawable_t,
                                  dst_drawable: xcb_drawable_t,
                                  gc:           xcb_gcontext_t,
                                  src_x:        i16,
                                  src_y:        i16,
                                  dst_x:        i16,
                                  dst_y:        i16,
                                  width:        u16,
                                  height:       u16)
            -> xcb_void_cookie_t;

    pub fn xcb_copy_plane (c:            *mut xcb_connection_t,
                           src_drawable: xcb_drawable_t,
                           dst_drawable: xcb_drawable_t,
                           gc:           xcb_gcontext_t,
                           src_x:        i16,
                           src_y:        i16,
                           dst_x:        i16,
                           dst_y:        i16,
                           width:        u16,
                           height:       u16,
                           bit_plane:    u32)
            -> xcb_void_cookie_t;

    pub fn xcb_copy_plane_checked (c:            *mut xcb_connection_t,
                                   src_drawable: xcb_drawable_t,
                                   dst_drawable: xcb_drawable_t,
                                   gc:           xcb_gcontext_t,
                                   src_x:        i16,
                                   src_y:        i16,
                                   dst_x:        i16,
                                   dst_y:        i16,
                                   width:        u16,
                                   height:       u16,
                                   bit_plane:    u32)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_point (c:               *mut xcb_connection_t,
                           coordinate_mode: u8,
                           drawable:        xcb_drawable_t,
                           gc:              xcb_gcontext_t,
                           points_len:      u32,
                           points:          *const xcb_point_t)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_point_checked (c:               *mut xcb_connection_t,
                                   coordinate_mode: u8,
                                   drawable:        xcb_drawable_t,
                                   gc:              xcb_gcontext_t,
                                   points_len:      u32,
                                   points:          *const xcb_point_t)
            -> xcb_void_cookie_t;

    /// draw lines
    ///
    /// Draws `points_len`-1 lines between each pair of points (point[i], point[i+1])
    /// in the `points` array. The lines are drawn in the order listed in the array.
    /// They join correctly at all intermediate points, and if the first and last
    /// points coincide, the first and last lines also join correctly. For any given
    /// line, a pixel is not drawn more than once. If thin (zero line-width) lines
    /// intersect, the intersecting pixels are drawn multiple times. If wide lines
    /// intersect, the intersecting pixels are drawn only once, as though the entire
    /// request were a single, filled shape.
    pub fn xcb_poly_line (c:               *mut xcb_connection_t,
                          coordinate_mode: u8,
                          drawable:        xcb_drawable_t,
                          gc:              xcb_gcontext_t,
                          points_len:      u32,
                          points:          *const xcb_point_t)
            -> xcb_void_cookie_t;

    /// draw lines
    ///
    /// Draws `points_len`-1 lines between each pair of points (point[i], point[i+1])
    /// in the `points` array. The lines are drawn in the order listed in the array.
    /// They join correctly at all intermediate points, and if the first and last
    /// points coincide, the first and last lines also join correctly. For any given
    /// line, a pixel is not drawn more than once. If thin (zero line-width) lines
    /// intersect, the intersecting pixels are drawn multiple times. If wide lines
    /// intersect, the intersecting pixels are drawn only once, as though the entire
    /// request were a single, filled shape.
    pub fn xcb_poly_line_checked (c:               *mut xcb_connection_t,
                                  coordinate_mode: u8,
                                  drawable:        xcb_drawable_t,
                                  gc:              xcb_gcontext_t,
                                  points_len:      u32,
                                  points:          *const xcb_point_t)
            -> xcb_void_cookie_t;

    pub fn xcb_segment_next (i: *mut xcb_segment_iterator_t);

    pub fn xcb_segment_end (i: *mut xcb_segment_iterator_t)
            -> xcb_generic_iterator_t;

    /// draw lines
    ///
    /// Draws multiple, unconnected lines. For each segment, a line is drawn between
    /// (x1, y1) and (x2, y2). The lines are drawn in the order listed in the array of
    /// `xcb_segment_t` structures and does not perform joining at coincident
    /// endpoints. For any given line, a pixel is not drawn more than once. If lines
    /// intersect, the intersecting pixels are drawn multiple times.
    ///
    /// TODO: include the xcb_segment_t data structure
    ///
    /// TODO: an example
    pub fn xcb_poly_segment (c:            *mut xcb_connection_t,
                             drawable:     xcb_drawable_t,
                             gc:           xcb_gcontext_t,
                             segments_len: u32,
                             segments:     *const xcb_segment_t)
            -> xcb_void_cookie_t;

    /// draw lines
    ///
    /// Draws multiple, unconnected lines. For each segment, a line is drawn between
    /// (x1, y1) and (x2, y2). The lines are drawn in the order listed in the array of
    /// `xcb_segment_t` structures and does not perform joining at coincident
    /// endpoints. For any given line, a pixel is not drawn more than once. If lines
    /// intersect, the intersecting pixels are drawn multiple times.
    ///
    /// TODO: include the xcb_segment_t data structure
    ///
    /// TODO: an example
    pub fn xcb_poly_segment_checked (c:            *mut xcb_connection_t,
                                     drawable:     xcb_drawable_t,
                                     gc:           xcb_gcontext_t,
                                     segments_len: u32,
                                     segments:     *const xcb_segment_t)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_rectangle (c:              *mut xcb_connection_t,
                               drawable:       xcb_drawable_t,
                               gc:             xcb_gcontext_t,
                               rectangles_len: u32,
                               rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_rectangle_checked (c:              *mut xcb_connection_t,
                                       drawable:       xcb_drawable_t,
                                       gc:             xcb_gcontext_t,
                                       rectangles_len: u32,
                                       rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_arc (c:        *mut xcb_connection_t,
                         drawable: xcb_drawable_t,
                         gc:       xcb_gcontext_t,
                         arcs_len: u32,
                         arcs:     *const xcb_arc_t)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_arc_checked (c:        *mut xcb_connection_t,
                                 drawable: xcb_drawable_t,
                                 gc:       xcb_gcontext_t,
                                 arcs_len: u32,
                                 arcs:     *const xcb_arc_t)
            -> xcb_void_cookie_t;

    pub fn xcb_fill_poly (c:               *mut xcb_connection_t,
                          drawable:        xcb_drawable_t,
                          gc:              xcb_gcontext_t,
                          shape:           u8,
                          coordinate_mode: u8,
                          points_len:      u32,
                          points:          *const xcb_point_t)
            -> xcb_void_cookie_t;

    pub fn xcb_fill_poly_checked (c:               *mut xcb_connection_t,
                                  drawable:        xcb_drawable_t,
                                  gc:              xcb_gcontext_t,
                                  shape:           u8,
                                  coordinate_mode: u8,
                                  points_len:      u32,
                                  points:          *const xcb_point_t)
            -> xcb_void_cookie_t;

    /// Fills rectangles
    ///
    /// Fills the specified rectangle(s) in the order listed in the array. For any
    /// given rectangle, each pixel is not drawn more than once. If rectangles
    /// intersect, the intersecting pixels are drawn multiple times.
    pub fn xcb_poly_fill_rectangle (c:              *mut xcb_connection_t,
                                    drawable:       xcb_drawable_t,
                                    gc:             xcb_gcontext_t,
                                    rectangles_len: u32,
                                    rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    /// Fills rectangles
    ///
    /// Fills the specified rectangle(s) in the order listed in the array. For any
    /// given rectangle, each pixel is not drawn more than once. If rectangles
    /// intersect, the intersecting pixels are drawn multiple times.
    pub fn xcb_poly_fill_rectangle_checked (c:              *mut xcb_connection_t,
                                            drawable:       xcb_drawable_t,
                                            gc:             xcb_gcontext_t,
                                            rectangles_len: u32,
                                            rectangles:     *const xcb_rectangle_t)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_fill_arc (c:        *mut xcb_connection_t,
                              drawable: xcb_drawable_t,
                              gc:       xcb_gcontext_t,
                              arcs_len: u32,
                              arcs:     *const xcb_arc_t)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_fill_arc_checked (c:        *mut xcb_connection_t,
                                      drawable: xcb_drawable_t,
                                      gc:       xcb_gcontext_t,
                                      arcs_len: u32,
                                      arcs:     *const xcb_arc_t)
            -> xcb_void_cookie_t;

    pub fn xcb_put_image (c:        *mut xcb_connection_t,
                          format:   u8,
                          drawable: xcb_drawable_t,
                          gc:       xcb_gcontext_t,
                          width:    u16,
                          height:   u16,
                          dst_x:    i16,
                          dst_y:    i16,
                          left_pad: u8,
                          depth:    u8,
                          data_len: u32,
                          data:     *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_put_image_checked (c:        *mut xcb_connection_t,
                                  format:   u8,
                                  drawable: xcb_drawable_t,
                                  gc:       xcb_gcontext_t,
                                  width:    u16,
                                  height:   u16,
                                  dst_x:    i16,
                                  dst_y:    i16,
                                  left_pad: u8,
                                  depth:    u8,
                                  data_len: u32,
                                  data:     *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_get_image_data (R: *const xcb_get_image_reply_t)
            -> *mut u8;

    pub fn xcb_get_image_data_length (R: *const xcb_get_image_reply_t)
            -> c_int;

    pub fn xcb_get_image_data_end (R: *const xcb_get_image_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_image_reply (c:      *mut xcb_connection_t,
                                cookie: xcb_get_image_cookie_t,
                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_image_reply_t;

    pub fn xcb_get_image (c:          *mut xcb_connection_t,
                          format:     u8,
                          drawable:   xcb_drawable_t,
                          x:          i16,
                          y:          i16,
                          width:      u16,
                          height:     u16,
                          plane_mask: u32)
            -> xcb_get_image_cookie_t;

    pub fn xcb_get_image_unchecked (c:          *mut xcb_connection_t,
                                    format:     u8,
                                    drawable:   xcb_drawable_t,
                                    x:          i16,
                                    y:          i16,
                                    width:      u16,
                                    height:     u16,
                                    plane_mask: u32)
            -> xcb_get_image_cookie_t;

    pub fn xcb_poly_text_8 (c:         *mut xcb_connection_t,
                            drawable:  xcb_drawable_t,
                            gc:        xcb_gcontext_t,
                            x:         i16,
                            y:         i16,
                            items_len: u32,
                            items:     *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_text_8_checked (c:         *mut xcb_connection_t,
                                    drawable:  xcb_drawable_t,
                                    gc:        xcb_gcontext_t,
                                    x:         i16,
                                    y:         i16,
                                    items_len: u32,
                                    items:     *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_text_16 (c:         *mut xcb_connection_t,
                             drawable:  xcb_drawable_t,
                             gc:        xcb_gcontext_t,
                             x:         i16,
                             y:         i16,
                             items_len: u32,
                             items:     *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_poly_text_16_checked (c:         *mut xcb_connection_t,
                                     drawable:  xcb_drawable_t,
                                     gc:        xcb_gcontext_t,
                                     x:         i16,
                                     y:         i16,
                                     items_len: u32,
                                     items:     *const u8)
            -> xcb_void_cookie_t;

    /// Draws text
    ///
    /// Fills the destination rectangle with the background pixel from `gc`, then
    /// paints the text with the foreground pixel from `gc`. The upper-left corner of
    /// the filled rectangle is at [x, y - font-ascent]. The width is overall-width,
    /// the height is font-ascent + font-descent. The overall-width, font-ascent and
    /// font-descent are as returned by `xcb_query_text_extents` (TODO).
    ///
    /// Note that using X core fonts is deprecated (but still supported) in favor of
    /// client-side rendering using Xft.
    pub fn xcb_image_text_8 (c:          *mut xcb_connection_t,
                             string_len: u8,
                             drawable:   xcb_drawable_t,
                             gc:         xcb_gcontext_t,
                             x:          i16,
                             y:          i16,
                             string:     *const c_char)
            -> xcb_void_cookie_t;

    /// Draws text
    ///
    /// Fills the destination rectangle with the background pixel from `gc`, then
    /// paints the text with the foreground pixel from `gc`. The upper-left corner of
    /// the filled rectangle is at [x, y - font-ascent]. The width is overall-width,
    /// the height is font-ascent + font-descent. The overall-width, font-ascent and
    /// font-descent are as returned by `xcb_query_text_extents` (TODO).
    ///
    /// Note that using X core fonts is deprecated (but still supported) in favor of
    /// client-side rendering using Xft.
    pub fn xcb_image_text_8_checked (c:          *mut xcb_connection_t,
                                     string_len: u8,
                                     drawable:   xcb_drawable_t,
                                     gc:         xcb_gcontext_t,
                                     x:          i16,
                                     y:          i16,
                                     string:     *const c_char)
            -> xcb_void_cookie_t;

    /// Draws text
    ///
    /// Fills the destination rectangle with the background pixel from `gc`, then
    /// paints the text with the foreground pixel from `gc`. The upper-left corner of
    /// the filled rectangle is at [x, y - font-ascent]. The width is overall-width,
    /// the height is font-ascent + font-descent. The overall-width, font-ascent and
    /// font-descent are as returned by `xcb_query_text_extents` (TODO).
    ///
    /// Note that using X core fonts is deprecated (but still supported) in favor of
    /// client-side rendering using Xft.
    pub fn xcb_image_text_16 (c:          *mut xcb_connection_t,
                              string_len: u8,
                              drawable:   xcb_drawable_t,
                              gc:         xcb_gcontext_t,
                              x:          i16,
                              y:          i16,
                              string:     *const xcb_char2b_t)
            -> xcb_void_cookie_t;

    /// Draws text
    ///
    /// Fills the destination rectangle with the background pixel from `gc`, then
    /// paints the text with the foreground pixel from `gc`. The upper-left corner of
    /// the filled rectangle is at [x, y - font-ascent]. The width is overall-width,
    /// the height is font-ascent + font-descent. The overall-width, font-ascent and
    /// font-descent are as returned by `xcb_query_text_extents` (TODO).
    ///
    /// Note that using X core fonts is deprecated (but still supported) in favor of
    /// client-side rendering using Xft.
    pub fn xcb_image_text_16_checked (c:          *mut xcb_connection_t,
                                      string_len: u8,
                                      drawable:   xcb_drawable_t,
                                      gc:         xcb_gcontext_t,
                                      x:          i16,
                                      y:          i16,
                                      string:     *const xcb_char2b_t)
            -> xcb_void_cookie_t;

    pub fn xcb_create_colormap (c:      *mut xcb_connection_t,
                                alloc:  u8,
                                mid:    xcb_colormap_t,
                                window: xcb_window_t,
                                visual: xcb_visualid_t)
            -> xcb_void_cookie_t;

    pub fn xcb_create_colormap_checked (c:      *mut xcb_connection_t,
                                        alloc:  u8,
                                        mid:    xcb_colormap_t,
                                        window: xcb_window_t,
                                        visual: xcb_visualid_t)
            -> xcb_void_cookie_t;

    pub fn xcb_free_colormap (c:    *mut xcb_connection_t,
                              cmap: xcb_colormap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_free_colormap_checked (c:    *mut xcb_connection_t,
                                      cmap: xcb_colormap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_copy_colormap_and_free (c:        *mut xcb_connection_t,
                                       mid:      xcb_colormap_t,
                                       src_cmap: xcb_colormap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_copy_colormap_and_free_checked (c:        *mut xcb_connection_t,
                                               mid:      xcb_colormap_t,
                                               src_cmap: xcb_colormap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_install_colormap (c:    *mut xcb_connection_t,
                                 cmap: xcb_colormap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_install_colormap_checked (c:    *mut xcb_connection_t,
                                         cmap: xcb_colormap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_uninstall_colormap (c:    *mut xcb_connection_t,
                                   cmap: xcb_colormap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_uninstall_colormap_checked (c:    *mut xcb_connection_t,
                                           cmap: xcb_colormap_t)
            -> xcb_void_cookie_t;

    pub fn xcb_list_installed_colormaps_cmaps (R: *const xcb_list_installed_colormaps_reply_t)
            -> *mut xcb_colormap_t;

    pub fn xcb_list_installed_colormaps_cmaps_length (R: *const xcb_list_installed_colormaps_reply_t)
            -> c_int;

    pub fn xcb_list_installed_colormaps_cmaps_end (R: *const xcb_list_installed_colormaps_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_list_installed_colormaps_reply (c:      *mut xcb_connection_t,
                                               cookie: xcb_list_installed_colormaps_cookie_t,
                                               error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_list_installed_colormaps_reply_t;

    pub fn xcb_list_installed_colormaps (c:      *mut xcb_connection_t,
                                         window: xcb_window_t)
            -> xcb_list_installed_colormaps_cookie_t;

    pub fn xcb_list_installed_colormaps_unchecked (c:      *mut xcb_connection_t,
                                                   window: xcb_window_t)
            -> xcb_list_installed_colormaps_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_alloc_color_reply (c:      *mut xcb_connection_t,
                                  cookie: xcb_alloc_color_cookie_t,
                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_alloc_color_reply_t;

    /// Allocate a color
    ///
    /// Allocates a read-only colormap entry corresponding to the closest RGB value
    /// supported by the hardware. If you are using TrueColor, you can take a shortcut
    /// and directly calculate the color pixel value to avoid the round trip. But, for
    /// example, on 16-bit color setups (VNC), you can easily get the closest supported
    /// RGB value to the RGB value you are specifying.
    pub fn xcb_alloc_color (c:     *mut xcb_connection_t,
                            cmap:  xcb_colormap_t,
                            red:   u16,
                            green: u16,
                            blue:  u16)
            -> xcb_alloc_color_cookie_t;

    /// Allocate a color
    ///
    /// Allocates a read-only colormap entry corresponding to the closest RGB value
    /// supported by the hardware. If you are using TrueColor, you can take a shortcut
    /// and directly calculate the color pixel value to avoid the round trip. But, for
    /// example, on 16-bit color setups (VNC), you can easily get the closest supported
    /// RGB value to the RGB value you are specifying.
    pub fn xcb_alloc_color_unchecked (c:     *mut xcb_connection_t,
                                      cmap:  xcb_colormap_t,
                                      red:   u16,
                                      green: u16,
                                      blue:  u16)
            -> xcb_alloc_color_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_alloc_named_color_reply (c:      *mut xcb_connection_t,
                                        cookie: xcb_alloc_named_color_cookie_t,
                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_alloc_named_color_reply_t;

    pub fn xcb_alloc_named_color (c:        *mut xcb_connection_t,
                                  cmap:     xcb_colormap_t,
                                  name_len: u16,
                                  name:     *const c_char)
            -> xcb_alloc_named_color_cookie_t;

    pub fn xcb_alloc_named_color_unchecked (c:        *mut xcb_connection_t,
                                            cmap:     xcb_colormap_t,
                                            name_len: u16,
                                            name:     *const c_char)
            -> xcb_alloc_named_color_cookie_t;

    pub fn xcb_alloc_color_cells_pixels (R: *const xcb_alloc_color_cells_reply_t)
            -> *mut u32;

    pub fn xcb_alloc_color_cells_pixels_length (R: *const xcb_alloc_color_cells_reply_t)
            -> c_int;

    pub fn xcb_alloc_color_cells_pixels_end (R: *const xcb_alloc_color_cells_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_alloc_color_cells_masks (R: *const xcb_alloc_color_cells_reply_t)
            -> *mut u32;

    pub fn xcb_alloc_color_cells_masks_length (R: *const xcb_alloc_color_cells_reply_t)
            -> c_int;

    pub fn xcb_alloc_color_cells_masks_end (R: *const xcb_alloc_color_cells_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_alloc_color_cells_reply (c:      *mut xcb_connection_t,
                                        cookie: xcb_alloc_color_cells_cookie_t,
                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_alloc_color_cells_reply_t;

    pub fn xcb_alloc_color_cells (c:          *mut xcb_connection_t,
                                  contiguous: u8,
                                  cmap:       xcb_colormap_t,
                                  colors:     u16,
                                  planes:     u16)
            -> xcb_alloc_color_cells_cookie_t;

    pub fn xcb_alloc_color_cells_unchecked (c:          *mut xcb_connection_t,
                                            contiguous: u8,
                                            cmap:       xcb_colormap_t,
                                            colors:     u16,
                                            planes:     u16)
            -> xcb_alloc_color_cells_cookie_t;

    pub fn xcb_alloc_color_planes_pixels (R: *const xcb_alloc_color_planes_reply_t)
            -> *mut u32;

    pub fn xcb_alloc_color_planes_pixels_length (R: *const xcb_alloc_color_planes_reply_t)
            -> c_int;

    pub fn xcb_alloc_color_planes_pixels_end (R: *const xcb_alloc_color_planes_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_alloc_color_planes_reply (c:      *mut xcb_connection_t,
                                         cookie: xcb_alloc_color_planes_cookie_t,
                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_alloc_color_planes_reply_t;

    pub fn xcb_alloc_color_planes (c:          *mut xcb_connection_t,
                                   contiguous: u8,
                                   cmap:       xcb_colormap_t,
                                   colors:     u16,
                                   reds:       u16,
                                   greens:     u16,
                                   blues:      u16)
            -> xcb_alloc_color_planes_cookie_t;

    pub fn xcb_alloc_color_planes_unchecked (c:          *mut xcb_connection_t,
                                             contiguous: u8,
                                             cmap:       xcb_colormap_t,
                                             colors:     u16,
                                             reds:       u16,
                                             greens:     u16,
                                             blues:      u16)
            -> xcb_alloc_color_planes_cookie_t;

    pub fn xcb_free_colors (c:          *mut xcb_connection_t,
                            cmap:       xcb_colormap_t,
                            plane_mask: u32,
                            pixels_len: u32,
                            pixels:     *const u32)
            -> xcb_void_cookie_t;

    pub fn xcb_free_colors_checked (c:          *mut xcb_connection_t,
                                    cmap:       xcb_colormap_t,
                                    plane_mask: u32,
                                    pixels_len: u32,
                                    pixels:     *const u32)
            -> xcb_void_cookie_t;

    pub fn xcb_coloritem_next (i: *mut xcb_coloritem_iterator_t);

    pub fn xcb_coloritem_end (i: *mut xcb_coloritem_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_store_colors (c:         *mut xcb_connection_t,
                             cmap:      xcb_colormap_t,
                             items_len: u32,
                             items:     *const xcb_coloritem_t)
            -> xcb_void_cookie_t;

    pub fn xcb_store_colors_checked (c:         *mut xcb_connection_t,
                                     cmap:      xcb_colormap_t,
                                     items_len: u32,
                                     items:     *const xcb_coloritem_t)
            -> xcb_void_cookie_t;

    pub fn xcb_store_named_color (c:        *mut xcb_connection_t,
                                  flags:    u8,
                                  cmap:     xcb_colormap_t,
                                  pixel:    u32,
                                  name_len: u16,
                                  name:     *const c_char)
            -> xcb_void_cookie_t;

    pub fn xcb_store_named_color_checked (c:        *mut xcb_connection_t,
                                          flags:    u8,
                                          cmap:     xcb_colormap_t,
                                          pixel:    u32,
                                          name_len: u16,
                                          name:     *const c_char)
            -> xcb_void_cookie_t;

    pub fn xcb_rgb_next (i: *mut xcb_rgb_iterator_t);

    pub fn xcb_rgb_end (i: *mut xcb_rgb_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_query_colors_colors (R: *const xcb_query_colors_reply_t)
            -> *mut xcb_rgb_t;

    pub fn xcb_query_colors_colors_length (R: *const xcb_query_colors_reply_t)
            -> c_int;

    pub fn xcb_query_colors_colors_iterator (R: *const xcb_query_colors_reply_t)
            -> xcb_rgb_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_query_colors_reply (c:      *mut xcb_connection_t,
                                   cookie: xcb_query_colors_cookie_t,
                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_query_colors_reply_t;

    pub fn xcb_query_colors (c:          *mut xcb_connection_t,
                             cmap:       xcb_colormap_t,
                             pixels_len: u32,
                             pixels:     *const u32)
            -> xcb_query_colors_cookie_t;

    pub fn xcb_query_colors_unchecked (c:          *mut xcb_connection_t,
                                       cmap:       xcb_colormap_t,
                                       pixels_len: u32,
                                       pixels:     *const u32)
            -> xcb_query_colors_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_lookup_color_reply (c:      *mut xcb_connection_t,
                                   cookie: xcb_lookup_color_cookie_t,
                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_lookup_color_reply_t;

    pub fn xcb_lookup_color (c:        *mut xcb_connection_t,
                             cmap:     xcb_colormap_t,
                             name_len: u16,
                             name:     *const c_char)
            -> xcb_lookup_color_cookie_t;

    pub fn xcb_lookup_color_unchecked (c:        *mut xcb_connection_t,
                                       cmap:     xcb_colormap_t,
                                       name_len: u16,
                                       name:     *const c_char)
            -> xcb_lookup_color_cookie_t;

    pub fn xcb_create_cursor (c:          *mut xcb_connection_t,
                              cid:        xcb_cursor_t,
                              source:     xcb_pixmap_t,
                              mask:       xcb_pixmap_t,
                              fore_red:   u16,
                              fore_green: u16,
                              fore_blue:  u16,
                              back_red:   u16,
                              back_green: u16,
                              back_blue:  u16,
                              x:          u16,
                              y:          u16)
            -> xcb_void_cookie_t;

    pub fn xcb_create_cursor_checked (c:          *mut xcb_connection_t,
                                      cid:        xcb_cursor_t,
                                      source:     xcb_pixmap_t,
                                      mask:       xcb_pixmap_t,
                                      fore_red:   u16,
                                      fore_green: u16,
                                      fore_blue:  u16,
                                      back_red:   u16,
                                      back_green: u16,
                                      back_blue:  u16,
                                      x:          u16,
                                      y:          u16)
            -> xcb_void_cookie_t;

    /// create cursor
    ///
    /// Creates a cursor from a font glyph. X provides a set of standard cursor shapes
    /// in a special font named cursor. Applications are encouraged to use this
    /// interface for their cursors because the font can be customized for the
    /// individual display type.
    ///
    /// All pixels which are set to 1 in the source will use the foreground color (as
    /// specified by `fore_red`, `fore_green` and `fore_blue`). All pixels set to 0
    /// will use the background color (as specified by `back_red`, `back_green` and
    /// `back_blue`).
    pub fn xcb_create_glyph_cursor (c:           *mut xcb_connection_t,
                                    cid:         xcb_cursor_t,
                                    source_font: xcb_font_t,
                                    mask_font:   xcb_font_t,
                                    source_char: u16,
                                    mask_char:   u16,
                                    fore_red:    u16,
                                    fore_green:  u16,
                                    fore_blue:   u16,
                                    back_red:    u16,
                                    back_green:  u16,
                                    back_blue:   u16)
            -> xcb_void_cookie_t;

    /// create cursor
    ///
    /// Creates a cursor from a font glyph. X provides a set of standard cursor shapes
    /// in a special font named cursor. Applications are encouraged to use this
    /// interface for their cursors because the font can be customized for the
    /// individual display type.
    ///
    /// All pixels which are set to 1 in the source will use the foreground color (as
    /// specified by `fore_red`, `fore_green` and `fore_blue`). All pixels set to 0
    /// will use the background color (as specified by `back_red`, `back_green` and
    /// `back_blue`).
    pub fn xcb_create_glyph_cursor_checked (c:           *mut xcb_connection_t,
                                            cid:         xcb_cursor_t,
                                            source_font: xcb_font_t,
                                            mask_font:   xcb_font_t,
                                            source_char: u16,
                                            mask_char:   u16,
                                            fore_red:    u16,
                                            fore_green:  u16,
                                            fore_blue:   u16,
                                            back_red:    u16,
                                            back_green:  u16,
                                            back_blue:   u16)
            -> xcb_void_cookie_t;

    /// Deletes a cursor
    ///
    /// Deletes the association between the cursor resource ID and the specified
    /// cursor. The cursor is freed when no other resource references it.
    pub fn xcb_free_cursor (c:      *mut xcb_connection_t,
                            cursor: xcb_cursor_t)
            -> xcb_void_cookie_t;

    /// Deletes a cursor
    ///
    /// Deletes the association between the cursor resource ID and the specified
    /// cursor. The cursor is freed when no other resource references it.
    pub fn xcb_free_cursor_checked (c:      *mut xcb_connection_t,
                                    cursor: xcb_cursor_t)
            -> xcb_void_cookie_t;

    pub fn xcb_recolor_cursor (c:          *mut xcb_connection_t,
                               cursor:     xcb_cursor_t,
                               fore_red:   u16,
                               fore_green: u16,
                               fore_blue:  u16,
                               back_red:   u16,
                               back_green: u16,
                               back_blue:  u16)
            -> xcb_void_cookie_t;

    pub fn xcb_recolor_cursor_checked (c:          *mut xcb_connection_t,
                                       cursor:     xcb_cursor_t,
                                       fore_red:   u16,
                                       fore_green: u16,
                                       fore_blue:  u16,
                                       back_red:   u16,
                                       back_green: u16,
                                       back_blue:  u16)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_query_best_size_reply (c:      *mut xcb_connection_t,
                                      cookie: xcb_query_best_size_cookie_t,
                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_query_best_size_reply_t;

    pub fn xcb_query_best_size (c:        *mut xcb_connection_t,
                                class:    u8,
                                drawable: xcb_drawable_t,
                                width:    u16,
                                height:   u16)
            -> xcb_query_best_size_cookie_t;

    pub fn xcb_query_best_size_unchecked (c:        *mut xcb_connection_t,
                                          class:    u8,
                                          drawable: xcb_drawable_t,
                                          width:    u16,
                                          height:   u16)
            -> xcb_query_best_size_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_query_extension_reply (c:      *mut xcb_connection_t,
                                      cookie: xcb_query_extension_cookie_t,
                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_query_extension_reply_t;

    /// check if extension is present
    ///
    /// Determines if the specified extension is present on this X11 server.
    ///
    /// Every extension has a unique `major_opcode` to identify requests, the minor
    /// opcodes and request formats are extension-specific. If the extension provides
    /// events and errors, the `first_event` and `first_error` fields in the reply are
    /// set accordingly.
    ///
    /// There should rarely be a need to use this request directly, XCB provides the
    /// `xcb_get_extension_data` function instead.
    pub fn xcb_query_extension (c:        *mut xcb_connection_t,
                                name_len: u16,
                                name:     *const c_char)
            -> xcb_query_extension_cookie_t;

    /// check if extension is present
    ///
    /// Determines if the specified extension is present on this X11 server.
    ///
    /// Every extension has a unique `major_opcode` to identify requests, the minor
    /// opcodes and request formats are extension-specific. If the extension provides
    /// events and errors, the `first_event` and `first_error` fields in the reply are
    /// set accordingly.
    ///
    /// There should rarely be a need to use this request directly, XCB provides the
    /// `xcb_get_extension_data` function instead.
    pub fn xcb_query_extension_unchecked (c:        *mut xcb_connection_t,
                                          name_len: u16,
                                          name:     *const c_char)
            -> xcb_query_extension_cookie_t;

    pub fn xcb_list_extensions_names_length (R: *const xcb_list_extensions_reply_t)
            -> c_int;

    pub fn xcb_list_extensions_names_iterator<'a> (R: *const xcb_list_extensions_reply_t)
            -> xcb_str_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_list_extensions_reply (c:      *mut xcb_connection_t,
                                      cookie: xcb_list_extensions_cookie_t,
                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_list_extensions_reply_t;

    pub fn xcb_list_extensions (c: *mut xcb_connection_t)
            -> xcb_list_extensions_cookie_t;

    pub fn xcb_list_extensions_unchecked (c: *mut xcb_connection_t)
            -> xcb_list_extensions_cookie_t;

    pub fn xcb_change_keyboard_mapping (c:                   *mut xcb_connection_t,
                                        keycode_count:       u8,
                                        first_keycode:       xcb_keycode_t,
                                        keysyms_per_keycode: u8,
                                        keysyms:             *const xcb_keysym_t)
            -> xcb_void_cookie_t;

    pub fn xcb_change_keyboard_mapping_checked (c:                   *mut xcb_connection_t,
                                                keycode_count:       u8,
                                                first_keycode:       xcb_keycode_t,
                                                keysyms_per_keycode: u8,
                                                keysyms:             *const xcb_keysym_t)
            -> xcb_void_cookie_t;

    pub fn xcb_get_keyboard_mapping_keysyms (R: *const xcb_get_keyboard_mapping_reply_t)
            -> *mut xcb_keysym_t;

    pub fn xcb_get_keyboard_mapping_keysyms_length (R: *const xcb_get_keyboard_mapping_reply_t)
            -> c_int;

    pub fn xcb_get_keyboard_mapping_keysyms_end (R: *const xcb_get_keyboard_mapping_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_keyboard_mapping_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_get_keyboard_mapping_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_keyboard_mapping_reply_t;

    pub fn xcb_get_keyboard_mapping (c:             *mut xcb_connection_t,
                                     first_keycode: xcb_keycode_t,
                                     count:         u8)
            -> xcb_get_keyboard_mapping_cookie_t;

    pub fn xcb_get_keyboard_mapping_unchecked (c:             *mut xcb_connection_t,
                                               first_keycode: xcb_keycode_t,
                                               count:         u8)
            -> xcb_get_keyboard_mapping_cookie_t;

    pub fn xcb_change_keyboard_control (c:          *mut xcb_connection_t,
                                        value_mask: u32,
                                        value_list: *const u32)
            -> xcb_void_cookie_t;

    pub fn xcb_change_keyboard_control_checked (c:          *mut xcb_connection_t,
                                                value_mask: u32,
                                                value_list: *const u32)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_keyboard_control_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_get_keyboard_control_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_keyboard_control_reply_t;

    pub fn xcb_get_keyboard_control (c: *mut xcb_connection_t)
            -> xcb_get_keyboard_control_cookie_t;

    pub fn xcb_get_keyboard_control_unchecked (c: *mut xcb_connection_t)
            -> xcb_get_keyboard_control_cookie_t;

    pub fn xcb_bell (c:       *mut xcb_connection_t,
                     percent: i8)
            -> xcb_void_cookie_t;

    pub fn xcb_bell_checked (c:       *mut xcb_connection_t,
                             percent: i8)
            -> xcb_void_cookie_t;

    pub fn xcb_change_pointer_control (c:                        *mut xcb_connection_t,
                                       acceleration_numerator:   i16,
                                       acceleration_denominator: i16,
                                       threshold:                i16,
                                       do_acceleration:          u8,
                                       do_threshold:             u8)
            -> xcb_void_cookie_t;

    pub fn xcb_change_pointer_control_checked (c:                        *mut xcb_connection_t,
                                               acceleration_numerator:   i16,
                                               acceleration_denominator: i16,
                                               threshold:                i16,
                                               do_acceleration:          u8,
                                               do_threshold:             u8)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_pointer_control_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_get_pointer_control_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_pointer_control_reply_t;

    pub fn xcb_get_pointer_control (c: *mut xcb_connection_t)
            -> xcb_get_pointer_control_cookie_t;

    pub fn xcb_get_pointer_control_unchecked (c: *mut xcb_connection_t)
            -> xcb_get_pointer_control_cookie_t;

    pub fn xcb_set_screen_saver (c:               *mut xcb_connection_t,
                                 timeout:         i16,
                                 interval:        i16,
                                 prefer_blanking: u8,
                                 allow_exposures: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_set_screen_saver_checked (c:               *mut xcb_connection_t,
                                         timeout:         i16,
                                         interval:        i16,
                                         prefer_blanking: u8,
                                         allow_exposures: u8)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_screen_saver_reply (c:      *mut xcb_connection_t,
                                       cookie: xcb_get_screen_saver_cookie_t,
                                       error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_screen_saver_reply_t;

    pub fn xcb_get_screen_saver (c: *mut xcb_connection_t)
            -> xcb_get_screen_saver_cookie_t;

    pub fn xcb_get_screen_saver_unchecked (c: *mut xcb_connection_t)
            -> xcb_get_screen_saver_cookie_t;

    pub fn xcb_change_hosts (c:           *mut xcb_connection_t,
                             mode:        u8,
                             family:      u8,
                             address_len: u16,
                             address:     *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_change_hosts_checked (c:           *mut xcb_connection_t,
                                     mode:        u8,
                                     family:      u8,
                                     address_len: u16,
                                     address:     *const u8)
            -> xcb_void_cookie_t;

    pub fn xcb_host_address (R: *const xcb_host_t)
            -> *mut u8;

    pub fn xcb_host_address_length (R: *const xcb_host_t)
            -> c_int;

    pub fn xcb_host_address_end (R: *const xcb_host_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_host_next (i: *mut xcb_host_iterator_t);

    pub fn xcb_host_end (i: *mut xcb_host_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_list_hosts_hosts_length (R: *const xcb_list_hosts_reply_t)
            -> c_int;

    pub fn xcb_list_hosts_hosts_iterator<'a> (R: *const xcb_list_hosts_reply_t)
            -> xcb_host_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_list_hosts_reply (c:      *mut xcb_connection_t,
                                 cookie: xcb_list_hosts_cookie_t,
                                 error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_list_hosts_reply_t;

    pub fn xcb_list_hosts (c: *mut xcb_connection_t)
            -> xcb_list_hosts_cookie_t;

    pub fn xcb_list_hosts_unchecked (c: *mut xcb_connection_t)
            -> xcb_list_hosts_cookie_t;

    pub fn xcb_set_access_control (c:    *mut xcb_connection_t,
                                   mode: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_set_access_control_checked (c:    *mut xcb_connection_t,
                                           mode: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_set_close_down_mode (c:    *mut xcb_connection_t,
                                    mode: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_set_close_down_mode_checked (c:    *mut xcb_connection_t,
                                            mode: u8)
            -> xcb_void_cookie_t;

    /// kills a client
    ///
    /// Forces a close down of the client that created the specified `resource`.
    pub fn xcb_kill_client (c:        *mut xcb_connection_t,
                            resource: u32)
            -> xcb_void_cookie_t;

    /// kills a client
    ///
    /// Forces a close down of the client that created the specified `resource`.
    pub fn xcb_kill_client_checked (c:        *mut xcb_connection_t,
                                    resource: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_rotate_properties (c:         *mut xcb_connection_t,
                                  window:    xcb_window_t,
                                  atoms_len: u16,
                                  delta:     i16,
                                  atoms:     *const xcb_atom_t)
            -> xcb_void_cookie_t;

    pub fn xcb_rotate_properties_checked (c:         *mut xcb_connection_t,
                                          window:    xcb_window_t,
                                          atoms_len: u16,
                                          delta:     i16,
                                          atoms:     *const xcb_atom_t)
            -> xcb_void_cookie_t;

    pub fn xcb_force_screen_saver (c:    *mut xcb_connection_t,
                                   mode: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_force_screen_saver_checked (c:    *mut xcb_connection_t,
                                           mode: u8)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_set_pointer_mapping_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_set_pointer_mapping_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_set_pointer_mapping_reply_t;

    pub fn xcb_set_pointer_mapping (c:       *mut xcb_connection_t,
                                    map_len: u8,
                                    map:     *const u8)
            -> xcb_set_pointer_mapping_cookie_t;

    pub fn xcb_set_pointer_mapping_unchecked (c:       *mut xcb_connection_t,
                                              map_len: u8,
                                              map:     *const u8)
            -> xcb_set_pointer_mapping_cookie_t;

    pub fn xcb_get_pointer_mapping_map (R: *const xcb_get_pointer_mapping_reply_t)
            -> *mut u8;

    pub fn xcb_get_pointer_mapping_map_length (R: *const xcb_get_pointer_mapping_reply_t)
            -> c_int;

    pub fn xcb_get_pointer_mapping_map_end (R: *const xcb_get_pointer_mapping_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_pointer_mapping_reply (c:      *mut xcb_connection_t,
                                          cookie: xcb_get_pointer_mapping_cookie_t,
                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_pointer_mapping_reply_t;

    pub fn xcb_get_pointer_mapping (c: *mut xcb_connection_t)
            -> xcb_get_pointer_mapping_cookie_t;

    pub fn xcb_get_pointer_mapping_unchecked (c: *mut xcb_connection_t)
            -> xcb_get_pointer_mapping_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_set_modifier_mapping_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_set_modifier_mapping_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_set_modifier_mapping_reply_t;

    pub fn xcb_set_modifier_mapping (c:                     *mut xcb_connection_t,
                                     keycodes_per_modifier: u8,
                                     keycodes:              *const xcb_keycode_t)
            -> xcb_set_modifier_mapping_cookie_t;

    pub fn xcb_set_modifier_mapping_unchecked (c:                     *mut xcb_connection_t,
                                               keycodes_per_modifier: u8,
                                               keycodes:              *const xcb_keycode_t)
            -> xcb_set_modifier_mapping_cookie_t;

    pub fn xcb_get_modifier_mapping_keycodes (R: *const xcb_get_modifier_mapping_reply_t)
            -> *mut xcb_keycode_t;

    pub fn xcb_get_modifier_mapping_keycodes_length (R: *const xcb_get_modifier_mapping_reply_t)
            -> c_int;

    pub fn xcb_get_modifier_mapping_keycodes_end (R: *const xcb_get_modifier_mapping_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_get_modifier_mapping_reply (c:      *mut xcb_connection_t,
                                           cookie: xcb_get_modifier_mapping_cookie_t,
                                           error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_get_modifier_mapping_reply_t;

    pub fn xcb_get_modifier_mapping (c: *mut xcb_connection_t)
            -> xcb_get_modifier_mapping_cookie_t;

    pub fn xcb_get_modifier_mapping_unchecked (c: *mut xcb_connection_t)
            -> xcb_get_modifier_mapping_cookie_t;

    pub fn xcb_no_operation (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_no_operation_checked (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

} // extern
