// Generated automatically from xinput.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use render;
use shape;
use xfixes;
use ffi::base::*;
use ffi::input::*;
use ffi::xproto::*;
use ffi::render::*;
use ffi::shape::*;
use ffi::xfixes::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_input_id
    }
}

pub const MAJOR_VERSION: u32 = 2;
pub const MINOR_VERSION: u32 = 3;

pub type EventClass = xcb_input_event_class_t;

pub type KeyCode = xcb_input_key_code_t;

pub type DeviceId = xcb_input_device_id_t;

pub type Fp1616 = xcb_input_fp1616_t;

pub type DeviceUse = u32;
pub const DEVICE_USE_IS_X_POINTER           : DeviceUse = 0x00;
pub const DEVICE_USE_IS_X_KEYBOARD          : DeviceUse = 0x01;
pub const DEVICE_USE_IS_X_EXTENSION_DEVICE  : DeviceUse = 0x02;
pub const DEVICE_USE_IS_X_EXTENSION_KEYBOARD: DeviceUse = 0x03;
pub const DEVICE_USE_IS_X_EXTENSION_POINTER : DeviceUse = 0x04;

pub type InputClass = u32;
pub const INPUT_CLASS_KEY      : InputClass = 0x00;
pub const INPUT_CLASS_BUTTON   : InputClass = 0x01;
pub const INPUT_CLASS_VALUATOR : InputClass = 0x02;
pub const INPUT_CLASS_FEEDBACK : InputClass = 0x03;
pub const INPUT_CLASS_PROXIMITY: InputClass = 0x04;
pub const INPUT_CLASS_FOCUS    : InputClass = 0x05;
pub const INPUT_CLASS_OTHER    : InputClass = 0x06;

pub type ValuatorMode = u32;
pub const VALUATOR_MODE_RELATIVE: ValuatorMode = 0x00;
pub const VALUATOR_MODE_ABSOLUTE: ValuatorMode = 0x01;

pub type PropagateMode = u32;
pub const PROPAGATE_MODE_ADD_TO_LIST     : PropagateMode = 0x00;
pub const PROPAGATE_MODE_DELETE_FROM_LIST: PropagateMode = 0x01;

pub type DeviceInputMode = u32;
pub const DEVICE_INPUT_MODE_ASYNC_THIS_DEVICE  : DeviceInputMode = 0x00;
pub const DEVICE_INPUT_MODE_SYNC_THIS_DEVICE   : DeviceInputMode = 0x01;
pub const DEVICE_INPUT_MODE_REPLAY_THIS_DEVICE : DeviceInputMode = 0x02;
pub const DEVICE_INPUT_MODE_ASYNC_OTHER_DEVICES: DeviceInputMode = 0x03;
pub const DEVICE_INPUT_MODE_ASYNC_ALL          : DeviceInputMode = 0x04;
pub const DEVICE_INPUT_MODE_SYNC_ALL           : DeviceInputMode = 0x05;

pub type FeedbackClass = u32;
pub const FEEDBACK_CLASS_KEYBOARD: FeedbackClass = 0x00;
pub const FEEDBACK_CLASS_POINTER : FeedbackClass = 0x01;
pub const FEEDBACK_CLASS_STRING  : FeedbackClass = 0x02;
pub const FEEDBACK_CLASS_INTEGER : FeedbackClass = 0x03;
pub const FEEDBACK_CLASS_LED     : FeedbackClass = 0x04;
pub const FEEDBACK_CLASS_BELL    : FeedbackClass = 0x05;

pub type DeviceControl = u32;
pub const DEVICE_CONTROL_RESOLUTION: DeviceControl = 0x01;
pub const DEVICE_CONTROL_ABS_CALIB : DeviceControl = 0x02;
pub const DEVICE_CONTROL_CORE      : DeviceControl = 0x03;
pub const DEVICE_CONTROL_ENABLE    : DeviceControl = 0x04;
pub const DEVICE_CONTROL_ABS_AREA  : DeviceControl = 0x05;

pub type PropertyFormat = u32;
pub const PROPERTY_FORMAT_8_BITS : PropertyFormat = 0x08;
pub const PROPERTY_FORMAT_16_BITS: PropertyFormat = 0x10;
pub const PROPERTY_FORMAT_32_BITS: PropertyFormat = 0x20;

pub type Device = u32;
pub const DEVICE_ALL       : Device = 0x00;
pub const DEVICE_ALL_MASTER: Device = 0x01;

pub type HierarchyChangeType = u32;
pub const HIERARCHY_CHANGE_TYPE_ADD_MASTER   : HierarchyChangeType = 0x01;
pub const HIERARCHY_CHANGE_TYPE_REMOVE_MASTER: HierarchyChangeType = 0x02;
pub const HIERARCHY_CHANGE_TYPE_ATTACH_SLAVE : HierarchyChangeType = 0x03;
pub const HIERARCHY_CHANGE_TYPE_DETACH_SLAVE : HierarchyChangeType = 0x04;

pub type ChangeMode = u32;
pub const CHANGE_MODE_ATTACH: ChangeMode = 0x01;
pub const CHANGE_MODE_FLOAT : ChangeMode = 0x02;

pub type XiEventMask = u32;
pub const XI_EVENT_MASK_DEVICE_CHANGED    : XiEventMask =      0x02;
pub const XI_EVENT_MASK_KEY_PRESS         : XiEventMask =      0x04;
pub const XI_EVENT_MASK_KEY_RELEASE       : XiEventMask =      0x08;
pub const XI_EVENT_MASK_BUTTON_PRESS      : XiEventMask =      0x10;
pub const XI_EVENT_MASK_BUTTON_RELEASE    : XiEventMask =      0x20;
pub const XI_EVENT_MASK_MOTION            : XiEventMask =      0x40;
pub const XI_EVENT_MASK_ENTER             : XiEventMask =      0x80;
pub const XI_EVENT_MASK_LEAVE             : XiEventMask =     0x100;
pub const XI_EVENT_MASK_FOCUS_IN          : XiEventMask =     0x200;
pub const XI_EVENT_MASK_FOCUS_OUT         : XiEventMask =     0x400;
pub const XI_EVENT_MASK_HIERARCHY         : XiEventMask =     0x800;
pub const XI_EVENT_MASK_PROPERTY          : XiEventMask =    0x1000;
pub const XI_EVENT_MASK_RAW_KEY_PRESS     : XiEventMask =    0x2000;
pub const XI_EVENT_MASK_RAW_KEY_RELEASE   : XiEventMask =    0x4000;
pub const XI_EVENT_MASK_RAW_BUTTON_PRESS  : XiEventMask =    0x8000;
pub const XI_EVENT_MASK_RAW_BUTTON_RELEASE: XiEventMask =   0x10000;
pub const XI_EVENT_MASK_RAW_MOTION        : XiEventMask =   0x20000;
pub const XI_EVENT_MASK_TOUCH_BEGIN       : XiEventMask =   0x40000;
pub const XI_EVENT_MASK_TOUCH_UPDATE      : XiEventMask =   0x80000;
pub const XI_EVENT_MASK_TOUCH_END         : XiEventMask =  0x100000;
pub const XI_EVENT_MASK_TOUCH_OWNERSHIP   : XiEventMask =  0x200000;
pub const XI_EVENT_MASK_RAW_TOUCH_BEGIN   : XiEventMask =  0x400000;
pub const XI_EVENT_MASK_RAW_TOUCH_UPDATE  : XiEventMask =  0x800000;
pub const XI_EVENT_MASK_RAW_TOUCH_END     : XiEventMask = 0x1000000;
pub const XI_EVENT_MASK_BARRIER_HIT       : XiEventMask = 0x2000000;
pub const XI_EVENT_MASK_BARRIER_LEAVE     : XiEventMask = 0x4000000;

pub type DeviceClassType = u32;
pub const DEVICE_CLASS_TYPE_KEY     : DeviceClassType = 0x00;
pub const DEVICE_CLASS_TYPE_BUTTON  : DeviceClassType = 0x01;
pub const DEVICE_CLASS_TYPE_VALUATOR: DeviceClassType = 0x02;
pub const DEVICE_CLASS_TYPE_SCROLL  : DeviceClassType = 0x03;
pub const DEVICE_CLASS_TYPE_TOUCH   : DeviceClassType = 0x08;

pub type DeviceType = u32;
pub const DEVICE_TYPE_MASTER_POINTER : DeviceType = 0x01;
pub const DEVICE_TYPE_MASTER_KEYBOARD: DeviceType = 0x02;
pub const DEVICE_TYPE_SLAVE_POINTER  : DeviceType = 0x03;
pub const DEVICE_TYPE_SLAVE_KEYBOARD : DeviceType = 0x04;
pub const DEVICE_TYPE_FLOATING_SLAVE : DeviceType = 0x05;

pub type ScrollFlags = u32;
pub const SCROLL_FLAGS_NO_EMULATION: ScrollFlags = 0x01;
pub const SCROLL_FLAGS_PREFERRED   : ScrollFlags = 0x02;

pub type ScrollType = u32;
pub const SCROLL_TYPE_VERTICAL  : ScrollType = 0x01;
pub const SCROLL_TYPE_HORIZONTAL: ScrollType = 0x02;

pub type TouchMode = u32;
pub const TOUCH_MODE_DIRECT   : TouchMode = 0x01;
pub const TOUCH_MODE_DEPENDENT: TouchMode = 0x02;

pub type GrabOwner = u32;
pub const GRAB_OWNER_NO_OWNER: GrabOwner = 0x00;
pub const GRAB_OWNER_OWNER   : GrabOwner = 0x01;

pub type EventMode = u32;
pub const EVENT_MODE_ASYNC_DEVICE       : EventMode = 0x00;
pub const EVENT_MODE_SYNC_DEVICE        : EventMode = 0x01;
pub const EVENT_MODE_REPLAY_DEVICE      : EventMode = 0x02;
pub const EVENT_MODE_ASYNC_PAIRED_DEVICE: EventMode = 0x03;
pub const EVENT_MODE_ASYNC_PAIR         : EventMode = 0x04;
pub const EVENT_MODE_SYNC_PAIR          : EventMode = 0x05;
pub const EVENT_MODE_ACCEPT_TOUCH       : EventMode = 0x06;
pub const EVENT_MODE_REJECT_TOUCH       : EventMode = 0x07;

pub type GrabMode22 = u32;
pub const GRAB_MODE_22_SYNC : GrabMode22 = 0x00;
pub const GRAB_MODE_22_ASYNC: GrabMode22 = 0x01;
pub const GRAB_MODE_22_TOUCH: GrabMode22 = 0x02;

pub type GrabType = u32;
pub const GRAB_TYPE_BUTTON     : GrabType = 0x00;
pub const GRAB_TYPE_KEYCODE    : GrabType = 0x01;
pub const GRAB_TYPE_ENTER      : GrabType = 0x02;
pub const GRAB_TYPE_FOCUS_IN   : GrabType = 0x03;
pub const GRAB_TYPE_TOUCH_BEGIN: GrabType = 0x04;

pub type ModifierMask = u32;
pub const MODIFIER_MASK_ANY: ModifierMask = 0x80000000;

pub type DeviceChange = u32;
pub const DEVICE_CHANGE_ADDED          : DeviceChange = 0x00;
pub const DEVICE_CHANGE_REMOVED        : DeviceChange = 0x01;
pub const DEVICE_CHANGE_ENABLED        : DeviceChange = 0x02;
pub const DEVICE_CHANGE_DISABLED       : DeviceChange = 0x03;
pub const DEVICE_CHANGE_UNRECOVERABLE  : DeviceChange = 0x04;
pub const DEVICE_CHANGE_CONTROL_CHANGED: DeviceChange = 0x05;

pub type ChangeReason = u32;
pub const CHANGE_REASON_SLAVE_SWITCH : ChangeReason = 0x01;
pub const CHANGE_REASON_DEVICE_CHANGE: ChangeReason = 0x02;

pub type KeyEventFlags = u32;
pub const KEY_EVENT_FLAGS_KEY_REPEAT: KeyEventFlags = 0x10000;

pub type PointerEventFlags = u32;
pub const POINTER_EVENT_FLAGS_POINTER_EMULATED: PointerEventFlags = 0x10000;

pub type NotifyMode = u32;
pub const NOTIFY_MODE_NORMAL        : NotifyMode = 0x00;
pub const NOTIFY_MODE_GRAB          : NotifyMode = 0x01;
pub const NOTIFY_MODE_UNGRAB        : NotifyMode = 0x02;
pub const NOTIFY_MODE_WHILE_GRABBED : NotifyMode = 0x03;
pub const NOTIFY_MODE_PASSIVE_GRAB  : NotifyMode = 0x04;
pub const NOTIFY_MODE_PASSIVE_UNGRAB: NotifyMode = 0x05;

pub type NotifyDetail = u32;
pub const NOTIFY_DETAIL_ANCESTOR         : NotifyDetail = 0x00;
pub const NOTIFY_DETAIL_VIRTUAL          : NotifyDetail = 0x01;
pub const NOTIFY_DETAIL_INFERIOR         : NotifyDetail = 0x02;
pub const NOTIFY_DETAIL_NONLINEAR        : NotifyDetail = 0x03;
pub const NOTIFY_DETAIL_NONLINEAR_VIRTUAL: NotifyDetail = 0x04;
pub const NOTIFY_DETAIL_POINTER          : NotifyDetail = 0x05;
pub const NOTIFY_DETAIL_POINTER_ROOT     : NotifyDetail = 0x06;
pub const NOTIFY_DETAIL_NONE             : NotifyDetail = 0x07;

pub type HierarchyMask = u32;
pub const HIERARCHY_MASK_MASTER_ADDED   : HierarchyMask = 0x01;
pub const HIERARCHY_MASK_MASTER_REMOVED : HierarchyMask = 0x02;
pub const HIERARCHY_MASK_SLAVE_ADDED    : HierarchyMask = 0x04;
pub const HIERARCHY_MASK_SLAVE_REMOVED  : HierarchyMask = 0x08;
pub const HIERARCHY_MASK_SLAVE_ATTACHED : HierarchyMask = 0x10;
pub const HIERARCHY_MASK_SLAVE_DETACHED : HierarchyMask = 0x20;
pub const HIERARCHY_MASK_DEVICE_ENABLED : HierarchyMask = 0x40;
pub const HIERARCHY_MASK_DEVICE_DISABLED: HierarchyMask = 0x80;

pub type PropertyFlag = u32;
pub const PROPERTY_FLAG_DELETED : PropertyFlag = 0x00;
pub const PROPERTY_FLAG_CREATED : PropertyFlag = 0x01;
pub const PROPERTY_FLAG_MODIFIED: PropertyFlag = 0x02;

pub type TouchEventFlags = u32;
pub const TOUCH_EVENT_FLAGS_TOUCH_PENDING_END      : TouchEventFlags = 0x10000;
pub const TOUCH_EVENT_FLAGS_TOUCH_EMULATING_POINTER: TouchEventFlags = 0x20000;

pub type TouchOwnershipFlags = u32;
pub const TOUCH_OWNERSHIP_FLAGS_NONE: TouchOwnershipFlags = 0x00;

pub struct DeviceError {
    pub base: base::Error<xcb_input_device_error_t>
}

pub struct EventError {
    pub base: base::Error<xcb_input_event_error_t>
}

pub struct ModeError {
    pub base: base::Error<xcb_input_mode_error_t>
}

pub struct DeviceBusyError {
    pub base: base::Error<xcb_input_device_busy_error_t>
}

pub struct ClassError {
    pub base: base::Error<xcb_input_class_error_t>
}



#[derive(Copy, Clone)]
pub struct Fp3232 {
    pub base: xcb_input_fp3232_t,
}

impl Fp3232 {
    #[allow(unused_unsafe)]
    pub fn new(integral: i32,
               frac:     u32)
            -> Fp3232 {
        unsafe {
            Fp3232 {
                base: xcb_input_fp3232_t {
                    integral: integral,
                    frac:     frac,
                }
            }
        }
    }
    pub fn integral(&self) -> i32 {
        unsafe {
            self.base.integral
        }
    }
    pub fn frac(&self) -> u32 {
        unsafe {
            self.base.frac
        }
    }
}

pub type Fp3232Iterator = xcb_input_fp3232_iterator_t;

impl Iterator for Fp3232Iterator {
    type Item = Fp3232;
    fn next(&mut self) -> std::option::Option<Fp3232> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_fp3232_iterator_t;
                let data = (*iter).data;
                xcb_input_fp3232_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const GET_EXTENSION_VERSION: u8 = 1;

pub type GetExtensionVersionCookie<'a> = base::Cookie<'a, xcb_input_get_extension_version_cookie_t>;

impl<'a> GetExtensionVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<GetExtensionVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetExtensionVersionReply {
                    ptr: xcb_input_get_extension_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetExtensionVersionReply {
                    ptr: xcb_input_get_extension_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetExtensionVersionReply = base::Reply<xcb_input_get_extension_version_reply_t>;

impl GetExtensionVersionReply {
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
    pub fn present(&self) -> bool {
        unsafe {
            (*self.ptr).present != 0
        }
    }
}

pub fn get_extension_version<'a>(c   : &'a base::Connection,
                                 name: &str)
        -> GetExtensionVersionCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_input_get_extension_version(c.get_raw_conn(),
                                                     name_len as u16,  // 0
                                                     name_ptr as *const c_char);  // 1
        GetExtensionVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_extension_version_unchecked<'a>(c   : &'a base::Connection,
                                           name: &str)
        -> GetExtensionVersionCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_input_get_extension_version_unchecked(c.get_raw_conn(),
                                                               name_len as u16,  // 0
                                                               name_ptr as *const c_char);  // 1
        GetExtensionVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceInfo {
    pub base: xcb_input_device_info_t,
}

impl DeviceInfo {
    #[allow(unused_unsafe)]
    pub fn new(device_type:    xproto::Atom,
               device_id:      u8,
               num_class_info: u8,
               device_use:     u8)
            -> DeviceInfo {
        unsafe {
            DeviceInfo {
                base: xcb_input_device_info_t {
                    device_type:    device_type,
                    device_id:      device_id,
                    num_class_info: num_class_info,
                    device_use:     device_use,
                    pad0:           0,
                }
            }
        }
    }
    pub fn device_type(&self) -> xproto::Atom {
        unsafe {
            self.base.device_type
        }
    }
    pub fn device_id(&self) -> u8 {
        unsafe {
            self.base.device_id
        }
    }
    pub fn num_class_info(&self) -> u8 {
        unsafe {
            self.base.num_class_info
        }
    }
    pub fn device_use(&self) -> u8 {
        unsafe {
            self.base.device_use
        }
    }
}

pub type DeviceInfoIterator = xcb_input_device_info_iterator_t;

impl Iterator for DeviceInfoIterator {
    type Item = DeviceInfo;
    fn next(&mut self) -> std::option::Option<DeviceInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_info_iterator_t;
                let data = (*iter).data;
                xcb_input_device_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct KeyInfo {
    pub base: xcb_input_key_info_t,
}

impl KeyInfo {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               len:         u8,
               min_keycode: KeyCode,
               max_keycode: KeyCode,
               num_keys:    u16)
            -> KeyInfo {
        unsafe {
            KeyInfo {
                base: xcb_input_key_info_t {
                    class_id:    class_id,
                    len:         len,
                    min_keycode: min_keycode,
                    max_keycode: max_keycode,
                    num_keys:    num_keys,
                    pad0:        [0; 2],
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn len(&self) -> u8 {
        unsafe {
            self.base.len
        }
    }
    pub fn min_keycode(&self) -> KeyCode {
        unsafe {
            self.base.min_keycode
        }
    }
    pub fn max_keycode(&self) -> KeyCode {
        unsafe {
            self.base.max_keycode
        }
    }
    pub fn num_keys(&self) -> u16 {
        unsafe {
            self.base.num_keys
        }
    }
}

pub type KeyInfoIterator = xcb_input_key_info_iterator_t;

impl Iterator for KeyInfoIterator {
    type Item = KeyInfo;
    fn next(&mut self) -> std::option::Option<KeyInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_key_info_iterator_t;
                let data = (*iter).data;
                xcb_input_key_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ButtonInfo {
    pub base: xcb_input_button_info_t,
}

impl ButtonInfo {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               len:         u8,
               num_buttons: u16)
            -> ButtonInfo {
        unsafe {
            ButtonInfo {
                base: xcb_input_button_info_t {
                    class_id:    class_id,
                    len:         len,
                    num_buttons: num_buttons,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn len(&self) -> u8 {
        unsafe {
            self.base.len
        }
    }
    pub fn num_buttons(&self) -> u16 {
        unsafe {
            self.base.num_buttons
        }
    }
}

pub type ButtonInfoIterator = xcb_input_button_info_iterator_t;

impl Iterator for ButtonInfoIterator {
    type Item = ButtonInfo;
    fn next(&mut self) -> std::option::Option<ButtonInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_button_info_iterator_t;
                let data = (*iter).data;
                xcb_input_button_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct AxisInfo {
    pub base: xcb_input_axis_info_t,
}

impl AxisInfo {
    #[allow(unused_unsafe)]
    pub fn new(resolution: u32,
               minimum:    i32,
               maximum:    i32)
            -> AxisInfo {
        unsafe {
            AxisInfo {
                base: xcb_input_axis_info_t {
                    resolution: resolution,
                    minimum:    minimum,
                    maximum:    maximum,
                }
            }
        }
    }
    pub fn resolution(&self) -> u32 {
        unsafe {
            self.base.resolution
        }
    }
    pub fn minimum(&self) -> i32 {
        unsafe {
            self.base.minimum
        }
    }
    pub fn maximum(&self) -> i32 {
        unsafe {
            self.base.maximum
        }
    }
}

pub type AxisInfoIterator = xcb_input_axis_info_iterator_t;

impl Iterator for AxisInfoIterator {
    type Item = AxisInfo;
    fn next(&mut self) -> std::option::Option<AxisInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_axis_info_iterator_t;
                let data = (*iter).data;
                xcb_input_axis_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type ValuatorInfo<'a> = base::StructPtr<'a, xcb_input_valuator_info_t>;

impl<'a> ValuatorInfo<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn len(&self) -> u8 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn axes_len(&self) -> u8 {
        unsafe {
            (*self.ptr).axes_len
        }
    }
    pub fn mode(&self) -> u8 {
        unsafe {
            (*self.ptr).mode
        }
    }
    pub fn motion_size(&self) -> u32 {
        unsafe {
            (*self.ptr).motion_size
        }
    }
    pub fn axes(&self) -> AxisInfoIterator {
        unsafe {
            xcb_input_valuator_info_axes_iterator(self.ptr)
        }
    }
}

pub type ValuatorInfoIterator<'a> = xcb_input_valuator_info_iterator_t<'a>;

impl<'a> Iterator for ValuatorInfoIterator<'a> {
    type Item = ValuatorInfo<'a>;
    fn next(&mut self) -> std::option::Option<ValuatorInfo<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_valuator_info_iterator_t;
                let data = (*iter).data;
                xcb_input_valuator_info_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct InputInfo {
    pub base: xcb_input_input_info_t,
}

impl InputInfo {
    #[allow(unused_unsafe)]
    pub fn new(class_id: u8,
               len:      u8)
            -> InputInfo {
        unsafe {
            InputInfo {
                base: xcb_input_input_info_t {
                    class_id: class_id,
                    len:      len,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn len(&self) -> u8 {
        unsafe {
            self.base.len
        }
    }
}

pub type InputInfoIterator = xcb_input_input_info_iterator_t;

impl Iterator for InputInfoIterator {
    type Item = InputInfo;
    fn next(&mut self) -> std::option::Option<InputInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_input_info_iterator_t;
                let data = (*iter).data;
                xcb_input_input_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type DeviceName<'a> = base::StructPtr<'a, xcb_input_device_name_t>;

impl<'a> DeviceName<'a> {
    pub fn len(&self) -> u8 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn string(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_device_name_string_length(field) as usize;
            let data = xcb_input_device_name_string(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type DeviceNameIterator<'a> = xcb_input_device_name_iterator_t<'a>;

impl<'a> Iterator for DeviceNameIterator<'a> {
    type Item = DeviceName<'a>;
    fn next(&mut self) -> std::option::Option<DeviceName<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_name_iterator_t;
                let data = (*iter).data;
                xcb_input_device_name_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const LIST_INPUT_DEVICES: u8 = 2;

pub type ListInputDevicesCookie<'a> = base::Cookie<'a, xcb_input_list_input_devices_cookie_t>;

impl<'a> ListInputDevicesCookie<'a> {
    pub fn get_reply(&self) -> Result<ListInputDevicesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListInputDevicesReply {
                    ptr: xcb_input_list_input_devices_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListInputDevicesReply {
                    ptr: xcb_input_list_input_devices_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListInputDevicesReply = base::Reply<xcb_input_list_input_devices_reply_t>;

impl ListInputDevicesReply {
    pub fn devices_len(&self) -> u8 {
        unsafe {
            (*self.ptr).devices_len
        }
    }
    pub fn devices(&self) -> DeviceInfoIterator {
        unsafe {
            xcb_input_list_input_devices_devices_iterator(self.ptr)
        }
    }
}

pub fn list_input_devices<'a>(c: &'a base::Connection)
        -> ListInputDevicesCookie<'a> {
    unsafe {
        let cookie = xcb_input_list_input_devices(c.get_raw_conn());
        ListInputDevicesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_input_devices_unchecked<'a>(c: &'a base::Connection)
        -> ListInputDevicesCookie<'a> {
    unsafe {
        let cookie = xcb_input_list_input_devices_unchecked(c.get_raw_conn());
        ListInputDevicesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

#[derive(Copy, Clone)]
pub struct InputClassInfo {
    pub base: xcb_input_input_class_info_t,
}

impl InputClassInfo {
    #[allow(unused_unsafe)]
    pub fn new(class_id:        u8,
               event_type_base: u8)
            -> InputClassInfo {
        unsafe {
            InputClassInfo {
                base: xcb_input_input_class_info_t {
                    class_id:        class_id,
                    event_type_base: event_type_base,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn event_type_base(&self) -> u8 {
        unsafe {
            self.base.event_type_base
        }
    }
}

pub type InputClassInfoIterator = xcb_input_input_class_info_iterator_t;

impl Iterator for InputClassInfoIterator {
    type Item = InputClassInfo;
    fn next(&mut self) -> std::option::Option<InputClassInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_input_class_info_iterator_t;
                let data = (*iter).data;
                xcb_input_input_class_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const OPEN_DEVICE: u8 = 3;

pub type OpenDeviceCookie<'a> = base::Cookie<'a, xcb_input_open_device_cookie_t>;

impl<'a> OpenDeviceCookie<'a> {
    pub fn get_reply(&self) -> Result<OpenDeviceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = OpenDeviceReply {
                    ptr: xcb_input_open_device_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( OpenDeviceReply {
                    ptr: xcb_input_open_device_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type OpenDeviceReply = base::Reply<xcb_input_open_device_reply_t>;

impl OpenDeviceReply {
    pub fn num_classes(&self) -> u8 {
        unsafe {
            (*self.ptr).num_classes
        }
    }
    pub fn class_info(&self) -> InputClassInfoIterator {
        unsafe {
            xcb_input_open_device_class_info_iterator(self.ptr)
        }
    }
}

pub fn open_device<'a>(c        : &'a base::Connection,
                       device_id: u8)
        -> OpenDeviceCookie<'a> {
    unsafe {
        let cookie = xcb_input_open_device(c.get_raw_conn(),
                                           device_id as u8);  // 0
        OpenDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn open_device_unchecked<'a>(c        : &'a base::Connection,
                                 device_id: u8)
        -> OpenDeviceCookie<'a> {
    unsafe {
        let cookie = xcb_input_open_device_unchecked(c.get_raw_conn(),
                                                     device_id as u8);  // 0
        OpenDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CLOSE_DEVICE: u8 = 4;

pub fn close_device<'a>(c        : &'a base::Connection,
                        device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_close_device(c.get_raw_conn(),
                                            device_id as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn close_device_checked<'a>(c        : &'a base::Connection,
                                device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_close_device_checked(c.get_raw_conn(),
                                                    device_id as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_DEVICE_MODE: u8 = 5;

pub type SetDeviceModeCookie<'a> = base::Cookie<'a, xcb_input_set_device_mode_cookie_t>;

impl<'a> SetDeviceModeCookie<'a> {
    pub fn get_reply(&self) -> Result<SetDeviceModeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetDeviceModeReply {
                    ptr: xcb_input_set_device_mode_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetDeviceModeReply {
                    ptr: xcb_input_set_device_mode_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetDeviceModeReply = base::Reply<xcb_input_set_device_mode_reply_t>;

impl SetDeviceModeReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn set_device_mode<'a>(c        : &'a base::Connection,
                           device_id: u8,
                           mode     : u8)
        -> SetDeviceModeCookie<'a> {
    unsafe {
        let cookie = xcb_input_set_device_mode(c.get_raw_conn(),
                                               device_id as u8,  // 0
                                               mode as u8);  // 1
        SetDeviceModeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_device_mode_unchecked<'a>(c        : &'a base::Connection,
                                     device_id: u8,
                                     mode     : u8)
        -> SetDeviceModeCookie<'a> {
    unsafe {
        let cookie = xcb_input_set_device_mode_unchecked(c.get_raw_conn(),
                                                         device_id as u8,  // 0
                                                         mode as u8);  // 1
        SetDeviceModeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SELECT_EXTENSION_EVENT: u8 = 6;

pub fn select_extension_event<'a>(c      : &'a base::Connection,
                                  window : xproto::Window,
                                  classes: &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_select_extension_event(c.get_raw_conn(),
                                                      window as xcb_window_t,  // 0
                                                      classes_len as u16,  // 1
                                                      classes_ptr as *const xcb_input_event_class_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_extension_event_checked<'a>(c      : &'a base::Connection,
                                          window : xproto::Window,
                                          classes: &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_select_extension_event_checked(c.get_raw_conn(),
                                                              window as xcb_window_t,  // 0
                                                              classes_len as u16,  // 1
                                                              classes_ptr as *const xcb_input_event_class_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_SELECTED_EXTENSION_EVENTS: u8 = 7;

pub type GetSelectedExtensionEventsCookie<'a> = base::Cookie<'a, xcb_input_get_selected_extension_events_cookie_t>;

impl<'a> GetSelectedExtensionEventsCookie<'a> {
    pub fn get_reply(&self) -> Result<GetSelectedExtensionEventsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetSelectedExtensionEventsReply {
                    ptr: xcb_input_get_selected_extension_events_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetSelectedExtensionEventsReply {
                    ptr: xcb_input_get_selected_extension_events_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetSelectedExtensionEventsReply = base::Reply<xcb_input_get_selected_extension_events_reply_t>;

impl GetSelectedExtensionEventsReply {
    pub fn num_this_classes(&self) -> u16 {
        unsafe {
            (*self.ptr).num_this_classes
        }
    }
    pub fn num_all_classes(&self) -> u16 {
        unsafe {
            (*self.ptr).num_all_classes
        }
    }
    pub fn this_classes(&self) -> &[EventClass] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_get_selected_extension_events_this_classes_length(field) as usize;
            let data = xcb_input_get_selected_extension_events_this_classes(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn all_classes(&self) -> &[EventClass] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_get_selected_extension_events_all_classes_length(field) as usize;
            let data = xcb_input_get_selected_extension_events_all_classes(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_selected_extension_events<'a>(c     : &'a base::Connection,
                                         window: xproto::Window)
        -> GetSelectedExtensionEventsCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_selected_extension_events(c.get_raw_conn(),
                                                             window as xcb_window_t);  // 0
        GetSelectedExtensionEventsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_selected_extension_events_unchecked<'a>(c     : &'a base::Connection,
                                                   window: xproto::Window)
        -> GetSelectedExtensionEventsCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_selected_extension_events_unchecked(c.get_raw_conn(),
                                                                       window as xcb_window_t);  // 0
        GetSelectedExtensionEventsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_DEVICE_DONT_PROPAGATE_LIST: u8 = 8;

pub fn change_device_dont_propagate_list<'a>(c      : &'a base::Connection,
                                             window : xproto::Window,
                                             mode   : u8,
                                             classes: &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_change_device_dont_propagate_list(c.get_raw_conn(),
                                                                 window as xcb_window_t,  // 0
                                                                 classes_len as u16,  // 1
                                                                 mode as u8,  // 2
                                                                 classes_ptr as *const xcb_input_event_class_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_device_dont_propagate_list_checked<'a>(c      : &'a base::Connection,
                                                     window : xproto::Window,
                                                     mode   : u8,
                                                     classes: &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_change_device_dont_propagate_list_checked(c.get_raw_conn(),
                                                                         window as xcb_window_t,  // 0
                                                                         classes_len as u16,  // 1
                                                                         mode as u8,  // 2
                                                                         classes_ptr as *const xcb_input_event_class_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DEVICE_DONT_PROPAGATE_LIST: u8 = 9;

pub type GetDeviceDontPropagateListCookie<'a> = base::Cookie<'a, xcb_input_get_device_dont_propagate_list_cookie_t>;

impl<'a> GetDeviceDontPropagateListCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceDontPropagateListReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceDontPropagateListReply {
                    ptr: xcb_input_get_device_dont_propagate_list_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceDontPropagateListReply {
                    ptr: xcb_input_get_device_dont_propagate_list_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceDontPropagateListReply = base::Reply<xcb_input_get_device_dont_propagate_list_reply_t>;

impl GetDeviceDontPropagateListReply {
    pub fn num_classes(&self) -> u16 {
        unsafe {
            (*self.ptr).num_classes
        }
    }
    pub fn classes(&self) -> &[EventClass] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_get_device_dont_propagate_list_classes_length(field) as usize;
            let data = xcb_input_get_device_dont_propagate_list_classes(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_device_dont_propagate_list<'a>(c     : &'a base::Connection,
                                          window: xproto::Window)
        -> GetDeviceDontPropagateListCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_dont_propagate_list(c.get_raw_conn(),
                                                              window as xcb_window_t);  // 0
        GetDeviceDontPropagateListCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_dont_propagate_list_unchecked<'a>(c     : &'a base::Connection,
                                                    window: xproto::Window)
        -> GetDeviceDontPropagateListCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_dont_propagate_list_unchecked(c.get_raw_conn(),
                                                                        window as xcb_window_t);  // 0
        GetDeviceDontPropagateListCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceTimeCoord {
    pub base: xcb_input_device_time_coord_t,
}

impl DeviceTimeCoord {
    #[allow(unused_unsafe)]
    pub fn new(time: xproto::Timestamp)
            -> DeviceTimeCoord {
        unsafe {
            DeviceTimeCoord {
                base: xcb_input_device_time_coord_t {
                    time: time,
                }
            }
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            self.base.time
        }
    }
}

pub type DeviceTimeCoordIterator = xcb_input_device_time_coord_iterator_t;

impl Iterator for DeviceTimeCoordIterator {
    type Item = DeviceTimeCoord;
    fn next(&mut self) -> std::option::Option<DeviceTimeCoord> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_time_coord_iterator_t;
                let data = (*iter).data;
                xcb_input_device_time_coord_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const GET_DEVICE_MOTION_EVENTS: u8 = 10;

pub type GetDeviceMotionEventsCookie<'a> = base::Cookie<'a, xcb_input_get_device_motion_events_cookie_t>;

impl<'a> GetDeviceMotionEventsCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceMotionEventsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceMotionEventsReply {
                    ptr: xcb_input_get_device_motion_events_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceMotionEventsReply {
                    ptr: xcb_input_get_device_motion_events_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceMotionEventsReply = base::Reply<xcb_input_get_device_motion_events_reply_t>;

impl GetDeviceMotionEventsReply {
    pub fn num_events(&self) -> u32 {
        unsafe {
            (*self.ptr).num_events
        }
    }
    pub fn num_axes(&self) -> u8 {
        unsafe {
            (*self.ptr).num_axes
        }
    }
    pub fn device_mode(&self) -> u8 {
        unsafe {
            (*self.ptr).device_mode
        }
    }
}

pub fn get_device_motion_events<'a>(c        : &'a base::Connection,
                                    start    : xproto::Timestamp,
                                    stop     : xproto::Timestamp,
                                    device_id: u8)
        -> GetDeviceMotionEventsCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_motion_events(c.get_raw_conn(),
                                                        start as xcb_timestamp_t,  // 0
                                                        stop as xcb_timestamp_t,  // 1
                                                        device_id as u8);  // 2
        GetDeviceMotionEventsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_motion_events_unchecked<'a>(c        : &'a base::Connection,
                                              start    : xproto::Timestamp,
                                              stop     : xproto::Timestamp,
                                              device_id: u8)
        -> GetDeviceMotionEventsCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_motion_events_unchecked(c.get_raw_conn(),
                                                                  start as xcb_timestamp_t,  // 0
                                                                  stop as xcb_timestamp_t,  // 1
                                                                  device_id as u8);  // 2
        GetDeviceMotionEventsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_KEYBOARD_DEVICE: u8 = 11;

pub type ChangeKeyboardDeviceCookie<'a> = base::Cookie<'a, xcb_input_change_keyboard_device_cookie_t>;

impl<'a> ChangeKeyboardDeviceCookie<'a> {
    pub fn get_reply(&self) -> Result<ChangeKeyboardDeviceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ChangeKeyboardDeviceReply {
                    ptr: xcb_input_change_keyboard_device_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ChangeKeyboardDeviceReply {
                    ptr: xcb_input_change_keyboard_device_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ChangeKeyboardDeviceReply = base::Reply<xcb_input_change_keyboard_device_reply_t>;

impl ChangeKeyboardDeviceReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn change_keyboard_device<'a>(c        : &'a base::Connection,
                                  device_id: u8)
        -> ChangeKeyboardDeviceCookie<'a> {
    unsafe {
        let cookie = xcb_input_change_keyboard_device(c.get_raw_conn(),
                                                      device_id as u8);  // 0
        ChangeKeyboardDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn change_keyboard_device_unchecked<'a>(c        : &'a base::Connection,
                                            device_id: u8)
        -> ChangeKeyboardDeviceCookie<'a> {
    unsafe {
        let cookie = xcb_input_change_keyboard_device_unchecked(c.get_raw_conn(),
                                                                device_id as u8);  // 0
        ChangeKeyboardDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_POINTER_DEVICE: u8 = 12;

pub type ChangePointerDeviceCookie<'a> = base::Cookie<'a, xcb_input_change_pointer_device_cookie_t>;

impl<'a> ChangePointerDeviceCookie<'a> {
    pub fn get_reply(&self) -> Result<ChangePointerDeviceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ChangePointerDeviceReply {
                    ptr: xcb_input_change_pointer_device_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ChangePointerDeviceReply {
                    ptr: xcb_input_change_pointer_device_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ChangePointerDeviceReply = base::Reply<xcb_input_change_pointer_device_reply_t>;

impl ChangePointerDeviceReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn change_pointer_device<'a>(c        : &'a base::Connection,
                                 x_axis   : u8,
                                 y_axis   : u8,
                                 device_id: u8)
        -> ChangePointerDeviceCookie<'a> {
    unsafe {
        let cookie = xcb_input_change_pointer_device(c.get_raw_conn(),
                                                     x_axis as u8,  // 0
                                                     y_axis as u8,  // 1
                                                     device_id as u8);  // 2
        ChangePointerDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn change_pointer_device_unchecked<'a>(c        : &'a base::Connection,
                                           x_axis   : u8,
                                           y_axis   : u8,
                                           device_id: u8)
        -> ChangePointerDeviceCookie<'a> {
    unsafe {
        let cookie = xcb_input_change_pointer_device_unchecked(c.get_raw_conn(),
                                                               x_axis as u8,  // 0
                                                               y_axis as u8,  // 1
                                                               device_id as u8);  // 2
        ChangePointerDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GRAB_DEVICE: u8 = 13;

pub type GrabDeviceCookie<'a> = base::Cookie<'a, xcb_input_grab_device_cookie_t>;

impl<'a> GrabDeviceCookie<'a> {
    pub fn get_reply(&self) -> Result<GrabDeviceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GrabDeviceReply {
                    ptr: xcb_input_grab_device_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GrabDeviceReply {
                    ptr: xcb_input_grab_device_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GrabDeviceReply = base::Reply<xcb_input_grab_device_reply_t>;

impl GrabDeviceReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn grab_device<'a>(c                : &'a base::Connection,
                       grab_window      : xproto::Window,
                       time             : xproto::Timestamp,
                       this_device_mode : u8,
                       other_device_mode: u8,
                       owner_events     : bool,
                       device_id        : u8,
                       classes          : &[EventClass])
        -> GrabDeviceCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_grab_device(c.get_raw_conn(),
                                           grab_window as xcb_window_t,  // 0
                                           time as xcb_timestamp_t,  // 1
                                           classes_len as u16,  // 2
                                           this_device_mode as u8,  // 3
                                           other_device_mode as u8,  // 4
                                           owner_events as u8,  // 5
                                           device_id as u8,  // 6
                                           classes_ptr as *const xcb_input_event_class_t);  // 7
        GrabDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn grab_device_unchecked<'a>(c                : &'a base::Connection,
                                 grab_window      : xproto::Window,
                                 time             : xproto::Timestamp,
                                 this_device_mode : u8,
                                 other_device_mode: u8,
                                 owner_events     : bool,
                                 device_id        : u8,
                                 classes          : &[EventClass])
        -> GrabDeviceCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_grab_device_unchecked(c.get_raw_conn(),
                                                     grab_window as xcb_window_t,  // 0
                                                     time as xcb_timestamp_t,  // 1
                                                     classes_len as u16,  // 2
                                                     this_device_mode as u8,  // 3
                                                     other_device_mode as u8,  // 4
                                                     owner_events as u8,  // 5
                                                     device_id as u8,  // 6
                                                     classes_ptr as *const xcb_input_event_class_t);  // 7
        GrabDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const UNGRAB_DEVICE: u8 = 14;

pub fn ungrab_device<'a>(c        : &'a base::Connection,
                         time     : xproto::Timestamp,
                         device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_ungrab_device(c.get_raw_conn(),
                                             time as xcb_timestamp_t,  // 0
                                             device_id as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn ungrab_device_checked<'a>(c        : &'a base::Connection,
                                 time     : xproto::Timestamp,
                                 device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_ungrab_device_checked(c.get_raw_conn(),
                                                     time as xcb_timestamp_t,  // 0
                                                     device_id as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GRAB_DEVICE_KEY: u8 = 15;

pub fn grab_device_key<'a>(c                : &'a base::Connection,
                           grab_window      : xproto::Window,
                           modifiers        : u16,
                           modifier_device  : u8,
                           grabbed_device   : u8,
                           key              : u8,
                           this_device_mode : u8,
                           other_device_mode: u8,
                           owner_events     : bool,
                           classes          : &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_grab_device_key(c.get_raw_conn(),
                                               grab_window as xcb_window_t,  // 0
                                               classes_len as u16,  // 1
                                               modifiers as u16,  // 2
                                               modifier_device as u8,  // 3
                                               grabbed_device as u8,  // 4
                                               key as u8,  // 5
                                               this_device_mode as u8,  // 6
                                               other_device_mode as u8,  // 7
                                               owner_events as u8,  // 8
                                               classes_ptr as *const xcb_input_event_class_t);  // 9
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn grab_device_key_checked<'a>(c                : &'a base::Connection,
                                   grab_window      : xproto::Window,
                                   modifiers        : u16,
                                   modifier_device  : u8,
                                   grabbed_device   : u8,
                                   key              : u8,
                                   this_device_mode : u8,
                                   other_device_mode: u8,
                                   owner_events     : bool,
                                   classes          : &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_grab_device_key_checked(c.get_raw_conn(),
                                                       grab_window as xcb_window_t,  // 0
                                                       classes_len as u16,  // 1
                                                       modifiers as u16,  // 2
                                                       modifier_device as u8,  // 3
                                                       grabbed_device as u8,  // 4
                                                       key as u8,  // 5
                                                       this_device_mode as u8,  // 6
                                                       other_device_mode as u8,  // 7
                                                       owner_events as u8,  // 8
                                                       classes_ptr as *const xcb_input_event_class_t);  // 9
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNGRAB_DEVICE_KEY: u8 = 16;

pub fn ungrab_device_key<'a>(c              : &'a base::Connection,
                             grab_window    : xproto::Window,
                             modifiers      : u16,
                             modifier_device: u8,
                             key            : u8,
                             grabbed_device : u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_ungrab_device_key(c.get_raw_conn(),
                                                 grab_window as xcb_window_t,  // 0
                                                 modifiers as u16,  // 1
                                                 modifier_device as u8,  // 2
                                                 key as u8,  // 3
                                                 grabbed_device as u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn ungrab_device_key_checked<'a>(c              : &'a base::Connection,
                                     grab_window    : xproto::Window,
                                     modifiers      : u16,
                                     modifier_device: u8,
                                     key            : u8,
                                     grabbed_device : u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_ungrab_device_key_checked(c.get_raw_conn(),
                                                         grab_window as xcb_window_t,  // 0
                                                         modifiers as u16,  // 1
                                                         modifier_device as u8,  // 2
                                                         key as u8,  // 3
                                                         grabbed_device as u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GRAB_DEVICE_BUTTON: u8 = 17;

pub fn grab_device_button<'a>(c                : &'a base::Connection,
                              grab_window      : xproto::Window,
                              grabbed_device   : u8,
                              modifier_device  : u8,
                              modifiers        : u16,
                              this_device_mode : u8,
                              other_device_mode: u8,
                              button           : u8,
                              owner_events     : u8,
                              classes          : &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_grab_device_button(c.get_raw_conn(),
                                                  grab_window as xcb_window_t,  // 0
                                                  grabbed_device as u8,  // 1
                                                  modifier_device as u8,  // 2
                                                  classes_len as u16,  // 3
                                                  modifiers as u16,  // 4
                                                  this_device_mode as u8,  // 5
                                                  other_device_mode as u8,  // 6
                                                  button as u8,  // 7
                                                  owner_events as u8,  // 8
                                                  classes_ptr as *const xcb_input_event_class_t);  // 9
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn grab_device_button_checked<'a>(c                : &'a base::Connection,
                                      grab_window      : xproto::Window,
                                      grabbed_device   : u8,
                                      modifier_device  : u8,
                                      modifiers        : u16,
                                      this_device_mode : u8,
                                      other_device_mode: u8,
                                      button           : u8,
                                      owner_events     : u8,
                                      classes          : &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_grab_device_button_checked(c.get_raw_conn(),
                                                          grab_window as xcb_window_t,  // 0
                                                          grabbed_device as u8,  // 1
                                                          modifier_device as u8,  // 2
                                                          classes_len as u16,  // 3
                                                          modifiers as u16,  // 4
                                                          this_device_mode as u8,  // 5
                                                          other_device_mode as u8,  // 6
                                                          button as u8,  // 7
                                                          owner_events as u8,  // 8
                                                          classes_ptr as *const xcb_input_event_class_t);  // 9
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNGRAB_DEVICE_BUTTON: u8 = 18;

pub fn ungrab_device_button<'a>(c              : &'a base::Connection,
                                grab_window    : xproto::Window,
                                modifiers      : u16,
                                modifier_device: u8,
                                button         : u8,
                                grabbed_device : u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_ungrab_device_button(c.get_raw_conn(),
                                                    grab_window as xcb_window_t,  // 0
                                                    modifiers as u16,  // 1
                                                    modifier_device as u8,  // 2
                                                    button as u8,  // 3
                                                    grabbed_device as u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn ungrab_device_button_checked<'a>(c              : &'a base::Connection,
                                        grab_window    : xproto::Window,
                                        modifiers      : u16,
                                        modifier_device: u8,
                                        button         : u8,
                                        grabbed_device : u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_ungrab_device_button_checked(c.get_raw_conn(),
                                                            grab_window as xcb_window_t,  // 0
                                                            modifiers as u16,  // 1
                                                            modifier_device as u8,  // 2
                                                            button as u8,  // 3
                                                            grabbed_device as u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ALLOW_DEVICE_EVENTS: u8 = 19;

pub fn allow_device_events<'a>(c        : &'a base::Connection,
                               time     : xproto::Timestamp,
                               mode     : u8,
                               device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_allow_device_events(c.get_raw_conn(),
                                                   time as xcb_timestamp_t,  // 0
                                                   mode as u8,  // 1
                                                   device_id as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn allow_device_events_checked<'a>(c        : &'a base::Connection,
                                       time     : xproto::Timestamp,
                                       mode     : u8,
                                       device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_allow_device_events_checked(c.get_raw_conn(),
                                                           time as xcb_timestamp_t,  // 0
                                                           mode as u8,  // 1
                                                           device_id as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DEVICE_FOCUS: u8 = 20;

pub type GetDeviceFocusCookie<'a> = base::Cookie<'a, xcb_input_get_device_focus_cookie_t>;

impl<'a> GetDeviceFocusCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceFocusReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceFocusReply {
                    ptr: xcb_input_get_device_focus_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceFocusReply {
                    ptr: xcb_input_get_device_focus_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceFocusReply = base::Reply<xcb_input_get_device_focus_reply_t>;

impl GetDeviceFocusReply {
    pub fn focus(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).focus
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn revert_to(&self) -> u8 {
        unsafe {
            (*self.ptr).revert_to
        }
    }
}

pub fn get_device_focus<'a>(c        : &'a base::Connection,
                            device_id: u8)
        -> GetDeviceFocusCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_focus(c.get_raw_conn(),
                                                device_id as u8);  // 0
        GetDeviceFocusCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_focus_unchecked<'a>(c        : &'a base::Connection,
                                      device_id: u8)
        -> GetDeviceFocusCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_focus_unchecked(c.get_raw_conn(),
                                                          device_id as u8);  // 0
        GetDeviceFocusCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_DEVICE_FOCUS: u8 = 21;

pub fn set_device_focus<'a>(c        : &'a base::Connection,
                            focus    : xproto::Window,
                            time     : xproto::Timestamp,
                            revert_to: u8,
                            device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_set_device_focus(c.get_raw_conn(),
                                                focus as xcb_window_t,  // 0
                                                time as xcb_timestamp_t,  // 1
                                                revert_to as u8,  // 2
                                                device_id as u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_device_focus_checked<'a>(c        : &'a base::Connection,
                                    focus    : xproto::Window,
                                    time     : xproto::Timestamp,
                                    revert_to: u8,
                                    device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_set_device_focus_checked(c.get_raw_conn(),
                                                        focus as xcb_window_t,  // 0
                                                        time as xcb_timestamp_t,  // 1
                                                        revert_to as u8,  // 2
                                                        device_id as u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub type KbdFeedbackState<'a> = base::StructPtr<'a, xcb_input_kbd_feedback_state_t>;

impl<'a> KbdFeedbackState<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            (*self.ptr).feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn pitch(&self) -> u16 {
        unsafe {
            (*self.ptr).pitch
        }
    }
    pub fn duration(&self) -> u16 {
        unsafe {
            (*self.ptr).duration
        }
    }
    pub fn led_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).led_mask
        }
    }
    pub fn led_values(&self) -> u32 {
        unsafe {
            (*self.ptr).led_values
        }
    }
    pub fn global_auto_repeat(&self) -> bool {
        unsafe {
            (*self.ptr).global_auto_repeat != 0
        }
    }
    pub fn click(&self) -> u8 {
        unsafe {
            (*self.ptr).click
        }
    }
    pub fn percent(&self) -> u8 {
        unsafe {
            (*self.ptr).percent
        }
    }
    pub fn auto_repeats(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).auto_repeats
        }
    }
}

pub type KbdFeedbackStateIterator<'a> = xcb_input_kbd_feedback_state_iterator_t<'a>;

impl<'a> Iterator for KbdFeedbackStateIterator<'a> {
    type Item = KbdFeedbackState<'a>;
    fn next(&mut self) -> std::option::Option<KbdFeedbackState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_kbd_feedback_state_iterator_t;
                let data = (*iter).data;
                xcb_input_kbd_feedback_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct PtrFeedbackState {
    pub base: xcb_input_ptr_feedback_state_t,
}

impl PtrFeedbackState {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               feedback_id: u8,
               len:         u16,
               accel_num:   u16,
               accel_denom: u16,
               threshold:   u16)
            -> PtrFeedbackState {
        unsafe {
            PtrFeedbackState {
                base: xcb_input_ptr_feedback_state_t {
                    class_id:    class_id,
                    feedback_id: feedback_id,
                    len:         len,
                    pad0:        [0; 2],
                    accel_num:   accel_num,
                    accel_denom: accel_denom,
                    threshold:   threshold,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn accel_num(&self) -> u16 {
        unsafe {
            self.base.accel_num
        }
    }
    pub fn accel_denom(&self) -> u16 {
        unsafe {
            self.base.accel_denom
        }
    }
    pub fn threshold(&self) -> u16 {
        unsafe {
            self.base.threshold
        }
    }
}

pub type PtrFeedbackStateIterator = xcb_input_ptr_feedback_state_iterator_t;

impl Iterator for PtrFeedbackStateIterator {
    type Item = PtrFeedbackState;
    fn next(&mut self) -> std::option::Option<PtrFeedbackState> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_ptr_feedback_state_iterator_t;
                let data = (*iter).data;
                xcb_input_ptr_feedback_state_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct IntegerFeedbackState {
    pub base: xcb_input_integer_feedback_state_t,
}

impl IntegerFeedbackState {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               feedback_id: u8,
               len:         u16,
               resolution:  u32,
               min_value:   i32,
               max_value:   i32)
            -> IntegerFeedbackState {
        unsafe {
            IntegerFeedbackState {
                base: xcb_input_integer_feedback_state_t {
                    class_id:    class_id,
                    feedback_id: feedback_id,
                    len:         len,
                    resolution:  resolution,
                    min_value:   min_value,
                    max_value:   max_value,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn resolution(&self) -> u32 {
        unsafe {
            self.base.resolution
        }
    }
    pub fn min_value(&self) -> i32 {
        unsafe {
            self.base.min_value
        }
    }
    pub fn max_value(&self) -> i32 {
        unsafe {
            self.base.max_value
        }
    }
}

pub type IntegerFeedbackStateIterator = xcb_input_integer_feedback_state_iterator_t;

impl Iterator for IntegerFeedbackStateIterator {
    type Item = IntegerFeedbackState;
    fn next(&mut self) -> std::option::Option<IntegerFeedbackState> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_integer_feedback_state_iterator_t;
                let data = (*iter).data;
                xcb_input_integer_feedback_state_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type StringFeedbackState<'a> = base::StructPtr<'a, xcb_input_string_feedback_state_t>;

impl<'a> StringFeedbackState<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            (*self.ptr).feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn max_symbols(&self) -> u16 {
        unsafe {
            (*self.ptr).max_symbols
        }
    }
    pub fn num_keysyms(&self) -> u16 {
        unsafe {
            (*self.ptr).num_keysyms
        }
    }
    pub fn keysyms(&self) -> &[xproto::Keysym] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_string_feedback_state_keysyms_length(field) as usize;
            let data = xcb_input_string_feedback_state_keysyms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type StringFeedbackStateIterator<'a> = xcb_input_string_feedback_state_iterator_t<'a>;

impl<'a> Iterator for StringFeedbackStateIterator<'a> {
    type Item = StringFeedbackState<'a>;
    fn next(&mut self) -> std::option::Option<StringFeedbackState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_string_feedback_state_iterator_t;
                let data = (*iter).data;
                xcb_input_string_feedback_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct BellFeedbackState {
    pub base: xcb_input_bell_feedback_state_t,
}

impl BellFeedbackState {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               feedback_id: u8,
               len:         u16,
               percent:     u8,
               pitch:       u16,
               duration:    u16)
            -> BellFeedbackState {
        unsafe {
            BellFeedbackState {
                base: xcb_input_bell_feedback_state_t {
                    class_id:    class_id,
                    feedback_id: feedback_id,
                    len:         len,
                    percent:     percent,
                    pad0:        [0; 3],
                    pitch:       pitch,
                    duration:    duration,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn percent(&self) -> u8 {
        unsafe {
            self.base.percent
        }
    }
    pub fn pitch(&self) -> u16 {
        unsafe {
            self.base.pitch
        }
    }
    pub fn duration(&self) -> u16 {
        unsafe {
            self.base.duration
        }
    }
}

pub type BellFeedbackStateIterator = xcb_input_bell_feedback_state_iterator_t;

impl Iterator for BellFeedbackStateIterator {
    type Item = BellFeedbackState;
    fn next(&mut self) -> std::option::Option<BellFeedbackState> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_bell_feedback_state_iterator_t;
                let data = (*iter).data;
                xcb_input_bell_feedback_state_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct LedFeedbackState {
    pub base: xcb_input_led_feedback_state_t,
}

impl LedFeedbackState {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               feedback_id: u8,
               len:         u16,
               led_mask:    u32,
               led_values:  u32)
            -> LedFeedbackState {
        unsafe {
            LedFeedbackState {
                base: xcb_input_led_feedback_state_t {
                    class_id:    class_id,
                    feedback_id: feedback_id,
                    len:         len,
                    led_mask:    led_mask,
                    led_values:  led_values,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn led_mask(&self) -> u32 {
        unsafe {
            self.base.led_mask
        }
    }
    pub fn led_values(&self) -> u32 {
        unsafe {
            self.base.led_values
        }
    }
}

pub type LedFeedbackStateIterator = xcb_input_led_feedback_state_iterator_t;

impl Iterator for LedFeedbackStateIterator {
    type Item = LedFeedbackState;
    fn next(&mut self) -> std::option::Option<LedFeedbackState> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_led_feedback_state_iterator_t;
                let data = (*iter).data;
                xcb_input_led_feedback_state_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type FeedbackState<'a> = base::StructPtr<'a, xcb_input_feedback_state_t>;

impl<'a> FeedbackState<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            (*self.ptr).feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn uninterpreted_data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_feedback_state_uninterpreted_data_length(field) as usize;
            let data = xcb_input_feedback_state_uninterpreted_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type FeedbackStateIterator<'a> = xcb_input_feedback_state_iterator_t<'a>;

impl<'a> Iterator for FeedbackStateIterator<'a> {
    type Item = FeedbackState<'a>;
    fn next(&mut self) -> std::option::Option<FeedbackState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_feedback_state_iterator_t;
                let data = (*iter).data;
                xcb_input_feedback_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const GET_FEEDBACK_CONTROL: u8 = 22;

pub type GetFeedbackControlCookie<'a> = base::Cookie<'a, xcb_input_get_feedback_control_cookie_t>;

impl<'a> GetFeedbackControlCookie<'a> {
    pub fn get_reply(&self) -> Result<GetFeedbackControlReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetFeedbackControlReply {
                    ptr: xcb_input_get_feedback_control_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetFeedbackControlReply {
                    ptr: xcb_input_get_feedback_control_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetFeedbackControlReply = base::Reply<xcb_input_get_feedback_control_reply_t>;

impl GetFeedbackControlReply {
    pub fn num_feedbacks(&self) -> u16 {
        unsafe {
            (*self.ptr).num_feedbacks
        }
    }
    pub fn feedbacks(&self) -> FeedbackStateIterator {
        unsafe {
            xcb_input_get_feedback_control_feedbacks_iterator(self.ptr)
        }
    }
}

pub fn get_feedback_control<'a>(c        : &'a base::Connection,
                                device_id: u8)
        -> GetFeedbackControlCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_feedback_control(c.get_raw_conn(),
                                                    device_id as u8);  // 0
        GetFeedbackControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_feedback_control_unchecked<'a>(c        : &'a base::Connection,
                                          device_id: u8)
        -> GetFeedbackControlCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_feedback_control_unchecked(c.get_raw_conn(),
                                                              device_id as u8);  // 0
        GetFeedbackControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

#[derive(Copy, Clone)]
pub struct KbdFeedbackCtl {
    pub base: xcb_input_kbd_feedback_ctl_t,
}

impl KbdFeedbackCtl {
    #[allow(unused_unsafe)]
    pub fn new(class_id:          u8,
               feedback_id:       u8,
               len:               u16,
               key:               KeyCode,
               auto_repeat_mode:  u8,
               key_click_percent: i8,
               bell_percent:      i8,
               bell_pitch:        i16,
               bell_duration:     i16,
               led_mask:          u32,
               led_values:        u32)
            -> KbdFeedbackCtl {
        unsafe {
            KbdFeedbackCtl {
                base: xcb_input_kbd_feedback_ctl_t {
                    class_id:          class_id,
                    feedback_id:       feedback_id,
                    len:               len,
                    key:               key,
                    auto_repeat_mode:  auto_repeat_mode,
                    key_click_percent: key_click_percent,
                    bell_percent:      bell_percent,
                    bell_pitch:        bell_pitch,
                    bell_duration:     bell_duration,
                    led_mask:          led_mask,
                    led_values:        led_values,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn key(&self) -> KeyCode {
        unsafe {
            self.base.key
        }
    }
    pub fn auto_repeat_mode(&self) -> u8 {
        unsafe {
            self.base.auto_repeat_mode
        }
    }
    pub fn key_click_percent(&self) -> i8 {
        unsafe {
            self.base.key_click_percent
        }
    }
    pub fn bell_percent(&self) -> i8 {
        unsafe {
            self.base.bell_percent
        }
    }
    pub fn bell_pitch(&self) -> i16 {
        unsafe {
            self.base.bell_pitch
        }
    }
    pub fn bell_duration(&self) -> i16 {
        unsafe {
            self.base.bell_duration
        }
    }
    pub fn led_mask(&self) -> u32 {
        unsafe {
            self.base.led_mask
        }
    }
    pub fn led_values(&self) -> u32 {
        unsafe {
            self.base.led_values
        }
    }
}

pub type KbdFeedbackCtlIterator = xcb_input_kbd_feedback_ctl_iterator_t;

impl Iterator for KbdFeedbackCtlIterator {
    type Item = KbdFeedbackCtl;
    fn next(&mut self) -> std::option::Option<KbdFeedbackCtl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_kbd_feedback_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_kbd_feedback_ctl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct PtrFeedbackCtl {
    pub base: xcb_input_ptr_feedback_ctl_t,
}

impl PtrFeedbackCtl {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               feedback_id: u8,
               len:         u16,
               num:         i16,
               denom:       i16,
               threshold:   i16)
            -> PtrFeedbackCtl {
        unsafe {
            PtrFeedbackCtl {
                base: xcb_input_ptr_feedback_ctl_t {
                    class_id:    class_id,
                    feedback_id: feedback_id,
                    len:         len,
                    pad0:        [0; 2],
                    num:         num,
                    denom:       denom,
                    threshold:   threshold,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn num(&self) -> i16 {
        unsafe {
            self.base.num
        }
    }
    pub fn denom(&self) -> i16 {
        unsafe {
            self.base.denom
        }
    }
    pub fn threshold(&self) -> i16 {
        unsafe {
            self.base.threshold
        }
    }
}

pub type PtrFeedbackCtlIterator = xcb_input_ptr_feedback_ctl_iterator_t;

impl Iterator for PtrFeedbackCtlIterator {
    type Item = PtrFeedbackCtl;
    fn next(&mut self) -> std::option::Option<PtrFeedbackCtl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_ptr_feedback_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_ptr_feedback_ctl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct IntegerFeedbackCtl {
    pub base: xcb_input_integer_feedback_ctl_t,
}

impl IntegerFeedbackCtl {
    #[allow(unused_unsafe)]
    pub fn new(class_id:       u8,
               feedback_id:    u8,
               len:            u16,
               int_to_display: i32)
            -> IntegerFeedbackCtl {
        unsafe {
            IntegerFeedbackCtl {
                base: xcb_input_integer_feedback_ctl_t {
                    class_id:       class_id,
                    feedback_id:    feedback_id,
                    len:            len,
                    int_to_display: int_to_display,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn int_to_display(&self) -> i32 {
        unsafe {
            self.base.int_to_display
        }
    }
}

pub type IntegerFeedbackCtlIterator = xcb_input_integer_feedback_ctl_iterator_t;

impl Iterator for IntegerFeedbackCtlIterator {
    type Item = IntegerFeedbackCtl;
    fn next(&mut self) -> std::option::Option<IntegerFeedbackCtl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_integer_feedback_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_integer_feedback_ctl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type StringFeedbackCtl<'a> = base::StructPtr<'a, xcb_input_string_feedback_ctl_t>;

impl<'a> StringFeedbackCtl<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            (*self.ptr).feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn num_keysyms(&self) -> u16 {
        unsafe {
            (*self.ptr).num_keysyms
        }
    }
    pub fn keysyms(&self) -> &[xproto::Keysym] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_string_feedback_ctl_keysyms_length(field) as usize;
            let data = xcb_input_string_feedback_ctl_keysyms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type StringFeedbackCtlIterator<'a> = xcb_input_string_feedback_ctl_iterator_t<'a>;

impl<'a> Iterator for StringFeedbackCtlIterator<'a> {
    type Item = StringFeedbackCtl<'a>;
    fn next(&mut self) -> std::option::Option<StringFeedbackCtl<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_string_feedback_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_string_feedback_ctl_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct BellFeedbackCtl {
    pub base: xcb_input_bell_feedback_ctl_t,
}

impl BellFeedbackCtl {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               feedback_id: u8,
               len:         u16,
               percent:     i8,
               pitch:       i16,
               duration:    i16)
            -> BellFeedbackCtl {
        unsafe {
            BellFeedbackCtl {
                base: xcb_input_bell_feedback_ctl_t {
                    class_id:    class_id,
                    feedback_id: feedback_id,
                    len:         len,
                    percent:     percent,
                    pad0:        [0; 3],
                    pitch:       pitch,
                    duration:    duration,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn percent(&self) -> i8 {
        unsafe {
            self.base.percent
        }
    }
    pub fn pitch(&self) -> i16 {
        unsafe {
            self.base.pitch
        }
    }
    pub fn duration(&self) -> i16 {
        unsafe {
            self.base.duration
        }
    }
}

pub type BellFeedbackCtlIterator = xcb_input_bell_feedback_ctl_iterator_t;

impl Iterator for BellFeedbackCtlIterator {
    type Item = BellFeedbackCtl;
    fn next(&mut self) -> std::option::Option<BellFeedbackCtl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_bell_feedback_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_bell_feedback_ctl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct LedFeedbackCtl {
    pub base: xcb_input_led_feedback_ctl_t,
}

impl LedFeedbackCtl {
    #[allow(unused_unsafe)]
    pub fn new(class_id:    u8,
               feedback_id: u8,
               len:         u16,
               led_mask:    u32,
               led_values:  u32)
            -> LedFeedbackCtl {
        unsafe {
            LedFeedbackCtl {
                base: xcb_input_led_feedback_ctl_t {
                    class_id:    class_id,
                    feedback_id: feedback_id,
                    len:         len,
                    led_mask:    led_mask,
                    led_values:  led_values,
                }
            }
        }
    }
    pub fn class_id(&self) -> u8 {
        unsafe {
            self.base.class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            self.base.feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn led_mask(&self) -> u32 {
        unsafe {
            self.base.led_mask
        }
    }
    pub fn led_values(&self) -> u32 {
        unsafe {
            self.base.led_values
        }
    }
}

pub type LedFeedbackCtlIterator = xcb_input_led_feedback_ctl_iterator_t;

impl Iterator for LedFeedbackCtlIterator {
    type Item = LedFeedbackCtl;
    fn next(&mut self) -> std::option::Option<LedFeedbackCtl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_led_feedback_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_led_feedback_ctl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type FeedbackCtl<'a> = base::StructPtr<'a, xcb_input_feedback_ctl_t>;

impl<'a> FeedbackCtl<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn feedback_id(&self) -> u8 {
        unsafe {
            (*self.ptr).feedback_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn uninterpreted_data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_feedback_ctl_uninterpreted_data_length(field) as usize;
            let data = xcb_input_feedback_ctl_uninterpreted_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type FeedbackCtlIterator<'a> = xcb_input_feedback_ctl_iterator_t<'a>;

impl<'a> Iterator for FeedbackCtlIterator<'a> {
    type Item = FeedbackCtl<'a>;
    fn next(&mut self) -> std::option::Option<FeedbackCtl<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_feedback_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_feedback_ctl_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const CHANGE_FEEDBACK_CONTROL: u8 = 23;

pub fn change_feedback_control<'a>(c          : &'a base::Connection,
                                   mask       : u32,
                                   device_id  : u8,
                                   feedback_id: u8,
                                   feedback   : std::option::Option<FeedbackCtl>)
        -> base::VoidCookie<'a> {
    unsafe {
        let feedback_ptr = match feedback {
            Some(p) => p.ptr as *mut xcb_input_feedback_ctl_t,
            None => std::ptr::null()
        };
        let cookie = xcb_input_change_feedback_control(c.get_raw_conn(),
                                                       mask as u32,  // 0
                                                       device_id as u8,  // 1
                                                       feedback_id as u8,  // 2
                                                       feedback_ptr);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_feedback_control_checked<'a>(c          : &'a base::Connection,
                                           mask       : u32,
                                           device_id  : u8,
                                           feedback_id: u8,
                                           feedback   : std::option::Option<FeedbackCtl>)
        -> base::VoidCookie<'a> {
    unsafe {
        let feedback_ptr = match feedback {
            Some(p) => p.ptr as *mut xcb_input_feedback_ctl_t,
            None => std::ptr::null()
        };
        let cookie = xcb_input_change_feedback_control_checked(c.get_raw_conn(),
                                                               mask as u32,  // 0
                                                               device_id as u8,  // 1
                                                               feedback_id as u8,  // 2
                                                               feedback_ptr);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DEVICE_KEY_MAPPING: u8 = 24;

pub type GetDeviceKeyMappingCookie<'a> = base::Cookie<'a, xcb_input_get_device_key_mapping_cookie_t>;

impl<'a> GetDeviceKeyMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceKeyMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceKeyMappingReply {
                    ptr: xcb_input_get_device_key_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceKeyMappingReply {
                    ptr: xcb_input_get_device_key_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceKeyMappingReply = base::Reply<xcb_input_get_device_key_mapping_reply_t>;

impl GetDeviceKeyMappingReply {
    pub fn keysyms_per_keycode(&self) -> u8 {
        unsafe {
            (*self.ptr).keysyms_per_keycode
        }
    }
    pub fn keysyms(&self) -> &[xproto::Keysym] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_get_device_key_mapping_keysyms_length(field) as usize;
            let data = xcb_input_get_device_key_mapping_keysyms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_device_key_mapping<'a>(c            : &'a base::Connection,
                                  device_id    : u8,
                                  first_keycode: KeyCode,
                                  count        : u8)
        -> GetDeviceKeyMappingCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_key_mapping(c.get_raw_conn(),
                                                      device_id as u8,  // 0
                                                      first_keycode as xcb_input_key_code_t,  // 1
                                                      count as u8);  // 2
        GetDeviceKeyMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_key_mapping_unchecked<'a>(c            : &'a base::Connection,
                                            device_id    : u8,
                                            first_keycode: KeyCode,
                                            count        : u8)
        -> GetDeviceKeyMappingCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_key_mapping_unchecked(c.get_raw_conn(),
                                                                device_id as u8,  // 0
                                                                first_keycode as xcb_input_key_code_t,  // 1
                                                                count as u8);  // 2
        GetDeviceKeyMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_DEVICE_KEY_MAPPING: u8 = 25;

pub fn change_device_key_mapping<'a>(c                  : &'a base::Connection,
                                     device_id          : u8,
                                     first_keycode      : KeyCode,
                                     keysyms_per_keycode: u8,
                                     keysyms            : &[xproto::Keysym])
        -> base::VoidCookie<'a> {
    unsafe {
        let keysyms_len = keysyms.len();
        let keysyms_ptr = keysyms.as_ptr();
        let cookie = xcb_input_change_device_key_mapping(c.get_raw_conn(),
                                                         device_id as u8,  // 0
                                                         first_keycode as xcb_input_key_code_t,  // 1
                                                         keysyms_per_keycode as u8,  // 2
                                                         keysyms_len as u8,  // 3
                                                         keysyms_ptr as *const xcb_keysym_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_device_key_mapping_checked<'a>(c                  : &'a base::Connection,
                                             device_id          : u8,
                                             first_keycode      : KeyCode,
                                             keysyms_per_keycode: u8,
                                             keysyms            : &[xproto::Keysym])
        -> base::VoidCookie<'a> {
    unsafe {
        let keysyms_len = keysyms.len();
        let keysyms_ptr = keysyms.as_ptr();
        let cookie = xcb_input_change_device_key_mapping_checked(c.get_raw_conn(),
                                                                 device_id as u8,  // 0
                                                                 first_keycode as xcb_input_key_code_t,  // 1
                                                                 keysyms_per_keycode as u8,  // 2
                                                                 keysyms_len as u8,  // 3
                                                                 keysyms_ptr as *const xcb_keysym_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DEVICE_MODIFIER_MAPPING: u8 = 26;

pub type GetDeviceModifierMappingCookie<'a> = base::Cookie<'a, xcb_input_get_device_modifier_mapping_cookie_t>;

impl<'a> GetDeviceModifierMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceModifierMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceModifierMappingReply {
                    ptr: xcb_input_get_device_modifier_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceModifierMappingReply {
                    ptr: xcb_input_get_device_modifier_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceModifierMappingReply = base::Reply<xcb_input_get_device_modifier_mapping_reply_t>;

impl GetDeviceModifierMappingReply {
    pub fn keycodes_per_modifier(&self) -> u8 {
        unsafe {
            (*self.ptr).keycodes_per_modifier
        }
    }
    pub fn keymaps(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_get_device_modifier_mapping_keymaps_length(field) as usize;
            let data = xcb_input_get_device_modifier_mapping_keymaps(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_device_modifier_mapping<'a>(c        : &'a base::Connection,
                                       device_id: u8)
        -> GetDeviceModifierMappingCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_modifier_mapping(c.get_raw_conn(),
                                                           device_id as u8);  // 0
        GetDeviceModifierMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_modifier_mapping_unchecked<'a>(c        : &'a base::Connection,
                                                 device_id: u8)
        -> GetDeviceModifierMappingCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_modifier_mapping_unchecked(c.get_raw_conn(),
                                                                     device_id as u8);  // 0
        GetDeviceModifierMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_DEVICE_MODIFIER_MAPPING: u8 = 27;

pub type SetDeviceModifierMappingCookie<'a> = base::Cookie<'a, xcb_input_set_device_modifier_mapping_cookie_t>;

impl<'a> SetDeviceModifierMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<SetDeviceModifierMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetDeviceModifierMappingReply {
                    ptr: xcb_input_set_device_modifier_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetDeviceModifierMappingReply {
                    ptr: xcb_input_set_device_modifier_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetDeviceModifierMappingReply = base::Reply<xcb_input_set_device_modifier_mapping_reply_t>;

impl SetDeviceModifierMappingReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn set_device_modifier_mapping<'a>(c        : &'a base::Connection,
                                       device_id: u8,
                                       keymaps  : &[u8])
        -> SetDeviceModifierMappingCookie<'a> {
    unsafe {
        let keymaps_len = keymaps.len();
        let keymaps_ptr = keymaps.as_ptr();
        let cookie = xcb_input_set_device_modifier_mapping(c.get_raw_conn(),
                                                           device_id as u8,  // 0
                                                           keymaps_len as u8,  // 1
                                                           keymaps_ptr as *const u8);  // 2
        SetDeviceModifierMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_device_modifier_mapping_unchecked<'a>(c        : &'a base::Connection,
                                                 device_id: u8,
                                                 keymaps  : &[u8])
        -> SetDeviceModifierMappingCookie<'a> {
    unsafe {
        let keymaps_len = keymaps.len();
        let keymaps_ptr = keymaps.as_ptr();
        let cookie = xcb_input_set_device_modifier_mapping_unchecked(c.get_raw_conn(),
                                                                     device_id as u8,  // 0
                                                                     keymaps_len as u8,  // 1
                                                                     keymaps_ptr as *const u8);  // 2
        SetDeviceModifierMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_DEVICE_BUTTON_MAPPING: u8 = 28;

pub type GetDeviceButtonMappingCookie<'a> = base::Cookie<'a, xcb_input_get_device_button_mapping_cookie_t>;

impl<'a> GetDeviceButtonMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceButtonMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceButtonMappingReply {
                    ptr: xcb_input_get_device_button_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceButtonMappingReply {
                    ptr: xcb_input_get_device_button_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceButtonMappingReply = base::Reply<xcb_input_get_device_button_mapping_reply_t>;

impl GetDeviceButtonMappingReply {
    pub fn map_size(&self) -> u8 {
        unsafe {
            (*self.ptr).map_size
        }
    }
    pub fn map(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_get_device_button_mapping_map_length(field) as usize;
            let data = xcb_input_get_device_button_mapping_map(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_device_button_mapping<'a>(c        : &'a base::Connection,
                                     device_id: u8)
        -> GetDeviceButtonMappingCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_button_mapping(c.get_raw_conn(),
                                                         device_id as u8);  // 0
        GetDeviceButtonMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_button_mapping_unchecked<'a>(c        : &'a base::Connection,
                                               device_id: u8)
        -> GetDeviceButtonMappingCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_button_mapping_unchecked(c.get_raw_conn(),
                                                                   device_id as u8);  // 0
        GetDeviceButtonMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_DEVICE_BUTTON_MAPPING: u8 = 29;

pub type SetDeviceButtonMappingCookie<'a> = base::Cookie<'a, xcb_input_set_device_button_mapping_cookie_t>;

impl<'a> SetDeviceButtonMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<SetDeviceButtonMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetDeviceButtonMappingReply {
                    ptr: xcb_input_set_device_button_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetDeviceButtonMappingReply {
                    ptr: xcb_input_set_device_button_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetDeviceButtonMappingReply = base::Reply<xcb_input_set_device_button_mapping_reply_t>;

impl SetDeviceButtonMappingReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn set_device_button_mapping<'a>(c        : &'a base::Connection,
                                     device_id: u8,
                                     map      : &[u8])
        -> SetDeviceButtonMappingCookie<'a> {
    unsafe {
        let map_len = map.len();
        let map_ptr = map.as_ptr();
        let cookie = xcb_input_set_device_button_mapping(c.get_raw_conn(),
                                                         device_id as u8,  // 0
                                                         map_len as u8,  // 1
                                                         map_ptr as *const u8);  // 2
        SetDeviceButtonMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_device_button_mapping_unchecked<'a>(c        : &'a base::Connection,
                                               device_id: u8,
                                               map      : &[u8])
        -> SetDeviceButtonMappingCookie<'a> {
    unsafe {
        let map_len = map.len();
        let map_ptr = map.as_ptr();
        let cookie = xcb_input_set_device_button_mapping_unchecked(c.get_raw_conn(),
                                                                   device_id as u8,  // 0
                                                                   map_len as u8,  // 1
                                                                   map_ptr as *const u8);  // 2
        SetDeviceButtonMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type KeyState<'a> = base::StructPtr<'a, xcb_input_key_state_t>;

impl<'a> KeyState<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn len(&self) -> u8 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn num_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).num_keys
        }
    }
    pub fn keys(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).keys
        }
    }
}

pub type KeyStateIterator<'a> = xcb_input_key_state_iterator_t<'a>;

impl<'a> Iterator for KeyStateIterator<'a> {
    type Item = KeyState<'a>;
    fn next(&mut self) -> std::option::Option<KeyState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_key_state_iterator_t;
                let data = (*iter).data;
                xcb_input_key_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type ButtonState<'a> = base::StructPtr<'a, xcb_input_button_state_t>;

impl<'a> ButtonState<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn len(&self) -> u8 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn num_buttons(&self) -> u8 {
        unsafe {
            (*self.ptr).num_buttons
        }
    }
    pub fn buttons(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).buttons
        }
    }
}

pub type ButtonStateIterator<'a> = xcb_input_button_state_iterator_t<'a>;

impl<'a> Iterator for ButtonStateIterator<'a> {
    type Item = ButtonState<'a>;
    fn next(&mut self) -> std::option::Option<ButtonState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_button_state_iterator_t;
                let data = (*iter).data;
                xcb_input_button_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type ValuatorState<'a> = base::StructPtr<'a, xcb_input_valuator_state_t>;

impl<'a> ValuatorState<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn len(&self) -> u8 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn num_valuators(&self) -> u8 {
        unsafe {
            (*self.ptr).num_valuators
        }
    }
    pub fn mode(&self) -> u8 {
        unsafe {
            (*self.ptr).mode
        }
    }
    pub fn valuators(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_valuator_state_valuators_length(field) as usize;
            let data = xcb_input_valuator_state_valuators(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type ValuatorStateIterator<'a> = xcb_input_valuator_state_iterator_t<'a>;

impl<'a> Iterator for ValuatorStateIterator<'a> {
    type Item = ValuatorState<'a>;
    fn next(&mut self) -> std::option::Option<ValuatorState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_valuator_state_iterator_t;
                let data = (*iter).data;
                xcb_input_valuator_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type InputState<'a> = base::StructPtr<'a, xcb_input_input_state_t>;

impl<'a> InputState<'a> {
    pub fn class_id(&self) -> u8 {
        unsafe {
            (*self.ptr).class_id
        }
    }
    pub fn len(&self) -> u8 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn num_items(&self) -> u8 {
        unsafe {
            (*self.ptr).num_items
        }
    }
    pub fn uninterpreted_data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_input_state_uninterpreted_data_length(field) as usize;
            let data = xcb_input_input_state_uninterpreted_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type InputStateIterator<'a> = xcb_input_input_state_iterator_t<'a>;

impl<'a> Iterator for InputStateIterator<'a> {
    type Item = InputState<'a>;
    fn next(&mut self) -> std::option::Option<InputState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_input_state_iterator_t;
                let data = (*iter).data;
                xcb_input_input_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const QUERY_DEVICE_STATE: u8 = 30;

pub type QueryDeviceStateCookie<'a> = base::Cookie<'a, xcb_input_query_device_state_cookie_t>;

impl<'a> QueryDeviceStateCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryDeviceStateReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryDeviceStateReply {
                    ptr: xcb_input_query_device_state_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryDeviceStateReply {
                    ptr: xcb_input_query_device_state_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryDeviceStateReply = base::Reply<xcb_input_query_device_state_reply_t>;

impl QueryDeviceStateReply {
    pub fn num_classes(&self) -> u8 {
        unsafe {
            (*self.ptr).num_classes
        }
    }
    pub fn classes(&self) -> InputStateIterator {
        unsafe {
            xcb_input_query_device_state_classes_iterator(self.ptr)
        }
    }
}

pub fn query_device_state<'a>(c        : &'a base::Connection,
                              device_id: u8)
        -> QueryDeviceStateCookie<'a> {
    unsafe {
        let cookie = xcb_input_query_device_state(c.get_raw_conn(),
                                                  device_id as u8);  // 0
        QueryDeviceStateCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_device_state_unchecked<'a>(c        : &'a base::Connection,
                                        device_id: u8)
        -> QueryDeviceStateCookie<'a> {
    unsafe {
        let cookie = xcb_input_query_device_state_unchecked(c.get_raw_conn(),
                                                            device_id as u8);  // 0
        QueryDeviceStateCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SEND_EXTENSION_EVENT: u8 = 31;

pub fn send_extension_event<'a>(c          : &'a base::Connection,
                                destination: xproto::Window,
                                device_id  : u8,
                                propagate  : bool,
                                events     : &[u8],
                                classes    : &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let events_len = events.len();
        let events_ptr = events.as_ptr();
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_send_extension_event(c.get_raw_conn(),
                                                    destination as xcb_window_t,  // 0
                                                    device_id as u8,  // 1
                                                    propagate as u8,  // 2
                                                    classes_len as u16,  // 3
                                                    events_len as u8,  // 4
                                                    events_ptr as *const u8,  // 5
                                                    classes_ptr as *const xcb_input_event_class_t);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn send_extension_event_checked<'a>(c          : &'a base::Connection,
                                        destination: xproto::Window,
                                        device_id  : u8,
                                        propagate  : bool,
                                        events     : &[u8],
                                        classes    : &[EventClass])
        -> base::VoidCookie<'a> {
    unsafe {
        let events_len = events.len();
        let events_ptr = events.as_ptr();
        let classes_len = classes.len();
        let classes_ptr = classes.as_ptr();
        let cookie = xcb_input_send_extension_event_checked(c.get_raw_conn(),
                                                            destination as xcb_window_t,  // 0
                                                            device_id as u8,  // 1
                                                            propagate as u8,  // 2
                                                            classes_len as u16,  // 3
                                                            events_len as u8,  // 4
                                                            events_ptr as *const u8,  // 5
                                                            classes_ptr as *const xcb_input_event_class_t);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DEVICE_BELL: u8 = 32;

pub fn device_bell<'a>(c             : &'a base::Connection,
                       device_id     : u8,
                       feedback_id   : u8,
                       feedback_class: u8,
                       percent       : i8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_device_bell(c.get_raw_conn(),
                                           device_id as u8,  // 0
                                           feedback_id as u8,  // 1
                                           feedback_class as u8,  // 2
                                           percent as i8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn device_bell_checked<'a>(c             : &'a base::Connection,
                               device_id     : u8,
                               feedback_id   : u8,
                               feedback_class: u8,
                               percent       : i8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_device_bell_checked(c.get_raw_conn(),
                                                   device_id as u8,  // 0
                                                   feedback_id as u8,  // 1
                                                   feedback_class as u8,  // 2
                                                   percent as i8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_DEVICE_VALUATORS: u8 = 33;

pub type SetDeviceValuatorsCookie<'a> = base::Cookie<'a, xcb_input_set_device_valuators_cookie_t>;

impl<'a> SetDeviceValuatorsCookie<'a> {
    pub fn get_reply(&self) -> Result<SetDeviceValuatorsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetDeviceValuatorsReply {
                    ptr: xcb_input_set_device_valuators_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetDeviceValuatorsReply {
                    ptr: xcb_input_set_device_valuators_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetDeviceValuatorsReply = base::Reply<xcb_input_set_device_valuators_reply_t>;

impl SetDeviceValuatorsReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn set_device_valuators<'a>(c             : &'a base::Connection,
                                device_id     : u8,
                                first_valuator: u8,
                                valuators     : &[i32])
        -> SetDeviceValuatorsCookie<'a> {
    unsafe {
        let valuators_len = valuators.len();
        let valuators_ptr = valuators.as_ptr();
        let cookie = xcb_input_set_device_valuators(c.get_raw_conn(),
                                                    device_id as u8,  // 0
                                                    first_valuator as u8,  // 1
                                                    valuators_len as u8,  // 2
                                                    valuators_ptr as *const i32);  // 3
        SetDeviceValuatorsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_device_valuators_unchecked<'a>(c             : &'a base::Connection,
                                          device_id     : u8,
                                          first_valuator: u8,
                                          valuators     : &[i32])
        -> SetDeviceValuatorsCookie<'a> {
    unsafe {
        let valuators_len = valuators.len();
        let valuators_ptr = valuators.as_ptr();
        let cookie = xcb_input_set_device_valuators_unchecked(c.get_raw_conn(),
                                                              device_id as u8,  // 0
                                                              first_valuator as u8,  // 1
                                                              valuators_len as u8,  // 2
                                                              valuators_ptr as *const i32);  // 3
        SetDeviceValuatorsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type DeviceResolutionState<'a> = base::StructPtr<'a, xcb_input_device_resolution_state_t>;

impl<'a> DeviceResolutionState<'a> {
    pub fn control_id(&self) -> u16 {
        unsafe {
            (*self.ptr).control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn num_valuators(&self) -> u32 {
        unsafe {
            (*self.ptr).num_valuators
        }
    }
    pub fn resolution_values(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_device_resolution_state_resolution_values_length(field) as usize;
            let data = xcb_input_device_resolution_state_resolution_values(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn resolution_min(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_device_resolution_state_resolution_min_length(field) as usize;
            let data = xcb_input_device_resolution_state_resolution_min(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn resolution_max(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_device_resolution_state_resolution_max_length(field) as usize;
            let data = xcb_input_device_resolution_state_resolution_max(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type DeviceResolutionStateIterator<'a> = xcb_input_device_resolution_state_iterator_t<'a>;

impl<'a> Iterator for DeviceResolutionStateIterator<'a> {
    type Item = DeviceResolutionState<'a>;
    fn next(&mut self) -> std::option::Option<DeviceResolutionState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_resolution_state_iterator_t;
                let data = (*iter).data;
                xcb_input_device_resolution_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceAbsCalibState {
    pub base: xcb_input_device_abs_calib_state_t,
}

impl DeviceAbsCalibState {
    #[allow(unused_unsafe)]
    pub fn new(control_id:       u16,
               len:              u16,
               min_x:            i32,
               max_x:            i32,
               min_y:            i32,
               max_y:            i32,
               flip_x:           u32,
               flip_y:           u32,
               rotation:         u32,
               button_threshold: u32)
            -> DeviceAbsCalibState {
        unsafe {
            DeviceAbsCalibState {
                base: xcb_input_device_abs_calib_state_t {
                    control_id:       control_id,
                    len:              len,
                    min_x:            min_x,
                    max_x:            max_x,
                    min_y:            min_y,
                    max_y:            max_y,
                    flip_x:           flip_x,
                    flip_y:           flip_y,
                    rotation:         rotation,
                    button_threshold: button_threshold,
                }
            }
        }
    }
    pub fn control_id(&self) -> u16 {
        unsafe {
            self.base.control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn min_x(&self) -> i32 {
        unsafe {
            self.base.min_x
        }
    }
    pub fn max_x(&self) -> i32 {
        unsafe {
            self.base.max_x
        }
    }
    pub fn min_y(&self) -> i32 {
        unsafe {
            self.base.min_y
        }
    }
    pub fn max_y(&self) -> i32 {
        unsafe {
            self.base.max_y
        }
    }
    pub fn flip_x(&self) -> u32 {
        unsafe {
            self.base.flip_x
        }
    }
    pub fn flip_y(&self) -> u32 {
        unsafe {
            self.base.flip_y
        }
    }
    pub fn rotation(&self) -> u32 {
        unsafe {
            self.base.rotation
        }
    }
    pub fn button_threshold(&self) -> u32 {
        unsafe {
            self.base.button_threshold
        }
    }
}

pub type DeviceAbsCalibStateIterator = xcb_input_device_abs_calib_state_iterator_t;

impl Iterator for DeviceAbsCalibStateIterator {
    type Item = DeviceAbsCalibState;
    fn next(&mut self) -> std::option::Option<DeviceAbsCalibState> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_abs_calib_state_iterator_t;
                let data = (*iter).data;
                xcb_input_device_abs_calib_state_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceAbsAreaState {
    pub base: xcb_input_device_abs_area_state_t,
}

impl DeviceAbsAreaState {
    #[allow(unused_unsafe)]
    pub fn new(control_id: u16,
               len:        u16,
               offset_x:   u32,
               offset_y:   u32,
               width:      u32,
               height:     u32,
               screen:     u32,
               following:  u32)
            -> DeviceAbsAreaState {
        unsafe {
            DeviceAbsAreaState {
                base: xcb_input_device_abs_area_state_t {
                    control_id: control_id,
                    len:        len,
                    offset_x:   offset_x,
                    offset_y:   offset_y,
                    width:      width,
                    height:     height,
                    screen:     screen,
                    following:  following,
                }
            }
        }
    }
    pub fn control_id(&self) -> u16 {
        unsafe {
            self.base.control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn offset_x(&self) -> u32 {
        unsafe {
            self.base.offset_x
        }
    }
    pub fn offset_y(&self) -> u32 {
        unsafe {
            self.base.offset_y
        }
    }
    pub fn width(&self) -> u32 {
        unsafe {
            self.base.width
        }
    }
    pub fn height(&self) -> u32 {
        unsafe {
            self.base.height
        }
    }
    pub fn screen(&self) -> u32 {
        unsafe {
            self.base.screen
        }
    }
    pub fn following(&self) -> u32 {
        unsafe {
            self.base.following
        }
    }
}

pub type DeviceAbsAreaStateIterator = xcb_input_device_abs_area_state_iterator_t;

impl Iterator for DeviceAbsAreaStateIterator {
    type Item = DeviceAbsAreaState;
    fn next(&mut self) -> std::option::Option<DeviceAbsAreaState> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_abs_area_state_iterator_t;
                let data = (*iter).data;
                xcb_input_device_abs_area_state_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceCoreState {
    pub base: xcb_input_device_core_state_t,
}

impl DeviceCoreState {
    #[allow(unused_unsafe)]
    pub fn new(control_id: u16,
               len:        u16,
               status:     u8,
               iscore:     u8)
            -> DeviceCoreState {
        unsafe {
            DeviceCoreState {
                base: xcb_input_device_core_state_t {
                    control_id: control_id,
                    len:        len,
                    status:     status,
                    iscore:     iscore,
                    pad0:       [0; 2],
                }
            }
        }
    }
    pub fn control_id(&self) -> u16 {
        unsafe {
            self.base.control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn status(&self) -> u8 {
        unsafe {
            self.base.status
        }
    }
    pub fn iscore(&self) -> u8 {
        unsafe {
            self.base.iscore
        }
    }
}

pub type DeviceCoreStateIterator = xcb_input_device_core_state_iterator_t;

impl Iterator for DeviceCoreStateIterator {
    type Item = DeviceCoreState;
    fn next(&mut self) -> std::option::Option<DeviceCoreState> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_core_state_iterator_t;
                let data = (*iter).data;
                xcb_input_device_core_state_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceEnableState {
    pub base: xcb_input_device_enable_state_t,
}

impl DeviceEnableState {
    #[allow(unused_unsafe)]
    pub fn new(control_id: u16,
               len:        u16,
               enable:     u8)
            -> DeviceEnableState {
        unsafe {
            DeviceEnableState {
                base: xcb_input_device_enable_state_t {
                    control_id: control_id,
                    len:        len,
                    enable:     enable,
                    pad0:       [0; 3],
                }
            }
        }
    }
    pub fn control_id(&self) -> u16 {
        unsafe {
            self.base.control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn enable(&self) -> u8 {
        unsafe {
            self.base.enable
        }
    }
}

pub type DeviceEnableStateIterator = xcb_input_device_enable_state_iterator_t;

impl Iterator for DeviceEnableStateIterator {
    type Item = DeviceEnableState;
    fn next(&mut self) -> std::option::Option<DeviceEnableState> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_enable_state_iterator_t;
                let data = (*iter).data;
                xcb_input_device_enable_state_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type DeviceState<'a> = base::StructPtr<'a, xcb_input_device_state_t>;

impl<'a> DeviceState<'a> {
    pub fn control_id(&self) -> u16 {
        unsafe {
            (*self.ptr).control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn uninterpreted_data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_device_state_uninterpreted_data_length(field) as usize;
            let data = xcb_input_device_state_uninterpreted_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type DeviceStateIterator<'a> = xcb_input_device_state_iterator_t<'a>;

impl<'a> Iterator for DeviceStateIterator<'a> {
    type Item = DeviceState<'a>;
    fn next(&mut self) -> std::option::Option<DeviceState<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_state_iterator_t;
                let data = (*iter).data;
                xcb_input_device_state_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const GET_DEVICE_CONTROL: u8 = 34;

pub type GetDeviceControlCookie<'a> = base::Cookie<'a, xcb_input_get_device_control_cookie_t>;

impl<'a> GetDeviceControlCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceControlReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceControlReply {
                    ptr: xcb_input_get_device_control_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceControlReply {
                    ptr: xcb_input_get_device_control_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceControlReply = base::Reply<xcb_input_get_device_control_reply_t>;

impl GetDeviceControlReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn control(&self) -> DeviceState {
        unsafe {
            std::mem::transmute(&(*self.ptr).control)
        }
    }
}

pub fn get_device_control<'a>(c         : &'a base::Connection,
                              control_id: u16,
                              device_id : u8)
        -> GetDeviceControlCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_control(c.get_raw_conn(),
                                                  control_id as u16,  // 0
                                                  device_id as u8);  // 1
        GetDeviceControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_control_unchecked<'a>(c         : &'a base::Connection,
                                        control_id: u16,
                                        device_id : u8)
        -> GetDeviceControlCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_control_unchecked(c.get_raw_conn(),
                                                            control_id as u16,  // 0
                                                            device_id as u8);  // 1
        GetDeviceControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type DeviceResolutionCtl<'a> = base::StructPtr<'a, xcb_input_device_resolution_ctl_t>;

impl<'a> DeviceResolutionCtl<'a> {
    pub fn control_id(&self) -> u16 {
        unsafe {
            (*self.ptr).control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn first_valuator(&self) -> u8 {
        unsafe {
            (*self.ptr).first_valuator
        }
    }
    pub fn num_valuators(&self) -> u8 {
        unsafe {
            (*self.ptr).num_valuators
        }
    }
    pub fn resolution_values(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_device_resolution_ctl_resolution_values_length(field) as usize;
            let data = xcb_input_device_resolution_ctl_resolution_values(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type DeviceResolutionCtlIterator<'a> = xcb_input_device_resolution_ctl_iterator_t<'a>;

impl<'a> Iterator for DeviceResolutionCtlIterator<'a> {
    type Item = DeviceResolutionCtl<'a>;
    fn next(&mut self) -> std::option::Option<DeviceResolutionCtl<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_resolution_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_device_resolution_ctl_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceAbsCalibCtl {
    pub base: xcb_input_device_abs_calib_ctl_t,
}

impl DeviceAbsCalibCtl {
    #[allow(unused_unsafe)]
    pub fn new(control_id:       u16,
               len:              u16,
               min_x:            i32,
               max_x:            i32,
               min_y:            i32,
               max_y:            i32,
               flip_x:           u32,
               flip_y:           u32,
               rotation:         u32,
               button_threshold: u32)
            -> DeviceAbsCalibCtl {
        unsafe {
            DeviceAbsCalibCtl {
                base: xcb_input_device_abs_calib_ctl_t {
                    control_id:       control_id,
                    len:              len,
                    min_x:            min_x,
                    max_x:            max_x,
                    min_y:            min_y,
                    max_y:            max_y,
                    flip_x:           flip_x,
                    flip_y:           flip_y,
                    rotation:         rotation,
                    button_threshold: button_threshold,
                }
            }
        }
    }
    pub fn control_id(&self) -> u16 {
        unsafe {
            self.base.control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn min_x(&self) -> i32 {
        unsafe {
            self.base.min_x
        }
    }
    pub fn max_x(&self) -> i32 {
        unsafe {
            self.base.max_x
        }
    }
    pub fn min_y(&self) -> i32 {
        unsafe {
            self.base.min_y
        }
    }
    pub fn max_y(&self) -> i32 {
        unsafe {
            self.base.max_y
        }
    }
    pub fn flip_x(&self) -> u32 {
        unsafe {
            self.base.flip_x
        }
    }
    pub fn flip_y(&self) -> u32 {
        unsafe {
            self.base.flip_y
        }
    }
    pub fn rotation(&self) -> u32 {
        unsafe {
            self.base.rotation
        }
    }
    pub fn button_threshold(&self) -> u32 {
        unsafe {
            self.base.button_threshold
        }
    }
}

pub type DeviceAbsCalibCtlIterator = xcb_input_device_abs_calib_ctl_iterator_t;

impl Iterator for DeviceAbsCalibCtlIterator {
    type Item = DeviceAbsCalibCtl;
    fn next(&mut self) -> std::option::Option<DeviceAbsCalibCtl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_abs_calib_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_device_abs_calib_ctl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceAbsAreaCtrl {
    pub base: xcb_input_device_abs_area_ctrl_t,
}

impl DeviceAbsAreaCtrl {
    #[allow(unused_unsafe)]
    pub fn new(control_id: u16,
               len:        u16,
               offset_x:   u32,
               offset_y:   u32,
               width:      i32,
               height:     i32,
               screen:     i32,
               following:  u32)
            -> DeviceAbsAreaCtrl {
        unsafe {
            DeviceAbsAreaCtrl {
                base: xcb_input_device_abs_area_ctrl_t {
                    control_id: control_id,
                    len:        len,
                    offset_x:   offset_x,
                    offset_y:   offset_y,
                    width:      width,
                    height:     height,
                    screen:     screen,
                    following:  following,
                }
            }
        }
    }
    pub fn control_id(&self) -> u16 {
        unsafe {
            self.base.control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn offset_x(&self) -> u32 {
        unsafe {
            self.base.offset_x
        }
    }
    pub fn offset_y(&self) -> u32 {
        unsafe {
            self.base.offset_y
        }
    }
    pub fn width(&self) -> i32 {
        unsafe {
            self.base.width
        }
    }
    pub fn height(&self) -> i32 {
        unsafe {
            self.base.height
        }
    }
    pub fn screen(&self) -> i32 {
        unsafe {
            self.base.screen
        }
    }
    pub fn following(&self) -> u32 {
        unsafe {
            self.base.following
        }
    }
}

pub type DeviceAbsAreaCtrlIterator = xcb_input_device_abs_area_ctrl_iterator_t;

impl Iterator for DeviceAbsAreaCtrlIterator {
    type Item = DeviceAbsAreaCtrl;
    fn next(&mut self) -> std::option::Option<DeviceAbsAreaCtrl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_abs_area_ctrl_iterator_t;
                let data = (*iter).data;
                xcb_input_device_abs_area_ctrl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceCoreCtrl {
    pub base: xcb_input_device_core_ctrl_t,
}

impl DeviceCoreCtrl {
    #[allow(unused_unsafe)]
    pub fn new(control_id: u16,
               len:        u16,
               status:     u8)
            -> DeviceCoreCtrl {
        unsafe {
            DeviceCoreCtrl {
                base: xcb_input_device_core_ctrl_t {
                    control_id: control_id,
                    len:        len,
                    status:     status,
                    pad0:       [0; 3],
                }
            }
        }
    }
    pub fn control_id(&self) -> u16 {
        unsafe {
            self.base.control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn status(&self) -> u8 {
        unsafe {
            self.base.status
        }
    }
}

pub type DeviceCoreCtrlIterator = xcb_input_device_core_ctrl_iterator_t;

impl Iterator for DeviceCoreCtrlIterator {
    type Item = DeviceCoreCtrl;
    fn next(&mut self) -> std::option::Option<DeviceCoreCtrl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_core_ctrl_iterator_t;
                let data = (*iter).data;
                xcb_input_device_core_ctrl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DeviceEnableCtrl {
    pub base: xcb_input_device_enable_ctrl_t,
}

impl DeviceEnableCtrl {
    #[allow(unused_unsafe)]
    pub fn new(control_id: u16,
               len:        u16,
               enable:     u8)
            -> DeviceEnableCtrl {
        unsafe {
            DeviceEnableCtrl {
                base: xcb_input_device_enable_ctrl_t {
                    control_id: control_id,
                    len:        len,
                    enable:     enable,
                    pad0:       [0; 3],
                }
            }
        }
    }
    pub fn control_id(&self) -> u16 {
        unsafe {
            self.base.control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn enable(&self) -> u8 {
        unsafe {
            self.base.enable
        }
    }
}

pub type DeviceEnableCtrlIterator = xcb_input_device_enable_ctrl_iterator_t;

impl Iterator for DeviceEnableCtrlIterator {
    type Item = DeviceEnableCtrl;
    fn next(&mut self) -> std::option::Option<DeviceEnableCtrl> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_enable_ctrl_iterator_t;
                let data = (*iter).data;
                xcb_input_device_enable_ctrl_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type DeviceCtl<'a> = base::StructPtr<'a, xcb_input_device_ctl_t>;

impl<'a> DeviceCtl<'a> {
    pub fn control_id(&self) -> u16 {
        unsafe {
            (*self.ptr).control_id
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn uninterpreted_data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_device_ctl_uninterpreted_data_length(field) as usize;
            let data = xcb_input_device_ctl_uninterpreted_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type DeviceCtlIterator<'a> = xcb_input_device_ctl_iterator_t<'a>;

impl<'a> Iterator for DeviceCtlIterator<'a> {
    type Item = DeviceCtl<'a>;
    fn next(&mut self) -> std::option::Option<DeviceCtl<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_ctl_iterator_t;
                let data = (*iter).data;
                xcb_input_device_ctl_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const CHANGE_DEVICE_CONTROL: u8 = 35;

pub type ChangeDeviceControlCookie<'a> = base::Cookie<'a, xcb_input_change_device_control_cookie_t>;

impl<'a> ChangeDeviceControlCookie<'a> {
    pub fn get_reply(&self) -> Result<ChangeDeviceControlReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ChangeDeviceControlReply {
                    ptr: xcb_input_change_device_control_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ChangeDeviceControlReply {
                    ptr: xcb_input_change_device_control_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ChangeDeviceControlReply = base::Reply<xcb_input_change_device_control_reply_t>;

impl ChangeDeviceControlReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn change_device_control<'a>(c         : &'a base::Connection,
                                 control_id: u16,
                                 device_id : u8,
                                 control   : std::option::Option<DeviceCtl>)
        -> ChangeDeviceControlCookie<'a> {
    unsafe {
        let control_ptr = match control {
            Some(p) => p.ptr as *mut xcb_input_device_ctl_t,
            None => std::ptr::null()
        };
        let cookie = xcb_input_change_device_control(c.get_raw_conn(),
                                                     control_id as u16,  // 0
                                                     device_id as u8,  // 1
                                                     control_ptr);  // 2
        ChangeDeviceControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn change_device_control_unchecked<'a>(c         : &'a base::Connection,
                                           control_id: u16,
                                           device_id : u8,
                                           control   : std::option::Option<DeviceCtl>)
        -> ChangeDeviceControlCookie<'a> {
    unsafe {
        let control_ptr = match control {
            Some(p) => p.ptr as *mut xcb_input_device_ctl_t,
            None => std::ptr::null()
        };
        let cookie = xcb_input_change_device_control_unchecked(c.get_raw_conn(),
                                                               control_id as u16,  // 0
                                                               device_id as u8,  // 1
                                                               control_ptr);  // 2
        ChangeDeviceControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_DEVICE_PROPERTIES: u8 = 36;

pub type ListDevicePropertiesCookie<'a> = base::Cookie<'a, xcb_input_list_device_properties_cookie_t>;

impl<'a> ListDevicePropertiesCookie<'a> {
    pub fn get_reply(&self) -> Result<ListDevicePropertiesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListDevicePropertiesReply {
                    ptr: xcb_input_list_device_properties_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListDevicePropertiesReply {
                    ptr: xcb_input_list_device_properties_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListDevicePropertiesReply = base::Reply<xcb_input_list_device_properties_reply_t>;

impl ListDevicePropertiesReply {
    pub fn num_atoms(&self) -> u16 {
        unsafe {
            (*self.ptr).num_atoms
        }
    }
    pub fn atoms(&self) -> &[xproto::Atom] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_list_device_properties_atoms_length(field) as usize;
            let data = xcb_input_list_device_properties_atoms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn list_device_properties<'a>(c        : &'a base::Connection,
                                  device_id: u8)
        -> ListDevicePropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_input_list_device_properties(c.get_raw_conn(),
                                                      device_id as u8);  // 0
        ListDevicePropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_device_properties_unchecked<'a>(c        : &'a base::Connection,
                                            device_id: u8)
        -> ListDevicePropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_input_list_device_properties_unchecked(c.get_raw_conn(),
                                                                device_id as u8);  // 0
        ListDevicePropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type ChangeDevicePropertyItems<'a> = base::StructPtr<'a, xcb_input_change_device_property_items_t>;

pub const CHANGE_DEVICE_PROPERTY: u8 = 37;

pub fn change_device_property<'a>(c        : &'a base::Connection,
                                  property : xproto::Atom,
                                  type_    : xproto::Atom,
                                  device_id: u8,
                                  format   : u8,
                                  mode     : u8,
                                  num_items: u32,
                                  items    : std::option::Option<ChangeDevicePropertyItems>)
        -> base::VoidCookie<'a> {
    unsafe {
        let items_ptr = match items {
            Some(p) => p.ptr as *const xcb_input_change_device_property_items_t,
            None => std::ptr::null()
        };
        let cookie = xcb_input_change_device_property(c.get_raw_conn(),
                                                      property as xcb_atom_t,  // 0
                                                      type_ as xcb_atom_t,  // 1
                                                      device_id as u8,  // 2
                                                      format as u8,  // 3
                                                      mode as u8,  // 4
                                                      num_items as u32,  // 5
                                                      items_ptr);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_device_property_checked<'a>(c        : &'a base::Connection,
                                          property : xproto::Atom,
                                          type_    : xproto::Atom,
                                          device_id: u8,
                                          format   : u8,
                                          mode     : u8,
                                          num_items: u32,
                                          items    : std::option::Option<ChangeDevicePropertyItems>)
        -> base::VoidCookie<'a> {
    unsafe {
        let items_ptr = match items {
            Some(p) => p.ptr as *const xcb_input_change_device_property_items_t,
            None => std::ptr::null()
        };
        let cookie = xcb_input_change_device_property_checked(c.get_raw_conn(),
                                                              property as xcb_atom_t,  // 0
                                                              type_ as xcb_atom_t,  // 1
                                                              device_id as u8,  // 2
                                                              format as u8,  // 3
                                                              mode as u8,  // 4
                                                              num_items as u32,  // 5
                                                              items_ptr);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_DEVICE_PROPERTY: u8 = 38;

pub fn delete_device_property<'a>(c        : &'a base::Connection,
                                  property : xproto::Atom,
                                  device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_delete_device_property(c.get_raw_conn(),
                                                      property as xcb_atom_t,  // 0
                                                      device_id as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_device_property_checked<'a>(c        : &'a base::Connection,
                                          property : xproto::Atom,
                                          device_id: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_delete_device_property_checked(c.get_raw_conn(),
                                                              property as xcb_atom_t,  // 0
                                                              device_id as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DEVICE_PROPERTY: u8 = 39;

pub type GetDevicePropertyCookie<'a> = base::Cookie<'a, xcb_input_get_device_property_cookie_t>;

impl<'a> GetDevicePropertyCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDevicePropertyReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDevicePropertyReply {
                    ptr: xcb_input_get_device_property_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDevicePropertyReply {
                    ptr: xcb_input_get_device_property_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDevicePropertyItems<'a> = base::StructPtr<'a, xcb_input_get_device_property_items_t>;

pub type GetDevicePropertyReply = base::Reply<xcb_input_get_device_property_reply_t>;

impl GetDevicePropertyReply {
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
    pub fn format(&self) -> u8 {
        unsafe {
            (*self.ptr).format
        }
    }
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
}

pub fn get_device_property<'a>(c        : &'a base::Connection,
                               property : xproto::Atom,
                               type_    : xproto::Atom,
                               offset   : u32,
                               len      : u32,
                               device_id: u8,
                               delete   : bool)
        -> GetDevicePropertyCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_property(c.get_raw_conn(),
                                                   property as xcb_atom_t,  // 0
                                                   type_ as xcb_atom_t,  // 1
                                                   offset as u32,  // 2
                                                   len as u32,  // 3
                                                   device_id as u8,  // 4
                                                   delete as u8);  // 5
        GetDevicePropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_property_unchecked<'a>(c        : &'a base::Connection,
                                         property : xproto::Atom,
                                         type_    : xproto::Atom,
                                         offset   : u32,
                                         len      : u32,
                                         device_id: u8,
                                         delete   : bool)
        -> GetDevicePropertyCookie<'a> {
    unsafe {
        let cookie = xcb_input_get_device_property_unchecked(c.get_raw_conn(),
                                                             property as xcb_atom_t,  // 0
                                                             type_ as xcb_atom_t,  // 1
                                                             offset as u32,  // 2
                                                             len as u32,  // 3
                                                             device_id as u8,  // 4
                                                             delete as u8);  // 5
        GetDevicePropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

#[derive(Copy, Clone)]
pub struct GroupInfo {
    pub base: xcb_input_group_info_t,
}

impl GroupInfo {
    #[allow(unused_unsafe)]
    pub fn new(base:      u8,
               latched:   u8,
               locked:    u8,
               effective: u8)
            -> GroupInfo {
        unsafe {
            GroupInfo {
                base: xcb_input_group_info_t {
                    base:      base,
                    latched:   latched,
                    locked:    locked,
                    effective: effective,
                }
            }
        }
    }
    pub fn base(&self) -> u8 {
        unsafe {
            self.base.base
        }
    }
    pub fn latched(&self) -> u8 {
        unsafe {
            self.base.latched
        }
    }
    pub fn locked(&self) -> u8 {
        unsafe {
            self.base.locked
        }
    }
    pub fn effective(&self) -> u8 {
        unsafe {
            self.base.effective
        }
    }
}

pub type GroupInfoIterator = xcb_input_group_info_iterator_t;

impl Iterator for GroupInfoIterator {
    type Item = GroupInfo;
    fn next(&mut self) -> std::option::Option<GroupInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_group_info_iterator_t;
                let data = (*iter).data;
                xcb_input_group_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ModifierInfo {
    pub base: xcb_input_modifier_info_t,
}

impl ModifierInfo {
    #[allow(unused_unsafe)]
    pub fn new(base:      u32,
               latched:   u32,
               locked:    u32,
               effective: u32)
            -> ModifierInfo {
        unsafe {
            ModifierInfo {
                base: xcb_input_modifier_info_t {
                    base:      base,
                    latched:   latched,
                    locked:    locked,
                    effective: effective,
                }
            }
        }
    }
    pub fn base(&self) -> u32 {
        unsafe {
            self.base.base
        }
    }
    pub fn latched(&self) -> u32 {
        unsafe {
            self.base.latched
        }
    }
    pub fn locked(&self) -> u32 {
        unsafe {
            self.base.locked
        }
    }
    pub fn effective(&self) -> u32 {
        unsafe {
            self.base.effective
        }
    }
}

pub type ModifierInfoIterator = xcb_input_modifier_info_iterator_t;

impl Iterator for ModifierInfoIterator {
    type Item = ModifierInfo;
    fn next(&mut self) -> std::option::Option<ModifierInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_modifier_info_iterator_t;
                let data = (*iter).data;
                xcb_input_modifier_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const XI_QUERY_POINTER: u8 = 40;

pub type XiQueryPointerCookie<'a> = base::Cookie<'a, xcb_input_xi_query_pointer_cookie_t>;

impl<'a> XiQueryPointerCookie<'a> {
    pub fn get_reply(&self) -> Result<XiQueryPointerReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiQueryPointerReply {
                    ptr: xcb_input_xi_query_pointer_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiQueryPointerReply {
                    ptr: xcb_input_xi_query_pointer_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiQueryPointerReply = base::Reply<xcb_input_xi_query_pointer_reply_t>;

impl XiQueryPointerReply {
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn child(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).child
        }
    }
    pub fn root_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    pub fn root_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    pub fn win_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).win_x
        }
    }
    pub fn win_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).win_y
        }
    }
    pub fn same_screen(&self) -> u8 {
        unsafe {
            (*self.ptr).same_screen
        }
    }
    pub fn buttons_len(&self) -> u16 {
        unsafe {
            (*self.ptr).buttons_len
        }
    }
    pub fn mods(&self) -> ModifierInfo {
        unsafe {
            std::mem::transmute((*self.ptr).mods)
        }
    }
    pub fn group(&self) -> GroupInfo {
        unsafe {
            std::mem::transmute((*self.ptr).group)
        }
    }
    pub fn buttons(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_xi_query_pointer_buttons_length(field) as usize;
            let data = xcb_input_xi_query_pointer_buttons(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn xi_query_pointer<'a>(c       : &'a base::Connection,
                            window  : xproto::Window,
                            deviceid: DeviceId)
        -> XiQueryPointerCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_query_pointer(c.get_raw_conn(),
                                                window as xcb_window_t,  // 0
                                                deviceid as xcb_input_device_id_t);  // 1
        XiQueryPointerCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_query_pointer_unchecked<'a>(c       : &'a base::Connection,
                                      window  : xproto::Window,
                                      deviceid: DeviceId)
        -> XiQueryPointerCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_query_pointer_unchecked(c.get_raw_conn(),
                                                          window as xcb_window_t,  // 0
                                                          deviceid as xcb_input_device_id_t);  // 1
        XiQueryPointerCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const XI_WARP_POINTER: u8 = 41;

pub fn xi_warp_pointer<'a>(c         : &'a base::Connection,
                           src_win   : xproto::Window,
                           dst_win   : xproto::Window,
                           src_x     : Fp1616,
                           src_y     : Fp1616,
                           src_width : u16,
                           src_height: u16,
                           dst_x     : Fp1616,
                           dst_y     : Fp1616,
                           deviceid  : DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_warp_pointer(c.get_raw_conn(),
                                               src_win as xcb_window_t,  // 0
                                               dst_win as xcb_window_t,  // 1
                                               src_x as xcb_input_fp1616_t,  // 2
                                               src_y as xcb_input_fp1616_t,  // 3
                                               src_width as u16,  // 4
                                               src_height as u16,  // 5
                                               dst_x as xcb_input_fp1616_t,  // 6
                                               dst_y as xcb_input_fp1616_t,  // 7
                                               deviceid as xcb_input_device_id_t);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_warp_pointer_checked<'a>(c         : &'a base::Connection,
                                   src_win   : xproto::Window,
                                   dst_win   : xproto::Window,
                                   src_x     : Fp1616,
                                   src_y     : Fp1616,
                                   src_width : u16,
                                   src_height: u16,
                                   dst_x     : Fp1616,
                                   dst_y     : Fp1616,
                                   deviceid  : DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_warp_pointer_checked(c.get_raw_conn(),
                                                       src_win as xcb_window_t,  // 0
                                                       dst_win as xcb_window_t,  // 1
                                                       src_x as xcb_input_fp1616_t,  // 2
                                                       src_y as xcb_input_fp1616_t,  // 3
                                                       src_width as u16,  // 4
                                                       src_height as u16,  // 5
                                                       dst_x as xcb_input_fp1616_t,  // 6
                                                       dst_y as xcb_input_fp1616_t,  // 7
                                                       deviceid as xcb_input_device_id_t);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_CHANGE_CURSOR: u8 = 42;

pub fn xi_change_cursor<'a>(c       : &'a base::Connection,
                            window  : xproto::Window,
                            cursor  : xproto::Cursor,
                            deviceid: DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_change_cursor(c.get_raw_conn(),
                                                window as xcb_window_t,  // 0
                                                cursor as xcb_cursor_t,  // 1
                                                deviceid as xcb_input_device_id_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_change_cursor_checked<'a>(c       : &'a base::Connection,
                                    window  : xproto::Window,
                                    cursor  : xproto::Cursor,
                                    deviceid: DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_change_cursor_checked(c.get_raw_conn(),
                                                        window as xcb_window_t,  // 0
                                                        cursor as xcb_cursor_t,  // 1
                                                        deviceid as xcb_input_device_id_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub type AddMaster<'a> = base::StructPtr<'a, xcb_input_add_master_t>;

impl<'a> AddMaster<'a> {
    pub fn type_(&self) -> u16 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn name_len(&self) -> u16 {
        unsafe {
            (*self.ptr).name_len
        }
    }
    pub fn send_core(&self) -> u8 {
        unsafe {
            (*self.ptr).send_core
        }
    }
    pub fn enable(&self) -> u8 {
        unsafe {
            (*self.ptr).enable
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_add_master_name_length(field) as usize;
            let data = xcb_input_add_master_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type AddMasterIterator<'a> = xcb_input_add_master_iterator_t<'a>;

impl<'a> Iterator for AddMasterIterator<'a> {
    type Item = AddMaster<'a>;
    fn next(&mut self) -> std::option::Option<AddMaster<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_add_master_iterator_t;
                let data = (*iter).data;
                xcb_input_add_master_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct RemoveMaster {
    pub base: xcb_input_remove_master_t,
}

impl RemoveMaster {
    #[allow(unused_unsafe)]
    pub fn new(type_:           u16,
               len:             u16,
               deviceid:        DeviceId,
               return_mode:     u8,
               return_pointer:  DeviceId,
               return_keyboard: DeviceId)
            -> RemoveMaster {
        unsafe {
            RemoveMaster {
                base: xcb_input_remove_master_t {
                    type_:           type_,
                    len:             len,
                    deviceid:        deviceid,
                    return_mode:     return_mode,
                    pad0:            0,
                    return_pointer:  return_pointer,
                    return_keyboard: return_keyboard,
                }
            }
        }
    }
    pub fn type_(&self) -> u16 {
        unsafe {
            self.base.type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            self.base.deviceid
        }
    }
    pub fn return_mode(&self) -> u8 {
        unsafe {
            self.base.return_mode
        }
    }
    pub fn return_pointer(&self) -> DeviceId {
        unsafe {
            self.base.return_pointer
        }
    }
    pub fn return_keyboard(&self) -> DeviceId {
        unsafe {
            self.base.return_keyboard
        }
    }
}

pub type RemoveMasterIterator = xcb_input_remove_master_iterator_t;

impl Iterator for RemoveMasterIterator {
    type Item = RemoveMaster;
    fn next(&mut self) -> std::option::Option<RemoveMaster> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_remove_master_iterator_t;
                let data = (*iter).data;
                xcb_input_remove_master_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct AttachSlave {
    pub base: xcb_input_attach_slave_t,
}

impl AttachSlave {
    #[allow(unused_unsafe)]
    pub fn new(type_:    u16,
               len:      u16,
               deviceid: DeviceId,
               master:   DeviceId)
            -> AttachSlave {
        unsafe {
            AttachSlave {
                base: xcb_input_attach_slave_t {
                    type_:    type_,
                    len:      len,
                    deviceid: deviceid,
                    master:   master,
                }
            }
        }
    }
    pub fn type_(&self) -> u16 {
        unsafe {
            self.base.type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            self.base.deviceid
        }
    }
    pub fn master(&self) -> DeviceId {
        unsafe {
            self.base.master
        }
    }
}

pub type AttachSlaveIterator = xcb_input_attach_slave_iterator_t;

impl Iterator for AttachSlaveIterator {
    type Item = AttachSlave;
    fn next(&mut self) -> std::option::Option<AttachSlave> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_attach_slave_iterator_t;
                let data = (*iter).data;
                xcb_input_attach_slave_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DetachSlave {
    pub base: xcb_input_detach_slave_t,
}

impl DetachSlave {
    #[allow(unused_unsafe)]
    pub fn new(type_:    u16,
               len:      u16,
               deviceid: DeviceId)
            -> DetachSlave {
        unsafe {
            DetachSlave {
                base: xcb_input_detach_slave_t {
                    type_:    type_,
                    len:      len,
                    deviceid: deviceid,
                    pad0:     [0; 2],
                }
            }
        }
    }
    pub fn type_(&self) -> u16 {
        unsafe {
            self.base.type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            self.base.deviceid
        }
    }
}

pub type DetachSlaveIterator = xcb_input_detach_slave_iterator_t;

impl Iterator for DetachSlaveIterator {
    type Item = DetachSlave;
    fn next(&mut self) -> std::option::Option<DetachSlave> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_detach_slave_iterator_t;
                let data = (*iter).data;
                xcb_input_detach_slave_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type HierarchyChange<'a> = base::StructPtr<'a, xcb_input_hierarchy_change_t>;

impl<'a> HierarchyChange<'a> {
    pub fn type_(&self) -> u16 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn uninterpreted_data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_hierarchy_change_uninterpreted_data_length(field) as usize;
            let data = xcb_input_hierarchy_change_uninterpreted_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type HierarchyChangeIterator<'a> = xcb_input_hierarchy_change_iterator_t<'a>;

impl<'a> Iterator for HierarchyChangeIterator<'a> {
    type Item = HierarchyChange<'a>;
    fn next(&mut self) -> std::option::Option<HierarchyChange<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_hierarchy_change_iterator_t;
                let data = (*iter).data;
                xcb_input_hierarchy_change_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const XI_CHANGE_HIERARCHY: u8 = 43;

pub fn xi_change_hierarchy<'a>(c      : &'a base::Connection,
                               changes: &[HierarchyChange])
        -> base::VoidCookie<'a> {
    unsafe {
        let changes_len = changes.len();
        let changes_ptr = changes.as_ptr();
        let cookie = xcb_input_xi_change_hierarchy(c.get_raw_conn(),
                                                   changes_len as u8,  // 0
                                                   changes_ptr as *const xcb_input_hierarchy_change_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_change_hierarchy_checked<'a>(c      : &'a base::Connection,
                                       changes: &[HierarchyChange])
        -> base::VoidCookie<'a> {
    unsafe {
        let changes_len = changes.len();
        let changes_ptr = changes.as_ptr();
        let cookie = xcb_input_xi_change_hierarchy_checked(c.get_raw_conn(),
                                                           changes_len as u8,  // 0
                                                           changes_ptr as *const xcb_input_hierarchy_change_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_SET_CLIENT_POINTER: u8 = 44;

pub fn xi_set_client_pointer<'a>(c       : &'a base::Connection,
                                 window  : xproto::Window,
                                 deviceid: DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_set_client_pointer(c.get_raw_conn(),
                                                     window as xcb_window_t,  // 0
                                                     deviceid as xcb_input_device_id_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_set_client_pointer_checked<'a>(c       : &'a base::Connection,
                                         window  : xproto::Window,
                                         deviceid: DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_set_client_pointer_checked(c.get_raw_conn(),
                                                             window as xcb_window_t,  // 0
                                                             deviceid as xcb_input_device_id_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_GET_CLIENT_POINTER: u8 = 45;

pub type XiGetClientPointerCookie<'a> = base::Cookie<'a, xcb_input_xi_get_client_pointer_cookie_t>;

impl<'a> XiGetClientPointerCookie<'a> {
    pub fn get_reply(&self) -> Result<XiGetClientPointerReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiGetClientPointerReply {
                    ptr: xcb_input_xi_get_client_pointer_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiGetClientPointerReply {
                    ptr: xcb_input_xi_get_client_pointer_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiGetClientPointerReply = base::Reply<xcb_input_xi_get_client_pointer_reply_t>;

impl XiGetClientPointerReply {
    pub fn set(&self) -> bool {
        unsafe {
            (*self.ptr).set != 0
        }
    }
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
}

pub fn xi_get_client_pointer<'a>(c     : &'a base::Connection,
                                 window: xproto::Window)
        -> XiGetClientPointerCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_get_client_pointer(c.get_raw_conn(),
                                                     window as xcb_window_t);  // 0
        XiGetClientPointerCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_get_client_pointer_unchecked<'a>(c     : &'a base::Connection,
                                           window: xproto::Window)
        -> XiGetClientPointerCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_get_client_pointer_unchecked(c.get_raw_conn(),
                                                               window as xcb_window_t);  // 0
        XiGetClientPointerCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type EventMask<'a> = base::StructPtr<'a, xcb_input_event_mask_t>;

impl<'a> EventMask<'a> {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn mask_len(&self) -> u16 {
        unsafe {
            (*self.ptr).mask_len
        }
    }
    pub fn mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_event_mask_mask_length(field) as usize;
            let data = xcb_input_event_mask_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type EventMaskIterator<'a> = xcb_input_event_mask_iterator_t<'a>;

impl<'a> Iterator for EventMaskIterator<'a> {
    type Item = EventMask<'a>;
    fn next(&mut self) -> std::option::Option<EventMask<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_event_mask_iterator_t;
                let data = (*iter).data;
                xcb_input_event_mask_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const XI_SELECT_EVENTS: u8 = 46;

pub fn xi_select_events<'a>(c     : &'a base::Connection,
                            window: xproto::Window,
                            masks : &[EventMask])
        -> base::VoidCookie<'a> {
    unsafe {
        let masks_len = masks.len();
        let masks_ptr = masks.as_ptr();
        let cookie = xcb_input_xi_select_events(c.get_raw_conn(),
                                                window as xcb_window_t,  // 0
                                                masks_len as u16,  // 1
                                                masks_ptr as *const xcb_input_event_mask_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_select_events_checked<'a>(c     : &'a base::Connection,
                                    window: xproto::Window,
                                    masks : &[EventMask])
        -> base::VoidCookie<'a> {
    unsafe {
        let masks_len = masks.len();
        let masks_ptr = masks.as_ptr();
        let cookie = xcb_input_xi_select_events_checked(c.get_raw_conn(),
                                                        window as xcb_window_t,  // 0
                                                        masks_len as u16,  // 1
                                                        masks_ptr as *const xcb_input_event_mask_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_QUERY_VERSION: u8 = 47;

pub type XiQueryVersionCookie<'a> = base::Cookie<'a, xcb_input_xi_query_version_cookie_t>;

impl<'a> XiQueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<XiQueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiQueryVersionReply {
                    ptr: xcb_input_xi_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiQueryVersionReply {
                    ptr: xcb_input_xi_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiQueryVersionReply = base::Reply<xcb_input_xi_query_version_reply_t>;

impl XiQueryVersionReply {
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

pub fn xi_query_version<'a>(c            : &'a base::Connection,
                            major_version: u16,
                            minor_version: u16)
        -> XiQueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_query_version(c.get_raw_conn(),
                                                major_version as u16,  // 0
                                                minor_version as u16);  // 1
        XiQueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_query_version_unchecked<'a>(c            : &'a base::Connection,
                                      major_version: u16,
                                      minor_version: u16)
        -> XiQueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_query_version_unchecked(c.get_raw_conn(),
                                                          major_version as u16,  // 0
                                                          minor_version as u16);  // 1
        XiQueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type ButtonClass<'a> = base::StructPtr<'a, xcb_input_button_class_t>;

impl<'a> ButtonClass<'a> {
    pub fn type_(&self) -> u16 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn num_buttons(&self) -> u16 {
        unsafe {
            (*self.ptr).num_buttons
        }
    }
    pub fn state(&self) -> &[xproto::Atom] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_button_class_state_length(field) as usize;
            let data = xcb_input_button_class_state(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn labels(&self) -> &[xproto::Atom] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_button_class_labels_length(field) as usize;
            let data = xcb_input_button_class_labels(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type ButtonClassIterator<'a> = xcb_input_button_class_iterator_t<'a>;

impl<'a> Iterator for ButtonClassIterator<'a> {
    type Item = ButtonClass<'a>;
    fn next(&mut self) -> std::option::Option<ButtonClass<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_button_class_iterator_t;
                let data = (*iter).data;
                xcb_input_button_class_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type KeyClass<'a> = base::StructPtr<'a, xcb_input_key_class_t>;

impl<'a> KeyClass<'a> {
    pub fn type_(&self) -> u16 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn num_keys(&self) -> u16 {
        unsafe {
            (*self.ptr).num_keys
        }
    }
    pub fn keys(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_key_class_keys_length(field) as usize;
            let data = xcb_input_key_class_keys(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type KeyClassIterator<'a> = xcb_input_key_class_iterator_t<'a>;

impl<'a> Iterator for KeyClassIterator<'a> {
    type Item = KeyClass<'a>;
    fn next(&mut self) -> std::option::Option<KeyClass<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_key_class_iterator_t;
                let data = (*iter).data;
                xcb_input_key_class_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ScrollClass {
    pub base: xcb_input_scroll_class_t,
}

impl ScrollClass {
    #[allow(unused_unsafe)]
    pub fn new(type_:       u16,
               len:         u16,
               sourceid:    DeviceId,
               number:      u16,
               scroll_type: u16,
               flags:       u32,
               increment:   Fp3232)
            -> ScrollClass {
        unsafe {
            ScrollClass {
                base: xcb_input_scroll_class_t {
                    type_:       type_,
                    len:         len,
                    sourceid:    sourceid,
                    number:      number,
                    scroll_type: scroll_type,
                    pad0:        [0; 2],
                    flags:       flags,
                    increment:   std::mem::transmute(increment),
                }
            }
        }
    }
    pub fn type_(&self) -> u16 {
        unsafe {
            self.base.type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            self.base.sourceid
        }
    }
    pub fn number(&self) -> u16 {
        unsafe {
            self.base.number
        }
    }
    pub fn scroll_type(&self) -> u16 {
        unsafe {
            self.base.scroll_type
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            self.base.flags
        }
    }
    pub fn increment(&self) -> Fp3232 {
        unsafe {
            std::mem::transmute(self.base.increment)
        }
    }
}

pub type ScrollClassIterator = xcb_input_scroll_class_iterator_t;

impl Iterator for ScrollClassIterator {
    type Item = ScrollClass;
    fn next(&mut self) -> std::option::Option<ScrollClass> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_scroll_class_iterator_t;
                let data = (*iter).data;
                xcb_input_scroll_class_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct TouchClass {
    pub base: xcb_input_touch_class_t,
}

impl TouchClass {
    #[allow(unused_unsafe)]
    pub fn new(type_:       u16,
               len:         u16,
               sourceid:    DeviceId,
               mode:        u8,
               num_touches: u8)
            -> TouchClass {
        unsafe {
            TouchClass {
                base: xcb_input_touch_class_t {
                    type_:       type_,
                    len:         len,
                    sourceid:    sourceid,
                    mode:        mode,
                    num_touches: num_touches,
                }
            }
        }
    }
    pub fn type_(&self) -> u16 {
        unsafe {
            self.base.type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            self.base.sourceid
        }
    }
    pub fn mode(&self) -> u8 {
        unsafe {
            self.base.mode
        }
    }
    pub fn num_touches(&self) -> u8 {
        unsafe {
            self.base.num_touches
        }
    }
}

pub type TouchClassIterator = xcb_input_touch_class_iterator_t;

impl Iterator for TouchClassIterator {
    type Item = TouchClass;
    fn next(&mut self) -> std::option::Option<TouchClass> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_touch_class_iterator_t;
                let data = (*iter).data;
                xcb_input_touch_class_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ValuatorClass {
    pub base: xcb_input_valuator_class_t,
}

impl ValuatorClass {
    #[allow(unused_unsafe)]
    pub fn new(type_:      u16,
               len:        u16,
               sourceid:   DeviceId,
               number:     u16,
               label:      xproto::Atom,
               min:        Fp3232,
               max:        Fp3232,
               value:      Fp3232,
               resolution: u32,
               mode:       u8)
            -> ValuatorClass {
        unsafe {
            ValuatorClass {
                base: xcb_input_valuator_class_t {
                    type_:      type_,
                    len:        len,
                    sourceid:   sourceid,
                    number:     number,
                    label:      label,
                    min:        std::mem::transmute(min),
                    max:        std::mem::transmute(max),
                    value:      std::mem::transmute(value),
                    resolution: resolution,
                    mode:       mode,
                    pad0:       [0; 3],
                }
            }
        }
    }
    pub fn type_(&self) -> u16 {
        unsafe {
            self.base.type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            self.base.len
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            self.base.sourceid
        }
    }
    pub fn number(&self) -> u16 {
        unsafe {
            self.base.number
        }
    }
    pub fn label(&self) -> xproto::Atom {
        unsafe {
            self.base.label
        }
    }
    pub fn min(&self) -> Fp3232 {
        unsafe {
            std::mem::transmute(self.base.min)
        }
    }
    pub fn max(&self) -> Fp3232 {
        unsafe {
            std::mem::transmute(self.base.max)
        }
    }
    pub fn value(&self) -> Fp3232 {
        unsafe {
            std::mem::transmute(self.base.value)
        }
    }
    pub fn resolution(&self) -> u32 {
        unsafe {
            self.base.resolution
        }
    }
    pub fn mode(&self) -> u8 {
        unsafe {
            self.base.mode
        }
    }
}

pub type ValuatorClassIterator = xcb_input_valuator_class_iterator_t;

impl Iterator for ValuatorClassIterator {
    type Item = ValuatorClass;
    fn next(&mut self) -> std::option::Option<ValuatorClass> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_valuator_class_iterator_t;
                let data = (*iter).data;
                xcb_input_valuator_class_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type DeviceClass<'a> = base::StructPtr<'a, xcb_input_device_class_t>;

impl<'a> DeviceClass<'a> {
    pub fn type_(&self) -> u16 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn len(&self) -> u16 {
        unsafe {
            (*self.ptr).len
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn uninterpreted_data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_device_class_uninterpreted_data_length(field) as usize;
            let data = xcb_input_device_class_uninterpreted_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type DeviceClassIterator<'a> = xcb_input_device_class_iterator_t<'a>;

impl<'a> Iterator for DeviceClassIterator<'a> {
    type Item = DeviceClass<'a>;
    fn next(&mut self) -> std::option::Option<DeviceClass<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_device_class_iterator_t;
                let data = (*iter).data;
                xcb_input_device_class_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type XiDeviceInfo<'a> = base::StructPtr<'a, xcb_input_xi_device_info_t>;

impl<'a> XiDeviceInfo<'a> {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn type_(&self) -> u16 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn attachment(&self) -> DeviceId {
        unsafe {
            (*self.ptr).attachment
        }
    }
    pub fn num_classes(&self) -> u16 {
        unsafe {
            (*self.ptr).num_classes
        }
    }
    pub fn name_len(&self) -> u16 {
        unsafe {
            (*self.ptr).name_len
        }
    }
    pub fn enabled(&self) -> bool {
        unsafe {
            (*self.ptr).enabled != 0
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_xi_device_info_name_length(field) as usize;
            let data = xcb_input_xi_device_info_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn classes(&self) -> DeviceClassIterator<'a> {
        unsafe {
            xcb_input_xi_device_info_classes_iterator(self.ptr)
        }
    }
}

pub type XiDeviceInfoIterator<'a> = xcb_input_xi_device_info_iterator_t<'a>;

impl<'a> Iterator for XiDeviceInfoIterator<'a> {
    type Item = XiDeviceInfo<'a>;
    fn next(&mut self) -> std::option::Option<XiDeviceInfo<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_xi_device_info_iterator_t;
                let data = (*iter).data;
                xcb_input_xi_device_info_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const XI_QUERY_DEVICE: u8 = 48;

pub type XiQueryDeviceCookie<'a> = base::Cookie<'a, xcb_input_xi_query_device_cookie_t>;

impl<'a> XiQueryDeviceCookie<'a> {
    pub fn get_reply(&self) -> Result<XiQueryDeviceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiQueryDeviceReply {
                    ptr: xcb_input_xi_query_device_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiQueryDeviceReply {
                    ptr: xcb_input_xi_query_device_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiQueryDeviceReply = base::Reply<xcb_input_xi_query_device_reply_t>;

impl XiQueryDeviceReply {
    pub fn num_infos(&self) -> u16 {
        unsafe {
            (*self.ptr).num_infos
        }
    }
    pub fn infos(&self) -> XiDeviceInfoIterator {
        unsafe {
            xcb_input_xi_query_device_infos_iterator(self.ptr)
        }
    }
}

pub fn xi_query_device<'a>(c       : &'a base::Connection,
                           deviceid: DeviceId)
        -> XiQueryDeviceCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_query_device(c.get_raw_conn(),
                                               deviceid as xcb_input_device_id_t);  // 0
        XiQueryDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_query_device_unchecked<'a>(c       : &'a base::Connection,
                                     deviceid: DeviceId)
        -> XiQueryDeviceCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_query_device_unchecked(c.get_raw_conn(),
                                                         deviceid as xcb_input_device_id_t);  // 0
        XiQueryDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const XI_SET_FOCUS: u8 = 49;

pub fn xi_set_focus<'a>(c       : &'a base::Connection,
                        window  : xproto::Window,
                        time    : xproto::Timestamp,
                        deviceid: DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_set_focus(c.get_raw_conn(),
                                            window as xcb_window_t,  // 0
                                            time as xcb_timestamp_t,  // 1
                                            deviceid as xcb_input_device_id_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_set_focus_checked<'a>(c       : &'a base::Connection,
                                window  : xproto::Window,
                                time    : xproto::Timestamp,
                                deviceid: DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_set_focus_checked(c.get_raw_conn(),
                                                    window as xcb_window_t,  // 0
                                                    time as xcb_timestamp_t,  // 1
                                                    deviceid as xcb_input_device_id_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_GET_FOCUS: u8 = 50;

pub type XiGetFocusCookie<'a> = base::Cookie<'a, xcb_input_xi_get_focus_cookie_t>;

impl<'a> XiGetFocusCookie<'a> {
    pub fn get_reply(&self) -> Result<XiGetFocusReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiGetFocusReply {
                    ptr: xcb_input_xi_get_focus_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiGetFocusReply {
                    ptr: xcb_input_xi_get_focus_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiGetFocusReply = base::Reply<xcb_input_xi_get_focus_reply_t>;

impl XiGetFocusReply {
    pub fn focus(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).focus
        }
    }
}

pub fn xi_get_focus<'a>(c       : &'a base::Connection,
                        deviceid: DeviceId)
        -> XiGetFocusCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_get_focus(c.get_raw_conn(),
                                            deviceid as xcb_input_device_id_t);  // 0
        XiGetFocusCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_get_focus_unchecked<'a>(c       : &'a base::Connection,
                                  deviceid: DeviceId)
        -> XiGetFocusCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_get_focus_unchecked(c.get_raw_conn(),
                                                      deviceid as xcb_input_device_id_t);  // 0
        XiGetFocusCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const XI_GRAB_DEVICE: u8 = 51;

pub type XiGrabDeviceCookie<'a> = base::Cookie<'a, xcb_input_xi_grab_device_cookie_t>;

impl<'a> XiGrabDeviceCookie<'a> {
    pub fn get_reply(&self) -> Result<XiGrabDeviceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiGrabDeviceReply {
                    ptr: xcb_input_xi_grab_device_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiGrabDeviceReply {
                    ptr: xcb_input_xi_grab_device_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiGrabDeviceReply = base::Reply<xcb_input_xi_grab_device_reply_t>;

impl XiGrabDeviceReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn xi_grab_device<'a>(c                 : &'a base::Connection,
                          window            : xproto::Window,
                          time              : xproto::Timestamp,
                          cursor            : xproto::Cursor,
                          deviceid          : DeviceId,
                          mode              : u8,
                          paired_device_mode: u8,
                          owner_events      : bool,
                          mask              : &[u32])
        -> XiGrabDeviceCookie<'a> {
    unsafe {
        let mask_len = mask.len();
        let mask_ptr = mask.as_ptr();
        let cookie = xcb_input_xi_grab_device(c.get_raw_conn(),
                                              window as xcb_window_t,  // 0
                                              time as xcb_timestamp_t,  // 1
                                              cursor as xcb_cursor_t,  // 2
                                              deviceid as xcb_input_device_id_t,  // 3
                                              mode as u8,  // 4
                                              paired_device_mode as u8,  // 5
                                              owner_events as u8,  // 6
                                              mask_len as u16,  // 7
                                              mask_ptr as *const u32);  // 8
        XiGrabDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_grab_device_unchecked<'a>(c                 : &'a base::Connection,
                                    window            : xproto::Window,
                                    time              : xproto::Timestamp,
                                    cursor            : xproto::Cursor,
                                    deviceid          : DeviceId,
                                    mode              : u8,
                                    paired_device_mode: u8,
                                    owner_events      : bool,
                                    mask              : &[u32])
        -> XiGrabDeviceCookie<'a> {
    unsafe {
        let mask_len = mask.len();
        let mask_ptr = mask.as_ptr();
        let cookie = xcb_input_xi_grab_device_unchecked(c.get_raw_conn(),
                                                        window as xcb_window_t,  // 0
                                                        time as xcb_timestamp_t,  // 1
                                                        cursor as xcb_cursor_t,  // 2
                                                        deviceid as xcb_input_device_id_t,  // 3
                                                        mode as u8,  // 4
                                                        paired_device_mode as u8,  // 5
                                                        owner_events as u8,  // 6
                                                        mask_len as u16,  // 7
                                                        mask_ptr as *const u32);  // 8
        XiGrabDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const XI_UNGRAB_DEVICE: u8 = 52;

pub fn xi_ungrab_device<'a>(c       : &'a base::Connection,
                            time    : xproto::Timestamp,
                            deviceid: DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_ungrab_device(c.get_raw_conn(),
                                                time as xcb_timestamp_t,  // 0
                                                deviceid as xcb_input_device_id_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_ungrab_device_checked<'a>(c       : &'a base::Connection,
                                    time    : xproto::Timestamp,
                                    deviceid: DeviceId)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_ungrab_device_checked(c.get_raw_conn(),
                                                        time as xcb_timestamp_t,  // 0
                                                        deviceid as xcb_input_device_id_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_ALLOW_EVENTS: u8 = 53;

pub fn xi_allow_events<'a>(c          : &'a base::Connection,
                           time       : xproto::Timestamp,
                           deviceid   : DeviceId,
                           event_mode : u8,
                           touchid    : u32,
                           grab_window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_allow_events(c.get_raw_conn(),
                                               time as xcb_timestamp_t,  // 0
                                               deviceid as xcb_input_device_id_t,  // 1
                                               event_mode as u8,  // 2
                                               touchid as u32,  // 3
                                               grab_window as xcb_window_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_allow_events_checked<'a>(c          : &'a base::Connection,
                                   time       : xproto::Timestamp,
                                   deviceid   : DeviceId,
                                   event_mode : u8,
                                   touchid    : u32,
                                   grab_window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_allow_events_checked(c.get_raw_conn(),
                                                       time as xcb_timestamp_t,  // 0
                                                       deviceid as xcb_input_device_id_t,  // 1
                                                       event_mode as u8,  // 2
                                                       touchid as u32,  // 3
                                                       grab_window as xcb_window_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct GrabModifierInfo {
    pub base: xcb_input_grab_modifier_info_t,
}

impl GrabModifierInfo {
    #[allow(unused_unsafe)]
    pub fn new(modifiers: u32,
               status:    u8)
            -> GrabModifierInfo {
        unsafe {
            GrabModifierInfo {
                base: xcb_input_grab_modifier_info_t {
                    modifiers: modifiers,
                    status:    status,
                    pad0:      [0; 3],
                }
            }
        }
    }
    pub fn modifiers(&self) -> u32 {
        unsafe {
            self.base.modifiers
        }
    }
    pub fn status(&self) -> u8 {
        unsafe {
            self.base.status
        }
    }
}

pub type GrabModifierInfoIterator = xcb_input_grab_modifier_info_iterator_t;

impl Iterator for GrabModifierInfoIterator {
    type Item = GrabModifierInfo;
    fn next(&mut self) -> std::option::Option<GrabModifierInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_grab_modifier_info_iterator_t;
                let data = (*iter).data;
                xcb_input_grab_modifier_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const XI_PASSIVE_GRAB_DEVICE: u8 = 54;

pub type XiPassiveGrabDeviceCookie<'a> = base::Cookie<'a, xcb_input_xi_passive_grab_device_cookie_t>;

impl<'a> XiPassiveGrabDeviceCookie<'a> {
    pub fn get_reply(&self) -> Result<XiPassiveGrabDeviceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiPassiveGrabDeviceReply {
                    ptr: xcb_input_xi_passive_grab_device_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiPassiveGrabDeviceReply {
                    ptr: xcb_input_xi_passive_grab_device_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiPassiveGrabDeviceReply = base::Reply<xcb_input_xi_passive_grab_device_reply_t>;

impl XiPassiveGrabDeviceReply {
    pub fn num_modifiers(&self) -> u16 {
        unsafe {
            (*self.ptr).num_modifiers
        }
    }
    pub fn modifiers(&self) -> GrabModifierInfoIterator {
        unsafe {
            xcb_input_xi_passive_grab_device_modifiers_iterator(self.ptr)
        }
    }
}

pub fn xi_passive_grab_device<'a>(c                 : &'a base::Connection,
                                  time              : xproto::Timestamp,
                                  grab_window       : xproto::Window,
                                  cursor            : xproto::Cursor,
                                  detail            : u32,
                                  deviceid          : DeviceId,
                                  grab_type         : u8,
                                  grab_mode         : u8,
                                  paired_device_mode: u8,
                                  owner_events      : bool,
                                  mask              : &[u32],
                                  modifiers         : &[u32])
        -> XiPassiveGrabDeviceCookie<'a> {
    unsafe {
        let mask_len = mask.len();
        let mask_ptr = mask.as_ptr();
        let modifiers_len = modifiers.len();
        let modifiers_ptr = modifiers.as_ptr();
        let cookie = xcb_input_xi_passive_grab_device(c.get_raw_conn(),
                                                      time as xcb_timestamp_t,  // 0
                                                      grab_window as xcb_window_t,  // 1
                                                      cursor as xcb_cursor_t,  // 2
                                                      detail as u32,  // 3
                                                      deviceid as xcb_input_device_id_t,  // 4
                                                      modifiers_len as u16,  // 5
                                                      mask_len as u16,  // 6
                                                      grab_type as u8,  // 7
                                                      grab_mode as u8,  // 8
                                                      paired_device_mode as u8,  // 9
                                                      owner_events as u8,  // 10
                                                      mask_ptr as *const u32,  // 11
                                                      modifiers_ptr as *const u32);  // 12
        XiPassiveGrabDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_passive_grab_device_unchecked<'a>(c                 : &'a base::Connection,
                                            time              : xproto::Timestamp,
                                            grab_window       : xproto::Window,
                                            cursor            : xproto::Cursor,
                                            detail            : u32,
                                            deviceid          : DeviceId,
                                            grab_type         : u8,
                                            grab_mode         : u8,
                                            paired_device_mode: u8,
                                            owner_events      : bool,
                                            mask              : &[u32],
                                            modifiers         : &[u32])
        -> XiPassiveGrabDeviceCookie<'a> {
    unsafe {
        let mask_len = mask.len();
        let mask_ptr = mask.as_ptr();
        let modifiers_len = modifiers.len();
        let modifiers_ptr = modifiers.as_ptr();
        let cookie = xcb_input_xi_passive_grab_device_unchecked(c.get_raw_conn(),
                                                                time as xcb_timestamp_t,  // 0
                                                                grab_window as xcb_window_t,  // 1
                                                                cursor as xcb_cursor_t,  // 2
                                                                detail as u32,  // 3
                                                                deviceid as xcb_input_device_id_t,  // 4
                                                                modifiers_len as u16,  // 5
                                                                mask_len as u16,  // 6
                                                                grab_type as u8,  // 7
                                                                grab_mode as u8,  // 8
                                                                paired_device_mode as u8,  // 9
                                                                owner_events as u8,  // 10
                                                                mask_ptr as *const u32,  // 11
                                                                modifiers_ptr as *const u32);  // 12
        XiPassiveGrabDeviceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const XI_PASSIVE_UNGRAB_DEVICE: u8 = 55;

pub fn xi_passive_ungrab_device<'a>(c          : &'a base::Connection,
                                    grab_window: xproto::Window,
                                    detail     : u32,
                                    deviceid   : DeviceId,
                                    grab_type  : u8,
                                    modifiers  : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let modifiers_len = modifiers.len();
        let modifiers_ptr = modifiers.as_ptr();
        let cookie = xcb_input_xi_passive_ungrab_device(c.get_raw_conn(),
                                                        grab_window as xcb_window_t,  // 0
                                                        detail as u32,  // 1
                                                        deviceid as xcb_input_device_id_t,  // 2
                                                        modifiers_len as u16,  // 3
                                                        grab_type as u8,  // 4
                                                        modifiers_ptr as *const u32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_passive_ungrab_device_checked<'a>(c          : &'a base::Connection,
                                            grab_window: xproto::Window,
                                            detail     : u32,
                                            deviceid   : DeviceId,
                                            grab_type  : u8,
                                            modifiers  : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let modifiers_len = modifiers.len();
        let modifiers_ptr = modifiers.as_ptr();
        let cookie = xcb_input_xi_passive_ungrab_device_checked(c.get_raw_conn(),
                                                                grab_window as xcb_window_t,  // 0
                                                                detail as u32,  // 1
                                                                deviceid as xcb_input_device_id_t,  // 2
                                                                modifiers_len as u16,  // 3
                                                                grab_type as u8,  // 4
                                                                modifiers_ptr as *const u32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_LIST_PROPERTIES: u8 = 56;

pub type XiListPropertiesCookie<'a> = base::Cookie<'a, xcb_input_xi_list_properties_cookie_t>;

impl<'a> XiListPropertiesCookie<'a> {
    pub fn get_reply(&self) -> Result<XiListPropertiesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiListPropertiesReply {
                    ptr: xcb_input_xi_list_properties_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiListPropertiesReply {
                    ptr: xcb_input_xi_list_properties_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiListPropertiesReply = base::Reply<xcb_input_xi_list_properties_reply_t>;

impl XiListPropertiesReply {
    pub fn num_properties(&self) -> u16 {
        unsafe {
            (*self.ptr).num_properties
        }
    }
    pub fn properties(&self) -> &[xproto::Atom] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_xi_list_properties_properties_length(field) as usize;
            let data = xcb_input_xi_list_properties_properties(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn xi_list_properties<'a>(c       : &'a base::Connection,
                              deviceid: DeviceId)
        -> XiListPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_list_properties(c.get_raw_conn(),
                                                  deviceid as xcb_input_device_id_t);  // 0
        XiListPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_list_properties_unchecked<'a>(c       : &'a base::Connection,
                                        deviceid: DeviceId)
        -> XiListPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_list_properties_unchecked(c.get_raw_conn(),
                                                            deviceid as xcb_input_device_id_t);  // 0
        XiListPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type XiChangePropertyItems<'a> = base::StructPtr<'a, xcb_input_xi_change_property_items_t>;

pub const XI_CHANGE_PROPERTY: u8 = 57;

pub fn xi_change_property<'a>(c        : &'a base::Connection,
                              deviceid : DeviceId,
                              mode     : u8,
                              format   : u8,
                              property : xproto::Atom,
                              type_    : xproto::Atom,
                              num_items: u32,
                              items    : std::option::Option<XiChangePropertyItems>)
        -> base::VoidCookie<'a> {
    unsafe {
        let items_ptr = match items {
            Some(p) => p.ptr as *const xcb_input_xi_change_property_items_t,
            None => std::ptr::null()
        };
        let cookie = xcb_input_xi_change_property(c.get_raw_conn(),
                                                  deviceid as xcb_input_device_id_t,  // 0
                                                  mode as u8,  // 1
                                                  format as u8,  // 2
                                                  property as xcb_atom_t,  // 3
                                                  type_ as xcb_atom_t,  // 4
                                                  num_items as u32,  // 5
                                                  items_ptr);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_change_property_checked<'a>(c        : &'a base::Connection,
                                      deviceid : DeviceId,
                                      mode     : u8,
                                      format   : u8,
                                      property : xproto::Atom,
                                      type_    : xproto::Atom,
                                      num_items: u32,
                                      items    : std::option::Option<XiChangePropertyItems>)
        -> base::VoidCookie<'a> {
    unsafe {
        let items_ptr = match items {
            Some(p) => p.ptr as *const xcb_input_xi_change_property_items_t,
            None => std::ptr::null()
        };
        let cookie = xcb_input_xi_change_property_checked(c.get_raw_conn(),
                                                          deviceid as xcb_input_device_id_t,  // 0
                                                          mode as u8,  // 1
                                                          format as u8,  // 2
                                                          property as xcb_atom_t,  // 3
                                                          type_ as xcb_atom_t,  // 4
                                                          num_items as u32,  // 5
                                                          items_ptr);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_DELETE_PROPERTY: u8 = 58;

pub fn xi_delete_property<'a>(c       : &'a base::Connection,
                              deviceid: DeviceId,
                              property: xproto::Atom)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_delete_property(c.get_raw_conn(),
                                                  deviceid as xcb_input_device_id_t,  // 0
                                                  property as xcb_atom_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_delete_property_checked<'a>(c       : &'a base::Connection,
                                      deviceid: DeviceId,
                                      property: xproto::Atom)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_delete_property_checked(c.get_raw_conn(),
                                                          deviceid as xcb_input_device_id_t,  // 0
                                                          property as xcb_atom_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const XI_GET_PROPERTY: u8 = 59;

pub type XiGetPropertyCookie<'a> = base::Cookie<'a, xcb_input_xi_get_property_cookie_t>;

impl<'a> XiGetPropertyCookie<'a> {
    pub fn get_reply(&self) -> Result<XiGetPropertyReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiGetPropertyReply {
                    ptr: xcb_input_xi_get_property_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiGetPropertyReply {
                    ptr: xcb_input_xi_get_property_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiGetPropertyItems<'a> = base::StructPtr<'a, xcb_input_xi_get_property_items_t>;

pub type XiGetPropertyReply = base::Reply<xcb_input_xi_get_property_reply_t>;

impl XiGetPropertyReply {
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
    pub fn format(&self) -> u8 {
        unsafe {
            (*self.ptr).format
        }
    }
}

pub fn xi_get_property<'a>(c       : &'a base::Connection,
                           deviceid: DeviceId,
                           delete  : bool,
                           property: xproto::Atom,
                           type_   : xproto::Atom,
                           offset  : u32,
                           len     : u32)
        -> XiGetPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_get_property(c.get_raw_conn(),
                                               deviceid as xcb_input_device_id_t,  // 0
                                               delete as u8,  // 1
                                               property as xcb_atom_t,  // 2
                                               type_ as xcb_atom_t,  // 3
                                               offset as u32,  // 4
                                               len as u32);  // 5
        XiGetPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_get_property_unchecked<'a>(c       : &'a base::Connection,
                                     deviceid: DeviceId,
                                     delete  : bool,
                                     property: xproto::Atom,
                                     type_   : xproto::Atom,
                                     offset  : u32,
                                     len     : u32)
        -> XiGetPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_get_property_unchecked(c.get_raw_conn(),
                                                         deviceid as xcb_input_device_id_t,  // 0
                                                         delete as u8,  // 1
                                                         property as xcb_atom_t,  // 2
                                                         type_ as xcb_atom_t,  // 3
                                                         offset as u32,  // 4
                                                         len as u32);  // 5
        XiGetPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const XI_GET_SELECTED_EVENTS: u8 = 60;

pub type XiGetSelectedEventsCookie<'a> = base::Cookie<'a, xcb_input_xi_get_selected_events_cookie_t>;

impl<'a> XiGetSelectedEventsCookie<'a> {
    pub fn get_reply(&self) -> Result<XiGetSelectedEventsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = XiGetSelectedEventsReply {
                    ptr: xcb_input_xi_get_selected_events_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( XiGetSelectedEventsReply {
                    ptr: xcb_input_xi_get_selected_events_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type XiGetSelectedEventsReply = base::Reply<xcb_input_xi_get_selected_events_reply_t>;

impl XiGetSelectedEventsReply {
    pub fn num_masks(&self) -> u16 {
        unsafe {
            (*self.ptr).num_masks
        }
    }
    pub fn masks(&self) -> EventMaskIterator {
        unsafe {
            xcb_input_xi_get_selected_events_masks_iterator(self.ptr)
        }
    }
}

pub fn xi_get_selected_events<'a>(c     : &'a base::Connection,
                                  window: xproto::Window)
        -> XiGetSelectedEventsCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_get_selected_events(c.get_raw_conn(),
                                                      window as xcb_window_t);  // 0
        XiGetSelectedEventsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn xi_get_selected_events_unchecked<'a>(c     : &'a base::Connection,
                                            window: xproto::Window)
        -> XiGetSelectedEventsCookie<'a> {
    unsafe {
        let cookie = xcb_input_xi_get_selected_events_unchecked(c.get_raw_conn(),
                                                                window as xcb_window_t);  // 0
        XiGetSelectedEventsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

#[derive(Copy, Clone)]
pub struct BarrierReleasePointerInfo {
    pub base: xcb_input_barrier_release_pointer_info_t,
}

impl BarrierReleasePointerInfo {
    #[allow(unused_unsafe)]
    pub fn new(deviceid: DeviceId,
               barrier:  xfixes::Barrier,
               eventid:  u32)
            -> BarrierReleasePointerInfo {
        unsafe {
            BarrierReleasePointerInfo {
                base: xcb_input_barrier_release_pointer_info_t {
                    deviceid: deviceid,
                    pad0:     [0; 2],
                    barrier:  barrier,
                    eventid:  eventid,
                }
            }
        }
    }
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            self.base.deviceid
        }
    }
    pub fn barrier(&self) -> xfixes::Barrier {
        unsafe {
            self.base.barrier
        }
    }
    pub fn eventid(&self) -> u32 {
        unsafe {
            self.base.eventid
        }
    }
}

pub type BarrierReleasePointerInfoIterator = xcb_input_barrier_release_pointer_info_iterator_t;

impl Iterator for BarrierReleasePointerInfoIterator {
    type Item = BarrierReleasePointerInfo;
    fn next(&mut self) -> std::option::Option<BarrierReleasePointerInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_barrier_release_pointer_info_iterator_t;
                let data = (*iter).data;
                xcb_input_barrier_release_pointer_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const XI_BARRIER_RELEASE_POINTER: u8 = 61;

pub fn xi_barrier_release_pointer<'a>(c       : &'a base::Connection,
                                      barriers: &[BarrierReleasePointerInfo])
        -> base::VoidCookie<'a> {
    unsafe {
        let barriers_len = barriers.len();
        let barriers_ptr = barriers.as_ptr();
        let cookie = xcb_input_xi_barrier_release_pointer(c.get_raw_conn(),
                                                          barriers_len as u32,  // 0
                                                          barriers_ptr as *const xcb_input_barrier_release_pointer_info_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn xi_barrier_release_pointer_checked<'a>(c       : &'a base::Connection,
                                              barriers: &[BarrierReleasePointerInfo])
        -> base::VoidCookie<'a> {
    unsafe {
        let barriers_len = barriers.len();
        let barriers_ptr = barriers.as_ptr();
        let cookie = xcb_input_xi_barrier_release_pointer_checked(c.get_raw_conn(),
                                                                  barriers_len as u32,  // 0
                                                                  barriers_ptr as *const xcb_input_barrier_release_pointer_info_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DEVICE_VALUATOR: u8 = 0;

pub type DeviceValuatorEvent = base::Event<xcb_input_device_valuator_event_t>;

impl DeviceValuatorEvent {
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    pub fn device_state(&self) -> u16 {
        unsafe {
            (*self.ptr).device_state
        }
    }
    pub fn num_valuators(&self) -> u8 {
        unsafe {
            (*self.ptr).num_valuators
        }
    }
    pub fn first_valuator(&self) -> u8 {
        unsafe {
            (*self.ptr).first_valuator
        }
    }
    pub fn valuators(&self) -> &[i32] {
        unsafe {
            &(*self.ptr).valuators
        }
    }
    /// Constructs a new DeviceValuatorEvent
    /// `response_type` will be set automatically to DEVICE_VALUATOR
    pub fn new(device_id: u8,
               device_state: u16,
               num_valuators: u8,
               first_valuator: u8,
               valuators: [i32; 6])
            -> DeviceValuatorEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_valuator_event_t;
            (*raw).response_type = DEVICE_VALUATOR;
            (*raw).device_id = device_id;
            (*raw).device_state = device_state;
            (*raw).num_valuators = num_valuators;
            (*raw).first_valuator = first_valuator;
            (*raw).valuators = valuators;
            DeviceValuatorEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_KEY_PRESS: u8 = 1;

pub type DeviceKeyPressEvent = base::Event<xcb_input_device_key_press_event_t>;

impl DeviceKeyPressEvent {
    pub fn detail(&self) -> u8 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).child
        }
    }
    pub fn root_x(&self) -> i16 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    pub fn root_y(&self) -> i16 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    pub fn event_x(&self) -> i16 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    pub fn event_y(&self) -> i16 {
        unsafe {
            (*self.ptr).event_y
        }
    }
    pub fn state(&self) -> u16 {
        unsafe {
            (*self.ptr).state
        }
    }
    pub fn same_screen(&self) -> bool {
        unsafe {
            (*self.ptr).same_screen != 0
        }
    }
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    /// Constructs a new DeviceKeyPressEvent
    /// `response_type` must be set to one of:
    ///     - `DEVICE_KEY_PRESS`
    ///     - `DEVICE_KEY_RELEASE`
    ///     - `DEVICE_BUTTON_PRESS`
    ///     - `DEVICE_BUTTON_RELEASE`
    ///     - `DEVICE_MOTION_NOTIFY`
    ///     - `PROXIMITY_IN`
    ///     - `PROXIMITY_OUT`
    pub fn new(response_type: u8,
               detail: u8,
               time: xproto::Timestamp,
               root: xproto::Window,
               event: xproto::Window,
               child: xproto::Window,
               root_x: i16,
               root_y: i16,
               event_x: i16,
               event_y: i16,
               state: u16,
               same_screen: bool,
               device_id: u8)
            -> DeviceKeyPressEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_key_press_event_t;
            assert!(response_type == DEVICE_KEY_PRESS ||
                    response_type == DEVICE_KEY_RELEASE ||
                    response_type == DEVICE_BUTTON_PRESS ||
                    response_type == DEVICE_BUTTON_RELEASE ||
                    response_type == DEVICE_MOTION_NOTIFY ||
                    response_type == PROXIMITY_IN ||
                    response_type == PROXIMITY_OUT,
                    "wrong response_type supplied to DeviceKeyPressEvent::new");
            (*raw).response_type = response_type;
            (*raw).detail = detail;
            (*raw).time = time;
            (*raw).root = root;
            (*raw).event = event;
            (*raw).child = child;
            (*raw).root_x = root_x;
            (*raw).root_y = root_y;
            (*raw).event_x = event_x;
            (*raw).event_y = event_y;
            (*raw).state = state;
            (*raw).same_screen = if same_screen { 1 } else { 0 };
            (*raw).device_id = device_id;
            DeviceKeyPressEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_KEY_RELEASE: u8 = 2;

pub type DeviceKeyReleaseEvent = base::Event<xcb_input_device_key_release_event_t>;

pub const DEVICE_BUTTON_PRESS: u8 = 3;

pub type DeviceButtonPressEvent = base::Event<xcb_input_device_button_press_event_t>;

pub const DEVICE_BUTTON_RELEASE: u8 = 4;

pub type DeviceButtonReleaseEvent = base::Event<xcb_input_device_button_release_event_t>;

pub const DEVICE_MOTION_NOTIFY: u8 = 5;

pub type DeviceMotionNotifyEvent = base::Event<xcb_input_device_motion_notify_event_t>;

pub const DEVICE_FOCUS_IN: u8 = 6;

pub type DeviceFocusInEvent = base::Event<xcb_input_device_focus_in_event_t>;

impl DeviceFocusInEvent {
    pub fn detail(&self) -> u8 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn mode(&self) -> u8 {
        unsafe {
            (*self.ptr).mode
        }
    }
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    /// Constructs a new DeviceFocusInEvent
    /// `response_type` must be set to one of:
    ///     - `DEVICE_FOCUS_IN`
    ///     - `DEVICE_FOCUS_OUT`
    pub fn new(response_type: u8,
               detail: u8,
               time: xproto::Timestamp,
               window: xproto::Window,
               mode: u8,
               device_id: u8)
            -> DeviceFocusInEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_focus_in_event_t;
            assert!(response_type == DEVICE_FOCUS_IN ||
                    response_type == DEVICE_FOCUS_OUT,
                    "wrong response_type supplied to DeviceFocusInEvent::new");
            (*raw).response_type = response_type;
            (*raw).detail = detail;
            (*raw).time = time;
            (*raw).window = window;
            (*raw).mode = mode;
            (*raw).device_id = device_id;
            DeviceFocusInEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_FOCUS_OUT: u8 = 7;

pub type DeviceFocusOutEvent = base::Event<xcb_input_device_focus_out_event_t>;

pub const PROXIMITY_IN: u8 = 8;

pub type ProximityInEvent = base::Event<xcb_input_proximity_in_event_t>;

pub const PROXIMITY_OUT: u8 = 9;

pub type ProximityOutEvent = base::Event<xcb_input_proximity_out_event_t>;

pub const DEVICE_STATE_NOTIFY: u8 = 10;

pub type DeviceStateNotifyEvent = base::Event<xcb_input_device_state_notify_event_t>;

impl DeviceStateNotifyEvent {
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn num_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).num_keys
        }
    }
    pub fn num_buttons(&self) -> u8 {
        unsafe {
            (*self.ptr).num_buttons
        }
    }
    pub fn num_valuators(&self) -> u8 {
        unsafe {
            (*self.ptr).num_valuators
        }
    }
    pub fn classes_reported(&self) -> u8 {
        unsafe {
            (*self.ptr).classes_reported
        }
    }
    pub fn buttons(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).buttons
        }
    }
    pub fn keys(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).keys
        }
    }
    pub fn valuators(&self) -> &[u32] {
        unsafe {
            &(*self.ptr).valuators
        }
    }
    /// Constructs a new DeviceStateNotifyEvent
    /// `response_type` will be set automatically to DEVICE_STATE_NOTIFY
    pub fn new(device_id: u8,
               time: xproto::Timestamp,
               num_keys: u8,
               num_buttons: u8,
               num_valuators: u8,
               classes_reported: u8,
               buttons: [u8; 4],
               keys: [u8; 4],
               valuators: [u32; 3])
            -> DeviceStateNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_state_notify_event_t;
            (*raw).response_type = DEVICE_STATE_NOTIFY;
            (*raw).device_id = device_id;
            (*raw).time = time;
            (*raw).num_keys = num_keys;
            (*raw).num_buttons = num_buttons;
            (*raw).num_valuators = num_valuators;
            (*raw).classes_reported = classes_reported;
            (*raw).buttons = buttons;
            (*raw).keys = keys;
            (*raw).valuators = valuators;
            DeviceStateNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_MAPPING_NOTIFY: u8 = 11;

pub type DeviceMappingNotifyEvent = base::Event<xcb_input_device_mapping_notify_event_t>;

impl DeviceMappingNotifyEvent {
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    pub fn request(&self) -> u8 {
        unsafe {
            (*self.ptr).request
        }
    }
    pub fn first_keycode(&self) -> KeyCode {
        unsafe {
            (*self.ptr).first_keycode
        }
    }
    pub fn count(&self) -> u8 {
        unsafe {
            (*self.ptr).count
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    /// Constructs a new DeviceMappingNotifyEvent
    /// `response_type` will be set automatically to DEVICE_MAPPING_NOTIFY
    pub fn new(device_id: u8,
               request: u8,
               first_keycode: KeyCode,
               count: u8,
               time: xproto::Timestamp)
            -> DeviceMappingNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_mapping_notify_event_t;
            (*raw).response_type = DEVICE_MAPPING_NOTIFY;
            (*raw).device_id = device_id;
            (*raw).request = request;
            (*raw).first_keycode = first_keycode;
            (*raw).count = count;
            (*raw).time = time;
            DeviceMappingNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const CHANGE_DEVICE_NOTIFY: u8 = 12;

pub type ChangeDeviceNotifyEvent = base::Event<xcb_input_change_device_notify_event_t>;

impl ChangeDeviceNotifyEvent {
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn request(&self) -> u8 {
        unsafe {
            (*self.ptr).request
        }
    }
    /// Constructs a new ChangeDeviceNotifyEvent
    /// `response_type` will be set automatically to CHANGE_DEVICE_NOTIFY
    pub fn new(device_id: u8,
               time: xproto::Timestamp,
               request: u8)
            -> ChangeDeviceNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_change_device_notify_event_t;
            (*raw).response_type = CHANGE_DEVICE_NOTIFY;
            (*raw).device_id = device_id;
            (*raw).time = time;
            (*raw).request = request;
            ChangeDeviceNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_KEY_STATE_NOTIFY: u8 = 13;

pub type DeviceKeyStateNotifyEvent = base::Event<xcb_input_device_key_state_notify_event_t>;

impl DeviceKeyStateNotifyEvent {
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    pub fn keys(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).keys
        }
    }
    /// Constructs a new DeviceKeyStateNotifyEvent
    /// `response_type` will be set automatically to DEVICE_KEY_STATE_NOTIFY
    pub fn new(device_id: u8,
               keys: [u8; 28])
            -> DeviceKeyStateNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_key_state_notify_event_t;
            (*raw).response_type = DEVICE_KEY_STATE_NOTIFY;
            (*raw).device_id = device_id;
            (*raw).keys = keys;
            DeviceKeyStateNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_BUTTON_STATE_NOTIFY: u8 = 14;

pub type DeviceButtonStateNotifyEvent = base::Event<xcb_input_device_button_state_notify_event_t>;

impl DeviceButtonStateNotifyEvent {
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    pub fn buttons(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).buttons
        }
    }
    /// Constructs a new DeviceButtonStateNotifyEvent
    /// `response_type` will be set automatically to DEVICE_BUTTON_STATE_NOTIFY
    pub fn new(device_id: u8,
               buttons: [u8; 28])
            -> DeviceButtonStateNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_button_state_notify_event_t;
            (*raw).response_type = DEVICE_BUTTON_STATE_NOTIFY;
            (*raw).device_id = device_id;
            (*raw).buttons = buttons;
            DeviceButtonStateNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_PRESENCE_NOTIFY: u8 = 15;

pub type DevicePresenceNotifyEvent = base::Event<xcb_input_device_presence_notify_event_t>;

impl DevicePresenceNotifyEvent {
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn devchange(&self) -> u8 {
        unsafe {
            (*self.ptr).devchange
        }
    }
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    pub fn control(&self) -> u16 {
        unsafe {
            (*self.ptr).control
        }
    }
    /// Constructs a new DevicePresenceNotifyEvent
    /// `response_type` will be set automatically to DEVICE_PRESENCE_NOTIFY
    pub fn new(time: xproto::Timestamp,
               devchange: u8,
               device_id: u8,
               control: u16)
            -> DevicePresenceNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_presence_notify_event_t;
            (*raw).response_type = DEVICE_PRESENCE_NOTIFY;
            (*raw).time = time;
            (*raw).devchange = devchange;
            (*raw).device_id = device_id;
            (*raw).control = control;
            DevicePresenceNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_PROPERTY_NOTIFY: u8 = 16;

pub type DevicePropertyNotifyEvent = base::Event<xcb_input_device_property_notify_event_t>;

impl DevicePropertyNotifyEvent {
    pub fn state(&self) -> u8 {
        unsafe {
            (*self.ptr).state
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn property(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).property
        }
    }
    pub fn device_id(&self) -> u8 {
        unsafe {
            (*self.ptr).device_id
        }
    }
    /// Constructs a new DevicePropertyNotifyEvent
    /// `response_type` will be set automatically to DEVICE_PROPERTY_NOTIFY
    pub fn new(state: u8,
               time: xproto::Timestamp,
               property: xproto::Atom,
               device_id: u8)
            -> DevicePropertyNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_property_notify_event_t;
            (*raw).response_type = DEVICE_PROPERTY_NOTIFY;
            (*raw).state = state;
            (*raw).time = time;
            (*raw).property = property;
            (*raw).device_id = device_id;
            DevicePropertyNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const DEVICE_CHANGED: u8 = 1;

pub type DeviceChangedEvent = base::Event<xcb_input_device_changed_event_t>;

impl DeviceChangedEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn reason(&self) -> u8 {
        unsafe {
            (*self.ptr).reason
        }
    }
    pub fn classes(&self) -> DeviceClassIterator {
        unsafe {
            xcb_input_device_changed_classes_iterator(self.ptr)
        }
    }
    /// Constructs a new DeviceChangedEvent
    /// `response_type` will be set automatically to DEVICE_CHANGED
    pub fn new(deviceid: DeviceId,
               time: xproto::Timestamp,
               sourceid: DeviceId,
               reason: u8,
               classes: DeviceClass)
            -> DeviceChangedEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_device_changed_event_t;
            (*raw).response_type = DEVICE_CHANGED;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).num_classes = num_classes;
            (*raw).sourceid = sourceid;
            (*raw).reason = reason;
            (*raw).classes = classes;
            DeviceChangedEvent {
                ptr: raw
            }
        }
    }
}

pub const KEY_PRESS: u8 = 2;

pub type KeyPressEvent = base::Event<xcb_input_key_press_event_t>;

impl KeyPressEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn detail(&self) -> u32 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).child
        }
    }
    pub fn root_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    pub fn root_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    pub fn event_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    pub fn event_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).event_y
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn mods(&self) -> ModifierInfo {
        unsafe {
            std::mem::transmute((*self.ptr).mods)
        }
    }
    pub fn group(&self) -> GroupInfo {
        unsafe {
            std::mem::transmute((*self.ptr).group)
        }
    }
    pub fn button_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_key_press_button_mask_length(field) as usize;
            let data = xcb_input_key_press_button_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn valuator_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_key_press_valuator_mask_length(field) as usize;
            let data = xcb_input_key_press_valuator_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    /// Constructs a new KeyPressEvent
    /// `response_type` must be set to one of:
    ///     - `KEY_PRESS`
    ///     - `KEY_RELEASE`
    pub fn new(response_type: u8,
               deviceid: DeviceId,
               time: xproto::Timestamp,
               detail: u32,
               root: xproto::Window,
               event: xproto::Window,
               child: xproto::Window,
               root_x: Fp1616,
               root_y: Fp1616,
               event_x: Fp1616,
               event_y: Fp1616,
               sourceid: DeviceId,
               flags: u32,
               mods: ModifierInfo,
               group: GroupInfo,
               button_mask: u32,
               valuator_mask: u32)
            -> KeyPressEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_key_press_event_t;
            assert!(response_type == KEY_PRESS ||
                    response_type == KEY_RELEASE,
                    "wrong response_type supplied to KeyPressEvent::new");
            (*raw).response_type = response_type;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).detail = detail;
            (*raw).root = root;
            (*raw).event = event;
            (*raw).child = child;
            (*raw).root_x = root_x;
            (*raw).root_y = root_y;
            (*raw).event_x = event_x;
            (*raw).event_y = event_y;
            (*raw).buttons_len = buttons_len;
            (*raw).valuators_len = valuators_len;
            (*raw).sourceid = sourceid;
            (*raw).flags = flags;
            (*raw).mods = mods.base;
            (*raw).group = group.base;
            (*raw).button_mask = button_mask;
            (*raw).valuator_mask = valuator_mask;
            KeyPressEvent {
                ptr: raw
            }
        }
    }
}

pub const KEY_RELEASE: u8 = 3;

pub type KeyReleaseEvent = base::Event<xcb_input_key_release_event_t>;

pub const BUTTON_PRESS: u8 = 4;

pub type ButtonPressEvent = base::Event<xcb_input_button_press_event_t>;

impl ButtonPressEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn detail(&self) -> u32 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).child
        }
    }
    pub fn root_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    pub fn root_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    pub fn event_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    pub fn event_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).event_y
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn mods(&self) -> ModifierInfo {
        unsafe {
            std::mem::transmute((*self.ptr).mods)
        }
    }
    pub fn group(&self) -> GroupInfo {
        unsafe {
            std::mem::transmute((*self.ptr).group)
        }
    }
    pub fn button_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_button_press_button_mask_length(field) as usize;
            let data = xcb_input_button_press_button_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn valuator_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_button_press_valuator_mask_length(field) as usize;
            let data = xcb_input_button_press_valuator_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    /// Constructs a new ButtonPressEvent
    /// `response_type` must be set to one of:
    ///     - `BUTTON_PRESS`
    ///     - `BUTTON_RELEASE`
    ///     - `MOTION`
    pub fn new(response_type: u8,
               deviceid: DeviceId,
               time: xproto::Timestamp,
               detail: u32,
               root: xproto::Window,
               event: xproto::Window,
               child: xproto::Window,
               root_x: Fp1616,
               root_y: Fp1616,
               event_x: Fp1616,
               event_y: Fp1616,
               sourceid: DeviceId,
               flags: u32,
               mods: ModifierInfo,
               group: GroupInfo,
               button_mask: u32,
               valuator_mask: u32)
            -> ButtonPressEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_button_press_event_t;
            assert!(response_type == BUTTON_PRESS ||
                    response_type == BUTTON_RELEASE ||
                    response_type == MOTION,
                    "wrong response_type supplied to ButtonPressEvent::new");
            (*raw).response_type = response_type;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).detail = detail;
            (*raw).root = root;
            (*raw).event = event;
            (*raw).child = child;
            (*raw).root_x = root_x;
            (*raw).root_y = root_y;
            (*raw).event_x = event_x;
            (*raw).event_y = event_y;
            (*raw).buttons_len = buttons_len;
            (*raw).valuators_len = valuators_len;
            (*raw).sourceid = sourceid;
            (*raw).flags = flags;
            (*raw).mods = mods.base;
            (*raw).group = group.base;
            (*raw).button_mask = button_mask;
            (*raw).valuator_mask = valuator_mask;
            ButtonPressEvent {
                ptr: raw
            }
        }
    }
}

pub const BUTTON_RELEASE: u8 = 5;

pub type ButtonReleaseEvent = base::Event<xcb_input_button_release_event_t>;

pub const MOTION: u8 = 6;

pub type MotionEvent = base::Event<xcb_input_motion_event_t>;

pub const ENTER: u8 = 7;

pub type EnterEvent = base::Event<xcb_input_enter_event_t>;

impl EnterEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn mode(&self) -> u8 {
        unsafe {
            (*self.ptr).mode
        }
    }
    pub fn detail(&self) -> u8 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).child
        }
    }
    pub fn root_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    pub fn root_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    pub fn event_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    pub fn event_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).event_y
        }
    }
    pub fn same_screen(&self) -> u8 {
        unsafe {
            (*self.ptr).same_screen
        }
    }
    pub fn focus(&self) -> u8 {
        unsafe {
            (*self.ptr).focus
        }
    }
    pub fn mods(&self) -> ModifierInfo {
        unsafe {
            std::mem::transmute((*self.ptr).mods)
        }
    }
    pub fn group(&self) -> GroupInfo {
        unsafe {
            std::mem::transmute((*self.ptr).group)
        }
    }
    pub fn buttons(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_enter_buttons_length(field) as usize;
            let data = xcb_input_enter_buttons(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    /// Constructs a new EnterEvent
    /// `response_type` must be set to one of:
    ///     - `ENTER`
    ///     - `LEAVE`
    ///     - `FOCUS_IN`
    ///     - `FOCUS_OUT`
    pub fn new(response_type: u8,
               deviceid: DeviceId,
               time: xproto::Timestamp,
               sourceid: DeviceId,
               mode: u8,
               detail: u8,
               root: xproto::Window,
               event: xproto::Window,
               child: xproto::Window,
               root_x: Fp1616,
               root_y: Fp1616,
               event_x: Fp1616,
               event_y: Fp1616,
               same_screen: u8,
               focus: u8,
               mods: ModifierInfo,
               group: GroupInfo,
               buttons: u32)
            -> EnterEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_enter_event_t;
            assert!(response_type == ENTER ||
                    response_type == LEAVE ||
                    response_type == FOCUS_IN ||
                    response_type == FOCUS_OUT,
                    "wrong response_type supplied to EnterEvent::new");
            (*raw).response_type = response_type;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).sourceid = sourceid;
            (*raw).mode = mode;
            (*raw).detail = detail;
            (*raw).root = root;
            (*raw).event = event;
            (*raw).child = child;
            (*raw).root_x = root_x;
            (*raw).root_y = root_y;
            (*raw).event_x = event_x;
            (*raw).event_y = event_y;
            (*raw).same_screen = same_screen;
            (*raw).focus = focus;
            (*raw).buttons_len = buttons_len;
            (*raw).mods = mods.base;
            (*raw).group = group.base;
            (*raw).buttons = buttons;
            EnterEvent {
                ptr: raw
            }
        }
    }
}

pub const LEAVE: u8 = 8;

pub type LeaveEvent = base::Event<xcb_input_leave_event_t>;

pub const FOCUS_IN: u8 = 9;

pub type FocusInEvent = base::Event<xcb_input_focus_in_event_t>;

pub const FOCUS_OUT: u8 = 10;

pub type FocusOutEvent = base::Event<xcb_input_focus_out_event_t>;

#[derive(Copy, Clone)]
pub struct HierarchyInfo {
    pub base: xcb_input_hierarchy_info_t,
}

impl HierarchyInfo {
    #[allow(unused_unsafe)]
    pub fn new(deviceid:   DeviceId,
               attachment: DeviceId,
               type_:      u8,
               enabled:    bool,
               flags:      u32)
            -> HierarchyInfo {
        unsafe {
            HierarchyInfo {
                base: xcb_input_hierarchy_info_t {
                    deviceid:   deviceid,
                    attachment: attachment,
                    type_:      type_,
                    enabled:    if enabled { 1 } else { 0 },
                    pad0:       [0; 2],
                    flags:      flags,
                }
            }
        }
    }
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            self.base.deviceid
        }
    }
    pub fn attachment(&self) -> DeviceId {
        unsafe {
            self.base.attachment
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn enabled(&self) -> bool {
        unsafe {
            self.base.enabled != 0
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            self.base.flags
        }
    }
}

pub type HierarchyInfoIterator = xcb_input_hierarchy_info_iterator_t;

impl Iterator for HierarchyInfoIterator {
    type Item = HierarchyInfo;
    fn next(&mut self) -> std::option::Option<HierarchyInfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_input_hierarchy_info_iterator_t;
                let data = (*iter).data;
                xcb_input_hierarchy_info_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const HIERARCHY: u8 = 11;

pub type HierarchyEvent = base::Event<xcb_input_hierarchy_event_t>;

impl HierarchyEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn infos(&self) -> HierarchyInfoIterator {
        unsafe {
            xcb_input_hierarchy_infos_iterator(self.ptr)
        }
    }
    /// Constructs a new HierarchyEvent
    /// `response_type` will be set automatically to HIERARCHY
    pub fn new(deviceid: DeviceId,
               time: xproto::Timestamp,
               flags: u32,
               infos: HierarchyInfo)
            -> HierarchyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_hierarchy_event_t;
            (*raw).response_type = HIERARCHY;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).flags = flags;
            (*raw).num_infos = num_infos;
            (*raw).infos = infos;
            HierarchyEvent {
                ptr: raw
            }
        }
    }
}

pub const PROPERTY: u8 = 12;

pub type PropertyEvent = base::Event<xcb_input_property_event_t>;

impl PropertyEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn property(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).property
        }
    }
    pub fn what(&self) -> u8 {
        unsafe {
            (*self.ptr).what
        }
    }
    /// Constructs a new PropertyEvent
    /// `response_type` will be set automatically to PROPERTY
    pub fn new(deviceid: DeviceId,
               time: xproto::Timestamp,
               property: xproto::Atom,
               what: u8)
            -> PropertyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_property_event_t;
            (*raw).response_type = PROPERTY;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).property = property;
            (*raw).what = what;
            PropertyEvent {
                ptr: raw
            }
        }
    }
}

pub const RAW_KEY_PRESS: u8 = 13;

pub type RawKeyPressEvent = base::Event<xcb_input_raw_key_press_event_t>;

impl RawKeyPressEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn detail(&self) -> u32 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn valuator_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_raw_key_press_valuator_mask_length(field) as usize;
            let data = xcb_input_raw_key_press_valuator_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    /// Constructs a new RawKeyPressEvent
    /// `response_type` must be set to one of:
    ///     - `RAW_KEY_PRESS`
    ///     - `RAW_KEY_RELEASE`
    pub fn new(response_type: u8,
               deviceid: DeviceId,
               time: xproto::Timestamp,
               detail: u32,
               sourceid: DeviceId,
               flags: u32,
               valuator_mask: u32)
            -> RawKeyPressEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_raw_key_press_event_t;
            assert!(response_type == RAW_KEY_PRESS ||
                    response_type == RAW_KEY_RELEASE,
                    "wrong response_type supplied to RawKeyPressEvent::new");
            (*raw).response_type = response_type;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).detail = detail;
            (*raw).sourceid = sourceid;
            (*raw).valuators_len = valuators_len;
            (*raw).flags = flags;
            (*raw).valuator_mask = valuator_mask;
            RawKeyPressEvent {
                ptr: raw
            }
        }
    }
}

pub const RAW_KEY_RELEASE: u8 = 14;

pub type RawKeyReleaseEvent = base::Event<xcb_input_raw_key_release_event_t>;

pub const RAW_BUTTON_PRESS: u8 = 15;

pub type RawButtonPressEvent = base::Event<xcb_input_raw_button_press_event_t>;

impl RawButtonPressEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn detail(&self) -> u32 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn valuator_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_raw_button_press_valuator_mask_length(field) as usize;
            let data = xcb_input_raw_button_press_valuator_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    /// Constructs a new RawButtonPressEvent
    /// `response_type` must be set to one of:
    ///     - `RAW_BUTTON_PRESS`
    ///     - `RAW_BUTTON_RELEASE`
    ///     - `RAW_MOTION`
    pub fn new(response_type: u8,
               deviceid: DeviceId,
               time: xproto::Timestamp,
               detail: u32,
               sourceid: DeviceId,
               flags: u32,
               valuator_mask: u32)
            -> RawButtonPressEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_raw_button_press_event_t;
            assert!(response_type == RAW_BUTTON_PRESS ||
                    response_type == RAW_BUTTON_RELEASE ||
                    response_type == RAW_MOTION,
                    "wrong response_type supplied to RawButtonPressEvent::new");
            (*raw).response_type = response_type;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).detail = detail;
            (*raw).sourceid = sourceid;
            (*raw).valuators_len = valuators_len;
            (*raw).flags = flags;
            (*raw).valuator_mask = valuator_mask;
            RawButtonPressEvent {
                ptr: raw
            }
        }
    }
}

pub const RAW_BUTTON_RELEASE: u8 = 16;

pub type RawButtonReleaseEvent = base::Event<xcb_input_raw_button_release_event_t>;

pub const RAW_MOTION: u8 = 17;

pub type RawMotionEvent = base::Event<xcb_input_raw_motion_event_t>;

pub const TOUCH_BEGIN: u8 = 18;

pub type TouchBeginEvent = base::Event<xcb_input_touch_begin_event_t>;

impl TouchBeginEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn detail(&self) -> u32 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).child
        }
    }
    pub fn root_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    pub fn root_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    pub fn event_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    pub fn event_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).event_y
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn mods(&self) -> ModifierInfo {
        unsafe {
            std::mem::transmute((*self.ptr).mods)
        }
    }
    pub fn group(&self) -> GroupInfo {
        unsafe {
            std::mem::transmute((*self.ptr).group)
        }
    }
    pub fn button_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_touch_begin_button_mask_length(field) as usize;
            let data = xcb_input_touch_begin_button_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn valuator_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_touch_begin_valuator_mask_length(field) as usize;
            let data = xcb_input_touch_begin_valuator_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    /// Constructs a new TouchBeginEvent
    /// `response_type` must be set to one of:
    ///     - `TOUCH_BEGIN`
    ///     - `TOUCH_UPDATE`
    ///     - `TOUCH_END`
    pub fn new(response_type: u8,
               deviceid: DeviceId,
               time: xproto::Timestamp,
               detail: u32,
               root: xproto::Window,
               event: xproto::Window,
               child: xproto::Window,
               root_x: Fp1616,
               root_y: Fp1616,
               event_x: Fp1616,
               event_y: Fp1616,
               sourceid: DeviceId,
               flags: u32,
               mods: ModifierInfo,
               group: GroupInfo,
               button_mask: u32,
               valuator_mask: u32)
            -> TouchBeginEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_touch_begin_event_t;
            assert!(response_type == TOUCH_BEGIN ||
                    response_type == TOUCH_UPDATE ||
                    response_type == TOUCH_END,
                    "wrong response_type supplied to TouchBeginEvent::new");
            (*raw).response_type = response_type;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).detail = detail;
            (*raw).root = root;
            (*raw).event = event;
            (*raw).child = child;
            (*raw).root_x = root_x;
            (*raw).root_y = root_y;
            (*raw).event_x = event_x;
            (*raw).event_y = event_y;
            (*raw).buttons_len = buttons_len;
            (*raw).valuators_len = valuators_len;
            (*raw).sourceid = sourceid;
            (*raw).flags = flags;
            (*raw).mods = mods.base;
            (*raw).group = group.base;
            (*raw).button_mask = button_mask;
            (*raw).valuator_mask = valuator_mask;
            TouchBeginEvent {
                ptr: raw
            }
        }
    }
}

pub const TOUCH_UPDATE: u8 = 19;

pub type TouchUpdateEvent = base::Event<xcb_input_touch_update_event_t>;

pub const TOUCH_END: u8 = 20;

pub type TouchEndEvent = base::Event<xcb_input_touch_end_event_t>;

pub const TOUCH_OWNERSHIP: u8 = 21;

pub type TouchOwnershipEvent = base::Event<xcb_input_touch_ownership_event_t>;

impl TouchOwnershipEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn touchid(&self) -> u32 {
        unsafe {
            (*self.ptr).touchid
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).child
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    /// Constructs a new TouchOwnershipEvent
    /// `response_type` will be set automatically to TOUCH_OWNERSHIP
    pub fn new(deviceid: DeviceId,
               time: xproto::Timestamp,
               touchid: u32,
               root: xproto::Window,
               event: xproto::Window,
               child: xproto::Window,
               sourceid: DeviceId,
               flags: u32)
            -> TouchOwnershipEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_touch_ownership_event_t;
            (*raw).response_type = TOUCH_OWNERSHIP;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).touchid = touchid;
            (*raw).root = root;
            (*raw).event = event;
            (*raw).child = child;
            (*raw).sourceid = sourceid;
            (*raw).flags = flags;
            TouchOwnershipEvent {
                ptr: raw
            }
        }
    }
}

pub const RAW_TOUCH_BEGIN: u8 = 22;

pub type RawTouchBeginEvent = base::Event<xcb_input_raw_touch_begin_event_t>;

impl RawTouchBeginEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn detail(&self) -> u32 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn valuator_mask(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_input_raw_touch_begin_valuator_mask_length(field) as usize;
            let data = xcb_input_raw_touch_begin_valuator_mask(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    /// Constructs a new RawTouchBeginEvent
    /// `response_type` must be set to one of:
    ///     - `RAW_TOUCH_BEGIN`
    ///     - `RAW_TOUCH_UPDATE`
    ///     - `RAW_TOUCH_END`
    pub fn new(response_type: u8,
               deviceid: DeviceId,
               time: xproto::Timestamp,
               detail: u32,
               sourceid: DeviceId,
               flags: u32,
               valuator_mask: u32)
            -> RawTouchBeginEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_raw_touch_begin_event_t;
            assert!(response_type == RAW_TOUCH_BEGIN ||
                    response_type == RAW_TOUCH_UPDATE ||
                    response_type == RAW_TOUCH_END,
                    "wrong response_type supplied to RawTouchBeginEvent::new");
            (*raw).response_type = response_type;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).detail = detail;
            (*raw).sourceid = sourceid;
            (*raw).valuators_len = valuators_len;
            (*raw).flags = flags;
            (*raw).valuator_mask = valuator_mask;
            RawTouchBeginEvent {
                ptr: raw
            }
        }
    }
}

pub const RAW_TOUCH_UPDATE: u8 = 23;

pub type RawTouchUpdateEvent = base::Event<xcb_input_raw_touch_update_event_t>;

pub const RAW_TOUCH_END: u8 = 24;

pub type RawTouchEndEvent = base::Event<xcb_input_raw_touch_end_event_t>;

pub const BARRIER_HIT: u8 = 25;

pub type BarrierHitEvent = base::Event<xcb_input_barrier_hit_event_t>;

impl BarrierHitEvent {
    pub fn deviceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).deviceid
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn eventid(&self) -> u32 {
        unsafe {
            (*self.ptr).eventid
        }
    }
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn barrier(&self) -> xfixes::Barrier {
        unsafe {
            (*self.ptr).barrier
        }
    }
    pub fn dtime(&self) -> u32 {
        unsafe {
            (*self.ptr).dtime
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn sourceid(&self) -> DeviceId {
        unsafe {
            (*self.ptr).sourceid
        }
    }
    pub fn root_x(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    pub fn root_y(&self) -> Fp1616 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    pub fn dx(&self) -> Fp3232 {
        unsafe {
            std::mem::transmute((*self.ptr).dx)
        }
    }
    pub fn dy(&self) -> Fp3232 {
        unsafe {
            std::mem::transmute((*self.ptr).dy)
        }
    }
    /// Constructs a new BarrierHitEvent
    /// `response_type` must be set to one of:
    ///     - `BARRIER_HIT`
    ///     - `BARRIER_LEAVE`
    pub fn new(response_type: u8,
               deviceid: DeviceId,
               time: xproto::Timestamp,
               eventid: u32,
               root: xproto::Window,
               event: xproto::Window,
               barrier: xfixes::Barrier,
               dtime: u32,
               flags: u32,
               sourceid: DeviceId,
               root_x: Fp1616,
               root_y: Fp1616,
               dx: Fp3232,
               dy: Fp3232)
            -> BarrierHitEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_input_barrier_hit_event_t;
            assert!(response_type == BARRIER_HIT ||
                    response_type == BARRIER_LEAVE,
                    "wrong response_type supplied to BarrierHitEvent::new");
            (*raw).response_type = response_type;
            (*raw).deviceid = deviceid;
            (*raw).time = time;
            (*raw).eventid = eventid;
            (*raw).root = root;
            (*raw).event = event;
            (*raw).barrier = barrier;
            (*raw).dtime = dtime;
            (*raw).flags = flags;
            (*raw).sourceid = sourceid;
            (*raw).root_x = root_x;
            (*raw).root_y = root_y;
            (*raw).dx = dx.base;
            (*raw).dy = dy.base;
            BarrierHitEvent {
                ptr: raw
            }
        }
    }
}

pub const BARRIER_LEAVE: u8 = 26;

pub type BarrierLeaveEvent = base::Event<xcb_input_barrier_leave_event_t>;

pub const DEVICE: u8 = 0;

pub const EVENT: u8 = 1;

pub const MODE: u8 = 2;

pub const DEVICE_BUSY: u8 = 3;

pub const CLASS: u8 = 4;
