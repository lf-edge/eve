// Generated automatically from xkb.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::xkb::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_xkb_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 0;

pub type Const = u32;
pub const CONST_MAX_LEGAL_KEY_CODE    : Const = 0xff;
pub const CONST_PER_KEY_BIT_ARRAY_SIZE: Const = 0x20;
pub const CONST_KEY_NAME_LENGTH       : Const = 0x04;

pub type EventType = u32;
pub const EVENT_TYPE_NEW_KEYBOARD_NOTIFY    : EventType =  0x01;
pub const EVENT_TYPE_MAP_NOTIFY             : EventType =  0x02;
pub const EVENT_TYPE_STATE_NOTIFY           : EventType =  0x04;
pub const EVENT_TYPE_CONTROLS_NOTIFY        : EventType =  0x08;
pub const EVENT_TYPE_INDICATOR_STATE_NOTIFY : EventType =  0x10;
pub const EVENT_TYPE_INDICATOR_MAP_NOTIFY   : EventType =  0x20;
pub const EVENT_TYPE_NAMES_NOTIFY           : EventType =  0x40;
pub const EVENT_TYPE_COMPAT_MAP_NOTIFY      : EventType =  0x80;
pub const EVENT_TYPE_BELL_NOTIFY            : EventType = 0x100;
pub const EVENT_TYPE_ACTION_MESSAGE         : EventType = 0x200;
pub const EVENT_TYPE_ACCESS_X_NOTIFY        : EventType = 0x400;
pub const EVENT_TYPE_EXTENSION_DEVICE_NOTIFY: EventType = 0x800;

pub type NknDetail = u32;
pub const NKN_DETAIL_KEYCODES : NknDetail = 0x01;
pub const NKN_DETAIL_GEOMETRY : NknDetail = 0x02;
pub const NKN_DETAIL_DEVICE_ID: NknDetail = 0x04;

pub type AxnDetail = u32;
pub const AXN_DETAIL_SK_PRESS   : AxnDetail = 0x01;
pub const AXN_DETAIL_SK_ACCEPT  : AxnDetail = 0x02;
pub const AXN_DETAIL_SK_REJECT  : AxnDetail = 0x04;
pub const AXN_DETAIL_SK_RELEASE : AxnDetail = 0x08;
pub const AXN_DETAIL_BK_ACCEPT  : AxnDetail = 0x10;
pub const AXN_DETAIL_BK_REJECT  : AxnDetail = 0x20;
pub const AXN_DETAIL_AXK_WARNING: AxnDetail = 0x40;

pub type MapPart = u32;
pub const MAP_PART_KEY_TYPES          : MapPart = 0x01;
pub const MAP_PART_KEY_SYMS           : MapPart = 0x02;
pub const MAP_PART_MODIFIER_MAP       : MapPart = 0x04;
pub const MAP_PART_EXPLICIT_COMPONENTS: MapPart = 0x08;
pub const MAP_PART_KEY_ACTIONS        : MapPart = 0x10;
pub const MAP_PART_KEY_BEHAVIORS      : MapPart = 0x20;
pub const MAP_PART_VIRTUAL_MODS       : MapPart = 0x40;
pub const MAP_PART_VIRTUAL_MOD_MAP    : MapPart = 0x80;

pub type SetMapFlags = u32;
pub const SET_MAP_FLAGS_RESIZE_TYPES     : SetMapFlags = 0x01;
pub const SET_MAP_FLAGS_RECOMPUTE_ACTIONS: SetMapFlags = 0x02;

pub type StatePart = u32;
pub const STATE_PART_MODIFIER_STATE    : StatePart =   0x01;
pub const STATE_PART_MODIFIER_BASE     : StatePart =   0x02;
pub const STATE_PART_MODIFIER_LATCH    : StatePart =   0x04;
pub const STATE_PART_MODIFIER_LOCK     : StatePart =   0x08;
pub const STATE_PART_GROUP_STATE       : StatePart =   0x10;
pub const STATE_PART_GROUP_BASE        : StatePart =   0x20;
pub const STATE_PART_GROUP_LATCH       : StatePart =   0x40;
pub const STATE_PART_GROUP_LOCK        : StatePart =   0x80;
pub const STATE_PART_COMPAT_STATE      : StatePart =  0x100;
pub const STATE_PART_GRAB_MODS         : StatePart =  0x200;
pub const STATE_PART_COMPAT_GRAB_MODS  : StatePart =  0x400;
pub const STATE_PART_LOOKUP_MODS       : StatePart =  0x800;
pub const STATE_PART_COMPAT_LOOKUP_MODS: StatePart = 0x1000;
pub const STATE_PART_POINTER_BUTTONS   : StatePart = 0x2000;

pub type BoolCtrl = u32;
pub const BOOL_CTRL_REPEAT_KEYS           : BoolCtrl =   0x01;
pub const BOOL_CTRL_SLOW_KEYS             : BoolCtrl =   0x02;
pub const BOOL_CTRL_BOUNCE_KEYS           : BoolCtrl =   0x04;
pub const BOOL_CTRL_STICKY_KEYS           : BoolCtrl =   0x08;
pub const BOOL_CTRL_MOUSE_KEYS            : BoolCtrl =   0x10;
pub const BOOL_CTRL_MOUSE_KEYS_ACCEL      : BoolCtrl =   0x20;
pub const BOOL_CTRL_ACCESS_X_KEYS         : BoolCtrl =   0x40;
pub const BOOL_CTRL_ACCESS_X_TIMEOUT_MASK : BoolCtrl =   0x80;
pub const BOOL_CTRL_ACCESS_X_FEEDBACK_MASK: BoolCtrl =  0x100;
pub const BOOL_CTRL_AUDIBLE_BELL_MASK     : BoolCtrl =  0x200;
pub const BOOL_CTRL_OVERLAY_1_MASK        : BoolCtrl =  0x400;
pub const BOOL_CTRL_OVERLAY_2_MASK        : BoolCtrl =  0x800;
pub const BOOL_CTRL_IGNORE_GROUP_LOCK_MASK: BoolCtrl = 0x1000;

pub type Control = u32;
pub const CONTROL_GROUPS_WRAP     : Control =  0x8000000;
pub const CONTROL_INTERNAL_MODS   : Control = 0x10000000;
pub const CONTROL_IGNORE_LOCK_MODS: Control = 0x20000000;
pub const CONTROL_PER_KEY_REPEAT  : Control = 0x40000000;
pub const CONTROL_CONTROLS_ENABLED: Control = 0x80000000;

pub type AxOption = u32;
pub const AX_OPTION_SK_PRESS_FB   : AxOption =  0x01;
pub const AX_OPTION_SK_ACCEPT_FB  : AxOption =  0x02;
pub const AX_OPTION_FEATURE_FB    : AxOption =  0x04;
pub const AX_OPTION_SLOW_WARN_FB  : AxOption =  0x08;
pub const AX_OPTION_INDICATOR_FB  : AxOption =  0x10;
pub const AX_OPTION_STICKY_KEYS_FB: AxOption =  0x20;
pub const AX_OPTION_TWO_KEYS      : AxOption =  0x40;
pub const AX_OPTION_LATCH_TO_LOCK : AxOption =  0x80;
pub const AX_OPTION_SK_RELEASE_FB : AxOption = 0x100;
pub const AX_OPTION_SK_REJECT_FB  : AxOption = 0x200;
pub const AX_OPTION_BK_REJECT_FB  : AxOption = 0x400;
pub const AX_OPTION_DUMB_BELL     : AxOption = 0x800;

pub type DeviceSpec = xcb_xkb_device_spec_t;

pub type LedClassResult = u32;
pub const LED_CLASS_RESULT_KBD_FEEDBACK_CLASS: LedClassResult = 0x00;
pub const LED_CLASS_RESULT_LED_FEEDBACK_CLASS: LedClassResult = 0x04;

pub type LedClass = u32;
pub const LED_CLASS_KBD_FEEDBACK_CLASS: LedClass =  0x00;
pub const LED_CLASS_LED_FEEDBACK_CLASS: LedClass =  0x04;
pub const LED_CLASS_DFLT_XI_CLASS     : LedClass = 0x300;
pub const LED_CLASS_ALL_XI_CLASSES    : LedClass = 0x500;

pub type LedClassSpec = xcb_xkb_led_class_spec_t;

pub type BellClassResult = u32;
pub const BELL_CLASS_RESULT_KBD_FEEDBACK_CLASS : BellClassResult = 0x00;
pub const BELL_CLASS_RESULT_BELL_FEEDBACK_CLASS: BellClassResult = 0x05;

pub type BellClass = u32;
pub const BELL_CLASS_KBD_FEEDBACK_CLASS : BellClass =  0x00;
pub const BELL_CLASS_BELL_FEEDBACK_CLASS: BellClass =  0x05;
pub const BELL_CLASS_DFLT_XI_CLASS      : BellClass = 0x300;

pub type BellClassSpec = xcb_xkb_bell_class_spec_t;

pub type Id = u32;
pub const ID_USE_CORE_KBD : Id =  0x100;
pub const ID_USE_CORE_PTR : Id =  0x200;
pub const ID_DFLT_XI_CLASS: Id =  0x300;
pub const ID_DFLT_XI_ID   : Id =  0x400;
pub const ID_ALL_XI_CLASS : Id =  0x500;
pub const ID_ALL_XI_ID    : Id =  0x600;
pub const ID_XI_NONE      : Id = 0xff00;

pub type IdSpec = xcb_xkb_id_spec_t;

pub type Group = u32;
pub const GROUP_1: Group = 0x00;
pub const GROUP_2: Group = 0x01;
pub const GROUP_3: Group = 0x02;
pub const GROUP_4: Group = 0x03;

pub type Groups = u32;
pub const GROUPS_ANY: Groups = 0xfe;
pub const GROUPS_ALL: Groups = 0xff;

pub type SetOfGroup = u32;
pub const SET_OF_GROUP_GROUP_1: SetOfGroup = 0x01;
pub const SET_OF_GROUP_GROUP_2: SetOfGroup = 0x02;
pub const SET_OF_GROUP_GROUP_3: SetOfGroup = 0x04;
pub const SET_OF_GROUP_GROUP_4: SetOfGroup = 0x08;

pub type SetOfGroups = u32;
pub const SET_OF_GROUPS_ANY: SetOfGroups = 0x80;

pub type GroupsWrap = u32;
pub const GROUPS_WRAP_WRAP_INTO_RANGE    : GroupsWrap = 0x00;
pub const GROUPS_WRAP_CLAMP_INTO_RANGE   : GroupsWrap = 0x40;
pub const GROUPS_WRAP_REDIRECT_INTO_RANGE: GroupsWrap = 0x80;

pub type VModsHigh = u32;
pub const V_MODS_HIGH_15: VModsHigh = 0x80;
pub const V_MODS_HIGH_14: VModsHigh = 0x40;
pub const V_MODS_HIGH_13: VModsHigh = 0x20;
pub const V_MODS_HIGH_12: VModsHigh = 0x10;
pub const V_MODS_HIGH_11: VModsHigh = 0x08;
pub const V_MODS_HIGH_10: VModsHigh = 0x04;
pub const V_MODS_HIGH_9 : VModsHigh = 0x02;
pub const V_MODS_HIGH_8 : VModsHigh = 0x01;

pub type VModsLow = u32;
pub const V_MODS_LOW_7: VModsLow = 0x80;
pub const V_MODS_LOW_6: VModsLow = 0x40;
pub const V_MODS_LOW_5: VModsLow = 0x20;
pub const V_MODS_LOW_4: VModsLow = 0x10;
pub const V_MODS_LOW_3: VModsLow = 0x08;
pub const V_MODS_LOW_2: VModsLow = 0x04;
pub const V_MODS_LOW_1: VModsLow = 0x02;
pub const V_MODS_LOW_0: VModsLow = 0x01;

pub type VMod = u32;
pub const V_MOD_15: VMod = 0x8000;
pub const V_MOD_14: VMod = 0x4000;
pub const V_MOD_13: VMod = 0x2000;
pub const V_MOD_12: VMod = 0x1000;
pub const V_MOD_11: VMod =  0x800;
pub const V_MOD_10: VMod =  0x400;
pub const V_MOD_9 : VMod =  0x200;
pub const V_MOD_8 : VMod =  0x100;
pub const V_MOD_7 : VMod =   0x80;
pub const V_MOD_6 : VMod =   0x40;
pub const V_MOD_5 : VMod =   0x20;
pub const V_MOD_4 : VMod =   0x10;
pub const V_MOD_3 : VMod =   0x08;
pub const V_MOD_2 : VMod =   0x04;
pub const V_MOD_1 : VMod =   0x02;
pub const V_MOD_0 : VMod =   0x01;

pub type Explicit = u32;
pub const EXPLICIT_V_MOD_MAP  : Explicit = 0x80;
pub const EXPLICIT_BEHAVIOR   : Explicit = 0x40;
pub const EXPLICIT_AUTO_REPEAT: Explicit = 0x20;
pub const EXPLICIT_INTERPRET  : Explicit = 0x10;
pub const EXPLICIT_KEY_TYPE_4 : Explicit = 0x08;
pub const EXPLICIT_KEY_TYPE_3 : Explicit = 0x04;
pub const EXPLICIT_KEY_TYPE_2 : Explicit = 0x02;
pub const EXPLICIT_KEY_TYPE_1 : Explicit = 0x01;

pub type SymInterpretMatch = u32;
pub const SYM_INTERPRET_MATCH_NONE_OF       : SymInterpretMatch = 0x00;
pub const SYM_INTERPRET_MATCH_ANY_OF_OR_NONE: SymInterpretMatch = 0x01;
pub const SYM_INTERPRET_MATCH_ANY_OF        : SymInterpretMatch = 0x02;
pub const SYM_INTERPRET_MATCH_ALL_OF        : SymInterpretMatch = 0x03;
pub const SYM_INTERPRET_MATCH_EXACTLY       : SymInterpretMatch = 0x04;

pub type SymInterpMatch = u32;
pub const SYM_INTERP_MATCH_LEVEL_ONE_ONLY: SymInterpMatch = 0x80;
pub const SYM_INTERP_MATCH_OP_MASK       : SymInterpMatch = 0x7f;

pub type ImFlag = u32;
pub const IM_FLAG_NO_EXPLICIT  : ImFlag = 0x80;
pub const IM_FLAG_NO_AUTOMATIC : ImFlag = 0x40;
pub const IM_FLAG_LED_DRIVES_KB: ImFlag = 0x20;

pub type ImModsWhich = u32;
pub const IM_MODS_WHICH_USE_COMPAT   : ImModsWhich = 0x10;
pub const IM_MODS_WHICH_USE_EFFECTIVE: ImModsWhich = 0x08;
pub const IM_MODS_WHICH_USE_LOCKED   : ImModsWhich = 0x04;
pub const IM_MODS_WHICH_USE_LATCHED  : ImModsWhich = 0x02;
pub const IM_MODS_WHICH_USE_BASE     : ImModsWhich = 0x01;

pub type ImGroupsWhich = u32;
pub const IM_GROUPS_WHICH_USE_COMPAT   : ImGroupsWhich = 0x10;
pub const IM_GROUPS_WHICH_USE_EFFECTIVE: ImGroupsWhich = 0x08;
pub const IM_GROUPS_WHICH_USE_LOCKED   : ImGroupsWhich = 0x04;
pub const IM_GROUPS_WHICH_USE_LATCHED  : ImGroupsWhich = 0x02;
pub const IM_GROUPS_WHICH_USE_BASE     : ImGroupsWhich = 0x01;

pub type CmDetail = u32;
pub const CM_DETAIL_SYM_INTERP  : CmDetail = 0x01;
pub const CM_DETAIL_GROUP_COMPAT: CmDetail = 0x02;

pub type NameDetail = u32;
pub const NAME_DETAIL_KEYCODES         : NameDetail =   0x01;
pub const NAME_DETAIL_GEOMETRY         : NameDetail =   0x02;
pub const NAME_DETAIL_SYMBOLS          : NameDetail =   0x04;
pub const NAME_DETAIL_PHYS_SYMBOLS     : NameDetail =   0x08;
pub const NAME_DETAIL_TYPES            : NameDetail =   0x10;
pub const NAME_DETAIL_COMPAT           : NameDetail =   0x20;
pub const NAME_DETAIL_KEY_TYPE_NAMES   : NameDetail =   0x40;
pub const NAME_DETAIL_KT_LEVEL_NAMES   : NameDetail =   0x80;
pub const NAME_DETAIL_INDICATOR_NAMES  : NameDetail =  0x100;
pub const NAME_DETAIL_KEY_NAMES        : NameDetail =  0x200;
pub const NAME_DETAIL_KEY_ALIASES      : NameDetail =  0x400;
pub const NAME_DETAIL_VIRTUAL_MOD_NAMES: NameDetail =  0x800;
pub const NAME_DETAIL_GROUP_NAMES      : NameDetail = 0x1000;
pub const NAME_DETAIL_RG_NAMES         : NameDetail = 0x2000;

pub type GbnDetail = u32;
pub const GBN_DETAIL_TYPES         : GbnDetail = 0x01;
pub const GBN_DETAIL_COMPAT_MAP    : GbnDetail = 0x02;
pub const GBN_DETAIL_CLIENT_SYMBOLS: GbnDetail = 0x04;
pub const GBN_DETAIL_SERVER_SYMBOLS: GbnDetail = 0x08;
pub const GBN_DETAIL_INDICATOR_MAPS: GbnDetail = 0x10;
pub const GBN_DETAIL_KEY_NAMES     : GbnDetail = 0x20;
pub const GBN_DETAIL_GEOMETRY      : GbnDetail = 0x40;
pub const GBN_DETAIL_OTHER_NAMES   : GbnDetail = 0x80;

pub type XiFeature = u32;
pub const XI_FEATURE_KEYBOARDS      : XiFeature = 0x01;
pub const XI_FEATURE_BUTTON_ACTIONS : XiFeature = 0x02;
pub const XI_FEATURE_INDICATOR_NAMES: XiFeature = 0x04;
pub const XI_FEATURE_INDICATOR_MAPS : XiFeature = 0x08;
pub const XI_FEATURE_INDICATOR_STATE: XiFeature = 0x10;

pub type PerClientFlag = u32;
pub const PER_CLIENT_FLAG_DETECTABLE_AUTO_REPEAT   : PerClientFlag = 0x01;
pub const PER_CLIENT_FLAG_GRABS_USE_XKB_STATE      : PerClientFlag = 0x02;
pub const PER_CLIENT_FLAG_AUTO_RESET_CONTROLS      : PerClientFlag = 0x04;
pub const PER_CLIENT_FLAG_LOOKUP_STATE_WHEN_GRABBED: PerClientFlag = 0x08;
pub const PER_CLIENT_FLAG_SEND_EVENT_USES_XKB_STATE: PerClientFlag = 0x10;

pub type BehaviorType = u32;
pub const BEHAVIOR_TYPE_DEFAULT              : BehaviorType = 0x00;
pub const BEHAVIOR_TYPE_LOCK                 : BehaviorType = 0x01;
pub const BEHAVIOR_TYPE_RADIO_GROUP          : BehaviorType = 0x02;
pub const BEHAVIOR_TYPE_OVERLAY_1            : BehaviorType = 0x03;
pub const BEHAVIOR_TYPE_OVERLAY_2            : BehaviorType = 0x04;
pub const BEHAVIOR_TYPE_PERMAMENT_LOCK       : BehaviorType = 0x81;
pub const BEHAVIOR_TYPE_PERMAMENT_RADIO_GROUP: BehaviorType = 0x82;
pub const BEHAVIOR_TYPE_PERMAMENT_OVERLAY_1  : BehaviorType = 0x83;
pub const BEHAVIOR_TYPE_PERMAMENT_OVERLAY_2  : BehaviorType = 0x84;

pub type String8 = xcb_xkb_string8_t;

pub type DoodadType = u32;
pub const DOODAD_TYPE_OUTLINE  : DoodadType = 0x01;
pub const DOODAD_TYPE_SOLID    : DoodadType = 0x02;
pub const DOODAD_TYPE_TEXT     : DoodadType = 0x03;
pub const DOODAD_TYPE_INDICATOR: DoodadType = 0x04;
pub const DOODAD_TYPE_LOGO     : DoodadType = 0x05;

pub type Error = u32;
pub const ERROR_BAD_DEVICE: Error = 0xff;
pub const ERROR_BAD_CLASS : Error = 0xfe;
pub const ERROR_BAD_ID    : Error = 0xfd;

pub struct KeyboardError {
    pub base: base::Error<xcb_xkb_keyboard_error_t>
}

pub type Sa = u32;
pub const SA_CLEAR_LOCKS     : Sa = 0x01;
pub const SA_LATCH_TO_LOCK   : Sa = 0x02;
pub const SA_USE_MOD_MAP_MODS: Sa = 0x04;
pub const SA_GROUP_ABSOLUTE  : Sa = 0x04;

pub type SaType = u32;
pub const SA_TYPE_NO_ACTION      : SaType = 0x00;
pub const SA_TYPE_SET_MODS       : SaType = 0x01;
pub const SA_TYPE_LATCH_MODS     : SaType = 0x02;
pub const SA_TYPE_LOCK_MODS      : SaType = 0x03;
pub const SA_TYPE_SET_GROUP      : SaType = 0x04;
pub const SA_TYPE_LATCH_GROUP    : SaType = 0x05;
pub const SA_TYPE_LOCK_GROUP     : SaType = 0x06;
pub const SA_TYPE_MOVE_PTR       : SaType = 0x07;
pub const SA_TYPE_PTR_BTN        : SaType = 0x08;
pub const SA_TYPE_LOCK_PTR_BTN   : SaType = 0x09;
pub const SA_TYPE_SET_PTR_DFLT   : SaType = 0x0a;
pub const SA_TYPE_ISO_LOCK       : SaType = 0x0b;
pub const SA_TYPE_TERMINATE      : SaType = 0x0c;
pub const SA_TYPE_SWITCH_SCREEN  : SaType = 0x0d;
pub const SA_TYPE_SET_CONTROLS   : SaType = 0x0e;
pub const SA_TYPE_LOCK_CONTROLS  : SaType = 0x0f;
pub const SA_TYPE_ACTION_MESSAGE : SaType = 0x10;
pub const SA_TYPE_REDIRECT_KEY   : SaType = 0x11;
pub const SA_TYPE_DEVICE_BTN     : SaType = 0x12;
pub const SA_TYPE_LOCK_DEVICE_BTN: SaType = 0x13;
pub const SA_TYPE_DEVICE_VALUATOR: SaType = 0x14;

pub type SaMovePtrFlag = u32;
pub const SA_MOVE_PTR_FLAG_NO_ACCELERATION: SaMovePtrFlag = 0x01;
pub const SA_MOVE_PTR_FLAG_MOVE_ABSOLUTE_X: SaMovePtrFlag = 0x02;
pub const SA_MOVE_PTR_FLAG_MOVE_ABSOLUTE_Y: SaMovePtrFlag = 0x04;

pub type SaSetPtrDfltFlag = u32;
pub const SA_SET_PTR_DFLT_FLAG_DFLT_BTN_ABSOLUTE : SaSetPtrDfltFlag = 0x04;
pub const SA_SET_PTR_DFLT_FLAG_AFFECT_DFLT_BUTTON: SaSetPtrDfltFlag = 0x01;

pub type SaIsoLockFlag = u32;
pub const SA_ISO_LOCK_FLAG_NO_LOCK          : SaIsoLockFlag = 0x01;
pub const SA_ISO_LOCK_FLAG_NO_UNLOCK        : SaIsoLockFlag = 0x02;
pub const SA_ISO_LOCK_FLAG_USE_MOD_MAP_MODS : SaIsoLockFlag = 0x04;
pub const SA_ISO_LOCK_FLAG_GROUP_ABSOLUTE   : SaIsoLockFlag = 0x04;
pub const SA_ISO_LOCK_FLAG_ISO_DFLT_IS_GROUP: SaIsoLockFlag = 0x08;

pub type SaIsoLockNoAffect = u32;
pub const SA_ISO_LOCK_NO_AFFECT_CTRLS: SaIsoLockNoAffect = 0x08;
pub const SA_ISO_LOCK_NO_AFFECT_PTR  : SaIsoLockNoAffect = 0x10;
pub const SA_ISO_LOCK_NO_AFFECT_GROUP: SaIsoLockNoAffect = 0x20;
pub const SA_ISO_LOCK_NO_AFFECT_MODS : SaIsoLockNoAffect = 0x40;

pub type SwitchScreenFlag = u32;
pub const SWITCH_SCREEN_FLAG_APPLICATION: SwitchScreenFlag = 0x01;
pub const SWITCH_SCREEN_FLAG_ABSOLUTE   : SwitchScreenFlag = 0x04;

pub type BoolCtrlsHigh = u32;
pub const BOOL_CTRLS_HIGH_ACCESS_X_FEEDBACK: BoolCtrlsHigh = 0x01;
pub const BOOL_CTRLS_HIGH_AUDIBLE_BELL     : BoolCtrlsHigh = 0x02;
pub const BOOL_CTRLS_HIGH_OVERLAY_1        : BoolCtrlsHigh = 0x04;
pub const BOOL_CTRLS_HIGH_OVERLAY_2        : BoolCtrlsHigh = 0x08;
pub const BOOL_CTRLS_HIGH_IGNORE_GROUP_LOCK: BoolCtrlsHigh = 0x10;

pub type BoolCtrlsLow = u32;
pub const BOOL_CTRLS_LOW_REPEAT_KEYS     : BoolCtrlsLow = 0x01;
pub const BOOL_CTRLS_LOW_SLOW_KEYS       : BoolCtrlsLow = 0x02;
pub const BOOL_CTRLS_LOW_BOUNCE_KEYS     : BoolCtrlsLow = 0x04;
pub const BOOL_CTRLS_LOW_STICKY_KEYS     : BoolCtrlsLow = 0x08;
pub const BOOL_CTRLS_LOW_MOUSE_KEYS      : BoolCtrlsLow = 0x10;
pub const BOOL_CTRLS_LOW_MOUSE_KEYS_ACCEL: BoolCtrlsLow = 0x20;
pub const BOOL_CTRLS_LOW_ACCESS_X_KEYS   : BoolCtrlsLow = 0x40;
pub const BOOL_CTRLS_LOW_ACCESS_X_TIMEOUT: BoolCtrlsLow = 0x80;

pub type ActionMessageFlag = u32;
pub const ACTION_MESSAGE_FLAG_ON_PRESS     : ActionMessageFlag = 0x01;
pub const ACTION_MESSAGE_FLAG_ON_RELEASE   : ActionMessageFlag = 0x02;
pub const ACTION_MESSAGE_FLAG_GEN_KEY_EVENT: ActionMessageFlag = 0x04;

pub type LockDeviceFlags = u32;
pub const LOCK_DEVICE_FLAGS_NO_LOCK  : LockDeviceFlags = 0x01;
pub const LOCK_DEVICE_FLAGS_NO_UNLOCK: LockDeviceFlags = 0x02;

pub type SaValWhat = u32;
pub const SA_VAL_WHAT_IGNORE_VAL      : SaValWhat = 0x00;
pub const SA_VAL_WHAT_SET_VAL_MIN     : SaValWhat = 0x01;
pub const SA_VAL_WHAT_SET_VAL_CENTER  : SaValWhat = 0x02;
pub const SA_VAL_WHAT_SET_VAL_MAX     : SaValWhat = 0x03;
pub const SA_VAL_WHAT_SET_VAL_RELATIVE: SaValWhat = 0x04;
pub const SA_VAL_WHAT_SET_VAL_ABSOLUTE: SaValWhat = 0x05;



#[derive(Copy, Clone)]
pub struct IndicatorMap {
    pub base: xcb_xkb_indicator_map_t,
}

impl IndicatorMap {
    #[allow(unused_unsafe)]
    pub fn new(flags:        u8,
               which_groups: u8,
               groups:       u8,
               which_mods:   u8,
               mods:         u8,
               real_mods:    u8,
               vmods:        u16,
               ctrls:        u32)
            -> IndicatorMap {
        unsafe {
            IndicatorMap {
                base: xcb_xkb_indicator_map_t {
                    flags:        flags,
                    whichGroups: which_groups,
                    groups:       groups,
                    whichMods:   which_mods,
                    mods:         mods,
                    realMods:    real_mods,
                    vmods:        vmods,
                    ctrls:        ctrls,
                }
            }
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn which_groups(&self) -> u8 {
        unsafe {
            self.base.whichGroups
        }
    }
    pub fn groups(&self) -> u8 {
        unsafe {
            self.base.groups
        }
    }
    pub fn which_mods(&self) -> u8 {
        unsafe {
            self.base.whichMods
        }
    }
    pub fn mods(&self) -> u8 {
        unsafe {
            self.base.mods
        }
    }
    pub fn real_mods(&self) -> u8 {
        unsafe {
            self.base.realMods
        }
    }
    pub fn vmods(&self) -> u16 {
        unsafe {
            self.base.vmods
        }
    }
    pub fn ctrls(&self) -> u32 {
        unsafe {
            self.base.ctrls
        }
    }
}

pub type IndicatorMapIterator = xcb_xkb_indicator_map_iterator_t;

impl Iterator for IndicatorMapIterator {
    type Item = IndicatorMap;
    fn next(&mut self) -> std::option::Option<IndicatorMap> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_indicator_map_iterator_t;
                let data = (*iter).data;
                xcb_xkb_indicator_map_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ModDef {
    pub base: xcb_xkb_mod_def_t,
}

impl ModDef {
    #[allow(unused_unsafe)]
    pub fn new(mask:      u8,
               real_mods: u8,
               vmods:     u16)
            -> ModDef {
        unsafe {
            ModDef {
                base: xcb_xkb_mod_def_t {
                    mask:      mask,
                    realMods: real_mods,
                    vmods:     vmods,
                }
            }
        }
    }
    pub fn mask(&self) -> u8 {
        unsafe {
            self.base.mask
        }
    }
    pub fn real_mods(&self) -> u8 {
        unsafe {
            self.base.realMods
        }
    }
    pub fn vmods(&self) -> u16 {
        unsafe {
            self.base.vmods
        }
    }
}

pub type ModDefIterator = xcb_xkb_mod_def_iterator_t;

impl Iterator for ModDefIterator {
    type Item = ModDef;
    fn next(&mut self) -> std::option::Option<ModDef> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_mod_def_iterator_t;
                let data = (*iter).data;
                xcb_xkb_mod_def_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type KeyName<'a> = base::StructPtr<'a, xcb_xkb_key_name_t>;

impl<'a> KeyName<'a> {
    pub fn name(&self) -> &[c_char] {
        unsafe {
            &(*self.ptr).name
        }
    }
}

pub type KeyNameIterator<'a> = xcb_xkb_key_name_iterator_t<'a>;

impl<'a> Iterator for KeyNameIterator<'a> {
    type Item = KeyName<'a>;
    fn next(&mut self) -> std::option::Option<KeyName<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_key_name_iterator_t;
                let data = (*iter).data;
                xcb_xkb_key_name_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type KeyAlias<'a> = base::StructPtr<'a, xcb_xkb_key_alias_t>;

impl<'a> KeyAlias<'a> {
    pub fn real(&self) -> &[c_char] {
        unsafe {
            &(*self.ptr).real
        }
    }
    pub fn alias(&self) -> &[c_char] {
        unsafe {
            &(*self.ptr).alias
        }
    }
}

pub type KeyAliasIterator<'a> = xcb_xkb_key_alias_iterator_t<'a>;

impl<'a> Iterator for KeyAliasIterator<'a> {
    type Item = KeyAlias<'a>;
    fn next(&mut self) -> std::option::Option<KeyAlias<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_key_alias_iterator_t;
                let data = (*iter).data;
                xcb_xkb_key_alias_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type CountedString16<'a> = base::StructPtr<'a, xcb_xkb_counted_string_16_t>;

impl<'a> CountedString16<'a> {
    pub fn length(&self) -> u16 {
        unsafe {
            (*self.ptr).length
        }
    }
    pub fn string(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xkb_counted_string_16_string_length(field) as usize;
            let data = xcb_xkb_counted_string_16_string(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn alignment_pad<T>(&self) -> &[T] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xkb_counted_string_16_alignment_pad_length(field) as usize;
            let data = xcb_xkb_counted_string_16_alignment_pad(field);
            debug_assert_eq!(len % std::mem::size_of::<T>(), 0);
            std::slice::from_raw_parts(data as *const T, len / std::mem::size_of::<T>())
        }
    }
}

pub type CountedString16Iterator<'a> = xcb_xkb_counted_string_16_iterator_t<'a>;

impl<'a> Iterator for CountedString16Iterator<'a> {
    type Item = CountedString16<'a>;
    fn next(&mut self) -> std::option::Option<CountedString16<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_counted_string_16_iterator_t;
                let data = (*iter).data;
                xcb_xkb_counted_string_16_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct KtMapEntry {
    pub base: xcb_xkb_kt_map_entry_t,
}

impl KtMapEntry {
    #[allow(unused_unsafe)]
    pub fn new(active:     bool,
               mods_mask:  u8,
               level:      u8,
               mods_mods:  u8,
               mods_vmods: u16)
            -> KtMapEntry {
        unsafe {
            KtMapEntry {
                base: xcb_xkb_kt_map_entry_t {
                    active:     if active { 1 } else { 0 },
                    mods_mask:  mods_mask,
                    level:      level,
                    mods_mods:  mods_mods,
                    mods_vmods: mods_vmods,
                    pad0:       [0; 2],
                }
            }
        }
    }
    pub fn active(&self) -> bool {
        unsafe {
            self.base.active != 0
        }
    }
    pub fn mods_mask(&self) -> u8 {
        unsafe {
            self.base.mods_mask
        }
    }
    pub fn level(&self) -> u8 {
        unsafe {
            self.base.level
        }
    }
    pub fn mods_mods(&self) -> u8 {
        unsafe {
            self.base.mods_mods
        }
    }
    pub fn mods_vmods(&self) -> u16 {
        unsafe {
            self.base.mods_vmods
        }
    }
}

pub type KtMapEntryIterator = xcb_xkb_kt_map_entry_iterator_t;

impl Iterator for KtMapEntryIterator {
    type Item = KtMapEntry;
    fn next(&mut self) -> std::option::Option<KtMapEntry> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_kt_map_entry_iterator_t;
                let data = (*iter).data;
                xcb_xkb_kt_map_entry_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type KeyType<'a> = base::StructPtr<'a, xcb_xkb_key_type_t>;

impl<'a> KeyType<'a> {
    pub fn mods_mask(&self) -> u8 {
        unsafe {
            (*self.ptr).mods_mask
        }
    }
    pub fn mods_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).mods_mods
        }
    }
    pub fn mods_vmods(&self) -> u16 {
        unsafe {
            (*self.ptr).mods_vmods
        }
    }
    pub fn num_levels(&self) -> u8 {
        unsafe {
            (*self.ptr).numLevels
        }
    }
    pub fn n_map_entries(&self) -> u8 {
        unsafe {
            (*self.ptr).nMapEntries
        }
    }
    pub fn has_preserve(&self) -> bool {
        unsafe {
            (*self.ptr).hasPreserve != 0
        }
    }
    pub fn map(&self) -> KtMapEntryIterator {
        unsafe {
            xcb_xkb_key_type_map_iterator(self.ptr)
        }
    }
    pub fn preserve(&self) -> ModDefIterator {
        unsafe {
            xcb_xkb_key_type_preserve_iterator(self.ptr)
        }
    }
}

pub type KeyTypeIterator<'a> = xcb_xkb_key_type_iterator_t<'a>;

impl<'a> Iterator for KeyTypeIterator<'a> {
    type Item = KeyType<'a>;
    fn next(&mut self) -> std::option::Option<KeyType<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_key_type_iterator_t;
                let data = (*iter).data;
                xcb_xkb_key_type_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type KeySymMap<'a> = base::StructPtr<'a, xcb_xkb_key_sym_map_t>;

impl<'a> KeySymMap<'a> {
    pub fn kt_index(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).kt_index
        }
    }
    pub fn group_info(&self) -> u8 {
        unsafe {
            (*self.ptr).groupInfo
        }
    }
    pub fn width(&self) -> u8 {
        unsafe {
            (*self.ptr).width
        }
    }
    pub fn n_syms(&self) -> u16 {
        unsafe {
            (*self.ptr).nSyms
        }
    }
    pub fn syms(&self) -> &[xproto::Keysym] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xkb_key_sym_map_syms_length(field) as usize;
            let data = xcb_xkb_key_sym_map_syms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type KeySymMapIterator<'a> = xcb_xkb_key_sym_map_iterator_t<'a>;

impl<'a> Iterator for KeySymMapIterator<'a> {
    type Item = KeySymMap<'a>;
    fn next(&mut self) -> std::option::Option<KeySymMap<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_key_sym_map_iterator_t;
                let data = (*iter).data;
                xcb_xkb_key_sym_map_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct CommonBehavior {
    pub base: xcb_xkb_common_behavior_t,
}

impl CommonBehavior {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8,
               data:  u8)
            -> CommonBehavior {
        unsafe {
            CommonBehavior {
                base: xcb_xkb_common_behavior_t {
                    type_: type_,
                    data:  data,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn data(&self) -> u8 {
        unsafe {
            self.base.data
        }
    }
}

pub type CommonBehaviorIterator = xcb_xkb_common_behavior_iterator_t;

impl Iterator for CommonBehaviorIterator {
    type Item = CommonBehavior;
    fn next(&mut self) -> std::option::Option<CommonBehavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_common_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_common_behavior_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct DefaultBehavior {
    pub base: xcb_xkb_default_behavior_t,
}

impl DefaultBehavior {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8)
            -> DefaultBehavior {
        unsafe {
            DefaultBehavior {
                base: xcb_xkb_default_behavior_t {
                    type_: type_,
                    pad0:  0,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
}

pub type DefaultBehaviorIterator = xcb_xkb_default_behavior_iterator_t;

impl Iterator for DefaultBehaviorIterator {
    type Item = DefaultBehavior;
    fn next(&mut self) -> std::option::Option<DefaultBehavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_default_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_default_behavior_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct LockBehavior {
    pub base: xcb_xkb_lock_behavior_t,
}

impl LockBehavior {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8)
            -> LockBehavior {
        unsafe {
            LockBehavior {
                base: xcb_xkb_lock_behavior_t {
                    type_: type_,
                    pad0:  0,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
}

pub type LockBehaviorIterator = xcb_xkb_lock_behavior_iterator_t;

impl Iterator for LockBehaviorIterator {
    type Item = LockBehavior;
    fn next(&mut self) -> std::option::Option<LockBehavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_lock_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_lock_behavior_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct RadioGroupBehavior {
    pub base: xcb_xkb_radio_group_behavior_t,
}

impl RadioGroupBehavior {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8,
               group: u8)
            -> RadioGroupBehavior {
        unsafe {
            RadioGroupBehavior {
                base: xcb_xkb_radio_group_behavior_t {
                    type_: type_,
                    group: group,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn group(&self) -> u8 {
        unsafe {
            self.base.group
        }
    }
}

pub type RadioGroupBehaviorIterator = xcb_xkb_radio_group_behavior_iterator_t;

impl Iterator for RadioGroupBehaviorIterator {
    type Item = RadioGroupBehavior;
    fn next(&mut self) -> std::option::Option<RadioGroupBehavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_radio_group_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_radio_group_behavior_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct OverlayBehavior {
    pub base: xcb_xkb_overlay_behavior_t,
}

impl OverlayBehavior {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8,
               key:   xproto::Keycode)
            -> OverlayBehavior {
        unsafe {
            OverlayBehavior {
                base: xcb_xkb_overlay_behavior_t {
                    type_: type_,
                    key:   key,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn key(&self) -> xproto::Keycode {
        unsafe {
            self.base.key
        }
    }
}

pub type OverlayBehaviorIterator = xcb_xkb_overlay_behavior_iterator_t;

impl Iterator for OverlayBehaviorIterator {
    type Item = OverlayBehavior;
    fn next(&mut self) -> std::option::Option<OverlayBehavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_overlay_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_overlay_behavior_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct PermamentLockBehavior {
    pub base: xcb_xkb_permament_lock_behavior_t,
}

impl PermamentLockBehavior {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8)
            -> PermamentLockBehavior {
        unsafe {
            PermamentLockBehavior {
                base: xcb_xkb_permament_lock_behavior_t {
                    type_: type_,
                    pad0:  0,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
}

pub type PermamentLockBehaviorIterator = xcb_xkb_permament_lock_behavior_iterator_t;

impl Iterator for PermamentLockBehaviorIterator {
    type Item = PermamentLockBehavior;
    fn next(&mut self) -> std::option::Option<PermamentLockBehavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_permament_lock_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_permament_lock_behavior_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct PermamentRadioGroupBehavior {
    pub base: xcb_xkb_permament_radio_group_behavior_t,
}

impl PermamentRadioGroupBehavior {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8,
               group: u8)
            -> PermamentRadioGroupBehavior {
        unsafe {
            PermamentRadioGroupBehavior {
                base: xcb_xkb_permament_radio_group_behavior_t {
                    type_: type_,
                    group: group,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn group(&self) -> u8 {
        unsafe {
            self.base.group
        }
    }
}

pub type PermamentRadioGroupBehaviorIterator = xcb_xkb_permament_radio_group_behavior_iterator_t;

impl Iterator for PermamentRadioGroupBehaviorIterator {
    type Item = PermamentRadioGroupBehavior;
    fn next(&mut self) -> std::option::Option<PermamentRadioGroupBehavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_permament_radio_group_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_permament_radio_group_behavior_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct PermamentOverlayBehavior {
    pub base: xcb_xkb_permament_overlay_behavior_t,
}

impl PermamentOverlayBehavior {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8,
               key:   xproto::Keycode)
            -> PermamentOverlayBehavior {
        unsafe {
            PermamentOverlayBehavior {
                base: xcb_xkb_permament_overlay_behavior_t {
                    type_: type_,
                    key:   key,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn key(&self) -> xproto::Keycode {
        unsafe {
            self.base.key
        }
    }
}

pub type PermamentOverlayBehaviorIterator = xcb_xkb_permament_overlay_behavior_iterator_t;

impl Iterator for PermamentOverlayBehaviorIterator {
    type Item = PermamentOverlayBehavior;
    fn next(&mut self) -> std::option::Option<PermamentOverlayBehavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_permament_overlay_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_permament_overlay_behavior_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type Behavior = xcb_xkb_behavior_t;

impl Behavior {
    pub fn common(&self) -> CommonBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const CommonBehavior;
            *_ptr
        }
    }
    pub fn from_common(common: CommonBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut CommonBehavior;
            *res_ptr = common;
            res
        }
    }
    pub fn default(&self) -> DefaultBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const DefaultBehavior;
            *_ptr
        }
    }
    pub fn from_default(default: DefaultBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut DefaultBehavior;
            *res_ptr = default;
            res
        }
    }
    pub fn lock(&self) -> LockBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const LockBehavior;
            *_ptr
        }
    }
    pub fn from_lock(lock: LockBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut LockBehavior;
            *res_ptr = lock;
            res
        }
    }
    pub fn radio_group(&self) -> RadioGroupBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const RadioGroupBehavior;
            *_ptr
        }
    }
    pub fn from_radio_group(radio_group: RadioGroupBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut RadioGroupBehavior;
            *res_ptr = radio_group;
            res
        }
    }
    pub fn overlay1(&self) -> OverlayBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const OverlayBehavior;
            *_ptr
        }
    }
    pub fn from_overlay1(overlay1: OverlayBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut OverlayBehavior;
            *res_ptr = overlay1;
            res
        }
    }
    pub fn overlay2(&self) -> OverlayBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const OverlayBehavior;
            *_ptr
        }
    }
    pub fn from_overlay2(overlay2: OverlayBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut OverlayBehavior;
            *res_ptr = overlay2;
            res
        }
    }
    pub fn permament_lock(&self) -> PermamentLockBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const PermamentLockBehavior;
            *_ptr
        }
    }
    pub fn from_permament_lock(permament_lock: PermamentLockBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut PermamentLockBehavior;
            *res_ptr = permament_lock;
            res
        }
    }
    pub fn permament_radio_group(&self) -> PermamentRadioGroupBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const PermamentRadioGroupBehavior;
            *_ptr
        }
    }
    pub fn from_permament_radio_group(permament_radio_group: PermamentRadioGroupBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut PermamentRadioGroupBehavior;
            *res_ptr = permament_radio_group;
            res
        }
    }
    pub fn permament_overlay1(&self) -> PermamentOverlayBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const PermamentOverlayBehavior;
            *_ptr
        }
    }
    pub fn from_permament_overlay1(permament_overlay1: PermamentOverlayBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut PermamentOverlayBehavior;
            *res_ptr = permament_overlay1;
            res
        }
    }
    pub fn permament_overlay2(&self) -> PermamentOverlayBehavior {
        unsafe {
            let _ptr = self.data.as_ptr() as *const PermamentOverlayBehavior;
            *_ptr
        }
    }
    pub fn from_permament_overlay2(permament_overlay2: PermamentOverlayBehavior) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut PermamentOverlayBehavior;
            *res_ptr = permament_overlay2;
            res
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            let _ptr = self.data.as_ptr() as *const u8;
            *_ptr
        }
    }
    pub fn from_type_(type_: u8) -> Behavior {
        unsafe {
            let mut res = Behavior { data: [0; 2] };
            let res_ptr = res.data.as_mut_ptr() as *mut u8;
            *res_ptr = type_;
            res
        }
    }
}

pub type BehaviorIterator = xcb_xkb_behavior_iterator_t;

impl Iterator for BehaviorIterator {
    type Item = Behavior;
    fn next(&mut self) -> std::option::Option<Behavior> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_behavior_next(iter);
                Some(*data)
            }
        }
    }
}

pub type SetBehavior<'a> = base::StructPtr<'a, xcb_xkb_set_behavior_t>;

impl<'a> SetBehavior<'a> {
    pub fn keycode(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).keycode
        }
    }
    pub fn behavior(&'a self) -> &'a Behavior {
        unsafe {
            &(*self.ptr).behavior
        }
    }
}

pub type SetBehaviorIterator<'a> = xcb_xkb_set_behavior_iterator_t<'a>;

impl<'a> Iterator for SetBehaviorIterator<'a> {
    type Item = SetBehavior<'a>;
    fn next(&mut self) -> std::option::Option<SetBehavior<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_set_behavior_iterator_t;
                let data = (*iter).data;
                xcb_xkb_set_behavior_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SetExplicit {
    pub base: xcb_xkb_set_explicit_t,
}

impl SetExplicit {
    #[allow(unused_unsafe)]
    pub fn new(keycode:  xproto::Keycode,
               explicit: u8)
            -> SetExplicit {
        unsafe {
            SetExplicit {
                base: xcb_xkb_set_explicit_t {
                    keycode:  keycode,
                    explicit: explicit,
                }
            }
        }
    }
    pub fn keycode(&self) -> xproto::Keycode {
        unsafe {
            self.base.keycode
        }
    }
    pub fn explicit(&self) -> u8 {
        unsafe {
            self.base.explicit
        }
    }
}

pub type SetExplicitIterator = xcb_xkb_set_explicit_iterator_t;

impl Iterator for SetExplicitIterator {
    type Item = SetExplicit;
    fn next(&mut self) -> std::option::Option<SetExplicit> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_set_explicit_iterator_t;
                let data = (*iter).data;
                xcb_xkb_set_explicit_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct KeyModMap {
    pub base: xcb_xkb_key_mod_map_t,
}

impl KeyModMap {
    #[allow(unused_unsafe)]
    pub fn new(keycode: xproto::Keycode,
               mods:    u8)
            -> KeyModMap {
        unsafe {
            KeyModMap {
                base: xcb_xkb_key_mod_map_t {
                    keycode: keycode,
                    mods:    mods,
                }
            }
        }
    }
    pub fn keycode(&self) -> xproto::Keycode {
        unsafe {
            self.base.keycode
        }
    }
    pub fn mods(&self) -> u8 {
        unsafe {
            self.base.mods
        }
    }
}

pub type KeyModMapIterator = xcb_xkb_key_mod_map_iterator_t;

impl Iterator for KeyModMapIterator {
    type Item = KeyModMap;
    fn next(&mut self) -> std::option::Option<KeyModMap> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_key_mod_map_iterator_t;
                let data = (*iter).data;
                xcb_xkb_key_mod_map_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct KeyVModMap {
    pub base: xcb_xkb_key_v_mod_map_t,
}

impl KeyVModMap {
    #[allow(unused_unsafe)]
    pub fn new(keycode: xproto::Keycode,
               vmods:   u16)
            -> KeyVModMap {
        unsafe {
            KeyVModMap {
                base: xcb_xkb_key_v_mod_map_t {
                    keycode: keycode,
                    pad0:    0,
                    vmods:   vmods,
                }
            }
        }
    }
    pub fn keycode(&self) -> xproto::Keycode {
        unsafe {
            self.base.keycode
        }
    }
    pub fn vmods(&self) -> u16 {
        unsafe {
            self.base.vmods
        }
    }
}

pub type KeyVModMapIterator = xcb_xkb_key_v_mod_map_iterator_t;

impl Iterator for KeyVModMapIterator {
    type Item = KeyVModMap;
    fn next(&mut self) -> std::option::Option<KeyVModMap> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_key_v_mod_map_iterator_t;
                let data = (*iter).data;
                xcb_xkb_key_v_mod_map_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct KtSetMapEntry {
    pub base: xcb_xkb_kt_set_map_entry_t,
}

impl KtSetMapEntry {
    #[allow(unused_unsafe)]
    pub fn new(level:        u8,
               real_mods:    u8,
               virtual_mods: u16)
            -> KtSetMapEntry {
        unsafe {
            KtSetMapEntry {
                base: xcb_xkb_kt_set_map_entry_t {
                    level:        level,
                    realMods:    real_mods,
                    virtualMods: virtual_mods,
                }
            }
        }
    }
    pub fn level(&self) -> u8 {
        unsafe {
            self.base.level
        }
    }
    pub fn real_mods(&self) -> u8 {
        unsafe {
            self.base.realMods
        }
    }
    pub fn virtual_mods(&self) -> u16 {
        unsafe {
            self.base.virtualMods
        }
    }
}

pub type KtSetMapEntryIterator = xcb_xkb_kt_set_map_entry_iterator_t;

impl Iterator for KtSetMapEntryIterator {
    type Item = KtSetMapEntry;
    fn next(&mut self) -> std::option::Option<KtSetMapEntry> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_kt_set_map_entry_iterator_t;
                let data = (*iter).data;
                xcb_xkb_kt_set_map_entry_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type SetKeyType<'a> = base::StructPtr<'a, xcb_xkb_set_key_type_t>;

impl<'a> SetKeyType<'a> {
    pub fn mask(&self) -> u8 {
        unsafe {
            (*self.ptr).mask
        }
    }
    pub fn real_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).realMods
        }
    }
    pub fn virtual_mods(&self) -> u16 {
        unsafe {
            (*self.ptr).virtualMods
        }
    }
    pub fn num_levels(&self) -> u8 {
        unsafe {
            (*self.ptr).numLevels
        }
    }
    pub fn n_map_entries(&self) -> u8 {
        unsafe {
            (*self.ptr).nMapEntries
        }
    }
    pub fn preserve(&self) -> bool {
        unsafe {
            (*self.ptr).preserve != 0
        }
    }
    pub fn entries(&self) -> KtSetMapEntryIterator {
        unsafe {
            xcb_xkb_set_key_type_entries_iterator(self.ptr)
        }
    }
    pub fn preserve_entries(&self) -> KtSetMapEntryIterator {
        unsafe {
            xcb_xkb_set_key_type_preserve_entries_iterator(self.ptr)
        }
    }
}

pub type SetKeyTypeIterator<'a> = xcb_xkb_set_key_type_iterator_t<'a>;

impl<'a> Iterator for SetKeyTypeIterator<'a> {
    type Item = SetKeyType<'a>;
    fn next(&mut self) -> std::option::Option<SetKeyType<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_set_key_type_iterator_t;
                let data = (*iter).data;
                xcb_xkb_set_key_type_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Outline<'a> = base::StructPtr<'a, xcb_xkb_outline_t>;

impl<'a> Outline<'a> {
    pub fn n_points(&self) -> u8 {
        unsafe {
            (*self.ptr).nPoints
        }
    }
    pub fn corner_radius(&self) -> u8 {
        unsafe {
            (*self.ptr).cornerRadius
        }
    }
    pub fn points(&self) -> xproto::PointIterator {
        unsafe {
            xcb_xkb_outline_points_iterator(self.ptr)
        }
    }
}

pub type OutlineIterator<'a> = xcb_xkb_outline_iterator_t<'a>;

impl<'a> Iterator for OutlineIterator<'a> {
    type Item = Outline<'a>;
    fn next(&mut self) -> std::option::Option<Outline<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_outline_iterator_t;
                let data = (*iter).data;
                xcb_xkb_outline_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Shape<'a> = base::StructPtr<'a, xcb_xkb_shape_t>;

impl<'a> Shape<'a> {
    pub fn name(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).name
        }
    }
    pub fn n_outlines(&self) -> u8 {
        unsafe {
            (*self.ptr).nOutlines
        }
    }
    pub fn primary_ndx(&self) -> u8 {
        unsafe {
            (*self.ptr).primaryNdx
        }
    }
    pub fn approx_ndx(&self) -> u8 {
        unsafe {
            (*self.ptr).approxNdx
        }
    }
    pub fn outlines(&self) -> OutlineIterator<'a> {
        unsafe {
            xcb_xkb_shape_outlines_iterator(self.ptr)
        }
    }
}

pub type ShapeIterator<'a> = xcb_xkb_shape_iterator_t<'a>;

impl<'a> Iterator for ShapeIterator<'a> {
    type Item = Shape<'a>;
    fn next(&mut self) -> std::option::Option<Shape<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_shape_iterator_t;
                let data = (*iter).data;
                xcb_xkb_shape_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Key<'a> = base::StructPtr<'a, xcb_xkb_key_t>;

impl<'a> Key<'a> {
    pub fn name(&self) -> &[String8] {
        unsafe {
            &(*self.ptr).name
        }
    }
    pub fn gap(&self) -> i16 {
        unsafe {
            (*self.ptr).gap
        }
    }
    pub fn shape_ndx(&self) -> u8 {
        unsafe {
            (*self.ptr).shapeNdx
        }
    }
    pub fn color_ndx(&self) -> u8 {
        unsafe {
            (*self.ptr).colorNdx
        }
    }
}

pub type KeyIterator<'a> = xcb_xkb_key_iterator_t<'a>;

impl<'a> Iterator for KeyIterator<'a> {
    type Item = Key<'a>;
    fn next(&mut self) -> std::option::Option<Key<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_key_iterator_t;
                let data = (*iter).data;
                xcb_xkb_key_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type OverlayKey<'a> = base::StructPtr<'a, xcb_xkb_overlay_key_t>;

impl<'a> OverlayKey<'a> {
    pub fn over(&self) -> &[String8] {
        unsafe {
            &(*self.ptr).over
        }
    }
    pub fn under(&self) -> &[String8] {
        unsafe {
            &(*self.ptr).under
        }
    }
}

pub type OverlayKeyIterator<'a> = xcb_xkb_overlay_key_iterator_t<'a>;

impl<'a> Iterator for OverlayKeyIterator<'a> {
    type Item = OverlayKey<'a>;
    fn next(&mut self) -> std::option::Option<OverlayKey<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_overlay_key_iterator_t;
                let data = (*iter).data;
                xcb_xkb_overlay_key_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type OverlayRow<'a> = base::StructPtr<'a, xcb_xkb_overlay_row_t>;

impl<'a> OverlayRow<'a> {
    pub fn row_under(&self) -> u8 {
        unsafe {
            (*self.ptr).rowUnder
        }
    }
    pub fn n_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeys
        }
    }
    pub fn keys(&self) -> OverlayKeyIterator<'a> {
        unsafe {
            xcb_xkb_overlay_row_keys_iterator(self.ptr)
        }
    }
}

pub type OverlayRowIterator<'a> = xcb_xkb_overlay_row_iterator_t<'a>;

impl<'a> Iterator for OverlayRowIterator<'a> {
    type Item = OverlayRow<'a>;
    fn next(&mut self) -> std::option::Option<OverlayRow<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_overlay_row_iterator_t;
                let data = (*iter).data;
                xcb_xkb_overlay_row_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Overlay<'a> = base::StructPtr<'a, xcb_xkb_overlay_t>;

impl<'a> Overlay<'a> {
    pub fn name(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).name
        }
    }
    pub fn n_rows(&self) -> u8 {
        unsafe {
            (*self.ptr).nRows
        }
    }
    pub fn rows(&self) -> OverlayRowIterator<'a> {
        unsafe {
            xcb_xkb_overlay_rows_iterator(self.ptr)
        }
    }
}

pub type OverlayIterator<'a> = xcb_xkb_overlay_iterator_t<'a>;

impl<'a> Iterator for OverlayIterator<'a> {
    type Item = Overlay<'a>;
    fn next(&mut self) -> std::option::Option<Overlay<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_overlay_iterator_t;
                let data = (*iter).data;
                xcb_xkb_overlay_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Row<'a> = base::StructPtr<'a, xcb_xkb_row_t>;

impl<'a> Row<'a> {
    pub fn top(&self) -> i16 {
        unsafe {
            (*self.ptr).top
        }
    }
    pub fn left(&self) -> i16 {
        unsafe {
            (*self.ptr).left
        }
    }
    pub fn n_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeys
        }
    }
    pub fn vertical(&self) -> bool {
        unsafe {
            (*self.ptr).vertical != 0
        }
    }
    pub fn keys(&self) -> KeyIterator<'a> {
        unsafe {
            xcb_xkb_row_keys_iterator(self.ptr)
        }
    }
}

pub type RowIterator<'a> = xcb_xkb_row_iterator_t<'a>;

impl<'a> Iterator for RowIterator<'a> {
    type Item = Row<'a>;
    fn next(&mut self) -> std::option::Option<Row<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_row_iterator_t;
                let data = (*iter).data;
                xcb_xkb_row_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Listing<'a> = base::StructPtr<'a, xcb_xkb_listing_t>;

impl<'a> Listing<'a> {
    pub fn flags(&self) -> u16 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn length(&self) -> u16 {
        unsafe {
            (*self.ptr).length
        }
    }
    pub fn string(&self) -> &[String8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xkb_listing_string_length(field) as usize;
            let data = xcb_xkb_listing_string(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type ListingIterator<'a> = xcb_xkb_listing_iterator_t<'a>;

impl<'a> Iterator for ListingIterator<'a> {
    type Item = Listing<'a>;
    fn next(&mut self) -> std::option::Option<Listing<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_listing_iterator_t;
                let data = (*iter).data;
                xcb_xkb_listing_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type DeviceLedInfo<'a> = base::StructPtr<'a, xcb_xkb_device_led_info_t>;

impl<'a> DeviceLedInfo<'a> {
    pub fn led_class(&self) -> LedClassSpec {
        unsafe {
            (*self.ptr).ledClass
        }
    }
    pub fn led_i_d(&self) -> IdSpec {
        unsafe {
            (*self.ptr).ledID
        }
    }
    pub fn names_present(&self) -> u32 {
        unsafe {
            (*self.ptr).namesPresent
        }
    }
    pub fn maps_present(&self) -> u32 {
        unsafe {
            (*self.ptr).mapsPresent
        }
    }
    pub fn phys_indicators(&self) -> u32 {
        unsafe {
            (*self.ptr).physIndicators
        }
    }
    pub fn state(&self) -> u32 {
        unsafe {
            (*self.ptr).state
        }
    }
    pub fn names(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xkb_device_led_info_names_length(field) as usize;
            let data = xcb_xkb_device_led_info_names(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn maps(&self) -> IndicatorMapIterator {
        unsafe {
            xcb_xkb_device_led_info_maps_iterator(self.ptr)
        }
    }
}

pub type DeviceLedInfoIterator<'a> = xcb_xkb_device_led_info_iterator_t<'a>;

impl<'a> Iterator for DeviceLedInfoIterator<'a> {
    type Item = DeviceLedInfo<'a>;
    fn next(&mut self) -> std::option::Option<DeviceLedInfo<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_device_led_info_iterator_t;
                let data = (*iter).data;
                xcb_xkb_device_led_info_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const KEYBOARD: u8 = 0;

#[derive(Copy, Clone)]
pub struct SaNoAction {
    pub base: xcb_xkb_sa_no_action_t,
}

impl SaNoAction {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8)
            -> SaNoAction {
        unsafe {
            SaNoAction {
                base: xcb_xkb_sa_no_action_t {
                    type_: type_,
                    pad0:  [0; 7],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
}

pub type SaNoActionIterator = xcb_xkb_sa_no_action_iterator_t;

impl Iterator for SaNoActionIterator {
    type Item = SaNoAction;
    fn next(&mut self) -> std::option::Option<SaNoAction> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_no_action_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_no_action_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaSetMods {
    pub base: xcb_xkb_sa_set_mods_t,
}

impl SaSetMods {
    #[allow(unused_unsafe)]
    pub fn new(type_:      u8,
               flags:      u8,
               mask:       u8,
               real_mods:  u8,
               vmods_high: u8,
               vmods_low:  u8)
            -> SaSetMods {
        unsafe {
            SaSetMods {
                base: xcb_xkb_sa_set_mods_t {
                    type_:      type_,
                    flags:      flags,
                    mask:       mask,
                    realMods:  real_mods,
                    vmodsHigh: vmods_high,
                    vmodsLow:  vmods_low,
                    pad0:       [0; 2],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn mask(&self) -> u8 {
        unsafe {
            self.base.mask
        }
    }
    pub fn real_mods(&self) -> u8 {
        unsafe {
            self.base.realMods
        }
    }
    pub fn vmods_high(&self) -> u8 {
        unsafe {
            self.base.vmodsHigh
        }
    }
    pub fn vmods_low(&self) -> u8 {
        unsafe {
            self.base.vmodsLow
        }
    }
}

pub type SaSetModsIterator = xcb_xkb_sa_set_mods_iterator_t;

impl Iterator for SaSetModsIterator {
    type Item = SaSetMods;
    fn next(&mut self) -> std::option::Option<SaSetMods> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_set_mods_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_set_mods_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaLatchMods {
    pub base: xcb_xkb_sa_latch_mods_t,
}

impl SaLatchMods {
    #[allow(unused_unsafe)]
    pub fn new(type_:      u8,
               flags:      u8,
               mask:       u8,
               real_mods:  u8,
               vmods_high: u8,
               vmods_low:  u8)
            -> SaLatchMods {
        unsafe {
            SaLatchMods {
                base: xcb_xkb_sa_latch_mods_t {
                    type_:      type_,
                    flags:      flags,
                    mask:       mask,
                    realMods:  real_mods,
                    vmodsHigh: vmods_high,
                    vmodsLow:  vmods_low,
                    pad0:       [0; 2],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn mask(&self) -> u8 {
        unsafe {
            self.base.mask
        }
    }
    pub fn real_mods(&self) -> u8 {
        unsafe {
            self.base.realMods
        }
    }
    pub fn vmods_high(&self) -> u8 {
        unsafe {
            self.base.vmodsHigh
        }
    }
    pub fn vmods_low(&self) -> u8 {
        unsafe {
            self.base.vmodsLow
        }
    }
}

pub type SaLatchModsIterator = xcb_xkb_sa_latch_mods_iterator_t;

impl Iterator for SaLatchModsIterator {
    type Item = SaLatchMods;
    fn next(&mut self) -> std::option::Option<SaLatchMods> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_latch_mods_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_latch_mods_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaLockMods {
    pub base: xcb_xkb_sa_lock_mods_t,
}

impl SaLockMods {
    #[allow(unused_unsafe)]
    pub fn new(type_:      u8,
               flags:      u8,
               mask:       u8,
               real_mods:  u8,
               vmods_high: u8,
               vmods_low:  u8)
            -> SaLockMods {
        unsafe {
            SaLockMods {
                base: xcb_xkb_sa_lock_mods_t {
                    type_:      type_,
                    flags:      flags,
                    mask:       mask,
                    realMods:  real_mods,
                    vmodsHigh: vmods_high,
                    vmodsLow:  vmods_low,
                    pad0:       [0; 2],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn mask(&self) -> u8 {
        unsafe {
            self.base.mask
        }
    }
    pub fn real_mods(&self) -> u8 {
        unsafe {
            self.base.realMods
        }
    }
    pub fn vmods_high(&self) -> u8 {
        unsafe {
            self.base.vmodsHigh
        }
    }
    pub fn vmods_low(&self) -> u8 {
        unsafe {
            self.base.vmodsLow
        }
    }
}

pub type SaLockModsIterator = xcb_xkb_sa_lock_mods_iterator_t;

impl Iterator for SaLockModsIterator {
    type Item = SaLockMods;
    fn next(&mut self) -> std::option::Option<SaLockMods> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_lock_mods_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_lock_mods_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaSetGroup {
    pub base: xcb_xkb_sa_set_group_t,
}

impl SaSetGroup {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8,
               flags: u8,
               group: i8)
            -> SaSetGroup {
        unsafe {
            SaSetGroup {
                base: xcb_xkb_sa_set_group_t {
                    type_: type_,
                    flags: flags,
                    group: group,
                    pad0:  [0; 5],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn group(&self) -> i8 {
        unsafe {
            self.base.group
        }
    }
}

pub type SaSetGroupIterator = xcb_xkb_sa_set_group_iterator_t;

impl Iterator for SaSetGroupIterator {
    type Item = SaSetGroup;
    fn next(&mut self) -> std::option::Option<SaSetGroup> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_set_group_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_set_group_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaLatchGroup {
    pub base: xcb_xkb_sa_latch_group_t,
}

impl SaLatchGroup {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8,
               flags: u8,
               group: i8)
            -> SaLatchGroup {
        unsafe {
            SaLatchGroup {
                base: xcb_xkb_sa_latch_group_t {
                    type_: type_,
                    flags: flags,
                    group: group,
                    pad0:  [0; 5],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn group(&self) -> i8 {
        unsafe {
            self.base.group
        }
    }
}

pub type SaLatchGroupIterator = xcb_xkb_sa_latch_group_iterator_t;

impl Iterator for SaLatchGroupIterator {
    type Item = SaLatchGroup;
    fn next(&mut self) -> std::option::Option<SaLatchGroup> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_latch_group_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_latch_group_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaLockGroup {
    pub base: xcb_xkb_sa_lock_group_t,
}

impl SaLockGroup {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8,
               flags: u8,
               group: i8)
            -> SaLockGroup {
        unsafe {
            SaLockGroup {
                base: xcb_xkb_sa_lock_group_t {
                    type_: type_,
                    flags: flags,
                    group: group,
                    pad0:  [0; 5],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn group(&self) -> i8 {
        unsafe {
            self.base.group
        }
    }
}

pub type SaLockGroupIterator = xcb_xkb_sa_lock_group_iterator_t;

impl Iterator for SaLockGroupIterator {
    type Item = SaLockGroup;
    fn next(&mut self) -> std::option::Option<SaLockGroup> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_lock_group_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_lock_group_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaMovePtr {
    pub base: xcb_xkb_sa_move_ptr_t,
}

impl SaMovePtr {
    #[allow(unused_unsafe)]
    pub fn new(type_:  u8,
               flags:  u8,
               x_high: i8,
               x_low:  u8,
               y_high: i8,
               y_low:  u8)
            -> SaMovePtr {
        unsafe {
            SaMovePtr {
                base: xcb_xkb_sa_move_ptr_t {
                    type_:  type_,
                    flags:  flags,
                    xHigh: x_high,
                    xLow:  x_low,
                    yHigh: y_high,
                    yLow:  y_low,
                    pad0:   [0; 2],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn x_high(&self) -> i8 {
        unsafe {
            self.base.xHigh
        }
    }
    pub fn x_low(&self) -> u8 {
        unsafe {
            self.base.xLow
        }
    }
    pub fn y_high(&self) -> i8 {
        unsafe {
            self.base.yHigh
        }
    }
    pub fn y_low(&self) -> u8 {
        unsafe {
            self.base.yLow
        }
    }
}

pub type SaMovePtrIterator = xcb_xkb_sa_move_ptr_iterator_t;

impl Iterator for SaMovePtrIterator {
    type Item = SaMovePtr;
    fn next(&mut self) -> std::option::Option<SaMovePtr> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_move_ptr_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_move_ptr_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaPtrBtn {
    pub base: xcb_xkb_sa_ptr_btn_t,
}

impl SaPtrBtn {
    #[allow(unused_unsafe)]
    pub fn new(type_:  u8,
               flags:  u8,
               count:  u8,
               button: u8)
            -> SaPtrBtn {
        unsafe {
            SaPtrBtn {
                base: xcb_xkb_sa_ptr_btn_t {
                    type_:  type_,
                    flags:  flags,
                    count:  count,
                    button: button,
                    pad0:   [0; 4],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn count(&self) -> u8 {
        unsafe {
            self.base.count
        }
    }
    pub fn button(&self) -> u8 {
        unsafe {
            self.base.button
        }
    }
}

pub type SaPtrBtnIterator = xcb_xkb_sa_ptr_btn_iterator_t;

impl Iterator for SaPtrBtnIterator {
    type Item = SaPtrBtn;
    fn next(&mut self) -> std::option::Option<SaPtrBtn> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_ptr_btn_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_ptr_btn_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaLockPtrBtn {
    pub base: xcb_xkb_sa_lock_ptr_btn_t,
}

impl SaLockPtrBtn {
    #[allow(unused_unsafe)]
    pub fn new(type_:  u8,
               flags:  u8,
               button: u8)
            -> SaLockPtrBtn {
        unsafe {
            SaLockPtrBtn {
                base: xcb_xkb_sa_lock_ptr_btn_t {
                    type_:  type_,
                    flags:  flags,
                    pad0:   0,
                    button: button,
                    pad1:   [0; 4],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn button(&self) -> u8 {
        unsafe {
            self.base.button
        }
    }
}

pub type SaLockPtrBtnIterator = xcb_xkb_sa_lock_ptr_btn_iterator_t;

impl Iterator for SaLockPtrBtnIterator {
    type Item = SaLockPtrBtn;
    fn next(&mut self) -> std::option::Option<SaLockPtrBtn> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_lock_ptr_btn_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_lock_ptr_btn_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaSetPtrDflt {
    pub base: xcb_xkb_sa_set_ptr_dflt_t,
}

impl SaSetPtrDflt {
    #[allow(unused_unsafe)]
    pub fn new(type_:  u8,
               flags:  u8,
               affect: u8,
               value:  i8)
            -> SaSetPtrDflt {
        unsafe {
            SaSetPtrDflt {
                base: xcb_xkb_sa_set_ptr_dflt_t {
                    type_:  type_,
                    flags:  flags,
                    affect: affect,
                    value:  value,
                    pad0:   [0; 4],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn affect(&self) -> u8 {
        unsafe {
            self.base.affect
        }
    }
    pub fn value(&self) -> i8 {
        unsafe {
            self.base.value
        }
    }
}

pub type SaSetPtrDfltIterator = xcb_xkb_sa_set_ptr_dflt_iterator_t;

impl Iterator for SaSetPtrDfltIterator {
    type Item = SaSetPtrDflt;
    fn next(&mut self) -> std::option::Option<SaSetPtrDflt> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_set_ptr_dflt_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_set_ptr_dflt_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaIsoLock {
    pub base: xcb_xkb_sa_iso_lock_t,
}

impl SaIsoLock {
    #[allow(unused_unsafe)]
    pub fn new(type_:      u8,
               flags:      u8,
               mask:       u8,
               real_mods:  u8,
               group:      i8,
               affect:     u8,
               vmods_high: u8,
               vmods_low:  u8)
            -> SaIsoLock {
        unsafe {
            SaIsoLock {
                base: xcb_xkb_sa_iso_lock_t {
                    type_:      type_,
                    flags:      flags,
                    mask:       mask,
                    realMods:  real_mods,
                    group:      group,
                    affect:     affect,
                    vmodsHigh: vmods_high,
                    vmodsLow:  vmods_low,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn mask(&self) -> u8 {
        unsafe {
            self.base.mask
        }
    }
    pub fn real_mods(&self) -> u8 {
        unsafe {
            self.base.realMods
        }
    }
    pub fn group(&self) -> i8 {
        unsafe {
            self.base.group
        }
    }
    pub fn affect(&self) -> u8 {
        unsafe {
            self.base.affect
        }
    }
    pub fn vmods_high(&self) -> u8 {
        unsafe {
            self.base.vmodsHigh
        }
    }
    pub fn vmods_low(&self) -> u8 {
        unsafe {
            self.base.vmodsLow
        }
    }
}

pub type SaIsoLockIterator = xcb_xkb_sa_iso_lock_iterator_t;

impl Iterator for SaIsoLockIterator {
    type Item = SaIsoLock;
    fn next(&mut self) -> std::option::Option<SaIsoLock> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_iso_lock_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_iso_lock_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaTerminate {
    pub base: xcb_xkb_sa_terminate_t,
}

impl SaTerminate {
    #[allow(unused_unsafe)]
    pub fn new(type_: u8)
            -> SaTerminate {
        unsafe {
            SaTerminate {
                base: xcb_xkb_sa_terminate_t {
                    type_: type_,
                    pad0:  [0; 7],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
}

pub type SaTerminateIterator = xcb_xkb_sa_terminate_iterator_t;

impl Iterator for SaTerminateIterator {
    type Item = SaTerminate;
    fn next(&mut self) -> std::option::Option<SaTerminate> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_terminate_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_terminate_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaSwitchScreen {
    pub base: xcb_xkb_sa_switch_screen_t,
}

impl SaSwitchScreen {
    #[allow(unused_unsafe)]
    pub fn new(type_:      u8,
               flags:      u8,
               new_screen: i8)
            -> SaSwitchScreen {
        unsafe {
            SaSwitchScreen {
                base: xcb_xkb_sa_switch_screen_t {
                    type_:      type_,
                    flags:      flags,
                    newScreen: new_screen,
                    pad0:       [0; 5],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn new_screen(&self) -> i8 {
        unsafe {
            self.base.newScreen
        }
    }
}

pub type SaSwitchScreenIterator = xcb_xkb_sa_switch_screen_iterator_t;

impl Iterator for SaSwitchScreenIterator {
    type Item = SaSwitchScreen;
    fn next(&mut self) -> std::option::Option<SaSwitchScreen> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_switch_screen_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_switch_screen_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaSetControls {
    pub base: xcb_xkb_sa_set_controls_t,
}

impl SaSetControls {
    #[allow(unused_unsafe)]
    pub fn new(type_:           u8,
               bool_ctrls_high: u8,
               bool_ctrls_low:  u8)
            -> SaSetControls {
        unsafe {
            SaSetControls {
                base: xcb_xkb_sa_set_controls_t {
                    type_:           type_,
                    pad0:            [0; 3],
                    boolCtrlsHigh: bool_ctrls_high,
                    boolCtrlsLow:  bool_ctrls_low,
                    pad1:            [0; 2],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn bool_ctrls_high(&self) -> u8 {
        unsafe {
            self.base.boolCtrlsHigh
        }
    }
    pub fn bool_ctrls_low(&self) -> u8 {
        unsafe {
            self.base.boolCtrlsLow
        }
    }
}

pub type SaSetControlsIterator = xcb_xkb_sa_set_controls_iterator_t;

impl Iterator for SaSetControlsIterator {
    type Item = SaSetControls;
    fn next(&mut self) -> std::option::Option<SaSetControls> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_set_controls_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_set_controls_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaLockControls {
    pub base: xcb_xkb_sa_lock_controls_t,
}

impl SaLockControls {
    #[allow(unused_unsafe)]
    pub fn new(type_:           u8,
               bool_ctrls_high: u8,
               bool_ctrls_low:  u8)
            -> SaLockControls {
        unsafe {
            SaLockControls {
                base: xcb_xkb_sa_lock_controls_t {
                    type_:           type_,
                    pad0:            [0; 3],
                    boolCtrlsHigh: bool_ctrls_high,
                    boolCtrlsLow:  bool_ctrls_low,
                    pad1:            [0; 2],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn bool_ctrls_high(&self) -> u8 {
        unsafe {
            self.base.boolCtrlsHigh
        }
    }
    pub fn bool_ctrls_low(&self) -> u8 {
        unsafe {
            self.base.boolCtrlsLow
        }
    }
}

pub type SaLockControlsIterator = xcb_xkb_sa_lock_controls_iterator_t;

impl Iterator for SaLockControlsIterator {
    type Item = SaLockControls;
    fn next(&mut self) -> std::option::Option<SaLockControls> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_lock_controls_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_lock_controls_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type SaActionMessage<'a> = base::StructPtr<'a, xcb_xkb_sa_action_message_t>;

impl<'a> SaActionMessage<'a> {
    pub fn type_(&self) -> u8 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn message(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).message
        }
    }
}

pub type SaActionMessageIterator<'a> = xcb_xkb_sa_action_message_iterator_t<'a>;

impl<'a> Iterator for SaActionMessageIterator<'a> {
    type Item = SaActionMessage<'a>;
    fn next(&mut self) -> std::option::Option<SaActionMessage<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_action_message_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_action_message_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaRedirectKey {
    pub base: xcb_xkb_sa_redirect_key_t,
}

impl SaRedirectKey {
    #[allow(unused_unsafe)]
    pub fn new(type_:           u8,
               newkey:          xproto::Keycode,
               mask:            u8,
               real_modifiers:  u8,
               vmods_mask_high: u8,
               vmods_mask_low:  u8,
               vmods_high:      u8,
               vmods_low:       u8)
            -> SaRedirectKey {
        unsafe {
            SaRedirectKey {
                base: xcb_xkb_sa_redirect_key_t {
                    type_:           type_,
                    newkey:          newkey,
                    mask:            mask,
                    realModifiers:  real_modifiers,
                    vmodsMaskHigh: vmods_mask_high,
                    vmodsMaskLow:  vmods_mask_low,
                    vmodsHigh:      vmods_high,
                    vmodsLow:       vmods_low,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn newkey(&self) -> xproto::Keycode {
        unsafe {
            self.base.newkey
        }
    }
    pub fn mask(&self) -> u8 {
        unsafe {
            self.base.mask
        }
    }
    pub fn real_modifiers(&self) -> u8 {
        unsafe {
            self.base.realModifiers
        }
    }
    pub fn vmods_mask_high(&self) -> u8 {
        unsafe {
            self.base.vmodsMaskHigh
        }
    }
    pub fn vmods_mask_low(&self) -> u8 {
        unsafe {
            self.base.vmodsMaskLow
        }
    }
    pub fn vmods_high(&self) -> u8 {
        unsafe {
            self.base.vmodsHigh
        }
    }
    pub fn vmods_low(&self) -> u8 {
        unsafe {
            self.base.vmodsLow
        }
    }
}

pub type SaRedirectKeyIterator = xcb_xkb_sa_redirect_key_iterator_t;

impl Iterator for SaRedirectKeyIterator {
    type Item = SaRedirectKey;
    fn next(&mut self) -> std::option::Option<SaRedirectKey> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_redirect_key_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_redirect_key_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaDeviceBtn {
    pub base: xcb_xkb_sa_device_btn_t,
}

impl SaDeviceBtn {
    #[allow(unused_unsafe)]
    pub fn new(type_:  u8,
               flags:  u8,
               count:  u8,
               button: u8,
               device: u8)
            -> SaDeviceBtn {
        unsafe {
            SaDeviceBtn {
                base: xcb_xkb_sa_device_btn_t {
                    type_:  type_,
                    flags:  flags,
                    count:  count,
                    button: button,
                    device: device,
                    pad0:   [0; 3],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn count(&self) -> u8 {
        unsafe {
            self.base.count
        }
    }
    pub fn button(&self) -> u8 {
        unsafe {
            self.base.button
        }
    }
    pub fn device(&self) -> u8 {
        unsafe {
            self.base.device
        }
    }
}

pub type SaDeviceBtnIterator = xcb_xkb_sa_device_btn_iterator_t;

impl Iterator for SaDeviceBtnIterator {
    type Item = SaDeviceBtn;
    fn next(&mut self) -> std::option::Option<SaDeviceBtn> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_device_btn_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_device_btn_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaLockDeviceBtn {
    pub base: xcb_xkb_sa_lock_device_btn_t,
}

impl SaLockDeviceBtn {
    #[allow(unused_unsafe)]
    pub fn new(type_:  u8,
               flags:  u8,
               button: u8,
               device: u8)
            -> SaLockDeviceBtn {
        unsafe {
            SaLockDeviceBtn {
                base: xcb_xkb_sa_lock_device_btn_t {
                    type_:  type_,
                    flags:  flags,
                    pad0:   0,
                    button: button,
                    device: device,
                    pad1:   [0; 3],
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
    pub fn button(&self) -> u8 {
        unsafe {
            self.base.button
        }
    }
    pub fn device(&self) -> u8 {
        unsafe {
            self.base.device
        }
    }
}

pub type SaLockDeviceBtnIterator = xcb_xkb_sa_lock_device_btn_iterator_t;

impl Iterator for SaLockDeviceBtnIterator {
    type Item = SaLockDeviceBtn;
    fn next(&mut self) -> std::option::Option<SaLockDeviceBtn> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_lock_device_btn_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_lock_device_btn_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct SaDeviceValuator {
    pub base: xcb_xkb_sa_device_valuator_t,
}

impl SaDeviceValuator {
    #[allow(unused_unsafe)]
    pub fn new(type_:     u8,
               device:    u8,
               val1what:  u8,
               val1index: u8,
               val1value: u8,
               val2what:  u8,
               val2index: u8,
               val2value: u8)
            -> SaDeviceValuator {
        unsafe {
            SaDeviceValuator {
                base: xcb_xkb_sa_device_valuator_t {
                    type_:     type_,
                    device:    device,
                    val1what:  val1what,
                    val1index: val1index,
                    val1value: val1value,
                    val2what:  val2what,
                    val2index: val2index,
                    val2value: val2value,
                }
            }
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn device(&self) -> u8 {
        unsafe {
            self.base.device
        }
    }
    pub fn val1what(&self) -> u8 {
        unsafe {
            self.base.val1what
        }
    }
    pub fn val1index(&self) -> u8 {
        unsafe {
            self.base.val1index
        }
    }
    pub fn val1value(&self) -> u8 {
        unsafe {
            self.base.val1value
        }
    }
    pub fn val2what(&self) -> u8 {
        unsafe {
            self.base.val2what
        }
    }
    pub fn val2index(&self) -> u8 {
        unsafe {
            self.base.val2index
        }
    }
    pub fn val2value(&self) -> u8 {
        unsafe {
            self.base.val2value
        }
    }
}

pub type SaDeviceValuatorIterator = xcb_xkb_sa_device_valuator_iterator_t;

impl Iterator for SaDeviceValuatorIterator {
    type Item = SaDeviceValuator;
    fn next(&mut self) -> std::option::Option<SaDeviceValuator> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sa_device_valuator_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sa_device_valuator_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type SiAction<'a> = base::StructPtr<'a, xcb_xkb_si_action_t>;

impl<'a> SiAction<'a> {
    pub fn type_(&self) -> u8 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).data
        }
    }
}

pub type SiActionIterator<'a> = xcb_xkb_si_action_iterator_t<'a>;

impl<'a> Iterator for SiActionIterator<'a> {
    type Item = SiAction<'a>;
    fn next(&mut self) -> std::option::Option<SiAction<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_si_action_iterator_t;
                let data = (*iter).data;
                xcb_xkb_si_action_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type SymInterpret<'a> = base::StructPtr<'a, xcb_xkb_sym_interpret_t>;

impl<'a> SymInterpret<'a> {
    pub fn sym(&self) -> xproto::Keysym {
        unsafe {
            (*self.ptr).sym
        }
    }
    pub fn mods(&self) -> u8 {
        unsafe {
            (*self.ptr).mods
        }
    }
    pub fn match_(&self) -> u8 {
        unsafe {
            (*self.ptr).match_
        }
    }
    pub fn virtual_mod(&self) -> u8 {
        unsafe {
            (*self.ptr).virtualMod
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn action(&self) -> SiAction {
        unsafe {
            std::mem::transmute(&(*self.ptr).action)
        }
    }
}

pub type SymInterpretIterator<'a> = xcb_xkb_sym_interpret_iterator_t<'a>;

impl<'a> Iterator for SymInterpretIterator<'a> {
    type Item = SymInterpret<'a>;
    fn next(&mut self) -> std::option::Option<SymInterpret<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_sym_interpret_iterator_t;
                let data = (*iter).data;
                xcb_xkb_sym_interpret_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Action = xcb_xkb_action_t;

impl Action {
    pub fn noaction(&self) -> SaNoAction {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaNoAction;
            *_ptr
        }
    }
    pub fn from_noaction(noaction: SaNoAction) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaNoAction;
            *res_ptr = noaction;
            res
        }
    }
    pub fn setmods(&self) -> SaSetMods {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaSetMods;
            *_ptr
        }
    }
    pub fn from_setmods(setmods: SaSetMods) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaSetMods;
            *res_ptr = setmods;
            res
        }
    }
    pub fn latchmods(&self) -> SaLatchMods {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaLatchMods;
            *_ptr
        }
    }
    pub fn from_latchmods(latchmods: SaLatchMods) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaLatchMods;
            *res_ptr = latchmods;
            res
        }
    }
    pub fn lockmods(&self) -> SaLockMods {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaLockMods;
            *_ptr
        }
    }
    pub fn from_lockmods(lockmods: SaLockMods) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaLockMods;
            *res_ptr = lockmods;
            res
        }
    }
    pub fn setgroup(&self) -> SaSetGroup {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaSetGroup;
            *_ptr
        }
    }
    pub fn from_setgroup(setgroup: SaSetGroup) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaSetGroup;
            *res_ptr = setgroup;
            res
        }
    }
    pub fn latchgroup(&self) -> SaLatchGroup {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaLatchGroup;
            *_ptr
        }
    }
    pub fn from_latchgroup(latchgroup: SaLatchGroup) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaLatchGroup;
            *res_ptr = latchgroup;
            res
        }
    }
    pub fn lockgroup(&self) -> SaLockGroup {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaLockGroup;
            *_ptr
        }
    }
    pub fn from_lockgroup(lockgroup: SaLockGroup) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaLockGroup;
            *res_ptr = lockgroup;
            res
        }
    }
    pub fn moveptr(&self) -> SaMovePtr {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaMovePtr;
            *_ptr
        }
    }
    pub fn from_moveptr(moveptr: SaMovePtr) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaMovePtr;
            *res_ptr = moveptr;
            res
        }
    }
    pub fn ptrbtn(&self) -> SaPtrBtn {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaPtrBtn;
            *_ptr
        }
    }
    pub fn from_ptrbtn(ptrbtn: SaPtrBtn) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaPtrBtn;
            *res_ptr = ptrbtn;
            res
        }
    }
    pub fn lockptrbtn(&self) -> SaLockPtrBtn {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaLockPtrBtn;
            *_ptr
        }
    }
    pub fn from_lockptrbtn(lockptrbtn: SaLockPtrBtn) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaLockPtrBtn;
            *res_ptr = lockptrbtn;
            res
        }
    }
    pub fn setptrdflt(&self) -> SaSetPtrDflt {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaSetPtrDflt;
            *_ptr
        }
    }
    pub fn from_setptrdflt(setptrdflt: SaSetPtrDflt) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaSetPtrDflt;
            *res_ptr = setptrdflt;
            res
        }
    }
    pub fn isolock(&self) -> SaIsoLock {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaIsoLock;
            *_ptr
        }
    }
    pub fn from_isolock(isolock: SaIsoLock) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaIsoLock;
            *res_ptr = isolock;
            res
        }
    }
    pub fn terminate(&self) -> SaTerminate {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaTerminate;
            *_ptr
        }
    }
    pub fn from_terminate(terminate: SaTerminate) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaTerminate;
            *res_ptr = terminate;
            res
        }
    }
    pub fn switchscreen(&self) -> SaSwitchScreen {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaSwitchScreen;
            *_ptr
        }
    }
    pub fn from_switchscreen(switchscreen: SaSwitchScreen) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaSwitchScreen;
            *res_ptr = switchscreen;
            res
        }
    }
    pub fn setcontrols(&self) -> SaSetControls {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaSetControls;
            *_ptr
        }
    }
    pub fn from_setcontrols(setcontrols: SaSetControls) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaSetControls;
            *res_ptr = setcontrols;
            res
        }
    }
    pub fn lockcontrols(&self) -> SaLockControls {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaLockControls;
            *_ptr
        }
    }
    pub fn from_lockcontrols(lockcontrols: SaLockControls) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaLockControls;
            *res_ptr = lockcontrols;
            res
        }
    }
    pub fn message<'a>(&'a self) -> SaActionMessage<'a> {
        unsafe {
            std::mem::transmute(self)
        }
    }
    pub fn redirect(&self) -> SaRedirectKey {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaRedirectKey;
            *_ptr
        }
    }
    pub fn from_redirect(redirect: SaRedirectKey) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaRedirectKey;
            *res_ptr = redirect;
            res
        }
    }
    pub fn devbtn(&self) -> SaDeviceBtn {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaDeviceBtn;
            *_ptr
        }
    }
    pub fn from_devbtn(devbtn: SaDeviceBtn) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaDeviceBtn;
            *res_ptr = devbtn;
            res
        }
    }
    pub fn lockdevbtn(&self) -> SaLockDeviceBtn {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaLockDeviceBtn;
            *_ptr
        }
    }
    pub fn from_lockdevbtn(lockdevbtn: SaLockDeviceBtn) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaLockDeviceBtn;
            *res_ptr = lockdevbtn;
            res
        }
    }
    pub fn devval(&self) -> SaDeviceValuator {
        unsafe {
            let _ptr = self.data.as_ptr() as *const SaDeviceValuator;
            *_ptr
        }
    }
    pub fn from_devval(devval: SaDeviceValuator) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut SaDeviceValuator;
            *res_ptr = devval;
            res
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            let _ptr = self.data.as_ptr() as *const u8;
            *_ptr
        }
    }
    pub fn from_type_(type_: u8) -> Action {
        unsafe {
            let mut res = Action { data: [0; 8] };
            let res_ptr = res.data.as_mut_ptr() as *mut u8;
            *res_ptr = type_;
            res
        }
    }
}

pub type ActionIterator = xcb_xkb_action_iterator_t;

impl Iterator for ActionIterator {
    type Item = Action;
    fn next(&mut self) -> std::option::Option<Action> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xkb_action_iterator_t;
                let data = (*iter).data;
                xcb_xkb_action_next(iter);
                Some(*data)
            }
        }
    }
}

pub const USE_EXTENSION: u8 = 0;

pub type UseExtensionCookie<'a> = base::Cookie<'a, xcb_xkb_use_extension_cookie_t>;

impl<'a> UseExtensionCookie<'a> {
    pub fn get_reply(&self) -> Result<UseExtensionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = UseExtensionReply {
                    ptr: xcb_xkb_use_extension_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( UseExtensionReply {
                    ptr: xcb_xkb_use_extension_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type UseExtensionReply = base::Reply<xcb_xkb_use_extension_reply_t>;

impl UseExtensionReply {
    pub fn supported(&self) -> bool {
        unsafe {
            (*self.ptr).supported != 0
        }
    }
    pub fn server_major(&self) -> u16 {
        unsafe {
            (*self.ptr).serverMajor
        }
    }
    pub fn server_minor(&self) -> u16 {
        unsafe {
            (*self.ptr).serverMinor
        }
    }
}

pub fn use_extension<'a>(c           : &'a base::Connection,
                         wanted_major: u16,
                         wanted_minor: u16)
        -> UseExtensionCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_use_extension(c.get_raw_conn(),
                                           wanted_major as u16,  // 0
                                           wanted_minor as u16);  // 1
        UseExtensionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn use_extension_unchecked<'a>(c           : &'a base::Connection,
                                   wanted_major: u16,
                                   wanted_minor: u16)
        -> UseExtensionCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_use_extension_unchecked(c.get_raw_conn(),
                                                     wanted_major as u16,  // 0
                                                     wanted_minor as u16);  // 1
        UseExtensionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type SelectEventsDetails<'a> = base::StructPtr<'a, xcb_xkb_select_events_details_t>;

pub const SELECT_EVENTS: u8 = 1;

pub fn select_events<'a>(c           : &'a base::Connection,
                         device_spec : DeviceSpec,
                         affect_which: u16,
                         clear       : u16,
                         select_all  : u16,
                         affect_map  : u16,
                         map         : u16,
                         details     : std::option::Option<SelectEventsDetails>)
        -> base::VoidCookie<'a> {
    unsafe {
        let details_ptr = match details {
            Some(p) => p.ptr as *const xcb_xkb_select_events_details_t,
            None => std::ptr::null()
        };
        let cookie = xcb_xkb_select_events(c.get_raw_conn(),
                                           device_spec as xcb_xkb_device_spec_t,  // 0
                                           affect_which as u16,  // 1
                                           clear as u16,  // 2
                                           select_all as u16,  // 3
                                           affect_map as u16,  // 4
                                           map as u16,  // 5
                                           details_ptr);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_events_checked<'a>(c           : &'a base::Connection,
                                 device_spec : DeviceSpec,
                                 affect_which: u16,
                                 clear       : u16,
                                 select_all  : u16,
                                 affect_map  : u16,
                                 map         : u16,
                                 details     : std::option::Option<SelectEventsDetails>)
        -> base::VoidCookie<'a> {
    unsafe {
        let details_ptr = match details {
            Some(p) => p.ptr as *const xcb_xkb_select_events_details_t,
            None => std::ptr::null()
        };
        let cookie = xcb_xkb_select_events_checked(c.get_raw_conn(),
                                                   device_spec as xcb_xkb_device_spec_t,  // 0
                                                   affect_which as u16,  // 1
                                                   clear as u16,  // 2
                                                   select_all as u16,  // 3
                                                   affect_map as u16,  // 4
                                                   map as u16,  // 5
                                                   details_ptr);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const BELL: u8 = 3;

pub fn bell<'a>(c          : &'a base::Connection,
                device_spec: DeviceSpec,
                bell_class : BellClassSpec,
                bell_i_d   : IdSpec,
                percent    : i8,
                force_sound: bool,
                event_only : bool,
                pitch      : i16,
                duration   : i16,
                name       : xproto::Atom,
                window     : xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_bell(c.get_raw_conn(),
                                  device_spec as xcb_xkb_device_spec_t,  // 0
                                  bell_class as xcb_xkb_bell_class_spec_t,  // 1
                                  bell_i_d as xcb_xkb_id_spec_t,  // 2
                                  percent as i8,  // 3
                                  force_sound as u8,  // 4
                                  event_only as u8,  // 5
                                  pitch as i16,  // 6
                                  duration as i16,  // 7
                                  name as xcb_atom_t,  // 8
                                  window as xcb_window_t);  // 9
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn bell_checked<'a>(c          : &'a base::Connection,
                        device_spec: DeviceSpec,
                        bell_class : BellClassSpec,
                        bell_i_d   : IdSpec,
                        percent    : i8,
                        force_sound: bool,
                        event_only : bool,
                        pitch      : i16,
                        duration   : i16,
                        name       : xproto::Atom,
                        window     : xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_bell_checked(c.get_raw_conn(),
                                          device_spec as xcb_xkb_device_spec_t,  // 0
                                          bell_class as xcb_xkb_bell_class_spec_t,  // 1
                                          bell_i_d as xcb_xkb_id_spec_t,  // 2
                                          percent as i8,  // 3
                                          force_sound as u8,  // 4
                                          event_only as u8,  // 5
                                          pitch as i16,  // 6
                                          duration as i16,  // 7
                                          name as xcb_atom_t,  // 8
                                          window as xcb_window_t);  // 9
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_STATE: u8 = 4;

pub type GetStateCookie<'a> = base::Cookie<'a, xcb_xkb_get_state_cookie_t>;

impl<'a> GetStateCookie<'a> {
    pub fn get_reply(&self) -> Result<GetStateReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetStateReply {
                    ptr: xcb_xkb_get_state_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetStateReply {
                    ptr: xcb_xkb_get_state_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetStateReply = base::Reply<xcb_xkb_get_state_reply_t>;

impl GetStateReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn mods(&self) -> u8 {
        unsafe {
            (*self.ptr).mods
        }
    }
    pub fn base_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).baseMods
        }
    }
    pub fn latched_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).latchedMods
        }
    }
    pub fn locked_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).lockedMods
        }
    }
    pub fn group(&self) -> u8 {
        unsafe {
            (*self.ptr).group
        }
    }
    pub fn locked_group(&self) -> u8 {
        unsafe {
            (*self.ptr).lockedGroup
        }
    }
    pub fn base_group(&self) -> i16 {
        unsafe {
            (*self.ptr).baseGroup
        }
    }
    pub fn latched_group(&self) -> i16 {
        unsafe {
            (*self.ptr).latchedGroup
        }
    }
    pub fn compat_state(&self) -> u8 {
        unsafe {
            (*self.ptr).compatState
        }
    }
    pub fn grab_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).grabMods
        }
    }
    pub fn compat_grab_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).compatGrabMods
        }
    }
    pub fn lookup_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).lookupMods
        }
    }
    pub fn compat_lookup_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).compatLookupMods
        }
    }
    pub fn ptr_btn_state(&self) -> u16 {
        unsafe {
            (*self.ptr).ptrBtnState
        }
    }
}

pub fn get_state<'a>(c          : &'a base::Connection,
                     device_spec: DeviceSpec)
        -> GetStateCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_state(c.get_raw_conn(),
                                       device_spec as xcb_xkb_device_spec_t);  // 0
        GetStateCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_state_unchecked<'a>(c          : &'a base::Connection,
                               device_spec: DeviceSpec)
        -> GetStateCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_state_unchecked(c.get_raw_conn(),
                                                 device_spec as xcb_xkb_device_spec_t);  // 0
        GetStateCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LATCH_LOCK_STATE: u8 = 5;

pub fn latch_lock_state<'a>(c                 : &'a base::Connection,
                            device_spec       : DeviceSpec,
                            affect_mod_locks  : u8,
                            mod_locks         : u8,
                            lock_group        : bool,
                            group_lock        : u8,
                            affect_mod_latches: u8,
                            latch_group       : bool,
                            group_latch       : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_latch_lock_state(c.get_raw_conn(),
                                              device_spec as xcb_xkb_device_spec_t,  // 0
                                              affect_mod_locks as u8,  // 1
                                              mod_locks as u8,  // 2
                                              lock_group as u8,  // 3
                                              group_lock as u8,  // 4
                                              affect_mod_latches as u8,  // 5
                                              latch_group as u8,  // 6
                                              group_latch as u16);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn latch_lock_state_checked<'a>(c                 : &'a base::Connection,
                                    device_spec       : DeviceSpec,
                                    affect_mod_locks  : u8,
                                    mod_locks         : u8,
                                    lock_group        : bool,
                                    group_lock        : u8,
                                    affect_mod_latches: u8,
                                    latch_group       : bool,
                                    group_latch       : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_latch_lock_state_checked(c.get_raw_conn(),
                                                      device_spec as xcb_xkb_device_spec_t,  // 0
                                                      affect_mod_locks as u8,  // 1
                                                      mod_locks as u8,  // 2
                                                      lock_group as u8,  // 3
                                                      group_lock as u8,  // 4
                                                      affect_mod_latches as u8,  // 5
                                                      latch_group as u8,  // 6
                                                      group_latch as u16);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_CONTROLS: u8 = 6;

pub type GetControlsCookie<'a> = base::Cookie<'a, xcb_xkb_get_controls_cookie_t>;

impl<'a> GetControlsCookie<'a> {
    pub fn get_reply(&self) -> Result<GetControlsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetControlsReply {
                    ptr: xcb_xkb_get_controls_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetControlsReply {
                    ptr: xcb_xkb_get_controls_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetControlsReply = base::Reply<xcb_xkb_get_controls_reply_t>;

impl GetControlsReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn mouse_keys_dflt_btn(&self) -> u8 {
        unsafe {
            (*self.ptr).mouseKeysDfltBtn
        }
    }
    pub fn num_groups(&self) -> u8 {
        unsafe {
            (*self.ptr).numGroups
        }
    }
    pub fn groups_wrap(&self) -> u8 {
        unsafe {
            (*self.ptr).groupsWrap
        }
    }
    pub fn internal_mods_mask(&self) -> u8 {
        unsafe {
            (*self.ptr).internalModsMask
        }
    }
    pub fn ignore_lock_mods_mask(&self) -> u8 {
        unsafe {
            (*self.ptr).ignoreLockModsMask
        }
    }
    pub fn internal_mods_real_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).internalModsRealMods
        }
    }
    pub fn ignore_lock_mods_real_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).ignoreLockModsRealMods
        }
    }
    pub fn internal_mods_vmods(&self) -> u16 {
        unsafe {
            (*self.ptr).internalModsVmods
        }
    }
    pub fn ignore_lock_mods_vmods(&self) -> u16 {
        unsafe {
            (*self.ptr).ignoreLockModsVmods
        }
    }
    pub fn repeat_delay(&self) -> u16 {
        unsafe {
            (*self.ptr).repeatDelay
        }
    }
    pub fn repeat_interval(&self) -> u16 {
        unsafe {
            (*self.ptr).repeatInterval
        }
    }
    pub fn slow_keys_delay(&self) -> u16 {
        unsafe {
            (*self.ptr).slowKeysDelay
        }
    }
    pub fn debounce_delay(&self) -> u16 {
        unsafe {
            (*self.ptr).debounceDelay
        }
    }
    pub fn mouse_keys_delay(&self) -> u16 {
        unsafe {
            (*self.ptr).mouseKeysDelay
        }
    }
    pub fn mouse_keys_interval(&self) -> u16 {
        unsafe {
            (*self.ptr).mouseKeysInterval
        }
    }
    pub fn mouse_keys_time_to_max(&self) -> u16 {
        unsafe {
            (*self.ptr).mouseKeysTimeToMax
        }
    }
    pub fn mouse_keys_max_speed(&self) -> u16 {
        unsafe {
            (*self.ptr).mouseKeysMaxSpeed
        }
    }
    pub fn mouse_keys_curve(&self) -> i16 {
        unsafe {
            (*self.ptr).mouseKeysCurve
        }
    }
    pub fn access_x_option(&self) -> u16 {
        unsafe {
            (*self.ptr).accessXOption
        }
    }
    pub fn access_x_timeout(&self) -> u16 {
        unsafe {
            (*self.ptr).accessXTimeout
        }
    }
    pub fn access_x_timeout_options_mask(&self) -> u16 {
        unsafe {
            (*self.ptr).accessXTimeoutOptionsMask
        }
    }
    pub fn access_x_timeout_options_values(&self) -> u16 {
        unsafe {
            (*self.ptr).accessXTimeoutOptionsValues
        }
    }
    pub fn access_x_timeout_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).accessXTimeoutMask
        }
    }
    pub fn access_x_timeout_values(&self) -> u32 {
        unsafe {
            (*self.ptr).accessXTimeoutValues
        }
    }
    pub fn enabled_controls(&self) -> u32 {
        unsafe {
            (*self.ptr).enabledControls
        }
    }
    pub fn per_key_repeat(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).perKeyRepeat
        }
    }
}

pub fn get_controls<'a>(c          : &'a base::Connection,
                        device_spec: DeviceSpec)
        -> GetControlsCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_controls(c.get_raw_conn(),
                                          device_spec as xcb_xkb_device_spec_t);  // 0
        GetControlsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_controls_unchecked<'a>(c          : &'a base::Connection,
                                  device_spec: DeviceSpec)
        -> GetControlsCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_controls_unchecked(c.get_raw_conn(),
                                                    device_spec as xcb_xkb_device_spec_t);  // 0
        GetControlsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_CONTROLS: u8 = 7;

pub fn set_controls<'a>(c                              : &'a base::Connection,
                        device_spec                    : DeviceSpec,
                        affect_internal_real_mods      : u8,
                        internal_real_mods             : u8,
                        affect_ignore_lock_real_mods   : u8,
                        ignore_lock_real_mods          : u8,
                        affect_internal_virtual_mods   : u16,
                        internal_virtual_mods          : u16,
                        affect_ignore_lock_virtual_mods: u16,
                        ignore_lock_virtual_mods       : u16,
                        mouse_keys_dflt_btn            : u8,
                        groups_wrap                    : u8,
                        access_x_options               : u16,
                        affect_enabled_controls        : u32,
                        enabled_controls               : u32,
                        change_controls                : u32,
                        repeat_delay                   : u16,
                        repeat_interval                : u16,
                        slow_keys_delay                : u16,
                        debounce_delay                 : u16,
                        mouse_keys_delay               : u16,
                        mouse_keys_interval            : u16,
                        mouse_keys_time_to_max         : u16,
                        mouse_keys_max_speed           : u16,
                        mouse_keys_curve               : i16,
                        access_x_timeout               : u16,
                        access_x_timeout_mask          : u32,
                        access_x_timeout_values        : u32,
                        access_x_timeout_options_mask  : u16,
                        access_x_timeout_options_values: u16,
                        per_key_repeat                 : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let per_key_repeat_ptr = per_key_repeat.as_ptr();
        let cookie = xcb_xkb_set_controls(c.get_raw_conn(),
                                          device_spec as xcb_xkb_device_spec_t,  // 0
                                          affect_internal_real_mods as u8,  // 1
                                          internal_real_mods as u8,  // 2
                                          affect_ignore_lock_real_mods as u8,  // 3
                                          ignore_lock_real_mods as u8,  // 4
                                          affect_internal_virtual_mods as u16,  // 5
                                          internal_virtual_mods as u16,  // 6
                                          affect_ignore_lock_virtual_mods as u16,  // 7
                                          ignore_lock_virtual_mods as u16,  // 8
                                          mouse_keys_dflt_btn as u8,  // 9
                                          groups_wrap as u8,  // 10
                                          access_x_options as u16,  // 11
                                          affect_enabled_controls as u32,  // 12
                                          enabled_controls as u32,  // 13
                                          change_controls as u32,  // 14
                                          repeat_delay as u16,  // 15
                                          repeat_interval as u16,  // 16
                                          slow_keys_delay as u16,  // 17
                                          debounce_delay as u16,  // 18
                                          mouse_keys_delay as u16,  // 19
                                          mouse_keys_interval as u16,  // 20
                                          mouse_keys_time_to_max as u16,  // 21
                                          mouse_keys_max_speed as u16,  // 22
                                          mouse_keys_curve as i16,  // 23
                                          access_x_timeout as u16,  // 24
                                          access_x_timeout_mask as u32,  // 25
                                          access_x_timeout_values as u32,  // 26
                                          access_x_timeout_options_mask as u16,  // 27
                                          access_x_timeout_options_values as u16,  // 28
                                          per_key_repeat_ptr as *const u8);  // 29
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_controls_checked<'a>(c                              : &'a base::Connection,
                                device_spec                    : DeviceSpec,
                                affect_internal_real_mods      : u8,
                                internal_real_mods             : u8,
                                affect_ignore_lock_real_mods   : u8,
                                ignore_lock_real_mods          : u8,
                                affect_internal_virtual_mods   : u16,
                                internal_virtual_mods          : u16,
                                affect_ignore_lock_virtual_mods: u16,
                                ignore_lock_virtual_mods       : u16,
                                mouse_keys_dflt_btn            : u8,
                                groups_wrap                    : u8,
                                access_x_options               : u16,
                                affect_enabled_controls        : u32,
                                enabled_controls               : u32,
                                change_controls                : u32,
                                repeat_delay                   : u16,
                                repeat_interval                : u16,
                                slow_keys_delay                : u16,
                                debounce_delay                 : u16,
                                mouse_keys_delay               : u16,
                                mouse_keys_interval            : u16,
                                mouse_keys_time_to_max         : u16,
                                mouse_keys_max_speed           : u16,
                                mouse_keys_curve               : i16,
                                access_x_timeout               : u16,
                                access_x_timeout_mask          : u32,
                                access_x_timeout_values        : u32,
                                access_x_timeout_options_mask  : u16,
                                access_x_timeout_options_values: u16,
                                per_key_repeat                 : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let per_key_repeat_ptr = per_key_repeat.as_ptr();
        let cookie = xcb_xkb_set_controls_checked(c.get_raw_conn(),
                                                  device_spec as xcb_xkb_device_spec_t,  // 0
                                                  affect_internal_real_mods as u8,  // 1
                                                  internal_real_mods as u8,  // 2
                                                  affect_ignore_lock_real_mods as u8,  // 3
                                                  ignore_lock_real_mods as u8,  // 4
                                                  affect_internal_virtual_mods as u16,  // 5
                                                  internal_virtual_mods as u16,  // 6
                                                  affect_ignore_lock_virtual_mods as u16,  // 7
                                                  ignore_lock_virtual_mods as u16,  // 8
                                                  mouse_keys_dflt_btn as u8,  // 9
                                                  groups_wrap as u8,  // 10
                                                  access_x_options as u16,  // 11
                                                  affect_enabled_controls as u32,  // 12
                                                  enabled_controls as u32,  // 13
                                                  change_controls as u32,  // 14
                                                  repeat_delay as u16,  // 15
                                                  repeat_interval as u16,  // 16
                                                  slow_keys_delay as u16,  // 17
                                                  debounce_delay as u16,  // 18
                                                  mouse_keys_delay as u16,  // 19
                                                  mouse_keys_interval as u16,  // 20
                                                  mouse_keys_time_to_max as u16,  // 21
                                                  mouse_keys_max_speed as u16,  // 22
                                                  mouse_keys_curve as i16,  // 23
                                                  access_x_timeout as u16,  // 24
                                                  access_x_timeout_mask as u32,  // 25
                                                  access_x_timeout_values as u32,  // 26
                                                  access_x_timeout_options_mask as u16,  // 27
                                                  access_x_timeout_options_values as u16,  // 28
                                                  per_key_repeat_ptr as *const u8);  // 29
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_MAP: u8 = 8;

pub type GetMapCookie<'a> = base::Cookie<'a, xcb_xkb_get_map_cookie_t>;

impl<'a> GetMapCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMapReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMapReply {
                    ptr: xcb_xkb_get_map_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMapReply {
                    ptr: xcb_xkb_get_map_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMapMap<'a> = base::StructPtr<'a, xcb_xkb_get_map_map_t>;

pub type GetMapReply = base::Reply<xcb_xkb_get_map_reply_t>;

impl GetMapReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn min_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).minKeyCode
        }
    }
    pub fn max_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).maxKeyCode
        }
    }
    pub fn present(&self) -> u16 {
        unsafe {
            (*self.ptr).present
        }
    }
    pub fn first_type(&self) -> u8 {
        unsafe {
            (*self.ptr).firstType
        }
    }
    pub fn n_types(&self) -> u8 {
        unsafe {
            (*self.ptr).nTypes
        }
    }
    pub fn total_types(&self) -> u8 {
        unsafe {
            (*self.ptr).totalTypes
        }
    }
    pub fn first_key_sym(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKeySym
        }
    }
    pub fn total_syms(&self) -> u16 {
        unsafe {
            (*self.ptr).totalSyms
        }
    }
    pub fn n_key_syms(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeySyms
        }
    }
    pub fn first_key_action(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKeyAction
        }
    }
    pub fn total_actions(&self) -> u16 {
        unsafe {
            (*self.ptr).totalActions
        }
    }
    pub fn n_key_actions(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeyActions
        }
    }
    pub fn first_key_behavior(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKeyBehavior
        }
    }
    pub fn n_key_behaviors(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeyBehaviors
        }
    }
    pub fn total_key_behaviors(&self) -> u8 {
        unsafe {
            (*self.ptr).totalKeyBehaviors
        }
    }
    pub fn first_key_explicit(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKeyExplicit
        }
    }
    pub fn n_key_explicit(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeyExplicit
        }
    }
    pub fn total_key_explicit(&self) -> u8 {
        unsafe {
            (*self.ptr).totalKeyExplicit
        }
    }
    pub fn first_mod_map_key(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstModMapKey
        }
    }
    pub fn n_mod_map_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).nModMapKeys
        }
    }
    pub fn total_mod_map_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).totalModMapKeys
        }
    }
    pub fn first_v_mod_map_key(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstVModMapKey
        }
    }
    pub fn n_v_mod_map_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).nVModMapKeys
        }
    }
    pub fn total_v_mod_map_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).totalVModMapKeys
        }
    }
    pub fn virtual_mods(&self) -> u16 {
        unsafe {
            (*self.ptr).virtualMods
        }
    }
}

pub fn get_map<'a>(c                  : &'a base::Connection,
                   device_spec        : DeviceSpec,
                   full               : u16,
                   partial            : u16,
                   first_type         : u8,
                   n_types            : u8,
                   first_key_sym      : xproto::Keycode,
                   n_key_syms         : u8,
                   first_key_action   : xproto::Keycode,
                   n_key_actions      : u8,
                   first_key_behavior : xproto::Keycode,
                   n_key_behaviors    : u8,
                   virtual_mods       : u16,
                   first_key_explicit : xproto::Keycode,
                   n_key_explicit     : u8,
                   first_mod_map_key  : xproto::Keycode,
                   n_mod_map_keys     : u8,
                   first_v_mod_map_key: xproto::Keycode,
                   n_v_mod_map_keys   : u8)
        -> GetMapCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_map(c.get_raw_conn(),
                                     device_spec as xcb_xkb_device_spec_t,  // 0
                                     full as u16,  // 1
                                     partial as u16,  // 2
                                     first_type as u8,  // 3
                                     n_types as u8,  // 4
                                     first_key_sym as xcb_keycode_t,  // 5
                                     n_key_syms as u8,  // 6
                                     first_key_action as xcb_keycode_t,  // 7
                                     n_key_actions as u8,  // 8
                                     first_key_behavior as xcb_keycode_t,  // 9
                                     n_key_behaviors as u8,  // 10
                                     virtual_mods as u16,  // 11
                                     first_key_explicit as xcb_keycode_t,  // 12
                                     n_key_explicit as u8,  // 13
                                     first_mod_map_key as xcb_keycode_t,  // 14
                                     n_mod_map_keys as u8,  // 15
                                     first_v_mod_map_key as xcb_keycode_t,  // 16
                                     n_v_mod_map_keys as u8);  // 17
        GetMapCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_map_unchecked<'a>(c                  : &'a base::Connection,
                             device_spec        : DeviceSpec,
                             full               : u16,
                             partial            : u16,
                             first_type         : u8,
                             n_types            : u8,
                             first_key_sym      : xproto::Keycode,
                             n_key_syms         : u8,
                             first_key_action   : xproto::Keycode,
                             n_key_actions      : u8,
                             first_key_behavior : xproto::Keycode,
                             n_key_behaviors    : u8,
                             virtual_mods       : u16,
                             first_key_explicit : xproto::Keycode,
                             n_key_explicit     : u8,
                             first_mod_map_key  : xproto::Keycode,
                             n_mod_map_keys     : u8,
                             first_v_mod_map_key: xproto::Keycode,
                             n_v_mod_map_keys   : u8)
        -> GetMapCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_map_unchecked(c.get_raw_conn(),
                                               device_spec as xcb_xkb_device_spec_t,  // 0
                                               full as u16,  // 1
                                               partial as u16,  // 2
                                               first_type as u8,  // 3
                                               n_types as u8,  // 4
                                               first_key_sym as xcb_keycode_t,  // 5
                                               n_key_syms as u8,  // 6
                                               first_key_action as xcb_keycode_t,  // 7
                                               n_key_actions as u8,  // 8
                                               first_key_behavior as xcb_keycode_t,  // 9
                                               n_key_behaviors as u8,  // 10
                                               virtual_mods as u16,  // 11
                                               first_key_explicit as xcb_keycode_t,  // 12
                                               n_key_explicit as u8,  // 13
                                               first_mod_map_key as xcb_keycode_t,  // 14
                                               n_mod_map_keys as u8,  // 15
                                               first_v_mod_map_key as xcb_keycode_t,  // 16
                                               n_v_mod_map_keys as u8);  // 17
        GetMapCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type SetMapValues<'a> = base::StructPtr<'a, xcb_xkb_set_map_values_t>;

pub const SET_MAP: u8 = 9;

pub fn set_map<'a>(c                   : &'a base::Connection,
                   device_spec         : DeviceSpec,
                   present             : u16,
                   flags               : u16,
                   min_key_code        : xproto::Keycode,
                   max_key_code        : xproto::Keycode,
                   first_type          : u8,
                   n_types             : u8,
                   first_key_sym       : xproto::Keycode,
                   n_key_syms          : u8,
                   total_syms          : u16,
                   first_key_action    : xproto::Keycode,
                   n_key_actions       : u8,
                   total_actions       : u16,
                   first_key_behavior  : xproto::Keycode,
                   n_key_behaviors     : u8,
                   total_key_behaviors : u8,
                   first_key_explicit  : xproto::Keycode,
                   n_key_explicit      : u8,
                   total_key_explicit  : u8,
                   first_mod_map_key   : xproto::Keycode,
                   n_mod_map_keys      : u8,
                   total_mod_map_keys  : u8,
                   first_v_mod_map_key : xproto::Keycode,
                   n_v_mod_map_keys    : u8,
                   total_v_mod_map_keys: u8,
                   virtual_mods        : u16,
                   values              : std::option::Option<SetMapValues>)
        -> base::VoidCookie<'a> {
    unsafe {
        let values_ptr = match values {
            Some(p) => p.ptr as *const xcb_xkb_set_map_values_t,
            None => std::ptr::null()
        };
        let cookie = xcb_xkb_set_map(c.get_raw_conn(),
                                     device_spec as xcb_xkb_device_spec_t,  // 0
                                     present as u16,  // 1
                                     flags as u16,  // 2
                                     min_key_code as xcb_keycode_t,  // 3
                                     max_key_code as xcb_keycode_t,  // 4
                                     first_type as u8,  // 5
                                     n_types as u8,  // 6
                                     first_key_sym as xcb_keycode_t,  // 7
                                     n_key_syms as u8,  // 8
                                     total_syms as u16,  // 9
                                     first_key_action as xcb_keycode_t,  // 10
                                     n_key_actions as u8,  // 11
                                     total_actions as u16,  // 12
                                     first_key_behavior as xcb_keycode_t,  // 13
                                     n_key_behaviors as u8,  // 14
                                     total_key_behaviors as u8,  // 15
                                     first_key_explicit as xcb_keycode_t,  // 16
                                     n_key_explicit as u8,  // 17
                                     total_key_explicit as u8,  // 18
                                     first_mod_map_key as xcb_keycode_t,  // 19
                                     n_mod_map_keys as u8,  // 20
                                     total_mod_map_keys as u8,  // 21
                                     first_v_mod_map_key as xcb_keycode_t,  // 22
                                     n_v_mod_map_keys as u8,  // 23
                                     total_v_mod_map_keys as u8,  // 24
                                     virtual_mods as u16,  // 25
                                     values_ptr);  // 26
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_map_checked<'a>(c                   : &'a base::Connection,
                           device_spec         : DeviceSpec,
                           present             : u16,
                           flags               : u16,
                           min_key_code        : xproto::Keycode,
                           max_key_code        : xproto::Keycode,
                           first_type          : u8,
                           n_types             : u8,
                           first_key_sym       : xproto::Keycode,
                           n_key_syms          : u8,
                           total_syms          : u16,
                           first_key_action    : xproto::Keycode,
                           n_key_actions       : u8,
                           total_actions       : u16,
                           first_key_behavior  : xproto::Keycode,
                           n_key_behaviors     : u8,
                           total_key_behaviors : u8,
                           first_key_explicit  : xproto::Keycode,
                           n_key_explicit      : u8,
                           total_key_explicit  : u8,
                           first_mod_map_key   : xproto::Keycode,
                           n_mod_map_keys      : u8,
                           total_mod_map_keys  : u8,
                           first_v_mod_map_key : xproto::Keycode,
                           n_v_mod_map_keys    : u8,
                           total_v_mod_map_keys: u8,
                           virtual_mods        : u16,
                           values              : std::option::Option<SetMapValues>)
        -> base::VoidCookie<'a> {
    unsafe {
        let values_ptr = match values {
            Some(p) => p.ptr as *const xcb_xkb_set_map_values_t,
            None => std::ptr::null()
        };
        let cookie = xcb_xkb_set_map_checked(c.get_raw_conn(),
                                             device_spec as xcb_xkb_device_spec_t,  // 0
                                             present as u16,  // 1
                                             flags as u16,  // 2
                                             min_key_code as xcb_keycode_t,  // 3
                                             max_key_code as xcb_keycode_t,  // 4
                                             first_type as u8,  // 5
                                             n_types as u8,  // 6
                                             first_key_sym as xcb_keycode_t,  // 7
                                             n_key_syms as u8,  // 8
                                             total_syms as u16,  // 9
                                             first_key_action as xcb_keycode_t,  // 10
                                             n_key_actions as u8,  // 11
                                             total_actions as u16,  // 12
                                             first_key_behavior as xcb_keycode_t,  // 13
                                             n_key_behaviors as u8,  // 14
                                             total_key_behaviors as u8,  // 15
                                             first_key_explicit as xcb_keycode_t,  // 16
                                             n_key_explicit as u8,  // 17
                                             total_key_explicit as u8,  // 18
                                             first_mod_map_key as xcb_keycode_t,  // 19
                                             n_mod_map_keys as u8,  // 20
                                             total_mod_map_keys as u8,  // 21
                                             first_v_mod_map_key as xcb_keycode_t,  // 22
                                             n_v_mod_map_keys as u8,  // 23
                                             total_v_mod_map_keys as u8,  // 24
                                             virtual_mods as u16,  // 25
                                             values_ptr);  // 26
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_COMPAT_MAP: u8 = 10;

pub type GetCompatMapCookie<'a> = base::Cookie<'a, xcb_xkb_get_compat_map_cookie_t>;

impl<'a> GetCompatMapCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCompatMapReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCompatMapReply {
                    ptr: xcb_xkb_get_compat_map_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCompatMapReply {
                    ptr: xcb_xkb_get_compat_map_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCompatMapReply = base::Reply<xcb_xkb_get_compat_map_reply_t>;

impl GetCompatMapReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn groups_rtrn(&self) -> u8 {
        unsafe {
            (*self.ptr).groupsRtrn
        }
    }
    pub fn first_s_i_rtrn(&self) -> u16 {
        unsafe {
            (*self.ptr).firstSIRtrn
        }
    }
    pub fn n_s_i_rtrn(&self) -> u16 {
        unsafe {
            (*self.ptr).nSIRtrn
        }
    }
    pub fn n_total_s_i(&self) -> u16 {
        unsafe {
            (*self.ptr).nTotalSI
        }
    }
    pub fn si_rtrn(&self) -> SymInterpretIterator {
        unsafe {
            xcb_xkb_get_compat_map_si_rtrn_iterator(self.ptr)
        }
    }
    pub fn group_rtrn(&self) -> ModDefIterator {
        unsafe {
            xcb_xkb_get_compat_map_group_rtrn_iterator(self.ptr)
        }
    }
}

pub fn get_compat_map<'a>(c          : &'a base::Connection,
                          device_spec: DeviceSpec,
                          groups     : u8,
                          get_all_s_i: bool,
                          first_s_i  : u16,
                          n_s_i      : u16)
        -> GetCompatMapCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_compat_map(c.get_raw_conn(),
                                            device_spec as xcb_xkb_device_spec_t,  // 0
                                            groups as u8,  // 1
                                            get_all_s_i as u8,  // 2
                                            first_s_i as u16,  // 3
                                            n_s_i as u16);  // 4
        GetCompatMapCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_compat_map_unchecked<'a>(c          : &'a base::Connection,
                                    device_spec: DeviceSpec,
                                    groups     : u8,
                                    get_all_s_i: bool,
                                    first_s_i  : u16,
                                    n_s_i      : u16)
        -> GetCompatMapCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_compat_map_unchecked(c.get_raw_conn(),
                                                      device_spec as xcb_xkb_device_spec_t,  // 0
                                                      groups as u8,  // 1
                                                      get_all_s_i as u8,  // 2
                                                      first_s_i as u16,  // 3
                                                      n_s_i as u16);  // 4
        GetCompatMapCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_COMPAT_MAP: u8 = 11;

pub fn set_compat_map<'a>(c                : &'a base::Connection,
                          device_spec      : DeviceSpec,
                          recompute_actions: bool,
                          truncate_s_i     : bool,
                          first_s_i        : u16,
                          si               : &[SymInterpret],
                          group_maps       : &[ModDef])
        -> base::VoidCookie<'a> {
    unsafe {
        let si_len = si.len();
        let si_ptr = si.as_ptr();
        let group_maps_len = group_maps.len();
        let group_maps_ptr = group_maps.as_ptr();
        let cookie = xcb_xkb_set_compat_map(c.get_raw_conn(),
                                            device_spec as xcb_xkb_device_spec_t,  // 0
                                            recompute_actions as u8,  // 1
                                            truncate_s_i as u8,  // 2
                                            group_maps_len as u8,  // 3
                                            first_s_i as u16,  // 4
                                            si_len as u16,  // 5
                                            si_ptr as *const xcb_xkb_sym_interpret_t,  // 6
                                            group_maps_ptr as *const xcb_xkb_mod_def_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_compat_map_checked<'a>(c                : &'a base::Connection,
                                  device_spec      : DeviceSpec,
                                  recompute_actions: bool,
                                  truncate_s_i     : bool,
                                  first_s_i        : u16,
                                  si               : &[SymInterpret],
                                  group_maps       : &[ModDef])
        -> base::VoidCookie<'a> {
    unsafe {
        let si_len = si.len();
        let si_ptr = si.as_ptr();
        let group_maps_len = group_maps.len();
        let group_maps_ptr = group_maps.as_ptr();
        let cookie = xcb_xkb_set_compat_map_checked(c.get_raw_conn(),
                                                    device_spec as xcb_xkb_device_spec_t,  // 0
                                                    recompute_actions as u8,  // 1
                                                    truncate_s_i as u8,  // 2
                                                    group_maps_len as u8,  // 3
                                                    first_s_i as u16,  // 4
                                                    si_len as u16,  // 5
                                                    si_ptr as *const xcb_xkb_sym_interpret_t,  // 6
                                                    group_maps_ptr as *const xcb_xkb_mod_def_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_INDICATOR_STATE: u8 = 12;

pub type GetIndicatorStateCookie<'a> = base::Cookie<'a, xcb_xkb_get_indicator_state_cookie_t>;

impl<'a> GetIndicatorStateCookie<'a> {
    pub fn get_reply(&self) -> Result<GetIndicatorStateReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetIndicatorStateReply {
                    ptr: xcb_xkb_get_indicator_state_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetIndicatorStateReply {
                    ptr: xcb_xkb_get_indicator_state_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetIndicatorStateReply = base::Reply<xcb_xkb_get_indicator_state_reply_t>;

impl GetIndicatorStateReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn state(&self) -> u32 {
        unsafe {
            (*self.ptr).state
        }
    }
}

pub fn get_indicator_state<'a>(c          : &'a base::Connection,
                               device_spec: DeviceSpec)
        -> GetIndicatorStateCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_indicator_state(c.get_raw_conn(),
                                                 device_spec as xcb_xkb_device_spec_t);  // 0
        GetIndicatorStateCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_indicator_state_unchecked<'a>(c          : &'a base::Connection,
                                         device_spec: DeviceSpec)
        -> GetIndicatorStateCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_indicator_state_unchecked(c.get_raw_conn(),
                                                           device_spec as xcb_xkb_device_spec_t);  // 0
        GetIndicatorStateCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_INDICATOR_MAP: u8 = 13;

pub type GetIndicatorMapCookie<'a> = base::Cookie<'a, xcb_xkb_get_indicator_map_cookie_t>;

impl<'a> GetIndicatorMapCookie<'a> {
    pub fn get_reply(&self) -> Result<GetIndicatorMapReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetIndicatorMapReply {
                    ptr: xcb_xkb_get_indicator_map_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetIndicatorMapReply {
                    ptr: xcb_xkb_get_indicator_map_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetIndicatorMapReply = base::Reply<xcb_xkb_get_indicator_map_reply_t>;

impl GetIndicatorMapReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn which(&self) -> u32 {
        unsafe {
            (*self.ptr).which
        }
    }
    pub fn real_indicators(&self) -> u32 {
        unsafe {
            (*self.ptr).realIndicators
        }
    }
    pub fn n_indicators(&self) -> u8 {
        unsafe {
            (*self.ptr).nIndicators
        }
    }
    pub fn maps(&self) -> IndicatorMapIterator {
        unsafe {
            xcb_xkb_get_indicator_map_maps_iterator(self.ptr)
        }
    }
}

pub fn get_indicator_map<'a>(c          : &'a base::Connection,
                             device_spec: DeviceSpec,
                             which      : u32)
        -> GetIndicatorMapCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_indicator_map(c.get_raw_conn(),
                                               device_spec as xcb_xkb_device_spec_t,  // 0
                                               which as u32);  // 1
        GetIndicatorMapCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_indicator_map_unchecked<'a>(c          : &'a base::Connection,
                                       device_spec: DeviceSpec,
                                       which      : u32)
        -> GetIndicatorMapCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_indicator_map_unchecked(c.get_raw_conn(),
                                                         device_spec as xcb_xkb_device_spec_t,  // 0
                                                         which as u32);  // 1
        GetIndicatorMapCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_INDICATOR_MAP: u8 = 14;

pub fn set_indicator_map<'a>(c          : &'a base::Connection,
                             device_spec: DeviceSpec,
                             maps       : &[IndicatorMap])
        -> base::VoidCookie<'a> {
    unsafe {
        let maps_len = maps.len();
        let maps_ptr = maps.as_ptr();
        let cookie = xcb_xkb_set_indicator_map(c.get_raw_conn(),
                                               device_spec as xcb_xkb_device_spec_t,  // 0
                                               maps_len as u32,  // 1
                                               maps_ptr as *const xcb_xkb_indicator_map_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_indicator_map_checked<'a>(c          : &'a base::Connection,
                                     device_spec: DeviceSpec,
                                     maps       : &[IndicatorMap])
        -> base::VoidCookie<'a> {
    unsafe {
        let maps_len = maps.len();
        let maps_ptr = maps.as_ptr();
        let cookie = xcb_xkb_set_indicator_map_checked(c.get_raw_conn(),
                                                       device_spec as xcb_xkb_device_spec_t,  // 0
                                                       maps_len as u32,  // 1
                                                       maps_ptr as *const xcb_xkb_indicator_map_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_NAMED_INDICATOR: u8 = 15;

pub type GetNamedIndicatorCookie<'a> = base::Cookie<'a, xcb_xkb_get_named_indicator_cookie_t>;

impl<'a> GetNamedIndicatorCookie<'a> {
    pub fn get_reply(&self) -> Result<GetNamedIndicatorReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetNamedIndicatorReply {
                    ptr: xcb_xkb_get_named_indicator_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetNamedIndicatorReply {
                    ptr: xcb_xkb_get_named_indicator_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetNamedIndicatorReply = base::Reply<xcb_xkb_get_named_indicator_reply_t>;

impl GetNamedIndicatorReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn indicator(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).indicator
        }
    }
    pub fn found(&self) -> bool {
        unsafe {
            (*self.ptr).found != 0
        }
    }
    pub fn on(&self) -> bool {
        unsafe {
            (*self.ptr).on != 0
        }
    }
    pub fn real_indicator(&self) -> bool {
        unsafe {
            (*self.ptr).realIndicator != 0
        }
    }
    pub fn ndx(&self) -> u8 {
        unsafe {
            (*self.ptr).ndx
        }
    }
    pub fn map_flags(&self) -> u8 {
        unsafe {
            (*self.ptr).map_flags
        }
    }
    pub fn map_which_groups(&self) -> u8 {
        unsafe {
            (*self.ptr).map_whichGroups
        }
    }
    pub fn map_groups(&self) -> u8 {
        unsafe {
            (*self.ptr).map_groups
        }
    }
    pub fn map_which_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).map_whichMods
        }
    }
    pub fn map_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).map_mods
        }
    }
    pub fn map_real_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).map_realMods
        }
    }
    pub fn map_vmod(&self) -> u16 {
        unsafe {
            (*self.ptr).map_vmod
        }
    }
    pub fn map_ctrls(&self) -> u32 {
        unsafe {
            (*self.ptr).map_ctrls
        }
    }
    pub fn supported(&self) -> bool {
        unsafe {
            (*self.ptr).supported != 0
        }
    }
}

pub fn get_named_indicator<'a>(c          : &'a base::Connection,
                               device_spec: DeviceSpec,
                               led_class  : LedClassSpec,
                               led_i_d    : IdSpec,
                               indicator  : xproto::Atom)
        -> GetNamedIndicatorCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_named_indicator(c.get_raw_conn(),
                                                 device_spec as xcb_xkb_device_spec_t,  // 0
                                                 led_class as xcb_xkb_led_class_spec_t,  // 1
                                                 led_i_d as xcb_xkb_id_spec_t,  // 2
                                                 indicator as xcb_atom_t);  // 3
        GetNamedIndicatorCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_named_indicator_unchecked<'a>(c          : &'a base::Connection,
                                         device_spec: DeviceSpec,
                                         led_class  : LedClassSpec,
                                         led_i_d    : IdSpec,
                                         indicator  : xproto::Atom)
        -> GetNamedIndicatorCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_named_indicator_unchecked(c.get_raw_conn(),
                                                           device_spec as xcb_xkb_device_spec_t,  // 0
                                                           led_class as xcb_xkb_led_class_spec_t,  // 1
                                                           led_i_d as xcb_xkb_id_spec_t,  // 2
                                                           indicator as xcb_atom_t);  // 3
        GetNamedIndicatorCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_NAMED_INDICATOR: u8 = 16;

pub fn set_named_indicator<'a>(c               : &'a base::Connection,
                               device_spec     : DeviceSpec,
                               led_class       : LedClassSpec,
                               led_i_d         : IdSpec,
                               indicator       : xproto::Atom,
                               set_state       : bool,
                               on              : bool,
                               set_map         : bool,
                               create_map      : bool,
                               map_flags       : u8,
                               map_which_groups: u8,
                               map_groups      : u8,
                               map_which_mods  : u8,
                               map_real_mods   : u8,
                               map_vmods       : u16,
                               map_ctrls       : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_set_named_indicator(c.get_raw_conn(),
                                                 device_spec as xcb_xkb_device_spec_t,  // 0
                                                 led_class as xcb_xkb_led_class_spec_t,  // 1
                                                 led_i_d as xcb_xkb_id_spec_t,  // 2
                                                 indicator as xcb_atom_t,  // 3
                                                 set_state as u8,  // 4
                                                 on as u8,  // 5
                                                 set_map as u8,  // 6
                                                 create_map as u8,  // 7
                                                 map_flags as u8,  // 8
                                                 map_which_groups as u8,  // 9
                                                 map_groups as u8,  // 10
                                                 map_which_mods as u8,  // 11
                                                 map_real_mods as u8,  // 12
                                                 map_vmods as u16,  // 13
                                                 map_ctrls as u32);  // 14
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_named_indicator_checked<'a>(c               : &'a base::Connection,
                                       device_spec     : DeviceSpec,
                                       led_class       : LedClassSpec,
                                       led_i_d         : IdSpec,
                                       indicator       : xproto::Atom,
                                       set_state       : bool,
                                       on              : bool,
                                       set_map         : bool,
                                       create_map      : bool,
                                       map_flags       : u8,
                                       map_which_groups: u8,
                                       map_groups      : u8,
                                       map_which_mods  : u8,
                                       map_real_mods   : u8,
                                       map_vmods       : u16,
                                       map_ctrls       : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_set_named_indicator_checked(c.get_raw_conn(),
                                                         device_spec as xcb_xkb_device_spec_t,  // 0
                                                         led_class as xcb_xkb_led_class_spec_t,  // 1
                                                         led_i_d as xcb_xkb_id_spec_t,  // 2
                                                         indicator as xcb_atom_t,  // 3
                                                         set_state as u8,  // 4
                                                         on as u8,  // 5
                                                         set_map as u8,  // 6
                                                         create_map as u8,  // 7
                                                         map_flags as u8,  // 8
                                                         map_which_groups as u8,  // 9
                                                         map_groups as u8,  // 10
                                                         map_which_mods as u8,  // 11
                                                         map_real_mods as u8,  // 12
                                                         map_vmods as u16,  // 13
                                                         map_ctrls as u32);  // 14
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_NAMES: u8 = 17;

pub type GetNamesCookie<'a> = base::Cookie<'a, xcb_xkb_get_names_cookie_t>;

impl<'a> GetNamesCookie<'a> {
    pub fn get_reply(&self) -> Result<GetNamesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetNamesReply {
                    ptr: xcb_xkb_get_names_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetNamesReply {
                    ptr: xcb_xkb_get_names_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetNamesValueList<'a> = base::StructPtr<'a, xcb_xkb_get_names_value_list_t>;

pub type GetNamesReply = base::Reply<xcb_xkb_get_names_reply_t>;

impl GetNamesReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn which(&self) -> u32 {
        unsafe {
            (*self.ptr).which
        }
    }
    pub fn min_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).minKeyCode
        }
    }
    pub fn max_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).maxKeyCode
        }
    }
    pub fn n_types(&self) -> u8 {
        unsafe {
            (*self.ptr).nTypes
        }
    }
    pub fn group_names(&self) -> u8 {
        unsafe {
            (*self.ptr).groupNames
        }
    }
    pub fn virtual_mods(&self) -> u16 {
        unsafe {
            (*self.ptr).virtualMods
        }
    }
    pub fn first_key(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKey
        }
    }
    pub fn n_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeys
        }
    }
    pub fn indicators(&self) -> u32 {
        unsafe {
            (*self.ptr).indicators
        }
    }
    pub fn n_radio_groups(&self) -> u8 {
        unsafe {
            (*self.ptr).nRadioGroups
        }
    }
    pub fn n_key_aliases(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeyAliases
        }
    }
    pub fn n_k_t_levels(&self) -> u16 {
        unsafe {
            (*self.ptr).nKTLevels
        }
    }
}

pub fn get_names<'a>(c          : &'a base::Connection,
                     device_spec: DeviceSpec,
                     which      : u32)
        -> GetNamesCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_names(c.get_raw_conn(),
                                       device_spec as xcb_xkb_device_spec_t,  // 0
                                       which as u32);  // 1
        GetNamesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_names_unchecked<'a>(c          : &'a base::Connection,
                               device_spec: DeviceSpec,
                               which      : u32)
        -> GetNamesCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_names_unchecked(c.get_raw_conn(),
                                                 device_spec as xcb_xkb_device_spec_t,  // 0
                                                 which as u32);  // 1
        GetNamesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type SetNamesValues<'a> = base::StructPtr<'a, xcb_xkb_set_names_values_t>;

pub const SET_NAMES: u8 = 18;

pub fn set_names<'a>(c                    : &'a base::Connection,
                     device_spec          : DeviceSpec,
                     virtual_mods         : u16,
                     which                : u32,
                     first_type           : u8,
                     n_types              : u8,
                     first_k_t_levelt     : u8,
                     n_k_t_levels         : u8,
                     indicators           : u32,
                     group_names          : u8,
                     n_radio_groups       : u8,
                     first_key            : xproto::Keycode,
                     n_keys               : u8,
                     n_key_aliases        : u8,
                     total_k_t_level_names: u16,
                     values               : std::option::Option<SetNamesValues>)
        -> base::VoidCookie<'a> {
    unsafe {
        let values_ptr = match values {
            Some(p) => p.ptr as *const xcb_xkb_set_names_values_t,
            None => std::ptr::null()
        };
        let cookie = xcb_xkb_set_names(c.get_raw_conn(),
                                       device_spec as xcb_xkb_device_spec_t,  // 0
                                       virtual_mods as u16,  // 1
                                       which as u32,  // 2
                                       first_type as u8,  // 3
                                       n_types as u8,  // 4
                                       first_k_t_levelt as u8,  // 5
                                       n_k_t_levels as u8,  // 6
                                       indicators as u32,  // 7
                                       group_names as u8,  // 8
                                       n_radio_groups as u8,  // 9
                                       first_key as xcb_keycode_t,  // 10
                                       n_keys as u8,  // 11
                                       n_key_aliases as u8,  // 12
                                       total_k_t_level_names as u16,  // 13
                                       values_ptr);  // 14
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_names_checked<'a>(c                    : &'a base::Connection,
                             device_spec          : DeviceSpec,
                             virtual_mods         : u16,
                             which                : u32,
                             first_type           : u8,
                             n_types              : u8,
                             first_k_t_levelt     : u8,
                             n_k_t_levels         : u8,
                             indicators           : u32,
                             group_names          : u8,
                             n_radio_groups       : u8,
                             first_key            : xproto::Keycode,
                             n_keys               : u8,
                             n_key_aliases        : u8,
                             total_k_t_level_names: u16,
                             values               : std::option::Option<SetNamesValues>)
        -> base::VoidCookie<'a> {
    unsafe {
        let values_ptr = match values {
            Some(p) => p.ptr as *const xcb_xkb_set_names_values_t,
            None => std::ptr::null()
        };
        let cookie = xcb_xkb_set_names_checked(c.get_raw_conn(),
                                               device_spec as xcb_xkb_device_spec_t,  // 0
                                               virtual_mods as u16,  // 1
                                               which as u32,  // 2
                                               first_type as u8,  // 3
                                               n_types as u8,  // 4
                                               first_k_t_levelt as u8,  // 5
                                               n_k_t_levels as u8,  // 6
                                               indicators as u32,  // 7
                                               group_names as u8,  // 8
                                               n_radio_groups as u8,  // 9
                                               first_key as xcb_keycode_t,  // 10
                                               n_keys as u8,  // 11
                                               n_key_aliases as u8,  // 12
                                               total_k_t_level_names as u16,  // 13
                                               values_ptr);  // 14
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PER_CLIENT_FLAGS: u8 = 21;

pub type PerClientFlagsCookie<'a> = base::Cookie<'a, xcb_xkb_per_client_flags_cookie_t>;

impl<'a> PerClientFlagsCookie<'a> {
    pub fn get_reply(&self) -> Result<PerClientFlagsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PerClientFlagsReply {
                    ptr: xcb_xkb_per_client_flags_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PerClientFlagsReply {
                    ptr: xcb_xkb_per_client_flags_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PerClientFlagsReply = base::Reply<xcb_xkb_per_client_flags_reply_t>;

impl PerClientFlagsReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn supported(&self) -> u32 {
        unsafe {
            (*self.ptr).supported
        }
    }
    pub fn value(&self) -> u32 {
        unsafe {
            (*self.ptr).value
        }
    }
    pub fn auto_ctrls(&self) -> u32 {
        unsafe {
            (*self.ptr).autoCtrls
        }
    }
    pub fn auto_ctrls_values(&self) -> u32 {
        unsafe {
            (*self.ptr).autoCtrlsValues
        }
    }
}

pub fn per_client_flags<'a>(c                : &'a base::Connection,
                            device_spec      : DeviceSpec,
                            change           : u32,
                            value            : u32,
                            ctrls_to_change  : u32,
                            auto_ctrls       : u32,
                            auto_ctrls_values: u32)
        -> PerClientFlagsCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_per_client_flags(c.get_raw_conn(),
                                              device_spec as xcb_xkb_device_spec_t,  // 0
                                              change as u32,  // 1
                                              value as u32,  // 2
                                              ctrls_to_change as u32,  // 3
                                              auto_ctrls as u32,  // 4
                                              auto_ctrls_values as u32);  // 5
        PerClientFlagsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn per_client_flags_unchecked<'a>(c                : &'a base::Connection,
                                      device_spec      : DeviceSpec,
                                      change           : u32,
                                      value            : u32,
                                      ctrls_to_change  : u32,
                                      auto_ctrls       : u32,
                                      auto_ctrls_values: u32)
        -> PerClientFlagsCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_per_client_flags_unchecked(c.get_raw_conn(),
                                                        device_spec as xcb_xkb_device_spec_t,  // 0
                                                        change as u32,  // 1
                                                        value as u32,  // 2
                                                        ctrls_to_change as u32,  // 3
                                                        auto_ctrls as u32,  // 4
                                                        auto_ctrls_values as u32);  // 5
        PerClientFlagsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_COMPONENTS: u8 = 22;

pub type ListComponentsCookie<'a> = base::Cookie<'a, xcb_xkb_list_components_cookie_t>;

impl<'a> ListComponentsCookie<'a> {
    pub fn get_reply(&self) -> Result<ListComponentsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListComponentsReply {
                    ptr: xcb_xkb_list_components_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListComponentsReply {
                    ptr: xcb_xkb_list_components_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListComponentsReply = base::Reply<xcb_xkb_list_components_reply_t>;

impl ListComponentsReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn n_keymaps(&self) -> u16 {
        unsafe {
            (*self.ptr).nKeymaps
        }
    }
    pub fn n_keycodes(&self) -> u16 {
        unsafe {
            (*self.ptr).nKeycodes
        }
    }
    pub fn n_types(&self) -> u16 {
        unsafe {
            (*self.ptr).nTypes
        }
    }
    pub fn n_compat_maps(&self) -> u16 {
        unsafe {
            (*self.ptr).nCompatMaps
        }
    }
    pub fn n_symbols(&self) -> u16 {
        unsafe {
            (*self.ptr).nSymbols
        }
    }
    pub fn n_geometries(&self) -> u16 {
        unsafe {
            (*self.ptr).nGeometries
        }
    }
    pub fn extra(&self) -> u16 {
        unsafe {
            (*self.ptr).extra
        }
    }
    pub fn keymaps(&self) -> ListingIterator {
        unsafe {
            xcb_xkb_list_components_keymaps_iterator(self.ptr)
        }
    }
    pub fn keycodes(&self) -> ListingIterator {
        unsafe {
            xcb_xkb_list_components_keycodes_iterator(self.ptr)
        }
    }
    pub fn types(&self) -> ListingIterator {
        unsafe {
            xcb_xkb_list_components_types_iterator(self.ptr)
        }
    }
    pub fn compat_maps(&self) -> ListingIterator {
        unsafe {
            xcb_xkb_list_components_compat_maps_iterator(self.ptr)
        }
    }
    pub fn symbols(&self) -> ListingIterator {
        unsafe {
            xcb_xkb_list_components_symbols_iterator(self.ptr)
        }
    }
    pub fn geometries(&self) -> ListingIterator {
        unsafe {
            xcb_xkb_list_components_geometries_iterator(self.ptr)
        }
    }
}

pub fn list_components<'a>(c          : &'a base::Connection,
                           device_spec: DeviceSpec,
                           max_names  : u16)
        -> ListComponentsCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_list_components(c.get_raw_conn(),
                                             device_spec as xcb_xkb_device_spec_t,  // 0
                                             max_names as u16);  // 1
        ListComponentsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_components_unchecked<'a>(c          : &'a base::Connection,
                                     device_spec: DeviceSpec,
                                     max_names  : u16)
        -> ListComponentsCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_list_components_unchecked(c.get_raw_conn(),
                                                       device_spec as xcb_xkb_device_spec_t,  // 0
                                                       max_names as u16);  // 1
        ListComponentsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_KBD_BY_NAME: u8 = 23;

pub type GetKbdByNameCookie<'a> = base::Cookie<'a, xcb_xkb_get_kbd_by_name_cookie_t>;

impl<'a> GetKbdByNameCookie<'a> {
    pub fn get_reply(&self) -> Result<GetKbdByNameReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetKbdByNameReply {
                    ptr: xcb_xkb_get_kbd_by_name_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetKbdByNameReply {
                    ptr: xcb_xkb_get_kbd_by_name_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetKbdByNameReplies<'a> = base::StructPtr<'a, xcb_xkb_get_kbd_by_name_replies_t>;

pub type GetKbdByNameRepliesTypesMap<'a> = base::StructPtr<'a, xcb_xkb_get_kbd_by_name_replies_types_map_t>;

pub type GetKbdByNameRepliesKeyNamesValueList<'a> = base::StructPtr<'a, xcb_xkb_get_kbd_by_name_replies_key_names_value_list_t>;

pub type GetKbdByNameReply = base::Reply<xcb_xkb_get_kbd_by_name_reply_t>;

impl GetKbdByNameReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn min_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).minKeyCode
        }
    }
    pub fn max_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).maxKeyCode
        }
    }
    pub fn loaded(&self) -> bool {
        unsafe {
            (*self.ptr).loaded != 0
        }
    }
    pub fn new_keyboard(&self) -> bool {
        unsafe {
            (*self.ptr).newKeyboard != 0
        }
    }
    pub fn found(&self) -> u16 {
        unsafe {
            (*self.ptr).found
        }
    }
    pub fn reported(&self) -> u16 {
        unsafe {
            (*self.ptr).reported
        }
    }
}

pub fn get_kbd_by_name<'a>(c          : &'a base::Connection,
                           device_spec: DeviceSpec,
                           need       : u16,
                           want       : u16,
                           load       : bool)
        -> GetKbdByNameCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_kbd_by_name(c.get_raw_conn(),
                                             device_spec as xcb_xkb_device_spec_t,  // 0
                                             need as u16,  // 1
                                             want as u16,  // 2
                                             load as u8);  // 3
        GetKbdByNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_kbd_by_name_unchecked<'a>(c          : &'a base::Connection,
                                     device_spec: DeviceSpec,
                                     need       : u16,
                                     want       : u16,
                                     load       : bool)
        -> GetKbdByNameCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_kbd_by_name_unchecked(c.get_raw_conn(),
                                                       device_spec as xcb_xkb_device_spec_t,  // 0
                                                       need as u16,  // 1
                                                       want as u16,  // 2
                                                       load as u8);  // 3
        GetKbdByNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_DEVICE_INFO: u8 = 24;

pub type GetDeviceInfoCookie<'a> = base::Cookie<'a, xcb_xkb_get_device_info_cookie_t>;

impl<'a> GetDeviceInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDeviceInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDeviceInfoReply {
                    ptr: xcb_xkb_get_device_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDeviceInfoReply {
                    ptr: xcb_xkb_get_device_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDeviceInfoReply = base::Reply<xcb_xkb_get_device_info_reply_t>;

impl GetDeviceInfoReply {
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn present(&self) -> u16 {
        unsafe {
            (*self.ptr).present
        }
    }
    pub fn supported(&self) -> u16 {
        unsafe {
            (*self.ptr).supported
        }
    }
    pub fn unsupported(&self) -> u16 {
        unsafe {
            (*self.ptr).unsupported
        }
    }
    pub fn n_device_led_f_bs(&self) -> u16 {
        unsafe {
            (*self.ptr).nDeviceLedFBs
        }
    }
    pub fn first_btn_wanted(&self) -> u8 {
        unsafe {
            (*self.ptr).firstBtnWanted
        }
    }
    pub fn n_btns_wanted(&self) -> u8 {
        unsafe {
            (*self.ptr).nBtnsWanted
        }
    }
    pub fn first_btn_rtrn(&self) -> u8 {
        unsafe {
            (*self.ptr).firstBtnRtrn
        }
    }
    pub fn n_btns_rtrn(&self) -> u8 {
        unsafe {
            (*self.ptr).nBtnsRtrn
        }
    }
    pub fn total_btns(&self) -> u8 {
        unsafe {
            (*self.ptr).totalBtns
        }
    }
    pub fn has_own_state(&self) -> bool {
        unsafe {
            (*self.ptr).hasOwnState != 0
        }
    }
    pub fn dflt_kbd_f_b(&self) -> u16 {
        unsafe {
            (*self.ptr).dfltKbdFB
        }
    }
    pub fn dflt_led_f_b(&self) -> u16 {
        unsafe {
            (*self.ptr).dfltLedFB
        }
    }
    pub fn dev_type(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).devType
        }
    }
    pub fn name_len(&self) -> u16 {
        unsafe {
            (*self.ptr).nameLen
        }
    }
    pub fn name(&self) -> &[String8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xkb_get_device_info_name_length(field) as usize;
            let data = xcb_xkb_get_device_info_name(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn btn_actions(&self) -> ActionIterator {
        unsafe {
            xcb_xkb_get_device_info_btn_actions_iterator(self.ptr)
        }
    }
    pub fn leds(&self) -> DeviceLedInfoIterator {
        unsafe {
            xcb_xkb_get_device_info_leds_iterator(self.ptr)
        }
    }
}

pub fn get_device_info<'a>(c           : &'a base::Connection,
                           device_spec : DeviceSpec,
                           wanted      : u16,
                           all_buttons : bool,
                           first_button: u8,
                           n_buttons   : u8,
                           led_class   : LedClassSpec,
                           led_i_d     : IdSpec)
        -> GetDeviceInfoCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_device_info(c.get_raw_conn(),
                                             device_spec as xcb_xkb_device_spec_t,  // 0
                                             wanted as u16,  // 1
                                             all_buttons as u8,  // 2
                                             first_button as u8,  // 3
                                             n_buttons as u8,  // 4
                                             led_class as xcb_xkb_led_class_spec_t,  // 5
                                             led_i_d as xcb_xkb_id_spec_t);  // 6
        GetDeviceInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_device_info_unchecked<'a>(c           : &'a base::Connection,
                                     device_spec : DeviceSpec,
                                     wanted      : u16,
                                     all_buttons : bool,
                                     first_button: u8,
                                     n_buttons   : u8,
                                     led_class   : LedClassSpec,
                                     led_i_d     : IdSpec)
        -> GetDeviceInfoCookie<'a> {
    unsafe {
        let cookie = xcb_xkb_get_device_info_unchecked(c.get_raw_conn(),
                                                       device_spec as xcb_xkb_device_spec_t,  // 0
                                                       wanted as u16,  // 1
                                                       all_buttons as u8,  // 2
                                                       first_button as u8,  // 3
                                                       n_buttons as u8,  // 4
                                                       led_class as xcb_xkb_led_class_spec_t,  // 5
                                                       led_i_d as xcb_xkb_id_spec_t);  // 6
        GetDeviceInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_DEVICE_INFO: u8 = 25;

pub fn set_device_info<'a>(c          : &'a base::Connection,
                           device_spec: DeviceSpec,
                           first_btn  : u8,
                           change     : u16,
                           btn_actions: &[Action],
                           leds       : &[DeviceLedInfo])
        -> base::VoidCookie<'a> {
    unsafe {
        let btn_actions_len = btn_actions.len();
        let btn_actions_ptr = btn_actions.as_ptr();
        let leds_len = leds.len();
        let leds_ptr = leds.as_ptr();
        let cookie = xcb_xkb_set_device_info(c.get_raw_conn(),
                                             device_spec as xcb_xkb_device_spec_t,  // 0
                                             first_btn as u8,  // 1
                                             btn_actions_len as u8,  // 2
                                             change as u16,  // 3
                                             leds_len as u16,  // 4
                                             btn_actions_ptr as *const xcb_xkb_action_t,  // 5
                                             leds_ptr as *const xcb_xkb_device_led_info_t);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_device_info_checked<'a>(c          : &'a base::Connection,
                                   device_spec: DeviceSpec,
                                   first_btn  : u8,
                                   change     : u16,
                                   btn_actions: &[Action],
                                   leds       : &[DeviceLedInfo])
        -> base::VoidCookie<'a> {
    unsafe {
        let btn_actions_len = btn_actions.len();
        let btn_actions_ptr = btn_actions.as_ptr();
        let leds_len = leds.len();
        let leds_ptr = leds.as_ptr();
        let cookie = xcb_xkb_set_device_info_checked(c.get_raw_conn(),
                                                     device_spec as xcb_xkb_device_spec_t,  // 0
                                                     first_btn as u8,  // 1
                                                     btn_actions_len as u8,  // 2
                                                     change as u16,  // 3
                                                     leds_len as u16,  // 4
                                                     btn_actions_ptr as *const xcb_xkb_action_t,  // 5
                                                     leds_ptr as *const xcb_xkb_device_led_info_t);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_DEBUGGING_FLAGS: u8 = 101;

pub type SetDebuggingFlagsCookie<'a> = base::Cookie<'a, xcb_xkb_set_debugging_flags_cookie_t>;

impl<'a> SetDebuggingFlagsCookie<'a> {
    pub fn get_reply(&self) -> Result<SetDebuggingFlagsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetDebuggingFlagsReply {
                    ptr: xcb_xkb_set_debugging_flags_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetDebuggingFlagsReply {
                    ptr: xcb_xkb_set_debugging_flags_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetDebuggingFlagsReply = base::Reply<xcb_xkb_set_debugging_flags_reply_t>;

impl SetDebuggingFlagsReply {
    pub fn current_flags(&self) -> u32 {
        unsafe {
            (*self.ptr).currentFlags
        }
    }
    pub fn current_ctrls(&self) -> u32 {
        unsafe {
            (*self.ptr).currentCtrls
        }
    }
    pub fn supported_flags(&self) -> u32 {
        unsafe {
            (*self.ptr).supportedFlags
        }
    }
    pub fn supported_ctrls(&self) -> u32 {
        unsafe {
            (*self.ptr).supportedCtrls
        }
    }
}

pub fn set_debugging_flags<'a>(c           : &'a base::Connection,
                               affect_flags: u32,
                               flags       : u32,
                               affect_ctrls: u32,
                               ctrls       : u32,
                               message     : &[String8])
        -> SetDebuggingFlagsCookie<'a> {
    unsafe {
        let message_len = message.len();
        let message_ptr = message.as_ptr();
        let cookie = xcb_xkb_set_debugging_flags(c.get_raw_conn(),
                                                 message_len as u16,  // 0
                                                 affect_flags as u32,  // 1
                                                 flags as u32,  // 2
                                                 affect_ctrls as u32,  // 3
                                                 ctrls as u32,  // 4
                                                 message_ptr as *const xcb_xkb_string8_t);  // 5
        SetDebuggingFlagsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_debugging_flags_unchecked<'a>(c           : &'a base::Connection,
                                         affect_flags: u32,
                                         flags       : u32,
                                         affect_ctrls: u32,
                                         ctrls       : u32,
                                         message     : &[String8])
        -> SetDebuggingFlagsCookie<'a> {
    unsafe {
        let message_len = message.len();
        let message_ptr = message.as_ptr();
        let cookie = xcb_xkb_set_debugging_flags_unchecked(c.get_raw_conn(),
                                                           message_len as u16,  // 0
                                                           affect_flags as u32,  // 1
                                                           flags as u32,  // 2
                                                           affect_ctrls as u32,  // 3
                                                           ctrls as u32,  // 4
                                                           message_ptr as *const xcb_xkb_string8_t);  // 5
        SetDebuggingFlagsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const NEW_KEYBOARD_NOTIFY: u8 = 0;

pub type NewKeyboardNotifyEvent = base::Event<xcb_xkb_new_keyboard_notify_event_t>;

impl NewKeyboardNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn old_device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).oldDeviceID
        }
    }
    pub fn min_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).minKeyCode
        }
    }
    pub fn max_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).maxKeyCode
        }
    }
    pub fn old_min_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).oldMinKeyCode
        }
    }
    pub fn old_max_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).oldMaxKeyCode
        }
    }
    pub fn request_major(&self) -> u8 {
        unsafe {
            (*self.ptr).requestMajor
        }
    }
    pub fn request_minor(&self) -> u8 {
        unsafe {
            (*self.ptr).requestMinor
        }
    }
    pub fn changed(&self) -> u16 {
        unsafe {
            (*self.ptr).changed
        }
    }
    /// Constructs a new NewKeyboardNotifyEvent
    /// `response_type` will be set automatically to NEW_KEYBOARD_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               old_device_i_d: u8,
               min_key_code: xproto::Keycode,
               max_key_code: xproto::Keycode,
               old_min_key_code: xproto::Keycode,
               old_max_key_code: xproto::Keycode,
               request_major: u8,
               request_minor: u8,
               changed: u16)
            -> NewKeyboardNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_new_keyboard_notify_event_t;
            (*raw).response_type = NEW_KEYBOARD_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).oldDeviceID = old_device_i_d;
            (*raw).minKeyCode = min_key_code;
            (*raw).maxKeyCode = max_key_code;
            (*raw).oldMinKeyCode = old_min_key_code;
            (*raw).oldMaxKeyCode = old_max_key_code;
            (*raw).requestMajor = request_major;
            (*raw).requestMinor = request_minor;
            (*raw).changed = changed;
            NewKeyboardNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const MAP_NOTIFY: u8 = 1;

pub type MapNotifyEvent = base::Event<xcb_xkb_map_notify_event_t>;

impl MapNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn ptr_btn_actions(&self) -> u8 {
        unsafe {
            (*self.ptr).ptrBtnActions
        }
    }
    pub fn changed(&self) -> u16 {
        unsafe {
            (*self.ptr).changed
        }
    }
    pub fn min_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).minKeyCode
        }
    }
    pub fn max_key_code(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).maxKeyCode
        }
    }
    pub fn first_type(&self) -> u8 {
        unsafe {
            (*self.ptr).firstType
        }
    }
    pub fn n_types(&self) -> u8 {
        unsafe {
            (*self.ptr).nTypes
        }
    }
    pub fn first_key_sym(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKeySym
        }
    }
    pub fn n_key_syms(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeySyms
        }
    }
    pub fn first_key_act(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKeyAct
        }
    }
    pub fn n_key_acts(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeyActs
        }
    }
    pub fn first_key_behavior(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKeyBehavior
        }
    }
    pub fn n_key_behavior(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeyBehavior
        }
    }
    pub fn first_key_explicit(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKeyExplicit
        }
    }
    pub fn n_key_explicit(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeyExplicit
        }
    }
    pub fn first_mod_map_key(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstModMapKey
        }
    }
    pub fn n_mod_map_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).nModMapKeys
        }
    }
    pub fn first_v_mod_map_key(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstVModMapKey
        }
    }
    pub fn n_v_mod_map_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).nVModMapKeys
        }
    }
    pub fn virtual_mods(&self) -> u16 {
        unsafe {
            (*self.ptr).virtualMods
        }
    }
    /// Constructs a new MapNotifyEvent
    /// `response_type` will be set automatically to MAP_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               ptr_btn_actions: u8,
               changed: u16,
               min_key_code: xproto::Keycode,
               max_key_code: xproto::Keycode,
               first_type: u8,
               n_types: u8,
               first_key_sym: xproto::Keycode,
               n_key_syms: u8,
               first_key_act: xproto::Keycode,
               n_key_acts: u8,
               first_key_behavior: xproto::Keycode,
               n_key_behavior: u8,
               first_key_explicit: xproto::Keycode,
               n_key_explicit: u8,
               first_mod_map_key: xproto::Keycode,
               n_mod_map_keys: u8,
               first_v_mod_map_key: xproto::Keycode,
               n_v_mod_map_keys: u8,
               virtual_mods: u16)
            -> MapNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_map_notify_event_t;
            (*raw).response_type = MAP_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).ptrBtnActions = ptr_btn_actions;
            (*raw).changed = changed;
            (*raw).minKeyCode = min_key_code;
            (*raw).maxKeyCode = max_key_code;
            (*raw).firstType = first_type;
            (*raw).nTypes = n_types;
            (*raw).firstKeySym = first_key_sym;
            (*raw).nKeySyms = n_key_syms;
            (*raw).firstKeyAct = first_key_act;
            (*raw).nKeyActs = n_key_acts;
            (*raw).firstKeyBehavior = first_key_behavior;
            (*raw).nKeyBehavior = n_key_behavior;
            (*raw).firstKeyExplicit = first_key_explicit;
            (*raw).nKeyExplicit = n_key_explicit;
            (*raw).firstModMapKey = first_mod_map_key;
            (*raw).nModMapKeys = n_mod_map_keys;
            (*raw).firstVModMapKey = first_v_mod_map_key;
            (*raw).nVModMapKeys = n_v_mod_map_keys;
            (*raw).virtualMods = virtual_mods;
            MapNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const STATE_NOTIFY: u8 = 2;

pub type StateNotifyEvent = base::Event<xcb_xkb_state_notify_event_t>;

impl StateNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn mods(&self) -> u8 {
        unsafe {
            (*self.ptr).mods
        }
    }
    pub fn base_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).baseMods
        }
    }
    pub fn latched_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).latchedMods
        }
    }
    pub fn locked_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).lockedMods
        }
    }
    pub fn group(&self) -> u8 {
        unsafe {
            (*self.ptr).group
        }
    }
    pub fn base_group(&self) -> i16 {
        unsafe {
            (*self.ptr).baseGroup
        }
    }
    pub fn latched_group(&self) -> i16 {
        unsafe {
            (*self.ptr).latchedGroup
        }
    }
    pub fn locked_group(&self) -> u8 {
        unsafe {
            (*self.ptr).lockedGroup
        }
    }
    pub fn compat_state(&self) -> u8 {
        unsafe {
            (*self.ptr).compatState
        }
    }
    pub fn grab_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).grabMods
        }
    }
    pub fn compat_grab_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).compatGrabMods
        }
    }
    pub fn lookup_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).lookupMods
        }
    }
    pub fn compat_loockup_mods(&self) -> u8 {
        unsafe {
            (*self.ptr).compatLoockupMods
        }
    }
    pub fn ptr_btn_state(&self) -> u16 {
        unsafe {
            (*self.ptr).ptrBtnState
        }
    }
    pub fn changed(&self) -> u16 {
        unsafe {
            (*self.ptr).changed
        }
    }
    pub fn keycode(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).keycode
        }
    }
    pub fn event_type(&self) -> u8 {
        unsafe {
            (*self.ptr).eventType
        }
    }
    pub fn request_major(&self) -> u8 {
        unsafe {
            (*self.ptr).requestMajor
        }
    }
    pub fn request_minor(&self) -> u8 {
        unsafe {
            (*self.ptr).requestMinor
        }
    }
    /// Constructs a new StateNotifyEvent
    /// `response_type` will be set automatically to STATE_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               mods: u8,
               base_mods: u8,
               latched_mods: u8,
               locked_mods: u8,
               group: u8,
               base_group: i16,
               latched_group: i16,
               locked_group: u8,
               compat_state: u8,
               grab_mods: u8,
               compat_grab_mods: u8,
               lookup_mods: u8,
               compat_loockup_mods: u8,
               ptr_btn_state: u16,
               changed: u16,
               keycode: xproto::Keycode,
               event_type: u8,
               request_major: u8,
               request_minor: u8)
            -> StateNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_state_notify_event_t;
            (*raw).response_type = STATE_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).mods = mods;
            (*raw).baseMods = base_mods;
            (*raw).latchedMods = latched_mods;
            (*raw).lockedMods = locked_mods;
            (*raw).group = group;
            (*raw).baseGroup = base_group;
            (*raw).latchedGroup = latched_group;
            (*raw).lockedGroup = locked_group;
            (*raw).compatState = compat_state;
            (*raw).grabMods = grab_mods;
            (*raw).compatGrabMods = compat_grab_mods;
            (*raw).lookupMods = lookup_mods;
            (*raw).compatLoockupMods = compat_loockup_mods;
            (*raw).ptrBtnState = ptr_btn_state;
            (*raw).changed = changed;
            (*raw).keycode = keycode;
            (*raw).eventType = event_type;
            (*raw).requestMajor = request_major;
            (*raw).requestMinor = request_minor;
            StateNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const CONTROLS_NOTIFY: u8 = 3;

pub type ControlsNotifyEvent = base::Event<xcb_xkb_controls_notify_event_t>;

impl ControlsNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn num_groups(&self) -> u8 {
        unsafe {
            (*self.ptr).numGroups
        }
    }
    pub fn changed_controls(&self) -> u32 {
        unsafe {
            (*self.ptr).changedControls
        }
    }
    pub fn enabled_controls(&self) -> u32 {
        unsafe {
            (*self.ptr).enabledControls
        }
    }
    pub fn enabled_control_changes(&self) -> u32 {
        unsafe {
            (*self.ptr).enabledControlChanges
        }
    }
    pub fn keycode(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).keycode
        }
    }
    pub fn event_type(&self) -> u8 {
        unsafe {
            (*self.ptr).eventType
        }
    }
    pub fn request_major(&self) -> u8 {
        unsafe {
            (*self.ptr).requestMajor
        }
    }
    pub fn request_minor(&self) -> u8 {
        unsafe {
            (*self.ptr).requestMinor
        }
    }
    /// Constructs a new ControlsNotifyEvent
    /// `response_type` will be set automatically to CONTROLS_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               num_groups: u8,
               changed_controls: u32,
               enabled_controls: u32,
               enabled_control_changes: u32,
               keycode: xproto::Keycode,
               event_type: u8,
               request_major: u8,
               request_minor: u8)
            -> ControlsNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_controls_notify_event_t;
            (*raw).response_type = CONTROLS_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).numGroups = num_groups;
            (*raw).changedControls = changed_controls;
            (*raw).enabledControls = enabled_controls;
            (*raw).enabledControlChanges = enabled_control_changes;
            (*raw).keycode = keycode;
            (*raw).eventType = event_type;
            (*raw).requestMajor = request_major;
            (*raw).requestMinor = request_minor;
            ControlsNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const INDICATOR_STATE_NOTIFY: u8 = 4;

pub type IndicatorStateNotifyEvent = base::Event<xcb_xkb_indicator_state_notify_event_t>;

impl IndicatorStateNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn state(&self) -> u32 {
        unsafe {
            (*self.ptr).state
        }
    }
    pub fn state_changed(&self) -> u32 {
        unsafe {
            (*self.ptr).stateChanged
        }
    }
    /// Constructs a new IndicatorStateNotifyEvent
    /// `response_type` will be set automatically to INDICATOR_STATE_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               state: u32,
               state_changed: u32)
            -> IndicatorStateNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_indicator_state_notify_event_t;
            (*raw).response_type = INDICATOR_STATE_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).state = state;
            (*raw).stateChanged = state_changed;
            IndicatorStateNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const INDICATOR_MAP_NOTIFY: u8 = 5;

pub type IndicatorMapNotifyEvent = base::Event<xcb_xkb_indicator_map_notify_event_t>;

impl IndicatorMapNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn state(&self) -> u32 {
        unsafe {
            (*self.ptr).state
        }
    }
    pub fn map_changed(&self) -> u32 {
        unsafe {
            (*self.ptr).mapChanged
        }
    }
    /// Constructs a new IndicatorMapNotifyEvent
    /// `response_type` will be set automatically to INDICATOR_MAP_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               state: u32,
               map_changed: u32)
            -> IndicatorMapNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_indicator_map_notify_event_t;
            (*raw).response_type = INDICATOR_MAP_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).state = state;
            (*raw).mapChanged = map_changed;
            IndicatorMapNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const NAMES_NOTIFY: u8 = 6;

pub type NamesNotifyEvent = base::Event<xcb_xkb_names_notify_event_t>;

impl NamesNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn changed(&self) -> u16 {
        unsafe {
            (*self.ptr).changed
        }
    }
    pub fn first_type(&self) -> u8 {
        unsafe {
            (*self.ptr).firstType
        }
    }
    pub fn n_types(&self) -> u8 {
        unsafe {
            (*self.ptr).nTypes
        }
    }
    pub fn first_level_name(&self) -> u8 {
        unsafe {
            (*self.ptr).firstLevelName
        }
    }
    pub fn n_level_names(&self) -> u8 {
        unsafe {
            (*self.ptr).nLevelNames
        }
    }
    pub fn n_radio_groups(&self) -> u8 {
        unsafe {
            (*self.ptr).nRadioGroups
        }
    }
    pub fn n_key_aliases(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeyAliases
        }
    }
    pub fn changed_group_names(&self) -> u8 {
        unsafe {
            (*self.ptr).changedGroupNames
        }
    }
    pub fn changed_virtual_mods(&self) -> u16 {
        unsafe {
            (*self.ptr).changedVirtualMods
        }
    }
    pub fn first_key(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).firstKey
        }
    }
    pub fn n_keys(&self) -> u8 {
        unsafe {
            (*self.ptr).nKeys
        }
    }
    pub fn changed_indicators(&self) -> u32 {
        unsafe {
            (*self.ptr).changedIndicators
        }
    }
    /// Constructs a new NamesNotifyEvent
    /// `response_type` will be set automatically to NAMES_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               changed: u16,
               first_type: u8,
               n_types: u8,
               first_level_name: u8,
               n_level_names: u8,
               n_radio_groups: u8,
               n_key_aliases: u8,
               changed_group_names: u8,
               changed_virtual_mods: u16,
               first_key: xproto::Keycode,
               n_keys: u8,
               changed_indicators: u32)
            -> NamesNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_names_notify_event_t;
            (*raw).response_type = NAMES_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).changed = changed;
            (*raw).firstType = first_type;
            (*raw).nTypes = n_types;
            (*raw).firstLevelName = first_level_name;
            (*raw).nLevelNames = n_level_names;
            (*raw).nRadioGroups = n_radio_groups;
            (*raw).nKeyAliases = n_key_aliases;
            (*raw).changedGroupNames = changed_group_names;
            (*raw).changedVirtualMods = changed_virtual_mods;
            (*raw).firstKey = first_key;
            (*raw).nKeys = n_keys;
            (*raw).changedIndicators = changed_indicators;
            NamesNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const COMPAT_MAP_NOTIFY: u8 = 7;

pub type CompatMapNotifyEvent = base::Event<xcb_xkb_compat_map_notify_event_t>;

impl CompatMapNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn changed_groups(&self) -> u8 {
        unsafe {
            (*self.ptr).changedGroups
        }
    }
    pub fn first_s_i(&self) -> u16 {
        unsafe {
            (*self.ptr).firstSI
        }
    }
    pub fn n_s_i(&self) -> u16 {
        unsafe {
            (*self.ptr).nSI
        }
    }
    pub fn n_total_s_i(&self) -> u16 {
        unsafe {
            (*self.ptr).nTotalSI
        }
    }
    /// Constructs a new CompatMapNotifyEvent
    /// `response_type` will be set automatically to COMPAT_MAP_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               changed_groups: u8,
               first_s_i: u16,
               n_s_i: u16,
               n_total_s_i: u16)
            -> CompatMapNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_compat_map_notify_event_t;
            (*raw).response_type = COMPAT_MAP_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).changedGroups = changed_groups;
            (*raw).firstSI = first_s_i;
            (*raw).nSI = n_s_i;
            (*raw).nTotalSI = n_total_s_i;
            CompatMapNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const BELL_NOTIFY: u8 = 8;

pub type BellNotifyEvent = base::Event<xcb_xkb_bell_notify_event_t>;

impl BellNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn bell_class(&self) -> u8 {
        unsafe {
            (*self.ptr).bellClass
        }
    }
    pub fn bell_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).bellID
        }
    }
    pub fn percent(&self) -> u8 {
        unsafe {
            (*self.ptr).percent
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
    pub fn name(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).name
        }
    }
    pub fn window(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn event_only(&self) -> bool {
        unsafe {
            (*self.ptr).eventOnly != 0
        }
    }
    /// Constructs a new BellNotifyEvent
    /// `response_type` will be set automatically to BELL_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               bell_class: u8,
               bell_i_d: u8,
               percent: u8,
               pitch: u16,
               duration: u16,
               name: xproto::Atom,
               window: xproto::Window,
               event_only: bool)
            -> BellNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_bell_notify_event_t;
            (*raw).response_type = BELL_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).bellClass = bell_class;
            (*raw).bellID = bell_i_d;
            (*raw).percent = percent;
            (*raw).pitch = pitch;
            (*raw).duration = duration;
            (*raw).name = name;
            (*raw).window = window;
            (*raw).eventOnly = if event_only { 1 } else { 0 };
            BellNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const ACTION_MESSAGE: u8 = 9;

pub type ActionMessageEvent = base::Event<xcb_xkb_action_message_event_t>;

impl ActionMessageEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn keycode(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).keycode
        }
    }
    pub fn press(&self) -> bool {
        unsafe {
            (*self.ptr).press != 0
        }
    }
    pub fn key_event_follows(&self) -> bool {
        unsafe {
            (*self.ptr).keyEventFollows != 0
        }
    }
    pub fn mods(&self) -> u8 {
        unsafe {
            (*self.ptr).mods
        }
    }
    pub fn group(&self) -> u8 {
        unsafe {
            (*self.ptr).group
        }
    }
    pub fn message(&self) -> &[String8] {
        unsafe {
            &(*self.ptr).message
        }
    }
    /// Constructs a new ActionMessageEvent
    /// `response_type` will be set automatically to ACTION_MESSAGE
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               keycode: xproto::Keycode,
               press: bool,
               key_event_follows: bool,
               mods: u8,
               group: u8,
               message: [String8; 8])
            -> ActionMessageEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_action_message_event_t;
            (*raw).response_type = ACTION_MESSAGE;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).keycode = keycode;
            (*raw).press = if press { 1 } else { 0 };
            (*raw).keyEventFollows = if key_event_follows { 1 } else { 0 };
            (*raw).mods = mods;
            (*raw).group = group;
            (*raw).message = message;
            ActionMessageEvent {
                ptr: raw
            }
        }
    }
}

pub const ACCESS_X_NOTIFY: u8 = 10;

pub type AccessXNotifyEvent = base::Event<xcb_xkb_access_x_notify_event_t>;

impl AccessXNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn keycode(&self) -> xproto::Keycode {
        unsafe {
            (*self.ptr).keycode
        }
    }
    pub fn detailt(&self) -> u16 {
        unsafe {
            (*self.ptr).detailt
        }
    }
    pub fn slow_keys_delay(&self) -> u16 {
        unsafe {
            (*self.ptr).slowKeysDelay
        }
    }
    pub fn debounce_delay(&self) -> u16 {
        unsafe {
            (*self.ptr).debounceDelay
        }
    }
    /// Constructs a new AccessXNotifyEvent
    /// `response_type` will be set automatically to ACCESS_X_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               keycode: xproto::Keycode,
               detailt: u16,
               slow_keys_delay: u16,
               debounce_delay: u16)
            -> AccessXNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_access_x_notify_event_t;
            (*raw).response_type = ACCESS_X_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).keycode = keycode;
            (*raw).detailt = detailt;
            (*raw).slowKeysDelay = slow_keys_delay;
            (*raw).debounceDelay = debounce_delay;
            AccessXNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const EXTENSION_DEVICE_NOTIFY: u8 = 11;

pub type ExtensionDeviceNotifyEvent = base::Event<xcb_xkb_extension_device_notify_event_t>;

impl ExtensionDeviceNotifyEvent {
    pub fn xkb_type(&self) -> u8 {
        unsafe {
            (*self.ptr).xkbType
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn device_i_d(&self) -> u8 {
        unsafe {
            (*self.ptr).deviceID
        }
    }
    pub fn reason(&self) -> u16 {
        unsafe {
            (*self.ptr).reason
        }
    }
    pub fn led_class(&self) -> u16 {
        unsafe {
            (*self.ptr).ledClass
        }
    }
    pub fn led_i_d(&self) -> u16 {
        unsafe {
            (*self.ptr).ledID
        }
    }
    pub fn leds_defined(&self) -> u32 {
        unsafe {
            (*self.ptr).ledsDefined
        }
    }
    pub fn led_state(&self) -> u32 {
        unsafe {
            (*self.ptr).ledState
        }
    }
    pub fn first_button(&self) -> u8 {
        unsafe {
            (*self.ptr).firstButton
        }
    }
    pub fn n_buttons(&self) -> u8 {
        unsafe {
            (*self.ptr).nButtons
        }
    }
    pub fn supported(&self) -> u16 {
        unsafe {
            (*self.ptr).supported
        }
    }
    pub fn unsupported(&self) -> u16 {
        unsafe {
            (*self.ptr).unsupported
        }
    }
    /// Constructs a new ExtensionDeviceNotifyEvent
    /// `response_type` will be set automatically to EXTENSION_DEVICE_NOTIFY
    pub fn new(xkb_type: u8,
               time: xproto::Timestamp,
               device_i_d: u8,
               reason: u16,
               led_class: u16,
               led_i_d: u16,
               leds_defined: u32,
               led_state: u32,
               first_button: u8,
               n_buttons: u8,
               supported: u16,
               unsupported: u16)
            -> ExtensionDeviceNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xkb_extension_device_notify_event_t;
            (*raw).response_type = EXTENSION_DEVICE_NOTIFY;
            (*raw).xkbType = xkb_type;
            (*raw).time = time;
            (*raw).deviceID = device_i_d;
            (*raw).reason = reason;
            (*raw).ledClass = led_class;
            (*raw).ledID = led_i_d;
            (*raw).ledsDefined = leds_defined;
            (*raw).ledState = led_state;
            (*raw).firstButton = first_button;
            (*raw).nButtons = n_buttons;
            (*raw).supported = supported;
            (*raw).unsupported = unsupported;
            ExtensionDeviceNotifyEvent {
                ptr: raw
            }
        }
    }
}
