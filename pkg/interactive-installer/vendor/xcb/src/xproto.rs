// Generated automatically from xproto.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use ffi::base::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub type Window = xcb_window_t;

pub type Pixmap = xcb_pixmap_t;

pub type Cursor = xcb_cursor_t;

pub type Font = xcb_font_t;

pub type Gcontext = xcb_gcontext_t;

pub type Colormap = xcb_colormap_t;

pub type Atom = xcb_atom_t;

pub type Drawable = xcb_drawable_t;

pub type Fontable = xcb_fontable_t;

pub type Visualid = xcb_visualid_t;

pub type Timestamp = xcb_timestamp_t;

pub type Keysym = xcb_keysym_t;

pub type Keycode = xcb_keycode_t;

pub type Button = xcb_button_t;

pub type VisualClass = u32;
pub const VISUAL_CLASS_STATIC_GRAY : VisualClass = 0x00;
pub const VISUAL_CLASS_GRAY_SCALE  : VisualClass = 0x01;
pub const VISUAL_CLASS_STATIC_COLOR: VisualClass = 0x02;
pub const VISUAL_CLASS_PSEUDO_COLOR: VisualClass = 0x03;
pub const VISUAL_CLASS_TRUE_COLOR  : VisualClass = 0x04;
pub const VISUAL_CLASS_DIRECT_COLOR: VisualClass = 0x05;

pub type EventMask = u32;
pub const EVENT_MASK_NO_EVENT             : EventMask =      0x00;
pub const EVENT_MASK_KEY_PRESS            : EventMask =      0x01;
pub const EVENT_MASK_KEY_RELEASE          : EventMask =      0x02;
pub const EVENT_MASK_BUTTON_PRESS         : EventMask =      0x04;
pub const EVENT_MASK_BUTTON_RELEASE       : EventMask =      0x08;
pub const EVENT_MASK_ENTER_WINDOW         : EventMask =      0x10;
pub const EVENT_MASK_LEAVE_WINDOW         : EventMask =      0x20;
pub const EVENT_MASK_POINTER_MOTION       : EventMask =      0x40;
pub const EVENT_MASK_POINTER_MOTION_HINT  : EventMask =      0x80;
pub const EVENT_MASK_BUTTON_1_MOTION      : EventMask =     0x100;
pub const EVENT_MASK_BUTTON_2_MOTION      : EventMask =     0x200;
pub const EVENT_MASK_BUTTON_3_MOTION      : EventMask =     0x400;
pub const EVENT_MASK_BUTTON_4_MOTION      : EventMask =     0x800;
pub const EVENT_MASK_BUTTON_5_MOTION      : EventMask =    0x1000;
pub const EVENT_MASK_BUTTON_MOTION        : EventMask =    0x2000;
pub const EVENT_MASK_KEYMAP_STATE         : EventMask =    0x4000;
pub const EVENT_MASK_EXPOSURE             : EventMask =    0x8000;
pub const EVENT_MASK_VISIBILITY_CHANGE    : EventMask =   0x10000;
pub const EVENT_MASK_STRUCTURE_NOTIFY     : EventMask =   0x20000;
pub const EVENT_MASK_RESIZE_REDIRECT      : EventMask =   0x40000;
pub const EVENT_MASK_SUBSTRUCTURE_NOTIFY  : EventMask =   0x80000;
pub const EVENT_MASK_SUBSTRUCTURE_REDIRECT: EventMask =  0x100000;
pub const EVENT_MASK_FOCUS_CHANGE         : EventMask =  0x200000;
pub const EVENT_MASK_PROPERTY_CHANGE      : EventMask =  0x400000;
pub const EVENT_MASK_COLOR_MAP_CHANGE     : EventMask =  0x800000;
pub const EVENT_MASK_OWNER_GRAB_BUTTON    : EventMask = 0x1000000;

pub type BackingStore = u32;
pub const BACKING_STORE_NOT_USEFUL : BackingStore = 0x00;
pub const BACKING_STORE_WHEN_MAPPED: BackingStore = 0x01;
pub const BACKING_STORE_ALWAYS     : BackingStore = 0x02;

pub type ImageOrder = u32;
pub const IMAGE_ORDER_LSB_FIRST: ImageOrder = 0x00;
pub const IMAGE_ORDER_MSB_FIRST: ImageOrder = 0x01;

pub type ModMask = u32;
pub const MOD_MASK_SHIFT  : ModMask =   0x01;
pub const MOD_MASK_LOCK   : ModMask =   0x02;
pub const MOD_MASK_CONTROL: ModMask =   0x04;
pub const MOD_MASK_1      : ModMask =   0x08;
pub const MOD_MASK_2      : ModMask =   0x10;
pub const MOD_MASK_3      : ModMask =   0x20;
pub const MOD_MASK_4      : ModMask =   0x40;
pub const MOD_MASK_5      : ModMask =   0x80;
pub const MOD_MASK_ANY    : ModMask = 0x8000;

pub type KeyButMask = u32;
pub const KEY_BUT_MASK_SHIFT   : KeyButMask =   0x01;
pub const KEY_BUT_MASK_LOCK    : KeyButMask =   0x02;
pub const KEY_BUT_MASK_CONTROL : KeyButMask =   0x04;
pub const KEY_BUT_MASK_MOD_1   : KeyButMask =   0x08;
pub const KEY_BUT_MASK_MOD_2   : KeyButMask =   0x10;
pub const KEY_BUT_MASK_MOD_3   : KeyButMask =   0x20;
pub const KEY_BUT_MASK_MOD_4   : KeyButMask =   0x40;
pub const KEY_BUT_MASK_MOD_5   : KeyButMask =   0x80;
pub const KEY_BUT_MASK_BUTTON_1: KeyButMask =  0x100;
pub const KEY_BUT_MASK_BUTTON_2: KeyButMask =  0x200;
pub const KEY_BUT_MASK_BUTTON_3: KeyButMask =  0x400;
pub const KEY_BUT_MASK_BUTTON_4: KeyButMask =  0x800;
pub const KEY_BUT_MASK_BUTTON_5: KeyButMask = 0x1000;

pub type WindowEnum = u32;
pub const WINDOW_NONE: WindowEnum = 0x00;

pub type ButtonMask = u32;
pub const BUTTON_MASK_1  : ButtonMask =  0x100;
pub const BUTTON_MASK_2  : ButtonMask =  0x200;
pub const BUTTON_MASK_3  : ButtonMask =  0x400;
pub const BUTTON_MASK_4  : ButtonMask =  0x800;
pub const BUTTON_MASK_5  : ButtonMask = 0x1000;
pub const BUTTON_MASK_ANY: ButtonMask = 0x8000;

pub type Motion = u32;
pub const MOTION_NORMAL: Motion = 0x00;
pub const MOTION_HINT  : Motion = 0x01;

pub type NotifyDetail = u32;
pub const NOTIFY_DETAIL_ANCESTOR         : NotifyDetail = 0x00;
pub const NOTIFY_DETAIL_VIRTUAL          : NotifyDetail = 0x01;
pub const NOTIFY_DETAIL_INFERIOR         : NotifyDetail = 0x02;
pub const NOTIFY_DETAIL_NONLINEAR        : NotifyDetail = 0x03;
pub const NOTIFY_DETAIL_NONLINEAR_VIRTUAL: NotifyDetail = 0x04;
pub const NOTIFY_DETAIL_POINTER          : NotifyDetail = 0x05;
pub const NOTIFY_DETAIL_POINTER_ROOT     : NotifyDetail = 0x06;
pub const NOTIFY_DETAIL_NONE             : NotifyDetail = 0x07;

pub type NotifyMode = u32;
pub const NOTIFY_MODE_NORMAL       : NotifyMode = 0x00;
pub const NOTIFY_MODE_GRAB         : NotifyMode = 0x01;
pub const NOTIFY_MODE_UNGRAB       : NotifyMode = 0x02;
pub const NOTIFY_MODE_WHILE_GRABBED: NotifyMode = 0x03;

pub type Visibility = u32;
pub const VISIBILITY_UNOBSCURED        : Visibility = 0x00;
pub const VISIBILITY_PARTIALLY_OBSCURED: Visibility = 0x01;
pub const VISIBILITY_FULLY_OBSCURED    : Visibility = 0x02;

pub type Place = u32;
/// The window is now on top of all siblings.
pub const PLACE_ON_TOP   : Place = 0x00;
/// The window is now below all siblings.
pub const PLACE_ON_BOTTOM: Place = 0x01;

pub type Property = u32;
pub const PROPERTY_NEW_VALUE: Property = 0x00;
pub const PROPERTY_DELETE   : Property = 0x01;

pub type Time = u32;
pub const TIME_CURRENT_TIME: Time = 0x00;

pub type AtomEnum = u32;
pub const ATOM_NONE               : AtomEnum = 0x00;
pub const ATOM_ANY                : AtomEnum = 0x00;
pub const ATOM_PRIMARY            : AtomEnum = 0x01;
pub const ATOM_SECONDARY          : AtomEnum = 0x02;
pub const ATOM_ARC                : AtomEnum = 0x03;
pub const ATOM_ATOM               : AtomEnum = 0x04;
pub const ATOM_BITMAP             : AtomEnum = 0x05;
pub const ATOM_CARDINAL           : AtomEnum = 0x06;
pub const ATOM_COLORMAP           : AtomEnum = 0x07;
pub const ATOM_CURSOR             : AtomEnum = 0x08;
pub const ATOM_CUT_BUFFER0        : AtomEnum = 0x09;
pub const ATOM_CUT_BUFFER1        : AtomEnum = 0x0a;
pub const ATOM_CUT_BUFFER2        : AtomEnum = 0x0b;
pub const ATOM_CUT_BUFFER3        : AtomEnum = 0x0c;
pub const ATOM_CUT_BUFFER4        : AtomEnum = 0x0d;
pub const ATOM_CUT_BUFFER5        : AtomEnum = 0x0e;
pub const ATOM_CUT_BUFFER6        : AtomEnum = 0x0f;
pub const ATOM_CUT_BUFFER7        : AtomEnum = 0x10;
pub const ATOM_DRAWABLE           : AtomEnum = 0x11;
pub const ATOM_FONT               : AtomEnum = 0x12;
pub const ATOM_INTEGER            : AtomEnum = 0x13;
pub const ATOM_PIXMAP             : AtomEnum = 0x14;
pub const ATOM_POINT              : AtomEnum = 0x15;
pub const ATOM_RECTANGLE          : AtomEnum = 0x16;
pub const ATOM_RESOURCE_MANAGER   : AtomEnum = 0x17;
pub const ATOM_RGB_COLOR_MAP      : AtomEnum = 0x18;
pub const ATOM_RGB_BEST_MAP       : AtomEnum = 0x19;
pub const ATOM_RGB_BLUE_MAP       : AtomEnum = 0x1a;
pub const ATOM_RGB_DEFAULT_MAP    : AtomEnum = 0x1b;
pub const ATOM_RGB_GRAY_MAP       : AtomEnum = 0x1c;
pub const ATOM_RGB_GREEN_MAP      : AtomEnum = 0x1d;
pub const ATOM_RGB_RED_MAP        : AtomEnum = 0x1e;
pub const ATOM_STRING             : AtomEnum = 0x1f;
pub const ATOM_VISUALID           : AtomEnum = 0x20;
pub const ATOM_WINDOW             : AtomEnum = 0x21;
pub const ATOM_WM_COMMAND         : AtomEnum = 0x22;
pub const ATOM_WM_HINTS           : AtomEnum = 0x23;
pub const ATOM_WM_CLIENT_MACHINE  : AtomEnum = 0x24;
pub const ATOM_WM_ICON_NAME       : AtomEnum = 0x25;
pub const ATOM_WM_ICON_SIZE       : AtomEnum = 0x26;
pub const ATOM_WM_NAME            : AtomEnum = 0x27;
pub const ATOM_WM_NORMAL_HINTS    : AtomEnum = 0x28;
pub const ATOM_WM_SIZE_HINTS      : AtomEnum = 0x29;
pub const ATOM_WM_ZOOM_HINTS      : AtomEnum = 0x2a;
pub const ATOM_MIN_SPACE          : AtomEnum = 0x2b;
pub const ATOM_NORM_SPACE         : AtomEnum = 0x2c;
pub const ATOM_MAX_SPACE          : AtomEnum = 0x2d;
pub const ATOM_END_SPACE          : AtomEnum = 0x2e;
pub const ATOM_SUPERSCRIPT_X      : AtomEnum = 0x2f;
pub const ATOM_SUPERSCRIPT_Y      : AtomEnum = 0x30;
pub const ATOM_SUBSCRIPT_X        : AtomEnum = 0x31;
pub const ATOM_SUBSCRIPT_Y        : AtomEnum = 0x32;
pub const ATOM_UNDERLINE_POSITION : AtomEnum = 0x33;
pub const ATOM_UNDERLINE_THICKNESS: AtomEnum = 0x34;
pub const ATOM_STRIKEOUT_ASCENT   : AtomEnum = 0x35;
pub const ATOM_STRIKEOUT_DESCENT  : AtomEnum = 0x36;
pub const ATOM_ITALIC_ANGLE       : AtomEnum = 0x37;
pub const ATOM_X_HEIGHT           : AtomEnum = 0x38;
pub const ATOM_QUAD_WIDTH         : AtomEnum = 0x39;
pub const ATOM_WEIGHT             : AtomEnum = 0x3a;
pub const ATOM_POINT_SIZE         : AtomEnum = 0x3b;
pub const ATOM_RESOLUTION         : AtomEnum = 0x3c;
pub const ATOM_COPYRIGHT          : AtomEnum = 0x3d;
pub const ATOM_NOTICE             : AtomEnum = 0x3e;
pub const ATOM_FONT_NAME          : AtomEnum = 0x3f;
pub const ATOM_FAMILY_NAME        : AtomEnum = 0x40;
pub const ATOM_FULL_NAME          : AtomEnum = 0x41;
pub const ATOM_CAP_HEIGHT         : AtomEnum = 0x42;
pub const ATOM_WM_CLASS           : AtomEnum = 0x43;
pub const ATOM_WM_TRANSIENT_FOR   : AtomEnum = 0x44;

pub type ColormapState = u32;
/// The colormap was uninstalled.
pub const COLORMAP_STATE_UNINSTALLED: ColormapState = 0x00;
/// The colormap was installed.
pub const COLORMAP_STATE_INSTALLED  : ColormapState = 0x01;

pub type ColormapEnum = u32;
pub const COLORMAP_NONE: ColormapEnum = 0x00;

pub type Mapping = u32;
pub const MAPPING_MODIFIER: Mapping = 0x00;
pub const MAPPING_KEYBOARD: Mapping = 0x01;
pub const MAPPING_POINTER : Mapping = 0x02;

pub struct RequestError {
    pub base: base::Error<xcb_request_error_t>
}

pub struct ValueError {
    pub base: base::Error<xcb_value_error_t>
}

pub struct WindowError {
    pub base: base::Error<xcb_window_error_t>
}

pub struct PixmapError {
    pub base: base::Error<xcb_pixmap_error_t>
}

pub struct AtomError {
    pub base: base::Error<xcb_atom_error_t>
}

pub struct CursorError {
    pub base: base::Error<xcb_cursor_error_t>
}

pub struct FontError {
    pub base: base::Error<xcb_font_error_t>
}

pub struct MatchError {
    pub base: base::Error<xcb_match_error_t>
}

pub struct DrawableError {
    pub base: base::Error<xcb_drawable_error_t>
}

pub struct AccessError {
    pub base: base::Error<xcb_access_error_t>
}

pub struct AllocError {
    pub base: base::Error<xcb_alloc_error_t>
}

pub struct ColormapError {
    pub base: base::Error<xcb_colormap_error_t>
}

pub struct GContextError {
    pub base: base::Error<xcb_g_context_error_t>
}

pub struct IdChoiceError {
    pub base: base::Error<xcb_id_choice_error_t>
}

pub struct NameError {
    pub base: base::Error<xcb_name_error_t>
}

pub struct LengthError {
    pub base: base::Error<xcb_length_error_t>
}

pub struct ImplementationError {
    pub base: base::Error<xcb_implementation_error_t>
}

pub type WindowClass = u32;
pub const WINDOW_CLASS_COPY_FROM_PARENT: WindowClass = 0x00;
pub const WINDOW_CLASS_INPUT_OUTPUT    : WindowClass = 0x01;
pub const WINDOW_CLASS_INPUT_ONLY      : WindowClass = 0x02;

pub type Cw = u32;
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
pub const CW_BACK_PIXMAP      : Cw =   0x01;
/// Overrides `BackPixmap`. A pixmap of undefined size filled with the specified
/// background pixel is used for the background. Range-checking is not performed,
/// the background pixel is truncated to the appropriate number of bits.
pub const CW_BACK_PIXEL       : Cw =   0x02;
/// Overrides the default border-pixmap. The border pixmap and window must have the
/// same root and the same depth. Any size pixmap can be used, although some sizes
/// may be faster than others.
///
/// The special value `XCB_COPY_FROM_PARENT` means the parent's border pixmap is
/// copied (subsequent changes to the parent's border attribute do not affect the
/// child), but the window must have the same depth as the parent.
pub const CW_BORDER_PIXMAP    : Cw =   0x04;
/// Overrides `BorderPixmap`. A pixmap of undefined size filled with the specified
/// border pixel is used for the border. Range checking is not performed on the
/// border-pixel value, it is truncated to the appropriate number of bits.
pub const CW_BORDER_PIXEL     : Cw =   0x08;
/// Defines which region of the window should be retained if the window is resized.
pub const CW_BIT_GRAVITY      : Cw =   0x10;
/// Defines how the window should be repositioned if the parent is resized (see
/// `ConfigureWindow`).
pub const CW_WIN_GRAVITY      : Cw =   0x20;
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
pub const CW_BACKING_STORE    : Cw =   0x40;
/// The backing-planes indicates (with bits set to 1) which bit planes of the
/// window hold dynamic data that must be preserved in backing-stores and during
/// save-unders.
pub const CW_BACKING_PLANES   : Cw =   0x80;
/// The backing-pixel specifies what value to use in planes not covered by
/// backing-planes. The server is free to save only the specified bit planes in the
/// backing-store or save-under and regenerate the remaining planes with the
/// specified pixel value. Any bits beyond the specified depth of the window in
/// these values are simply ignored.
pub const CW_BACKING_PIXEL    : Cw =  0x100;
/// The override-redirect specifies whether map and configure requests on this
/// window should override a SubstructureRedirect on the parent, typically to
/// inform a window manager not to tamper with the window.
pub const CW_OVERRIDE_REDIRECT: Cw =  0x200;
/// If 1, the server is advised that when this window is mapped, saving the
/// contents of windows it obscures would be beneficial.
pub const CW_SAVE_UNDER       : Cw =  0x400;
/// The event-mask defines which events the client is interested in for this window
/// (or for some event types, inferiors of the window).
pub const CW_EVENT_MASK       : Cw =  0x800;
/// The do-not-propagate-mask defines which events should not be propagated to
/// ancestor windows when no client has the event type selected in this window.
pub const CW_DONT_PROPAGATE   : Cw = 0x1000;
/// The colormap specifies the colormap that best reflects the true colors of the window. Servers
/// capable of supporting multiple hardware colormaps may use this information, and window man-
/// agers may use it for InstallColormap requests. The colormap must have the same visual type
/// and root as the window (or a Match error results). If CopyFromParent is specified, the parent's
/// colormap is copied (subsequent changes to the parent's colormap attribute do not affect the child).
/// However, the window must have the same visual type as the parent (or a Match error results),
/// and the parent must not have a colormap of None (or a Match error results). For an explanation
/// of None, see FreeColormap request. The colormap is copied by sharing the colormap object
/// between the child and the parent, not by making a complete copy of the colormap contents.
pub const CW_COLORMAP         : Cw = 0x2000;
/// If a cursor is specified, it will be used whenever the pointer is in the window. If None is speci-
/// fied, the parent's cursor will be used when the pointer is in the window, and any change in the
/// parent's cursor will cause an immediate change in the displayed cursor.
pub const CW_CURSOR           : Cw = 0x4000;

pub type BackPixmap = u32;
pub const BACK_PIXMAP_NONE           : BackPixmap = 0x00;
pub const BACK_PIXMAP_PARENT_RELATIVE: BackPixmap = 0x01;

pub type Gravity = u32;
pub const GRAVITY_BIT_FORGET: Gravity = 0x00;
pub const GRAVITY_WIN_UNMAP : Gravity = 0x00;
pub const GRAVITY_NORTH_WEST: Gravity = 0x01;
pub const GRAVITY_NORTH     : Gravity = 0x02;
pub const GRAVITY_NORTH_EAST: Gravity = 0x03;
pub const GRAVITY_WEST      : Gravity = 0x04;
pub const GRAVITY_CENTER    : Gravity = 0x05;
pub const GRAVITY_EAST      : Gravity = 0x06;
pub const GRAVITY_SOUTH_WEST: Gravity = 0x07;
pub const GRAVITY_SOUTH     : Gravity = 0x08;
pub const GRAVITY_SOUTH_EAST: Gravity = 0x09;
pub const GRAVITY_STATIC    : Gravity = 0x0a;

pub type MapState = u32;
pub const MAP_STATE_UNMAPPED  : MapState = 0x00;
pub const MAP_STATE_UNVIEWABLE: MapState = 0x01;
pub const MAP_STATE_VIEWABLE  : MapState = 0x02;

pub type SetMode = u32;
pub const SET_MODE_INSERT: SetMode = 0x00;
pub const SET_MODE_DELETE: SetMode = 0x01;

pub type ConfigWindow = u32;
pub const CONFIG_WINDOW_X           : ConfigWindow = 0x01;
pub const CONFIG_WINDOW_Y           : ConfigWindow = 0x02;
pub const CONFIG_WINDOW_WIDTH       : ConfigWindow = 0x04;
pub const CONFIG_WINDOW_HEIGHT      : ConfigWindow = 0x08;
pub const CONFIG_WINDOW_BORDER_WIDTH: ConfigWindow = 0x10;
pub const CONFIG_WINDOW_SIBLING     : ConfigWindow = 0x20;
pub const CONFIG_WINDOW_STACK_MODE  : ConfigWindow = 0x40;

pub type StackMode = u32;
pub const STACK_MODE_ABOVE    : StackMode = 0x00;
pub const STACK_MODE_BELOW    : StackMode = 0x01;
pub const STACK_MODE_TOP_IF   : StackMode = 0x02;
pub const STACK_MODE_BOTTOM_IF: StackMode = 0x03;
pub const STACK_MODE_OPPOSITE : StackMode = 0x04;

pub type Circulate = u32;
pub const CIRCULATE_RAISE_LOWEST : Circulate = 0x00;
pub const CIRCULATE_LOWER_HIGHEST: Circulate = 0x01;

pub type PropMode = u32;
/// Discard the previous property value and store the new data.
pub const PROP_MODE_REPLACE: PropMode = 0x00;
/// Insert the new data before the beginning of existing data. The `format` must
/// match existing property value. If the property is undefined, it is treated as
/// defined with the correct type and format with zero-length data.
pub const PROP_MODE_PREPEND: PropMode = 0x01;
/// Insert the new data after the beginning of existing data. The `format` must
/// match existing property value. If the property is undefined, it is treated as
/// defined with the correct type and format with zero-length data.
pub const PROP_MODE_APPEND : PropMode = 0x02;

pub type GetPropertyType = u32;
pub const GET_PROPERTY_TYPE_ANY: GetPropertyType = 0x00;

pub type SendEventDest = u32;
pub const SEND_EVENT_DEST_POINTER_WINDOW: SendEventDest = 0x00;
pub const SEND_EVENT_DEST_ITEM_FOCUS    : SendEventDest = 0x01;

pub type GrabMode = u32;
/// The state of the keyboard appears to freeze: No further keyboard events are
/// generated by the server until the grabbing client issues a releasing
/// `AllowEvents` request or until the keyboard grab is released.
pub const GRAB_MODE_SYNC : GrabMode = 0x00;
/// Keyboard event processing continues normally.
pub const GRAB_MODE_ASYNC: GrabMode = 0x01;

pub type GrabStatus = u32;
pub const GRAB_STATUS_SUCCESS        : GrabStatus = 0x00;
pub const GRAB_STATUS_ALREADY_GRABBED: GrabStatus = 0x01;
pub const GRAB_STATUS_INVALID_TIME   : GrabStatus = 0x02;
pub const GRAB_STATUS_NOT_VIEWABLE   : GrabStatus = 0x03;
pub const GRAB_STATUS_FROZEN         : GrabStatus = 0x04;

pub type CursorEnum = u32;
pub const CURSOR_NONE: CursorEnum = 0x00;

pub type ButtonIndex = u32;
/// Any of the following (or none):
pub const BUTTON_INDEX_ANY: ButtonIndex = 0x00;
/// The left mouse button.
pub const BUTTON_INDEX_1  : ButtonIndex = 0x01;
/// The right mouse button.
pub const BUTTON_INDEX_2  : ButtonIndex = 0x02;
/// The middle mouse button.
pub const BUTTON_INDEX_3  : ButtonIndex = 0x03;
/// Scroll wheel. TODO: direction?
pub const BUTTON_INDEX_4  : ButtonIndex = 0x04;
/// Scroll wheel. TODO: direction?
pub const BUTTON_INDEX_5  : ButtonIndex = 0x05;

pub type Grab = u32;
pub const GRAB_ANY: Grab = 0x00;

pub type Allow = u32;
/// For AsyncPointer, if the pointer is frozen by the client, pointer event
/// processing continues normally. If the pointer is frozen twice by the client on
/// behalf of two separate grabs, AsyncPointer thaws for both. AsyncPointer has no
/// effect if the pointer is not frozen by the client, but the pointer need not be
/// grabbed by the client.
///
/// TODO: rewrite this in more understandable terms.
pub const ALLOW_ASYNC_POINTER  : Allow = 0x00;
/// For SyncPointer, if the pointer is frozen and actively grabbed by the client,
/// pointer event processing continues normally until the next ButtonPress or
/// ButtonRelease event is reported to the client, at which time the pointer again
/// appears to freeze. However, if the reported event causes the pointer grab to be
/// released, then the pointer does not freeze. SyncPointer has no effect if the
/// pointer is not frozen by the client or if the pointer is not grabbed by the
/// client.
pub const ALLOW_SYNC_POINTER   : Allow = 0x01;
/// For ReplayPointer, if the pointer is actively grabbed by the client and is
/// frozen as the result of an event having been sent to the client (either from
/// the activation of a GrabButton or from a previous AllowEvents with mode
/// SyncPointer but not from a GrabPointer), then the pointer grab is released and
/// that event is completely reprocessed, this time ignoring any passive grabs at
/// or above (towards the root) the grab-window of the grab just released. The
/// request has no effect if the pointer is not grabbed by the client or if the
/// pointer is not frozen as the result of an event.
pub const ALLOW_REPLAY_POINTER : Allow = 0x02;
/// For AsyncKeyboard, if the keyboard is frozen by the client, keyboard event
/// processing continues normally. If the keyboard is frozen twice by the client on
/// behalf of two separate grabs, AsyncKeyboard thaws for both. AsyncKeyboard has
/// no effect if the keyboard is not frozen by the client, but the keyboard need
/// not be grabbed by the client.
pub const ALLOW_ASYNC_KEYBOARD : Allow = 0x03;
/// For SyncKeyboard, if the keyboard is frozen and actively grabbed by the client,
/// keyboard event processing continues normally until the next KeyPress or
/// KeyRelease event is reported to the client, at which time the keyboard again
/// appears to freeze. However, if the reported event causes the keyboard grab to
/// be released, then the keyboard does not freeze. SyncKeyboard has no effect if
/// the keyboard is not frozen by the client or if the keyboard is not grabbed by
/// the client.
pub const ALLOW_SYNC_KEYBOARD  : Allow = 0x04;
/// For ReplayKeyboard, if the keyboard is actively grabbed by the client and is
/// frozen as the result of an event having been sent to the client (either from
/// the activation of a GrabKey or from a previous AllowEvents with mode
/// SyncKeyboard but not from a GrabKeyboard), then the keyboard grab is released
/// and that event is completely reprocessed, this time ignoring any passive grabs
/// at or above (towards the root) the grab-window of the grab just released. The
/// request has no effect if the keyboard is not grabbed by the client or if the
/// keyboard is not frozen as the result of an event.
pub const ALLOW_REPLAY_KEYBOARD: Allow = 0x05;
/// For AsyncBoth, if the pointer and the keyboard are frozen by the client, event
/// processing for both devices continues normally. If a device is frozen twice by
/// the client on behalf of two separate grabs, AsyncBoth thaws for both. AsyncBoth
/// has no effect unless both pointer and keyboard are frozen by the client.
pub const ALLOW_ASYNC_BOTH     : Allow = 0x06;
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
pub const ALLOW_SYNC_BOTH      : Allow = 0x07;

pub type InputFocus = u32;
/// The focus reverts to `XCB_NONE`, so no window will have the input focus.
pub const INPUT_FOCUS_NONE           : InputFocus = 0x00;
/// The focus reverts to `XCB_POINTER_ROOT` respectively. When the focus reverts,
/// FocusIn and FocusOut events are generated, but the last-focus-change time is
/// not changed.
pub const INPUT_FOCUS_POINTER_ROOT   : InputFocus = 0x01;
/// The focus reverts to the parent (or closest viewable ancestor) and the new
/// revert_to value is `XCB_INPUT_FOCUS_NONE`.
pub const INPUT_FOCUS_PARENT         : InputFocus = 0x02;
/// NOT YET DOCUMENTED. Only relevant for the xinput extension.
pub const INPUT_FOCUS_FOLLOW_KEYBOARD: InputFocus = 0x03;

pub type FontDraw = u32;
pub const FONT_DRAW_LEFT_TO_RIGHT: FontDraw = 0x00;
pub const FONT_DRAW_RIGHT_TO_LEFT: FontDraw = 0x01;

pub type Gc = u32;
/// TODO: Refer to GX
pub const GC_FUNCTION             : Gc =     0x01;
/// In graphics operations, given a source and destination pixel, the result is
/// computed bitwise on corresponding bits of the pixels; that is, a Boolean
/// operation is performed in each bit plane. The plane-mask restricts the
/// operation to a subset of planes, so the result is:
///
///         ((src FUNC dst) AND plane-mask) OR (dst AND (NOT plane-mask))
pub const GC_PLANE_MASK           : Gc =     0x02;
/// Foreground colorpixel.
pub const GC_FOREGROUND           : Gc =     0x04;
/// Background colorpixel.
pub const GC_BACKGROUND           : Gc =     0x08;
/// The line-width is measured in pixels and can be greater than or equal to one, a wide line, or the
/// special value zero, a thin line.
pub const GC_LINE_WIDTH           : Gc =     0x10;
/// The line-style defines which sections of a line are drawn:
/// Solid                The full path of the line is drawn.
/// DoubleDash           The full path of the line is drawn, but the even dashes are filled differently
///                      than the odd dashes (see fill-style), with Butt cap-style used where even and
///                      odd dashes meet.
/// OnOffDash            Only the even dashes are drawn, and cap-style applies to all internal ends of
///                      the individual dashes (except NotLast is treated as Butt).
pub const GC_LINE_STYLE           : Gc =     0x20;
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
pub const GC_CAP_STYLE            : Gc =     0x40;
/// The join-style defines how corners are drawn for wide lines:
/// Miter               The outer edges of the two lines extend to meet at an angle. However, if the
///                     angle is less than 11 degrees, a Bevel join-style is used instead.
/// Round               The result is a circular arc with a diameter equal to the line-width, centered
///                     on the joinpoint.
/// Bevel               The result is Butt endpoint styles, and then the triangular notch is filled.
pub const GC_JOIN_STYLE           : Gc =     0x80;
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
pub const GC_FILL_STYLE           : Gc =    0x100;
pub const GC_FILL_RULE            : Gc =    0x200;
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
pub const GC_TILE                 : Gc =    0x400;
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
pub const GC_STIPPLE              : Gc =    0x800;
/// TODO
pub const GC_TILE_STIPPLE_ORIGIN_X: Gc =   0x1000;
/// TODO
pub const GC_TILE_STIPPLE_ORIGIN_Y: Gc =   0x2000;
/// Which font to use for the `ImageText8` and `ImageText16` requests.
pub const GC_FONT                 : Gc =   0x4000;
/// For ClipByChildren, both source and destination windows are additionally
/// clipped by all viewable InputOutput children. For IncludeInferiors, neither
/// source nor destination window is
/// clipped by inferiors. This will result in including subwindow contents in the source and drawing
/// through subwindow boundaries of the destination. The use of IncludeInferiors with a source or
/// destination window of one depth with mapped inferiors of differing depth is not illegal, but the
/// semantics is undefined by the core protocol.
pub const GC_SUBWINDOW_MODE       : Gc =   0x8000;
/// Whether ExposureEvents should be generated (1) or not (0).
///
/// The default is 1.
pub const GC_GRAPHICS_EXPOSURES   : Gc =  0x10000;
/// TODO
pub const GC_CLIP_ORIGIN_X        : Gc =  0x20000;
/// TODO
pub const GC_CLIP_ORIGIN_Y        : Gc =  0x40000;
/// The clip-mask restricts writes to the destination drawable. Only pixels where the clip-mask has
/// bits set to 1 are drawn. Pixels are not drawn outside the area covered by the clip-mask or where
/// the clip-mask has bits set to 0. The clip-mask affects all graphics requests, but it does not clip
/// sources. The clip-mask origin is interpreted relative to the origin of whatever destination drawable is specified in a graphics request. If a pixmap is specified as the clip-mask, it must have
/// depth 1 and have the same root as the gcontext (or a Match error results). If clip-mask is None,
/// then pixels are always drawn, regardless of the clip origin. The clip-mask can also be set with the
/// SetClipRectangles request.
pub const GC_CLIP_MASK            : Gc =  0x80000;
/// TODO
pub const GC_DASH_OFFSET          : Gc = 0x100000;
/// TODO
pub const GC_DASH_LIST            : Gc = 0x200000;
/// TODO
pub const GC_ARC_MODE             : Gc = 0x400000;

pub type Gx = u32;
pub const GX_CLEAR        : Gx = 0x00;
pub const GX_AND          : Gx = 0x01;
pub const GX_AND_REVERSE  : Gx = 0x02;
pub const GX_COPY         : Gx = 0x03;
pub const GX_AND_INVERTED : Gx = 0x04;
pub const GX_NOOP         : Gx = 0x05;
pub const GX_XOR          : Gx = 0x06;
pub const GX_OR           : Gx = 0x07;
pub const GX_NOR          : Gx = 0x08;
pub const GX_EQUIV        : Gx = 0x09;
pub const GX_INVERT       : Gx = 0x0a;
pub const GX_OR_REVERSE   : Gx = 0x0b;
pub const GX_COPY_INVERTED: Gx = 0x0c;
pub const GX_OR_INVERTED  : Gx = 0x0d;
pub const GX_NAND         : Gx = 0x0e;
pub const GX_SET          : Gx = 0x0f;

pub type LineStyle = u32;
pub const LINE_STYLE_SOLID      : LineStyle = 0x00;
pub const LINE_STYLE_ON_OFF_DASH: LineStyle = 0x01;
pub const LINE_STYLE_DOUBLE_DASH: LineStyle = 0x02;

pub type CapStyle = u32;
pub const CAP_STYLE_NOT_LAST  : CapStyle = 0x00;
pub const CAP_STYLE_BUTT      : CapStyle = 0x01;
pub const CAP_STYLE_ROUND     : CapStyle = 0x02;
pub const CAP_STYLE_PROJECTING: CapStyle = 0x03;

pub type JoinStyle = u32;
pub const JOIN_STYLE_MITER: JoinStyle = 0x00;
pub const JOIN_STYLE_ROUND: JoinStyle = 0x01;
pub const JOIN_STYLE_BEVEL: JoinStyle = 0x02;

pub type FillStyle = u32;
pub const FILL_STYLE_SOLID          : FillStyle = 0x00;
pub const FILL_STYLE_TILED          : FillStyle = 0x01;
pub const FILL_STYLE_STIPPLED       : FillStyle = 0x02;
pub const FILL_STYLE_OPAQUE_STIPPLED: FillStyle = 0x03;

pub type FillRule = u32;
pub const FILL_RULE_EVEN_ODD: FillRule = 0x00;
pub const FILL_RULE_WINDING : FillRule = 0x01;

pub type SubwindowMode = u32;
pub const SUBWINDOW_MODE_CLIP_BY_CHILDREN : SubwindowMode = 0x00;
pub const SUBWINDOW_MODE_INCLUDE_INFERIORS: SubwindowMode = 0x01;

pub type ArcMode = u32;
pub const ARC_MODE_CHORD    : ArcMode = 0x00;
pub const ARC_MODE_PIE_SLICE: ArcMode = 0x01;

pub type ClipOrdering = u32;
pub const CLIP_ORDERING_UNSORTED : ClipOrdering = 0x00;
pub const CLIP_ORDERING_Y_SORTED : ClipOrdering = 0x01;
pub const CLIP_ORDERING_YX_SORTED: ClipOrdering = 0x02;
pub const CLIP_ORDERING_YX_BANDED: ClipOrdering = 0x03;

pub type CoordMode = u32;
/// Treats all coordinates as relative to the origin.
pub const COORD_MODE_ORIGIN  : CoordMode = 0x00;
/// Treats all coordinates after the first as relative to the previous coordinate.
pub const COORD_MODE_PREVIOUS: CoordMode = 0x01;

pub type PolyShape = u32;
pub const POLY_SHAPE_COMPLEX  : PolyShape = 0x00;
pub const POLY_SHAPE_NONCONVEX: PolyShape = 0x01;
pub const POLY_SHAPE_CONVEX   : PolyShape = 0x02;

pub type ImageFormat = u32;
pub const IMAGE_FORMAT_XY_BITMAP: ImageFormat = 0x00;
pub const IMAGE_FORMAT_XY_PIXMAP: ImageFormat = 0x01;
pub const IMAGE_FORMAT_Z_PIXMAP : ImageFormat = 0x02;

pub type ColormapAlloc = u32;
pub const COLORMAP_ALLOC_NONE: ColormapAlloc = 0x00;
pub const COLORMAP_ALLOC_ALL : ColormapAlloc = 0x01;

pub type ColorFlag = u32;
pub const COLOR_FLAG_RED  : ColorFlag = 0x01;
pub const COLOR_FLAG_GREEN: ColorFlag = 0x02;
pub const COLOR_FLAG_BLUE : ColorFlag = 0x04;

pub type PixmapEnum = u32;
pub const PIXMAP_NONE: PixmapEnum = 0x00;

pub type FontEnum = u32;
pub const FONT_NONE: FontEnum = 0x00;

pub type QueryShapeOf = u32;
pub const QUERY_SHAPE_OF_LARGEST_CURSOR : QueryShapeOf = 0x00;
pub const QUERY_SHAPE_OF_FASTEST_TILE   : QueryShapeOf = 0x01;
pub const QUERY_SHAPE_OF_FASTEST_STIPPLE: QueryShapeOf = 0x02;

pub type Kb = u32;
pub const KB_KEY_CLICK_PERCENT: Kb = 0x01;
pub const KB_BELL_PERCENT     : Kb = 0x02;
pub const KB_BELL_PITCH       : Kb = 0x04;
pub const KB_BELL_DURATION    : Kb = 0x08;
pub const KB_LED              : Kb = 0x10;
pub const KB_LED_MODE         : Kb = 0x20;
pub const KB_KEY              : Kb = 0x40;
pub const KB_AUTO_REPEAT_MODE : Kb = 0x80;

pub type LedMode = u32;
pub const LED_MODE_OFF: LedMode = 0x00;
pub const LED_MODE_ON : LedMode = 0x01;

pub type AutoRepeatMode = u32;
pub const AUTO_REPEAT_MODE_OFF    : AutoRepeatMode = 0x00;
pub const AUTO_REPEAT_MODE_ON     : AutoRepeatMode = 0x01;
pub const AUTO_REPEAT_MODE_DEFAULT: AutoRepeatMode = 0x02;

pub type Blanking = u32;
pub const BLANKING_NOT_PREFERRED: Blanking = 0x00;
pub const BLANKING_PREFERRED    : Blanking = 0x01;
pub const BLANKING_DEFAULT      : Blanking = 0x02;

pub type Exposures = u32;
pub const EXPOSURES_NOT_ALLOWED: Exposures = 0x00;
pub const EXPOSURES_ALLOWED    : Exposures = 0x01;
pub const EXPOSURES_DEFAULT    : Exposures = 0x02;

pub type HostMode = u32;
pub const HOST_MODE_INSERT: HostMode = 0x00;
pub const HOST_MODE_DELETE: HostMode = 0x01;

pub type Family = u32;
pub const FAMILY_INTERNET          : Family = 0x00;
pub const FAMILY_DE_CNET           : Family = 0x01;
pub const FAMILY_CHAOS             : Family = 0x02;
pub const FAMILY_SERVER_INTERPRETED: Family = 0x05;
pub const FAMILY_INTERNET_6        : Family = 0x06;

pub type AccessControl = u32;
pub const ACCESS_CONTROL_DISABLE: AccessControl = 0x00;
pub const ACCESS_CONTROL_ENABLE : AccessControl = 0x01;

pub type CloseDown = u32;
pub const CLOSE_DOWN_DESTROY_ALL     : CloseDown = 0x00;
pub const CLOSE_DOWN_RETAIN_PERMANENT: CloseDown = 0x01;
pub const CLOSE_DOWN_RETAIN_TEMPORARY: CloseDown = 0x02;

pub type Kill = u32;
pub const KILL_ALL_TEMPORARY: Kill = 0x00;

pub type ScreenSaver = u32;
pub const SCREEN_SAVER_RESET : ScreenSaver = 0x00;
pub const SCREEN_SAVER_ACTIVE: ScreenSaver = 0x01;

pub type MappingStatus = u32;
pub const MAPPING_STATUS_SUCCESS: MappingStatus = 0x00;
pub const MAPPING_STATUS_BUSY   : MappingStatus = 0x01;
pub const MAPPING_STATUS_FAILURE: MappingStatus = 0x02;

pub type MapIndex = u32;
pub const MAP_INDEX_SHIFT  : MapIndex = 0x00;
pub const MAP_INDEX_LOCK   : MapIndex = 0x01;
pub const MAP_INDEX_CONTROL: MapIndex = 0x02;
pub const MAP_INDEX_1      : MapIndex = 0x03;
pub const MAP_INDEX_2      : MapIndex = 0x04;
pub const MAP_INDEX_3      : MapIndex = 0x05;
pub const MAP_INDEX_4      : MapIndex = 0x06;
pub const MAP_INDEX_5      : MapIndex = 0x07;



#[derive(Copy, Clone)]
pub struct Char2b {
    pub base: xcb_char2b_t,
}

impl Char2b {
    #[allow(unused_unsafe)]
    pub fn new(byte1: u8,
               byte2: u8)
            -> Char2b {
        unsafe {
            Char2b {
                base: xcb_char2b_t {
                    byte1: byte1,
                    byte2: byte2,
                }
            }
        }
    }
    pub fn byte1(&self) -> u8 {
        unsafe {
            self.base.byte1
        }
    }
    pub fn byte2(&self) -> u8 {
        unsafe {
            self.base.byte2
        }
    }
}

pub type Char2bIterator = xcb_char2b_iterator_t;

impl Iterator for Char2bIterator {
    type Item = Char2b;
    fn next(&mut self) -> std::option::Option<Char2b> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_char2b_iterator_t;
                let data = (*iter).data;
                xcb_char2b_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Point {
    pub base: xcb_point_t,
}

impl Point {
    #[allow(unused_unsafe)]
    pub fn new(x: i16,
               y: i16)
            -> Point {
        unsafe {
            Point {
                base: xcb_point_t {
                    x: x,
                    y: y,
                }
            }
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
}

pub type PointIterator = xcb_point_iterator_t;

impl Iterator for PointIterator {
    type Item = Point;
    fn next(&mut self) -> std::option::Option<Point> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_point_iterator_t;
                let data = (*iter).data;
                xcb_point_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Rectangle {
    pub base: xcb_rectangle_t,
}

impl Rectangle {
    #[allow(unused_unsafe)]
    pub fn new(x:      i16,
               y:      i16,
               width:  u16,
               height: u16)
            -> Rectangle {
        unsafe {
            Rectangle {
                base: xcb_rectangle_t {
                    x:      x,
                    y:      y,
                    width:  width,
                    height: height,
                }
            }
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

pub type RectangleIterator = xcb_rectangle_iterator_t;

impl Iterator for RectangleIterator {
    type Item = Rectangle;
    fn next(&mut self) -> std::option::Option<Rectangle> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_rectangle_iterator_t;
                let data = (*iter).data;
                xcb_rectangle_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Arc {
    pub base: xcb_arc_t,
}

impl Arc {
    #[allow(unused_unsafe)]
    pub fn new(x:      i16,
               y:      i16,
               width:  u16,
               height: u16,
               angle1: i16,
               angle2: i16)
            -> Arc {
        unsafe {
            Arc {
                base: xcb_arc_t {
                    x:      x,
                    y:      y,
                    width:  width,
                    height: height,
                    angle1: angle1,
                    angle2: angle2,
                }
            }
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
    pub fn angle1(&self) -> i16 {
        unsafe {
            self.base.angle1
        }
    }
    pub fn angle2(&self) -> i16 {
        unsafe {
            self.base.angle2
        }
    }
}

pub type ArcIterator = xcb_arc_iterator_t;

impl Iterator for ArcIterator {
    type Item = Arc;
    fn next(&mut self) -> std::option::Option<Arc> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_arc_iterator_t;
                let data = (*iter).data;
                xcb_arc_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Format {
    pub base: xcb_format_t,
}

impl Format {
    #[allow(unused_unsafe)]
    pub fn new(depth:          u8,
               bits_per_pixel: u8,
               scanline_pad:   u8)
            -> Format {
        unsafe {
            Format {
                base: xcb_format_t {
                    depth:          depth,
                    bits_per_pixel: bits_per_pixel,
                    scanline_pad:   scanline_pad,
                    pad0:           [0; 5],
                }
            }
        }
    }
    pub fn depth(&self) -> u8 {
        unsafe {
            self.base.depth
        }
    }
    pub fn bits_per_pixel(&self) -> u8 {
        unsafe {
            self.base.bits_per_pixel
        }
    }
    pub fn scanline_pad(&self) -> u8 {
        unsafe {
            self.base.scanline_pad
        }
    }
}

pub type FormatIterator = xcb_format_iterator_t;

impl Iterator for FormatIterator {
    type Item = Format;
    fn next(&mut self) -> std::option::Option<Format> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_format_iterator_t;
                let data = (*iter).data;
                xcb_format_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Visualtype {
    pub base: xcb_visualtype_t,
}

impl Visualtype {
    #[allow(unused_unsafe)]
    pub fn new(visual_id:          Visualid,
               class:              u8,
               bits_per_rgb_value: u8,
               colormap_entries:   u16,
               red_mask:           u32,
               green_mask:         u32,
               blue_mask:          u32)
            -> Visualtype {
        unsafe {
            Visualtype {
                base: xcb_visualtype_t {
                    visual_id:          visual_id,
                    class:              class,
                    bits_per_rgb_value: bits_per_rgb_value,
                    colormap_entries:   colormap_entries,
                    red_mask:           red_mask,
                    green_mask:         green_mask,
                    blue_mask:          blue_mask,
                    pad0:               [0; 4],
                }
            }
        }
    }
    pub fn visual_id(&self) -> Visualid {
        unsafe {
            self.base.visual_id
        }
    }
    pub fn class(&self) -> u8 {
        unsafe {
            self.base.class
        }
    }
    pub fn bits_per_rgb_value(&self) -> u8 {
        unsafe {
            self.base.bits_per_rgb_value
        }
    }
    pub fn colormap_entries(&self) -> u16 {
        unsafe {
            self.base.colormap_entries
        }
    }
    pub fn red_mask(&self) -> u32 {
        unsafe {
            self.base.red_mask
        }
    }
    pub fn green_mask(&self) -> u32 {
        unsafe {
            self.base.green_mask
        }
    }
    pub fn blue_mask(&self) -> u32 {
        unsafe {
            self.base.blue_mask
        }
    }
}

pub type VisualtypeIterator = xcb_visualtype_iterator_t;

impl Iterator for VisualtypeIterator {
    type Item = Visualtype;
    fn next(&mut self) -> std::option::Option<Visualtype> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_visualtype_iterator_t;
                let data = (*iter).data;
                xcb_visualtype_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type Depth<'a> = base::StructPtr<'a, xcb_depth_t>;

impl<'a> Depth<'a> {
    pub fn depth(&self) -> u8 {
        unsafe {
            (*self.ptr).depth
        }
    }
    pub fn visuals_len(&self) -> u16 {
        unsafe {
            (*self.ptr).visuals_len
        }
    }
    pub fn visuals(&self) -> VisualtypeIterator {
        unsafe {
            xcb_depth_visuals_iterator(self.ptr)
        }
    }
}

pub type DepthIterator<'a> = xcb_depth_iterator_t<'a>;

impl<'a> Iterator for DepthIterator<'a> {
    type Item = Depth<'a>;
    fn next(&mut self) -> std::option::Option<Depth<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_depth_iterator_t;
                let data = (*iter).data;
                xcb_depth_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Screen<'a> = base::StructPtr<'a, xcb_screen_t>;

impl<'a> Screen<'a> {
    pub fn root(&self) -> Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn default_colormap(&self) -> Colormap {
        unsafe {
            (*self.ptr).default_colormap
        }
    }
    pub fn white_pixel(&self) -> u32 {
        unsafe {
            (*self.ptr).white_pixel
        }
    }
    pub fn black_pixel(&self) -> u32 {
        unsafe {
            (*self.ptr).black_pixel
        }
    }
    pub fn current_input_masks(&self) -> u32 {
        unsafe {
            (*self.ptr).current_input_masks
        }
    }
    pub fn width_in_pixels(&self) -> u16 {
        unsafe {
            (*self.ptr).width_in_pixels
        }
    }
    pub fn height_in_pixels(&self) -> u16 {
        unsafe {
            (*self.ptr).height_in_pixels
        }
    }
    pub fn width_in_millimeters(&self) -> u16 {
        unsafe {
            (*self.ptr).width_in_millimeters
        }
    }
    pub fn height_in_millimeters(&self) -> u16 {
        unsafe {
            (*self.ptr).height_in_millimeters
        }
    }
    pub fn min_installed_maps(&self) -> u16 {
        unsafe {
            (*self.ptr).min_installed_maps
        }
    }
    pub fn max_installed_maps(&self) -> u16 {
        unsafe {
            (*self.ptr).max_installed_maps
        }
    }
    pub fn root_visual(&self) -> Visualid {
        unsafe {
            (*self.ptr).root_visual
        }
    }
    pub fn backing_stores(&self) -> u8 {
        unsafe {
            (*self.ptr).backing_stores
        }
    }
    pub fn save_unders(&self) -> bool {
        unsafe {
            (*self.ptr).save_unders != 0
        }
    }
    pub fn root_depth(&self) -> u8 {
        unsafe {
            (*self.ptr).root_depth
        }
    }
    pub fn allowed_depths_len(&self) -> u8 {
        unsafe {
            (*self.ptr).allowed_depths_len
        }
    }
    pub fn allowed_depths(&self) -> DepthIterator<'a> {
        unsafe {
            xcb_screen_allowed_depths_iterator(self.ptr)
        }
    }
}

pub type ScreenIterator<'a> = xcb_screen_iterator_t<'a>;

impl<'a> Iterator for ScreenIterator<'a> {
    type Item = Screen<'a>;
    fn next(&mut self) -> std::option::Option<Screen<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_screen_iterator_t;
                let data = (*iter).data;
                xcb_screen_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type SetupRequest<'a> = base::StructPtr<'a, xcb_setup_request_t>;

impl<'a> SetupRequest<'a> {
    pub fn byte_order(&self) -> u8 {
        unsafe {
            (*self.ptr).byte_order
        }
    }
    pub fn protocol_major_version(&self) -> u16 {
        unsafe {
            (*self.ptr).protocol_major_version
        }
    }
    pub fn protocol_minor_version(&self) -> u16 {
        unsafe {
            (*self.ptr).protocol_minor_version
        }
    }
    pub fn authorization_protocol_name_len(&self) -> u16 {
        unsafe {
            (*self.ptr).authorization_protocol_name_len
        }
    }
    pub fn authorization_protocol_data_len(&self) -> u16 {
        unsafe {
            (*self.ptr).authorization_protocol_data_len
        }
    }
    pub fn authorization_protocol_name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_setup_request_authorization_protocol_name_length(field) as usize;
            let data = xcb_setup_request_authorization_protocol_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn authorization_protocol_data(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_setup_request_authorization_protocol_data_length(field) as usize;
            let data = xcb_setup_request_authorization_protocol_data(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type SetupRequestIterator<'a> = xcb_setup_request_iterator_t<'a>;

impl<'a> Iterator for SetupRequestIterator<'a> {
    type Item = SetupRequest<'a>;
    fn next(&mut self) -> std::option::Option<SetupRequest<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_setup_request_iterator_t;
                let data = (*iter).data;
                xcb_setup_request_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type SetupFailed<'a> = base::StructPtr<'a, xcb_setup_failed_t>;

impl<'a> SetupFailed<'a> {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn reason_len(&self) -> u8 {
        unsafe {
            (*self.ptr).reason_len
        }
    }
    pub fn protocol_major_version(&self) -> u16 {
        unsafe {
            (*self.ptr).protocol_major_version
        }
    }
    pub fn protocol_minor_version(&self) -> u16 {
        unsafe {
            (*self.ptr).protocol_minor_version
        }
    }
    pub fn length(&self) -> u16 {
        unsafe {
            (*self.ptr).length
        }
    }
    pub fn reason(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_setup_failed_reason_length(field) as usize;
            let data = xcb_setup_failed_reason(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type SetupFailedIterator<'a> = xcb_setup_failed_iterator_t<'a>;

impl<'a> Iterator for SetupFailedIterator<'a> {
    type Item = SetupFailed<'a>;
    fn next(&mut self) -> std::option::Option<SetupFailed<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_setup_failed_iterator_t;
                let data = (*iter).data;
                xcb_setup_failed_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type SetupAuthenticate<'a> = base::StructPtr<'a, xcb_setup_authenticate_t>;

impl<'a> SetupAuthenticate<'a> {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn length(&self) -> u16 {
        unsafe {
            (*self.ptr).length
        }
    }
    pub fn reason(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_setup_authenticate_reason_length(field) as usize;
            let data = xcb_setup_authenticate_reason(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type SetupAuthenticateIterator<'a> = xcb_setup_authenticate_iterator_t<'a>;

impl<'a> Iterator for SetupAuthenticateIterator<'a> {
    type Item = SetupAuthenticate<'a>;
    fn next(&mut self) -> std::option::Option<SetupAuthenticate<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_setup_authenticate_iterator_t;
                let data = (*iter).data;
                xcb_setup_authenticate_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Setup<'a> = base::StructPtr<'a, xcb_setup_t>;

impl<'a> Setup<'a> {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
    pub fn protocol_major_version(&self) -> u16 {
        unsafe {
            (*self.ptr).protocol_major_version
        }
    }
    pub fn protocol_minor_version(&self) -> u16 {
        unsafe {
            (*self.ptr).protocol_minor_version
        }
    }
    pub fn length(&self) -> u16 {
        unsafe {
            (*self.ptr).length
        }
    }
    pub fn release_number(&self) -> u32 {
        unsafe {
            (*self.ptr).release_number
        }
    }
    pub fn resource_id_base(&self) -> u32 {
        unsafe {
            (*self.ptr).resource_id_base
        }
    }
    pub fn resource_id_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).resource_id_mask
        }
    }
    pub fn motion_buffer_size(&self) -> u32 {
        unsafe {
            (*self.ptr).motion_buffer_size
        }
    }
    pub fn vendor_len(&self) -> u16 {
        unsafe {
            (*self.ptr).vendor_len
        }
    }
    pub fn maximum_request_length(&self) -> u16 {
        unsafe {
            (*self.ptr).maximum_request_length
        }
    }
    pub fn roots_len(&self) -> u8 {
        unsafe {
            (*self.ptr).roots_len
        }
    }
    pub fn pixmap_formats_len(&self) -> u8 {
        unsafe {
            (*self.ptr).pixmap_formats_len
        }
    }
    pub fn image_byte_order(&self) -> u8 {
        unsafe {
            (*self.ptr).image_byte_order
        }
    }
    pub fn bitmap_format_bit_order(&self) -> u8 {
        unsafe {
            (*self.ptr).bitmap_format_bit_order
        }
    }
    pub fn bitmap_format_scanline_unit(&self) -> u8 {
        unsafe {
            (*self.ptr).bitmap_format_scanline_unit
        }
    }
    pub fn bitmap_format_scanline_pad(&self) -> u8 {
        unsafe {
            (*self.ptr).bitmap_format_scanline_pad
        }
    }
    pub fn min_keycode(&self) -> Keycode {
        unsafe {
            (*self.ptr).min_keycode
        }
    }
    pub fn max_keycode(&self) -> Keycode {
        unsafe {
            (*self.ptr).max_keycode
        }
    }
    pub fn vendor(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_setup_vendor_length(field) as usize;
            let data = xcb_setup_vendor(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn pixmap_formats(&self) -> FormatIterator {
        unsafe {
            xcb_setup_pixmap_formats_iterator(self.ptr)
        }
    }
    pub fn roots(&self) -> ScreenIterator<'a> {
        unsafe {
            xcb_setup_roots_iterator(self.ptr)
        }
    }
}

pub type SetupIterator<'a> = xcb_setup_iterator_t<'a>;

impl<'a> Iterator for SetupIterator<'a> {
    type Item = Setup<'a>;
    fn next(&mut self) -> std::option::Option<Setup<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_setup_iterator_t;
                let data = (*iter).data;
                xcb_setup_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const KEY_PRESS: u8 = 2;

/// a key was pressed/released
pub type KeyPressEvent = base::Event<xcb_key_press_event_t>;

impl KeyPressEvent {
    /// The keycode (a number representing a physical key on the keyboard) of the key
    /// which was pressed.
    pub fn detail(&self) -> Keycode {
        unsafe {
            (*self.ptr).detail
        }
    }
    /// Time when the event was generated (in milliseconds).
    pub fn time(&self) -> Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    /// The root window of `child`.
    pub fn root(&self) -> Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> Window {
        unsafe {
            (*self.ptr).child
        }
    }
    /// The X coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub fn root_x(&self) -> i16 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    /// The Y coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub fn root_y(&self) -> i16 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    /// If `same_screen` is true, this is the X coordinate relative to the `event`
    /// window's origin. Otherwise, `event_x` will be set to zero.
    pub fn event_x(&self) -> i16 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    /// If `same_screen` is true, this is the Y coordinate relative to the `event`
    /// window's origin. Otherwise, `event_y` will be set to zero.
    pub fn event_y(&self) -> i16 {
        unsafe {
            (*self.ptr).event_y
        }
    }
    /// The logical state of the pointer buttons and modifier keys just prior to the
    /// event.
    pub fn state(&self) -> u16 {
        unsafe {
            (*self.ptr).state
        }
    }
    /// Whether the `event` window is on the same screen as the `root` window.
    pub fn same_screen(&self) -> bool {
        unsafe {
            (*self.ptr).same_screen != 0
        }
    }
    /// Constructs a new KeyPressEvent
    /// `response_type` must be set to one of:
    ///     - `KEY_PRESS`
    ///     - `KEY_RELEASE`
    pub fn new(response_type: u8,
               detail: Keycode,
               time: Timestamp,
               root: Window,
               event: Window,
               child: Window,
               root_x: i16,
               root_y: i16,
               event_x: i16,
               event_y: i16,
               state: u16,
               same_screen: bool)
            -> KeyPressEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_key_press_event_t;
            assert!(response_type == KEY_PRESS ||
                    response_type == KEY_RELEASE,
                    "wrong response_type supplied to KeyPressEvent::new");
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
            KeyPressEvent {
                ptr: raw
            }
        }
    }
}

pub const KEY_RELEASE: u8 = 3;

/// a key was pressed/released
pub type KeyReleaseEvent = base::Event<xcb_key_release_event_t>;

pub const BUTTON_PRESS: u8 = 4;

/// a mouse button was pressed/released
pub type ButtonPressEvent = base::Event<xcb_button_press_event_t>;

impl ButtonPressEvent {
    /// The keycode (a number representing a physical key on the keyboard) of the key
    /// which was pressed.
    pub fn detail(&self) -> Button {
        unsafe {
            (*self.ptr).detail
        }
    }
    /// Time when the event was generated (in milliseconds).
    pub fn time(&self) -> Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    /// The root window of `child`.
    pub fn root(&self) -> Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> Window {
        unsafe {
            (*self.ptr).child
        }
    }
    /// The X coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub fn root_x(&self) -> i16 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    /// The Y coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub fn root_y(&self) -> i16 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    /// If `same_screen` is true, this is the X coordinate relative to the `event`
    /// window's origin. Otherwise, `event_x` will be set to zero.
    pub fn event_x(&self) -> i16 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    /// If `same_screen` is true, this is the Y coordinate relative to the `event`
    /// window's origin. Otherwise, `event_y` will be set to zero.
    pub fn event_y(&self) -> i16 {
        unsafe {
            (*self.ptr).event_y
        }
    }
    /// The logical state of the pointer buttons and modifier keys just prior to the
    /// event.
    pub fn state(&self) -> u16 {
        unsafe {
            (*self.ptr).state
        }
    }
    /// Whether the `event` window is on the same screen as the `root` window.
    pub fn same_screen(&self) -> bool {
        unsafe {
            (*self.ptr).same_screen != 0
        }
    }
    /// Constructs a new ButtonPressEvent
    /// `response_type` must be set to one of:
    ///     - `BUTTON_PRESS`
    ///     - `BUTTON_RELEASE`
    pub fn new(response_type: u8,
               detail: Button,
               time: Timestamp,
               root: Window,
               event: Window,
               child: Window,
               root_x: i16,
               root_y: i16,
               event_x: i16,
               event_y: i16,
               state: u16,
               same_screen: bool)
            -> ButtonPressEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_button_press_event_t;
            assert!(response_type == BUTTON_PRESS ||
                    response_type == BUTTON_RELEASE,
                    "wrong response_type supplied to ButtonPressEvent::new");
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
            ButtonPressEvent {
                ptr: raw
            }
        }
    }
}

pub const BUTTON_RELEASE: u8 = 5;

/// a mouse button was pressed/released
pub type ButtonReleaseEvent = base::Event<xcb_button_release_event_t>;

pub const MOTION_NOTIFY: u8 = 6;

/// a key was pressed
pub type MotionNotifyEvent = base::Event<xcb_motion_notify_event_t>;

impl MotionNotifyEvent {
    /// The keycode (a number representing a physical key on the keyboard) of the key
    /// which was pressed.
    pub fn detail(&self) -> u8 {
        unsafe {
            (*self.ptr).detail
        }
    }
    /// Time when the event was generated (in milliseconds).
    pub fn time(&self) -> Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    /// The root window of `child`.
    pub fn root(&self) -> Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn child(&self) -> Window {
        unsafe {
            (*self.ptr).child
        }
    }
    /// The X coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub fn root_x(&self) -> i16 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    /// The Y coordinate of the pointer relative to the `root` window at the time of
    /// the event.
    pub fn root_y(&self) -> i16 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    /// If `same_screen` is true, this is the X coordinate relative to the `event`
    /// window's origin. Otherwise, `event_x` will be set to zero.
    pub fn event_x(&self) -> i16 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    /// If `same_screen` is true, this is the Y coordinate relative to the `event`
    /// window's origin. Otherwise, `event_y` will be set to zero.
    pub fn event_y(&self) -> i16 {
        unsafe {
            (*self.ptr).event_y
        }
    }
    /// The logical state of the pointer buttons and modifier keys just prior to the
    /// event.
    pub fn state(&self) -> u16 {
        unsafe {
            (*self.ptr).state
        }
    }
    /// Whether the `event` window is on the same screen as the `root` window.
    pub fn same_screen(&self) -> bool {
        unsafe {
            (*self.ptr).same_screen != 0
        }
    }
    /// Constructs a new MotionNotifyEvent
    /// `response_type` will be set automatically to MOTION_NOTIFY
    pub fn new(detail: u8,
               time: Timestamp,
               root: Window,
               event: Window,
               child: Window,
               root_x: i16,
               root_y: i16,
               event_x: i16,
               event_y: i16,
               state: u16,
               same_screen: bool)
            -> MotionNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_motion_notify_event_t;
            (*raw).response_type = MOTION_NOTIFY;
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
            MotionNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const ENTER_NOTIFY: u8 = 7;

/// the pointer is in a different window
pub type EnterNotifyEvent = base::Event<xcb_enter_notify_event_t>;

impl EnterNotifyEvent {
    pub fn detail(&self) -> u8 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn time(&self) -> Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    /// The root window for the final cursor position.
    pub fn root(&self) -> Window {
        unsafe {
            (*self.ptr).root
        }
    }
    /// The window on which the event was generated.
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    /// If the `event` window has subwindows and the final pointer position is in one
    /// of them, then `child` is set to that subwindow, `XCB_WINDOW_NONE` otherwise.
    pub fn child(&self) -> Window {
        unsafe {
            (*self.ptr).child
        }
    }
    /// The pointer X coordinate relative to `root`'s origin at the time of the event.
    pub fn root_x(&self) -> i16 {
        unsafe {
            (*self.ptr).root_x
        }
    }
    /// The pointer Y coordinate relative to `root`'s origin at the time of the event.
    pub fn root_y(&self) -> i16 {
        unsafe {
            (*self.ptr).root_y
        }
    }
    /// If `event` is on the same screen as `root`, this is the pointer X coordinate
    /// relative to the event window's origin.
    pub fn event_x(&self) -> i16 {
        unsafe {
            (*self.ptr).event_x
        }
    }
    /// If `event` is on the same screen as `root`, this is the pointer Y coordinate
    /// relative to the event window's origin.
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
    ///
    pub fn mode(&self) -> u8 {
        unsafe {
            (*self.ptr).mode
        }
    }
    pub fn same_screen_focus(&self) -> u8 {
        unsafe {
            (*self.ptr).same_screen_focus
        }
    }
    /// Constructs a new EnterNotifyEvent
    /// `response_type` must be set to one of:
    ///     - `ENTER_NOTIFY`
    ///     - `LEAVE_NOTIFY`
    pub fn new(response_type: u8,
               detail: u8,
               time: Timestamp,
               root: Window,
               event: Window,
               child: Window,
               root_x: i16,
               root_y: i16,
               event_x: i16,
               event_y: i16,
               state: u16,
               mode: u8,
               same_screen_focus: u8)
            -> EnterNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_enter_notify_event_t;
            assert!(response_type == ENTER_NOTIFY ||
                    response_type == LEAVE_NOTIFY,
                    "wrong response_type supplied to EnterNotifyEvent::new");
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
            (*raw).mode = mode;
            (*raw).same_screen_focus = same_screen_focus;
            EnterNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const LEAVE_NOTIFY: u8 = 8;

/// the pointer is in a different window
pub type LeaveNotifyEvent = base::Event<xcb_leave_notify_event_t>;

pub const FOCUS_IN: u8 = 9;

/// NOT YET DOCUMENTED
pub type FocusInEvent = base::Event<xcb_focus_in_event_t>;

impl FocusInEvent {
    ///
    pub fn detail(&self) -> u8 {
        unsafe {
            (*self.ptr).detail
        }
    }
    /// The window on which the focus event was generated. This is the window used by
    /// the X server to report the event.
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    ///
    pub fn mode(&self) -> u8 {
        unsafe {
            (*self.ptr).mode
        }
    }
    /// Constructs a new FocusInEvent
    /// `response_type` must be set to one of:
    ///     - `FOCUS_IN`
    ///     - `FOCUS_OUT`
    pub fn new(response_type: u8,
               detail: u8,
               event: Window,
               mode: u8)
            -> FocusInEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_focus_in_event_t;
            assert!(response_type == FOCUS_IN ||
                    response_type == FOCUS_OUT,
                    "wrong response_type supplied to FocusInEvent::new");
            (*raw).response_type = response_type;
            (*raw).detail = detail;
            (*raw).event = event;
            (*raw).mode = mode;
            FocusInEvent {
                ptr: raw
            }
        }
    }
}

pub const FOCUS_OUT: u8 = 10;

/// NOT YET DOCUMENTED
pub type FocusOutEvent = base::Event<xcb_focus_out_event_t>;

pub const KEYMAP_NOTIFY: u8 = 11;

pub type KeymapNotifyEvent = base::Event<xcb_keymap_notify_event_t>;

impl KeymapNotifyEvent {
    pub fn keys(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).keys
        }
    }
    /// Constructs a new KeymapNotifyEvent
    /// `response_type` will be set automatically to KEYMAP_NOTIFY
    pub fn new(keys: [u8; 31])
            -> KeymapNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_keymap_notify_event_t;
            (*raw).response_type = KEYMAP_NOTIFY;
            (*raw).keys = keys;
            KeymapNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const EXPOSE: u8 = 12;

/// NOT YET DOCUMENTED
pub type ExposeEvent = base::Event<xcb_expose_event_t>;

impl ExposeEvent {
    /// The exposed (damaged) window.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// The X coordinate of the left-upper corner of the exposed rectangle, relative to
    /// the `window`'s origin.
    pub fn x(&self) -> u16 {
        unsafe {
            (*self.ptr).x
        }
    }
    /// The Y coordinate of the left-upper corner of the exposed rectangle, relative to
    /// the `window`'s origin.
    pub fn y(&self) -> u16 {
        unsafe {
            (*self.ptr).y
        }
    }
    /// The width of the exposed rectangle.
    pub fn width(&self) -> u16 {
        unsafe {
            (*self.ptr).width
        }
    }
    /// The height of the exposed rectangle.
    pub fn height(&self) -> u16 {
        unsafe {
            (*self.ptr).height
        }
    }
    /// The amount of `Expose` events following this one. Simple applications that do
    /// not want to optimize redisplay by distinguishing between subareas of its window
    /// can just ignore all Expose events with nonzero counts and perform full
    /// redisplays on events with zero counts.
    pub fn count(&self) -> u16 {
        unsafe {
            (*self.ptr).count
        }
    }
    /// Constructs a new ExposeEvent
    /// `response_type` will be set automatically to EXPOSE
    pub fn new(window: Window,
               x: u16,
               y: u16,
               width: u16,
               height: u16,
               count: u16)
            -> ExposeEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_expose_event_t;
            (*raw).response_type = EXPOSE;
            (*raw).window = window;
            (*raw).x = x;
            (*raw).y = y;
            (*raw).width = width;
            (*raw).height = height;
            (*raw).count = count;
            ExposeEvent {
                ptr: raw
            }
        }
    }
}

pub const GRAPHICS_EXPOSURE: u8 = 13;

pub type GraphicsExposureEvent = base::Event<xcb_graphics_exposure_event_t>;

impl GraphicsExposureEvent {
    pub fn drawable(&self) -> Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    pub fn x(&self) -> u16 {
        unsafe {
            (*self.ptr).x
        }
    }
    pub fn y(&self) -> u16 {
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
    pub fn minor_opcode(&self) -> u16 {
        unsafe {
            (*self.ptr).minor_opcode
        }
    }
    pub fn count(&self) -> u16 {
        unsafe {
            (*self.ptr).count
        }
    }
    pub fn major_opcode(&self) -> u8 {
        unsafe {
            (*self.ptr).major_opcode
        }
    }
    /// Constructs a new GraphicsExposureEvent
    /// `response_type` will be set automatically to GRAPHICS_EXPOSURE
    pub fn new(drawable: Drawable,
               x: u16,
               y: u16,
               width: u16,
               height: u16,
               minor_opcode: u16,
               count: u16,
               major_opcode: u8)
            -> GraphicsExposureEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_graphics_exposure_event_t;
            (*raw).response_type = GRAPHICS_EXPOSURE;
            (*raw).drawable = drawable;
            (*raw).x = x;
            (*raw).y = y;
            (*raw).width = width;
            (*raw).height = height;
            (*raw).minor_opcode = minor_opcode;
            (*raw).count = count;
            (*raw).major_opcode = major_opcode;
            GraphicsExposureEvent {
                ptr: raw
            }
        }
    }
}

pub const NO_EXPOSURE: u8 = 14;

pub type NoExposureEvent = base::Event<xcb_no_exposure_event_t>;

impl NoExposureEvent {
    pub fn drawable(&self) -> Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    pub fn minor_opcode(&self) -> u16 {
        unsafe {
            (*self.ptr).minor_opcode
        }
    }
    pub fn major_opcode(&self) -> u8 {
        unsafe {
            (*self.ptr).major_opcode
        }
    }
    /// Constructs a new NoExposureEvent
    /// `response_type` will be set automatically to NO_EXPOSURE
    pub fn new(drawable: Drawable,
               minor_opcode: u16,
               major_opcode: u8)
            -> NoExposureEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_no_exposure_event_t;
            (*raw).response_type = NO_EXPOSURE;
            (*raw).drawable = drawable;
            (*raw).minor_opcode = minor_opcode;
            (*raw).major_opcode = major_opcode;
            NoExposureEvent {
                ptr: raw
            }
        }
    }
}

pub const VISIBILITY_NOTIFY: u8 = 15;

pub type VisibilityNotifyEvent = base::Event<xcb_visibility_notify_event_t>;

impl VisibilityNotifyEvent {
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn state(&self) -> u8 {
        unsafe {
            (*self.ptr).state
        }
    }
    /// Constructs a new VisibilityNotifyEvent
    /// `response_type` will be set automatically to VISIBILITY_NOTIFY
    pub fn new(window: Window,
               state: u8)
            -> VisibilityNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_visibility_notify_event_t;
            (*raw).response_type = VISIBILITY_NOTIFY;
            (*raw).window = window;
            (*raw).state = state;
            VisibilityNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const CREATE_NOTIFY: u8 = 16;

pub type CreateNotifyEvent = base::Event<xcb_create_notify_event_t>;

impl CreateNotifyEvent {
    pub fn parent(&self) -> Window {
        unsafe {
            (*self.ptr).parent
        }
    }
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
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
    pub fn border_width(&self) -> u16 {
        unsafe {
            (*self.ptr).border_width
        }
    }
    pub fn override_redirect(&self) -> bool {
        unsafe {
            (*self.ptr).override_redirect != 0
        }
    }
    /// Constructs a new CreateNotifyEvent
    /// `response_type` will be set automatically to CREATE_NOTIFY
    pub fn new(parent: Window,
               window: Window,
               x: i16,
               y: i16,
               width: u16,
               height: u16,
               border_width: u16,
               override_redirect: bool)
            -> CreateNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_create_notify_event_t;
            (*raw).response_type = CREATE_NOTIFY;
            (*raw).parent = parent;
            (*raw).window = window;
            (*raw).x = x;
            (*raw).y = y;
            (*raw).width = width;
            (*raw).height = height;
            (*raw).border_width = border_width;
            (*raw).override_redirect = if override_redirect { 1 } else { 0 };
            CreateNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const DESTROY_NOTIFY: u8 = 17;

/// a window is destroyed
pub type DestroyNotifyEvent = base::Event<xcb_destroy_notify_event_t>;

impl DestroyNotifyEvent {
    /// The reconfigured window or its parent, depending on whether `StructureNotify`
    /// or `SubstructureNotify` was selected.
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    /// The window that is destroyed.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// Constructs a new DestroyNotifyEvent
    /// `response_type` will be set automatically to DESTROY_NOTIFY
    pub fn new(event: Window,
               window: Window)
            -> DestroyNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_destroy_notify_event_t;
            (*raw).response_type = DESTROY_NOTIFY;
            (*raw).event = event;
            (*raw).window = window;
            DestroyNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const UNMAP_NOTIFY: u8 = 18;

/// a window is unmapped
pub type UnmapNotifyEvent = base::Event<xcb_unmap_notify_event_t>;

impl UnmapNotifyEvent {
    /// The reconfigured window or its parent, depending on whether `StructureNotify`
    /// or `SubstructureNotify` was selected.
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    /// The window that was unmapped.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// Set to 1 if the event was generated as a result of a resizing of the window's
    /// parent when `window` had a win_gravity of `UnmapGravity`.
    pub fn from_configure(&self) -> bool {
        unsafe {
            (*self.ptr).from_configure != 0
        }
    }
    /// Constructs a new UnmapNotifyEvent
    /// `response_type` will be set automatically to UNMAP_NOTIFY
    pub fn new(event: Window,
               window: Window,
               from_configure: bool)
            -> UnmapNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_unmap_notify_event_t;
            (*raw).response_type = UNMAP_NOTIFY;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).from_configure = if from_configure { 1 } else { 0 };
            UnmapNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const MAP_NOTIFY: u8 = 19;

/// a window was mapped
pub type MapNotifyEvent = base::Event<xcb_map_notify_event_t>;

impl MapNotifyEvent {
    /// The window which was mapped or its parent, depending on whether
    /// `StructureNotify` or `SubstructureNotify` was selected.
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    /// The window that was mapped.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// Window managers should ignore this window if `override_redirect` is 1.
    pub fn override_redirect(&self) -> bool {
        unsafe {
            (*self.ptr).override_redirect != 0
        }
    }
    /// Constructs a new MapNotifyEvent
    /// `response_type` will be set automatically to MAP_NOTIFY
    pub fn new(event: Window,
               window: Window,
               override_redirect: bool)
            -> MapNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_map_notify_event_t;
            (*raw).response_type = MAP_NOTIFY;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).override_redirect = if override_redirect { 1 } else { 0 };
            MapNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const MAP_REQUEST: u8 = 20;

/// window wants to be mapped
pub type MapRequestEvent = base::Event<xcb_map_request_event_t>;

impl MapRequestEvent {
    /// The parent of `window`.
    pub fn parent(&self) -> Window {
        unsafe {
            (*self.ptr).parent
        }
    }
    /// The window to be mapped.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// Constructs a new MapRequestEvent
    /// `response_type` will be set automatically to MAP_REQUEST
    pub fn new(parent: Window,
               window: Window)
            -> MapRequestEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_map_request_event_t;
            (*raw).response_type = MAP_REQUEST;
            (*raw).parent = parent;
            (*raw).window = window;
            MapRequestEvent {
                ptr: raw
            }
        }
    }
}

pub const REPARENT_NOTIFY: u8 = 21;

pub type ReparentNotifyEvent = base::Event<xcb_reparent_notify_event_t>;

impl ReparentNotifyEvent {
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn parent(&self) -> Window {
        unsafe {
            (*self.ptr).parent
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
    pub fn override_redirect(&self) -> bool {
        unsafe {
            (*self.ptr).override_redirect != 0
        }
    }
    /// Constructs a new ReparentNotifyEvent
    /// `response_type` will be set automatically to REPARENT_NOTIFY
    pub fn new(event: Window,
               window: Window,
               parent: Window,
               x: i16,
               y: i16,
               override_redirect: bool)
            -> ReparentNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_reparent_notify_event_t;
            (*raw).response_type = REPARENT_NOTIFY;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).parent = parent;
            (*raw).x = x;
            (*raw).y = y;
            (*raw).override_redirect = if override_redirect { 1 } else { 0 };
            ReparentNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const CONFIGURE_NOTIFY: u8 = 22;

/// NOT YET DOCUMENTED
pub type ConfigureNotifyEvent = base::Event<xcb_configure_notify_event_t>;

impl ConfigureNotifyEvent {
    /// The reconfigured window or its parent, depending on whether `StructureNotify`
    /// or `SubstructureNotify` was selected.
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    /// The window whose size, position, border, and/or stacking order was changed.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// If `XCB_NONE`, the `window` is on the bottom of the stack with respect to
    /// sibling windows. However, if set to a sibling window, the `window` is placed on
    /// top of this sibling window.
    pub fn above_sibling(&self) -> Window {
        unsafe {
            (*self.ptr).above_sibling
        }
    }
    /// The X coordinate of the upper-left outside corner of `window`, relative to the
    /// parent window's origin.
    pub fn x(&self) -> i16 {
        unsafe {
            (*self.ptr).x
        }
    }
    /// The Y coordinate of the upper-left outside corner of `window`, relative to the
    /// parent window's origin.
    pub fn y(&self) -> i16 {
        unsafe {
            (*self.ptr).y
        }
    }
    /// The inside width of `window`, not including the border.
    pub fn width(&self) -> u16 {
        unsafe {
            (*self.ptr).width
        }
    }
    /// The inside height of `window`, not including the border.
    pub fn height(&self) -> u16 {
        unsafe {
            (*self.ptr).height
        }
    }
    /// The border width of `window`.
    pub fn border_width(&self) -> u16 {
        unsafe {
            (*self.ptr).border_width
        }
    }
    /// Window managers should ignore this window if `override_redirect` is 1.
    pub fn override_redirect(&self) -> bool {
        unsafe {
            (*self.ptr).override_redirect != 0
        }
    }
    /// Constructs a new ConfigureNotifyEvent
    /// `response_type` will be set automatically to CONFIGURE_NOTIFY
    pub fn new(event: Window,
               window: Window,
               above_sibling: Window,
               x: i16,
               y: i16,
               width: u16,
               height: u16,
               border_width: u16,
               override_redirect: bool)
            -> ConfigureNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_configure_notify_event_t;
            (*raw).response_type = CONFIGURE_NOTIFY;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).above_sibling = above_sibling;
            (*raw).x = x;
            (*raw).y = y;
            (*raw).width = width;
            (*raw).height = height;
            (*raw).border_width = border_width;
            (*raw).override_redirect = if override_redirect { 1 } else { 0 };
            ConfigureNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const CONFIGURE_REQUEST: u8 = 23;

pub type ConfigureRequestEvent = base::Event<xcb_configure_request_event_t>;

impl ConfigureRequestEvent {
    pub fn stack_mode(&self) -> u8 {
        unsafe {
            (*self.ptr).stack_mode
        }
    }
    pub fn parent(&self) -> Window {
        unsafe {
            (*self.ptr).parent
        }
    }
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    pub fn sibling(&self) -> Window {
        unsafe {
            (*self.ptr).sibling
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
    pub fn border_width(&self) -> u16 {
        unsafe {
            (*self.ptr).border_width
        }
    }
    pub fn value_mask(&self) -> u16 {
        unsafe {
            (*self.ptr).value_mask
        }
    }
    /// Constructs a new ConfigureRequestEvent
    /// `response_type` will be set automatically to CONFIGURE_REQUEST
    pub fn new(stack_mode: u8,
               parent: Window,
               window: Window,
               sibling: Window,
               x: i16,
               y: i16,
               width: u16,
               height: u16,
               border_width: u16,
               value_mask: u16)
            -> ConfigureRequestEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_configure_request_event_t;
            (*raw).response_type = CONFIGURE_REQUEST;
            (*raw).stack_mode = stack_mode;
            (*raw).parent = parent;
            (*raw).window = window;
            (*raw).sibling = sibling;
            (*raw).x = x;
            (*raw).y = y;
            (*raw).width = width;
            (*raw).height = height;
            (*raw).border_width = border_width;
            (*raw).value_mask = value_mask;
            ConfigureRequestEvent {
                ptr: raw
            }
        }
    }
}

pub const GRAVITY_NOTIFY: u8 = 24;

pub type GravityNotifyEvent = base::Event<xcb_gravity_notify_event_t>;

impl GravityNotifyEvent {
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
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
    /// Constructs a new GravityNotifyEvent
    /// `response_type` will be set automatically to GRAVITY_NOTIFY
    pub fn new(event: Window,
               window: Window,
               x: i16,
               y: i16)
            -> GravityNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_gravity_notify_event_t;
            (*raw).response_type = GRAVITY_NOTIFY;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).x = x;
            (*raw).y = y;
            GravityNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const RESIZE_REQUEST: u8 = 25;

pub type ResizeRequestEvent = base::Event<xcb_resize_request_event_t>;

impl ResizeRequestEvent {
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
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
    /// Constructs a new ResizeRequestEvent
    /// `response_type` will be set automatically to RESIZE_REQUEST
    pub fn new(window: Window,
               width: u16,
               height: u16)
            -> ResizeRequestEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_resize_request_event_t;
            (*raw).response_type = RESIZE_REQUEST;
            (*raw).window = window;
            (*raw).width = width;
            (*raw).height = height;
            ResizeRequestEvent {
                ptr: raw
            }
        }
    }
}

pub const CIRCULATE_NOTIFY: u8 = 26;

/// NOT YET DOCUMENTED
pub type CirculateNotifyEvent = base::Event<xcb_circulate_notify_event_t>;

impl CirculateNotifyEvent {
    /// Either the restacked window or its parent, depending on whether
    /// `StructureNotify` or `SubstructureNotify` was selected.
    pub fn event(&self) -> Window {
        unsafe {
            (*self.ptr).event
        }
    }
    /// The restacked window.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    ///
    pub fn place(&self) -> u8 {
        unsafe {
            (*self.ptr).place
        }
    }
    /// Constructs a new CirculateNotifyEvent
    /// `response_type` must be set to one of:
    ///     - `CIRCULATE_NOTIFY`
    ///     - `CIRCULATE_REQUEST`
    pub fn new(response_type: u8,
               event: Window,
               window: Window,
               place: u8)
            -> CirculateNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_circulate_notify_event_t;
            assert!(response_type == CIRCULATE_NOTIFY ||
                    response_type == CIRCULATE_REQUEST,
                    "wrong response_type supplied to CirculateNotifyEvent::new");
            (*raw).response_type = response_type;
            (*raw).event = event;
            (*raw).window = window;
            (*raw).place = place;
            CirculateNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const CIRCULATE_REQUEST: u8 = 27;

/// NOT YET DOCUMENTED
pub type CirculateRequestEvent = base::Event<xcb_circulate_request_event_t>;

pub const PROPERTY_NOTIFY: u8 = 28;

/// a window property changed
pub type PropertyNotifyEvent = base::Event<xcb_property_notify_event_t>;

impl PropertyNotifyEvent {
    /// The window whose associated property was changed.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// The property's atom, to indicate which property was changed.
    pub fn atom(&self) -> Atom {
        unsafe {
            (*self.ptr).atom
        }
    }
    /// A timestamp of the server time when the property was changed.
    pub fn time(&self) -> Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    ///
    pub fn state(&self) -> u8 {
        unsafe {
            (*self.ptr).state
        }
    }
    /// Constructs a new PropertyNotifyEvent
    /// `response_type` will be set automatically to PROPERTY_NOTIFY
    pub fn new(window: Window,
               atom: Atom,
               time: Timestamp,
               state: u8)
            -> PropertyNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_property_notify_event_t;
            (*raw).response_type = PROPERTY_NOTIFY;
            (*raw).window = window;
            (*raw).atom = atom;
            (*raw).time = time;
            (*raw).state = state;
            PropertyNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const SELECTION_CLEAR: u8 = 29;

pub type SelectionClearEvent = base::Event<xcb_selection_clear_event_t>;

impl SelectionClearEvent {
    pub fn time(&self) -> Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn owner(&self) -> Window {
        unsafe {
            (*self.ptr).owner
        }
    }
    pub fn selection(&self) -> Atom {
        unsafe {
            (*self.ptr).selection
        }
    }
    /// Constructs a new SelectionClearEvent
    /// `response_type` will be set automatically to SELECTION_CLEAR
    pub fn new(time: Timestamp,
               owner: Window,
               selection: Atom)
            -> SelectionClearEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_selection_clear_event_t;
            (*raw).response_type = SELECTION_CLEAR;
            (*raw).time = time;
            (*raw).owner = owner;
            (*raw).selection = selection;
            SelectionClearEvent {
                ptr: raw
            }
        }
    }
}

pub const SELECTION_REQUEST: u8 = 30;

pub type SelectionRequestEvent = base::Event<xcb_selection_request_event_t>;

impl SelectionRequestEvent {
    pub fn time(&self) -> Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn owner(&self) -> Window {
        unsafe {
            (*self.ptr).owner
        }
    }
    pub fn requestor(&self) -> Window {
        unsafe {
            (*self.ptr).requestor
        }
    }
    pub fn selection(&self) -> Atom {
        unsafe {
            (*self.ptr).selection
        }
    }
    pub fn target(&self) -> Atom {
        unsafe {
            (*self.ptr).target
        }
    }
    pub fn property(&self) -> Atom {
        unsafe {
            (*self.ptr).property
        }
    }
    /// Constructs a new SelectionRequestEvent
    /// `response_type` will be set automatically to SELECTION_REQUEST
    pub fn new(time: Timestamp,
               owner: Window,
               requestor: Window,
               selection: Atom,
               target: Atom,
               property: Atom)
            -> SelectionRequestEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_selection_request_event_t;
            (*raw).response_type = SELECTION_REQUEST;
            (*raw).time = time;
            (*raw).owner = owner;
            (*raw).requestor = requestor;
            (*raw).selection = selection;
            (*raw).target = target;
            (*raw).property = property;
            SelectionRequestEvent {
                ptr: raw
            }
        }
    }
}

pub const SELECTION_NOTIFY: u8 = 31;

pub type SelectionNotifyEvent = base::Event<xcb_selection_notify_event_t>;

impl SelectionNotifyEvent {
    pub fn time(&self) -> Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn requestor(&self) -> Window {
        unsafe {
            (*self.ptr).requestor
        }
    }
    pub fn selection(&self) -> Atom {
        unsafe {
            (*self.ptr).selection
        }
    }
    pub fn target(&self) -> Atom {
        unsafe {
            (*self.ptr).target
        }
    }
    pub fn property(&self) -> Atom {
        unsafe {
            (*self.ptr).property
        }
    }
    /// Constructs a new SelectionNotifyEvent
    /// `response_type` will be set automatically to SELECTION_NOTIFY
    pub fn new(time: Timestamp,
               requestor: Window,
               selection: Atom,
               target: Atom,
               property: Atom)
            -> SelectionNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_selection_notify_event_t;
            (*raw).response_type = SELECTION_NOTIFY;
            (*raw).time = time;
            (*raw).requestor = requestor;
            (*raw).selection = selection;
            (*raw).target = target;
            (*raw).property = property;
            SelectionNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const COLORMAP_NOTIFY: u8 = 32;

/// the colormap for some window changed
pub type ColormapNotifyEvent = base::Event<xcb_colormap_notify_event_t>;

impl ColormapNotifyEvent {
    /// The window whose associated colormap is changed, installed or uninstalled.
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// The colormap which is changed, installed or uninstalled. This is `XCB_NONE`
    /// when the colormap is changed by a call to `FreeColormap`.
    pub fn colormap(&self) -> Colormap {
        unsafe {
            (*self.ptr).colormap
        }
    }
    pub fn new_(&self) -> bool {
        unsafe {
            (*self.ptr).new_ != 0
        }
    }
    ///
    pub fn state(&self) -> u8 {
        unsafe {
            (*self.ptr).state
        }
    }
    /// Constructs a new ColormapNotifyEvent
    /// `response_type` will be set automatically to COLORMAP_NOTIFY
    pub fn new(window: Window,
               colormap: Colormap,
               new_: bool,
               state: u8)
            -> ColormapNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_colormap_notify_event_t;
            (*raw).response_type = COLORMAP_NOTIFY;
            (*raw).window = window;
            (*raw).colormap = colormap;
            (*raw).new_ = if new_ { 1 } else { 0 };
            (*raw).state = state;
            ColormapNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub type ClientMessageData = xcb_client_message_data_t;

impl ClientMessageData {
    pub fn data8(&self) -> &[u8] {
        unsafe {
            let ptr = self.data.as_ptr() as *const u8;
            std::slice::from_raw_parts(ptr, 20)
        }
    }
    pub fn from_data8(data8: [u8; 20]) -> ClientMessageData {
        unsafe {
            ClientMessageData { data: std::mem::transmute(data8) }
        }
    }
    pub fn data16(&self) -> &[u16] {
        unsafe {
            let ptr = self.data.as_ptr() as *const u16;
            std::slice::from_raw_parts(ptr, 10)
        }
    }
    pub fn from_data16(data16: [u16; 10]) -> ClientMessageData {
        unsafe {
            ClientMessageData { data: std::mem::transmute(data16) }
        }
    }
    pub fn data32(&self) -> &[u32] {
        unsafe {
            let ptr = self.data.as_ptr() as *const u32;
            std::slice::from_raw_parts(ptr, 5)
        }
    }
    pub fn from_data32(data32: [u32; 5]) -> ClientMessageData {
        unsafe {
            ClientMessageData { data: std::mem::transmute(data32) }
        }
    }
}

pub type ClientMessageDataIterator = xcb_client_message_data_iterator_t;

impl Iterator for ClientMessageDataIterator {
    type Item = ClientMessageData;
    fn next(&mut self) -> std::option::Option<ClientMessageData> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_client_message_data_iterator_t;
                let data = (*iter).data;
                xcb_client_message_data_next(iter);
                Some(*data)
            }
        }
    }
}

pub const CLIENT_MESSAGE: u8 = 33;

/// NOT YET DOCUMENTED
///
/// This event represents a ClientMessage, sent by another X11 client. An example
/// is a client sending the `_NET_WM_STATE` ClientMessage to the root window
/// to indicate the fullscreen window state, effectively requesting that the window
/// manager puts it into fullscreen mode.
pub type ClientMessageEvent = base::Event<xcb_client_message_event_t>;

impl ClientMessageEvent {
    /// Specifies how to interpret `data`. Can be either 8, 16 or 32.
    pub fn format(&self) -> u8 {
        unsafe {
            (*self.ptr).format
        }
    }
    pub fn window(&self) -> Window {
        unsafe {
            (*self.ptr).window
        }
    }
    /// An atom which indicates how the data should be interpreted by the receiving
    /// client.
    pub fn type_(&self) -> Atom {
        unsafe {
            (*self.ptr).type_
        }
    }
    /// The data itself (20 bytes max).
    pub fn data<'a>(&'a self) -> &'a ClientMessageData {
        unsafe {
            &(*self.ptr).data
        }
    }
    /// Constructs a new ClientMessageEvent
    /// `response_type` will be set automatically to CLIENT_MESSAGE
    pub fn new(format: u8,
               window: Window,
               type_: Atom,
               data: ClientMessageData)
            -> ClientMessageEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_client_message_event_t;
            (*raw).response_type = CLIENT_MESSAGE;
            (*raw).format = format;
            (*raw).window = window;
            (*raw).type_ = type_;
            (*raw).data = data;
            ClientMessageEvent {
                ptr: raw
            }
        }
    }
}

pub const MAPPING_NOTIFY: u8 = 34;

/// keyboard mapping changed
pub type MappingNotifyEvent = base::Event<xcb_mapping_notify_event_t>;

impl MappingNotifyEvent {
    ///
    pub fn request(&self) -> u8 {
        unsafe {
            (*self.ptr).request
        }
    }
    /// The first number in the range of the altered mapping.
    pub fn first_keycode(&self) -> Keycode {
        unsafe {
            (*self.ptr).first_keycode
        }
    }
    /// The number of keycodes altered.
    pub fn count(&self) -> u8 {
        unsafe {
            (*self.ptr).count
        }
    }
    /// Constructs a new MappingNotifyEvent
    /// `response_type` will be set automatically to MAPPING_NOTIFY
    pub fn new(request: u8,
               first_keycode: Keycode,
               count: u8)
            -> MappingNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_mapping_notify_event_t;
            (*raw).response_type = MAPPING_NOTIFY;
            (*raw).request = request;
            (*raw).first_keycode = first_keycode;
            (*raw).count = count;
            MappingNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const GE_GENERIC: u8 = 35;

/// generic event (with length)
pub type GeGenericEvent = base::Event<xcb_ge_generic_event_t>;

impl GeGenericEvent {
    /// Constructs a new GeGenericEvent
    /// `response_type` will be set automatically to GE_GENERIC
    pub fn new()
            -> GeGenericEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_ge_generic_event_t;
            (*raw).response_type = GE_GENERIC;
            GeGenericEvent {
                ptr: raw
            }
        }
    }
}

pub const REQUEST: u8 = 1;

pub const VALUE: u8 = 2;

pub const WINDOW: u8 = 3;

pub const PIXMAP: u8 = 4;

pub const ATOM: u8 = 5;

pub const CURSOR: u8 = 6;

pub const FONT: u8 = 7;

pub const MATCH: u8 = 8;

pub const DRAWABLE: u8 = 9;

pub const ACCESS: u8 = 10;

pub const ALLOC: u8 = 11;

pub const COLORMAP: u8 = 12;

pub const G_CONTEXT: u8 = 13;

pub const ID_CHOICE: u8 = 14;

pub const NAME: u8 = 15;

pub const LENGTH: u8 = 16;

pub const IMPLEMENTATION: u8 = 17;

pub const CREATE_WINDOW: u8 = 1;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __depth__:
///       Specifies the new window's depth (TODO: what unit?).
///
///       The special value `XCB_COPY_FROM_PARENT` means the depth is taken from the
///       `parent` window.
///
///   - __wid__:
///       The ID with which you will refer to the new window, created by
///       `xcb_generate_id`.
///
///   - __parent__:
///       The parent window of the new window.
///
///   - __x__:
///       The X coordinate of the new window.
///
///   - __y__:
///       The Y coordinate of the new window.
///
///   - __width__:
///       The width of the new window.
///
///   - __height__:
///       The height of the new window.
///
///   - __border_width__:
///       TODO:
///
///       Must be zero if the `class` is `InputOnly` or a `xcb_match_error_t` occurs.
///
///   - __class__:
///
///
///   - __visual__:
///       Specifies the id for the new window's visual.
///
///       The special value `XCB_COPY_FROM_PARENT` means the visual is taken from the
///       `parent` window.
///
///   - __value_list__:
pub fn create_window<'a>(c           : &'a base::Connection,
                         depth       : u8,
                         wid         : Window,
                         parent      : Window,
                         x           : i16,
                         y           : i16,
                         width       : u16,
                         height      : u16,
                         border_width: u16,
                         class       : u16,
                         visual      : Visualid,
                         value_list  : &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_create_window(c.get_raw_conn(),
                                       depth as u8,  // 0
                                       wid as xcb_window_t,  // 1
                                       parent as xcb_window_t,  // 2
                                       x as i16,  // 3
                                       y as i16,  // 4
                                       width as u16,  // 5
                                       height as u16,  // 6
                                       border_width as u16,  // 7
                                       class as u16,  // 8
                                       visual as xcb_visualid_t,  // 9
                                       value_list_mask as u32,  // 10
                                       value_list_ptr as *const u32);  // 11
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __depth__:
///       Specifies the new window's depth (TODO: what unit?).
///
///       The special value `XCB_COPY_FROM_PARENT` means the depth is taken from the
///       `parent` window.
///
///   - __wid__:
///       The ID with which you will refer to the new window, created by
///       `xcb_generate_id`.
///
///   - __parent__:
///       The parent window of the new window.
///
///   - __x__:
///       The X coordinate of the new window.
///
///   - __y__:
///       The Y coordinate of the new window.
///
///   - __width__:
///       The width of the new window.
///
///   - __height__:
///       The height of the new window.
///
///   - __border_width__:
///       TODO:
///
///       Must be zero if the `class` is `InputOnly` or a `xcb_match_error_t` occurs.
///
///   - __class__:
///
///
///   - __visual__:
///       Specifies the id for the new window's visual.
///
///       The special value `XCB_COPY_FROM_PARENT` means the visual is taken from the
///       `parent` window.
///
///   - __value_list__:
pub fn create_window_checked<'a>(c           : &'a base::Connection,
                                 depth       : u8,
                                 wid         : Window,
                                 parent      : Window,
                                 x           : i16,
                                 y           : i16,
                                 width       : u16,
                                 height      : u16,
                                 border_width: u16,
                                 class       : u16,
                                 visual      : Visualid,
                                 value_list  : &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_create_window_checked(c.get_raw_conn(),
                                               depth as u8,  // 0
                                               wid as xcb_window_t,  // 1
                                               parent as xcb_window_t,  // 2
                                               x as i16,  // 3
                                               y as i16,  // 4
                                               width as u16,  // 5
                                               height as u16,  // 6
                                               border_width as u16,  // 7
                                               class as u16,  // 8
                                               visual as xcb_visualid_t,  // 9
                                               value_list_mask as u32,  // 10
                                               value_list_ptr as *const u32);  // 11
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_WINDOW_ATTRIBUTES: u8 = 2;

/// change window attributes
///
/// Changes the attributes specified by `value_mask` for the specified `window`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to change.
///
///   - __value_list__:
///       Values for each of the attributes specified in the bitmask `value_mask`. The
///       order has to correspond to the order of possible `value_mask` bits. See the
///       example.
pub fn change_window_attributes<'a>(c         : &'a base::Connection,
                                    window    : Window,
                                    value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_change_window_attributes(c.get_raw_conn(),
                                                  window as xcb_window_t,  // 0
                                                  value_list_mask as u32,  // 1
                                                  value_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// change window attributes
///
/// Changes the attributes specified by `value_mask` for the specified `window`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to change.
///
///   - __value_list__:
///       Values for each of the attributes specified in the bitmask `value_mask`. The
///       order has to correspond to the order of possible `value_mask` bits. See the
///       example.
pub fn change_window_attributes_checked<'a>(c         : &'a base::Connection,
                                            window    : Window,
                                            value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_change_window_attributes_checked(c.get_raw_conn(),
                                                          window as xcb_window_t,  // 0
                                                          value_list_mask as u32,  // 1
                                                          value_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_WINDOW_ATTRIBUTES: u8 = 3;

pub type GetWindowAttributesCookie<'a> = base::Cookie<'a, xcb_get_window_attributes_cookie_t>;

impl<'a> GetWindowAttributesCookie<'a> {
    pub fn get_reply(&self) -> Result<GetWindowAttributesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetWindowAttributesReply {
                    ptr: xcb_get_window_attributes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetWindowAttributesReply {
                    ptr: xcb_get_window_attributes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetWindowAttributesReply = base::Reply<xcb_get_window_attributes_reply_t>;

impl GetWindowAttributesReply {
    pub fn backing_store(&self) -> u8 {
        unsafe {
            (*self.ptr).backing_store
        }
    }
    pub fn visual(&self) -> Visualid {
        unsafe {
            (*self.ptr).visual
        }
    }
    pub fn class(&self) -> u16 {
        unsafe {
            (*self.ptr).class
        }
    }
    pub fn bit_gravity(&self) -> u8 {
        unsafe {
            (*self.ptr).bit_gravity
        }
    }
    pub fn win_gravity(&self) -> u8 {
        unsafe {
            (*self.ptr).win_gravity
        }
    }
    pub fn backing_planes(&self) -> u32 {
        unsafe {
            (*self.ptr).backing_planes
        }
    }
    pub fn backing_pixel(&self) -> u32 {
        unsafe {
            (*self.ptr).backing_pixel
        }
    }
    pub fn save_under(&self) -> bool {
        unsafe {
            (*self.ptr).save_under != 0
        }
    }
    pub fn map_is_installed(&self) -> bool {
        unsafe {
            (*self.ptr).map_is_installed != 0
        }
    }
    pub fn map_state(&self) -> u8 {
        unsafe {
            (*self.ptr).map_state
        }
    }
    pub fn override_redirect(&self) -> bool {
        unsafe {
            (*self.ptr).override_redirect != 0
        }
    }
    pub fn colormap(&self) -> Colormap {
        unsafe {
            (*self.ptr).colormap
        }
    }
    pub fn all_event_masks(&self) -> u32 {
        unsafe {
            (*self.ptr).all_event_masks
        }
    }
    pub fn your_event_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).your_event_mask
        }
    }
    pub fn do_not_propagate_mask(&self) -> u16 {
        unsafe {
            (*self.ptr).do_not_propagate_mask
        }
    }
}

/// Gets window attributes
///
/// Gets the current attributes for the specified `window`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to get the attributes from.
pub fn get_window_attributes<'a>(c     : &'a base::Connection,
                                 window: Window)
        -> GetWindowAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_get_window_attributes(c.get_raw_conn(),
                                               window as xcb_window_t);  // 0
        GetWindowAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// Gets window attributes
///
/// Gets the current attributes for the specified `window`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to get the attributes from.
pub fn get_window_attributes_unchecked<'a>(c     : &'a base::Connection,
                                           window: Window)
        -> GetWindowAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_get_window_attributes_unchecked(c.get_raw_conn(),
                                                         window as xcb_window_t);  // 0
        GetWindowAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DESTROY_WINDOW: u8 = 4;

/// Destroys a window
///
/// Destroys the specified window and all of its subwindows. A DestroyNotify event
/// is generated for each destroyed window (a DestroyNotify event is first generated
/// for any given window's inferiors). If the window was mapped, it will be
/// automatically unmapped before destroying.
///
/// Calling DestroyWindow on the root window will do nothing.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to destroy.
pub fn destroy_window<'a>(c     : &'a base::Connection,
                          window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_destroy_window(c.get_raw_conn(),
                                        window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Destroys a window
///
/// Destroys the specified window and all of its subwindows. A DestroyNotify event
/// is generated for each destroyed window (a DestroyNotify event is first generated
/// for any given window's inferiors). If the window was mapped, it will be
/// automatically unmapped before destroying.
///
/// Calling DestroyWindow on the root window will do nothing.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to destroy.
pub fn destroy_window_checked<'a>(c     : &'a base::Connection,
                                  window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_destroy_window_checked(c.get_raw_conn(),
                                                window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_SUBWINDOWS: u8 = 5;

pub fn destroy_subwindows<'a>(c     : &'a base::Connection,
                              window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_destroy_subwindows(c.get_raw_conn(),
                                            window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_subwindows_checked<'a>(c     : &'a base::Connection,
                                      window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_destroy_subwindows_checked(c.get_raw_conn(),
                                                    window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_SAVE_SET: u8 = 6;

/// Changes a client's save set
///
/// TODO: explain what the save set is for.
///
/// This function either adds or removes the specified window to the client's (your
/// application's) save set.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __mode__:
///       Insert to add the specified window to the save set or Delete to delete it from the save set.
///
///   - __window__:
///       The window to add or delete to/from your save set.
pub fn change_save_set<'a>(c     : &'a base::Connection,
                           mode  : u8,
                           window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_change_save_set(c.get_raw_conn(),
                                         mode as u8,  // 0
                                         window as xcb_window_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Changes a client's save set
///
/// TODO: explain what the save set is for.
///
/// This function either adds or removes the specified window to the client's (your
/// application's) save set.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __mode__:
///       Insert to add the specified window to the save set or Delete to delete it from the save set.
///
///   - __window__:
///       The window to add or delete to/from your save set.
pub fn change_save_set_checked<'a>(c     : &'a base::Connection,
                                   mode  : u8,
                                   window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_change_save_set_checked(c.get_raw_conn(),
                                                 mode as u8,  // 0
                                                 window as xcb_window_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const REPARENT_WINDOW: u8 = 7;

/// Reparents a window
///
/// Makes the specified window a child of the specified parent window. If the
/// window is mapped, it will automatically be unmapped before reparenting and
/// re-mapped after reparenting. The window is placed in the stacking order on top
/// with respect to sibling windows.
///
/// After reparenting, a ReparentNotify event is generated.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to reparent.
///
///   - __parent__:
///       The new parent of the window.
///
///   - __x__:
///       The X position of the window within its new parent.
///
///   - __y__:
///       The Y position of the window within its new parent.
pub fn reparent_window<'a>(c     : &'a base::Connection,
                           window: Window,
                           parent: Window,
                           x     : i16,
                           y     : i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_reparent_window(c.get_raw_conn(),
                                         window as xcb_window_t,  // 0
                                         parent as xcb_window_t,  // 1
                                         x as i16,  // 2
                                         y as i16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Reparents a window
///
/// Makes the specified window a child of the specified parent window. If the
/// window is mapped, it will automatically be unmapped before reparenting and
/// re-mapped after reparenting. The window is placed in the stacking order on top
/// with respect to sibling windows.
///
/// After reparenting, a ReparentNotify event is generated.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to reparent.
///
///   - __parent__:
///       The new parent of the window.
///
///   - __x__:
///       The X position of the window within its new parent.
///
///   - __y__:
///       The Y position of the window within its new parent.
pub fn reparent_window_checked<'a>(c     : &'a base::Connection,
                                   window: Window,
                                   parent: Window,
                                   x     : i16,
                                   y     : i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_reparent_window_checked(c.get_raw_conn(),
                                                 window as xcb_window_t,  // 0
                                                 parent as xcb_window_t,  // 1
                                                 x as i16,  // 2
                                                 y as i16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const MAP_WINDOW: u8 = 8;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to make visible.
pub fn map_window<'a>(c     : &'a base::Connection,
                      window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_map_window(c.get_raw_conn(),
                                    window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to make visible.
pub fn map_window_checked<'a>(c     : &'a base::Connection,
                              window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_map_window_checked(c.get_raw_conn(),
                                            window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const MAP_SUBWINDOWS: u8 = 9;

pub fn map_subwindows<'a>(c     : &'a base::Connection,
                          window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_map_subwindows(c.get_raw_conn(),
                                        window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn map_subwindows_checked<'a>(c     : &'a base::Connection,
                                  window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_map_subwindows_checked(c.get_raw_conn(),
                                                window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNMAP_WINDOW: u8 = 10;

/// Makes a window invisible
///
/// Unmaps the specified window. This means making the window invisible (and all
/// its child windows).
///
/// Unmapping a window leads to the `UnmapNotify` event being generated. Also,
/// `Expose` events are generated for formerly obscured windows.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to make invisible.
pub fn unmap_window<'a>(c     : &'a base::Connection,
                        window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_unmap_window(c.get_raw_conn(),
                                      window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Makes a window invisible
///
/// Unmaps the specified window. This means making the window invisible (and all
/// its child windows).
///
/// Unmapping a window leads to the `UnmapNotify` event being generated. Also,
/// `Expose` events are generated for formerly obscured windows.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to make invisible.
pub fn unmap_window_checked<'a>(c     : &'a base::Connection,
                                window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_unmap_window_checked(c.get_raw_conn(),
                                              window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNMAP_SUBWINDOWS: u8 = 11;

pub fn unmap_subwindows<'a>(c     : &'a base::Connection,
                            window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_unmap_subwindows(c.get_raw_conn(),
                                          window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn unmap_subwindows_checked<'a>(c     : &'a base::Connection,
                                    window: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_unmap_subwindows_checked(c.get_raw_conn(),
                                                  window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CONFIGURE_WINDOW: u8 = 12;

/// Configures window attributes
///
/// Configures a window's size, position, border width and stacking order.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to configure.
///
///   - __value_list__:
///       New values, corresponding to the attributes in value_mask. The order has to
///       correspond to the order of possible `value_mask` bits. See the example.
pub fn configure_window<'a>(c         : &'a base::Connection,
                            window    : Window,
                            value_list: &[(u16, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_configure_window(c.get_raw_conn(),
                                          window as xcb_window_t,  // 0
                                          value_list_mask as u16,  // 1
                                          value_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Configures window attributes
///
/// Configures a window's size, position, border width and stacking order.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The window to configure.
///
///   - __value_list__:
///       New values, corresponding to the attributes in value_mask. The order has to
///       correspond to the order of possible `value_mask` bits. See the example.
pub fn configure_window_checked<'a>(c         : &'a base::Connection,
                                    window    : Window,
                                    value_list: &[(u16, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_configure_window_checked(c.get_raw_conn(),
                                                  window as xcb_window_t,  // 0
                                                  value_list_mask as u16,  // 1
                                                  value_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CIRCULATE_WINDOW: u8 = 13;

/// Change window stacking order
///
/// If `direction` is `XCB_CIRCULATE_RAISE_LOWEST`, the lowest mapped child (if
/// any) will be raised to the top of the stack.
///
/// If `direction` is `XCB_CIRCULATE_LOWER_HIGHEST`, the highest mapped child will
/// be lowered to the bottom of the stack.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __direction__:
///
///
///   - __window__:
///       The window to raise/lower (depending on `direction`).
pub fn circulate_window<'a>(c        : &'a base::Connection,
                            direction: u8,
                            window   : Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_circulate_window(c.get_raw_conn(),
                                          direction as u8,  // 0
                                          window as xcb_window_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Change window stacking order
///
/// If `direction` is `XCB_CIRCULATE_RAISE_LOWEST`, the lowest mapped child (if
/// any) will be raised to the top of the stack.
///
/// If `direction` is `XCB_CIRCULATE_LOWER_HIGHEST`, the highest mapped child will
/// be lowered to the bottom of the stack.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __direction__:
///
///
///   - __window__:
///       The window to raise/lower (depending on `direction`).
pub fn circulate_window_checked<'a>(c        : &'a base::Connection,
                                    direction: u8,
                                    window   : Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_circulate_window_checked(c.get_raw_conn(),
                                                  direction as u8,  // 0
                                                  window as xcb_window_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_GEOMETRY: u8 = 14;

pub type GetGeometryCookie<'a> = base::Cookie<'a, xcb_get_geometry_cookie_t>;

impl<'a> GetGeometryCookie<'a> {
    pub fn get_reply(&self) -> Result<GetGeometryReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetGeometryReply {
                    ptr: xcb_get_geometry_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetGeometryReply {
                    ptr: xcb_get_geometry_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetGeometryReply = base::Reply<xcb_get_geometry_reply_t>;

impl GetGeometryReply {
    pub fn depth(&self) -> u8 {
        unsafe {
            (*self.ptr).depth
        }
    }
    pub fn root(&self) -> Window {
        unsafe {
            (*self.ptr).root
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
    pub fn border_width(&self) -> u16 {
        unsafe {
            (*self.ptr).border_width
        }
    }
}

/// Get current window geometry
///
/// Gets the current geometry of the specified drawable (either `Window` or `Pixmap`).
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       The drawable (`Window` or `Pixmap`) of which the geometry will be received.
pub fn get_geometry<'a>(c       : &'a base::Connection,
                        drawable: Drawable)
        -> GetGeometryCookie<'a> {
    unsafe {
        let cookie = xcb_get_geometry(c.get_raw_conn(),
                                      drawable as xcb_drawable_t);  // 0
        GetGeometryCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// Get current window geometry
///
/// Gets the current geometry of the specified drawable (either `Window` or `Pixmap`).
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       The drawable (`Window` or `Pixmap`) of which the geometry will be received.
pub fn get_geometry_unchecked<'a>(c       : &'a base::Connection,
                                  drawable: Drawable)
        -> GetGeometryCookie<'a> {
    unsafe {
        let cookie = xcb_get_geometry_unchecked(c.get_raw_conn(),
                                                drawable as xcb_drawable_t);  // 0
        GetGeometryCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_TREE: u8 = 15;

pub type QueryTreeCookie<'a> = base::Cookie<'a, xcb_query_tree_cookie_t>;

impl<'a> QueryTreeCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryTreeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryTreeReply {
                    ptr: xcb_query_tree_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryTreeReply {
                    ptr: xcb_query_tree_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryTreeReply = base::Reply<xcb_query_tree_reply_t>;

impl QueryTreeReply {
    pub fn root(&self) -> Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn parent(&self) -> Window {
        unsafe {
            (*self.ptr).parent
        }
    }
    pub fn children_len(&self) -> u16 {
        unsafe {
            (*self.ptr).children_len
        }
    }
    pub fn children(&self) -> &[Window] {
        unsafe {
            let field = self.ptr;
            let len = xcb_query_tree_children_length(field) as usize;
            let data = xcb_query_tree_children(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

/// query the window tree
///
/// Gets the root window ID, parent window ID and list of children windows for the
/// specified `window`. The children are listed in bottom-to-top stacking order.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The `window` to query.
pub fn query_tree<'a>(c     : &'a base::Connection,
                      window: Window)
        -> QueryTreeCookie<'a> {
    unsafe {
        let cookie = xcb_query_tree(c.get_raw_conn(),
                                    window as xcb_window_t);  // 0
        QueryTreeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// query the window tree
///
/// Gets the root window ID, parent window ID and list of children windows for the
/// specified `window`. The children are listed in bottom-to-top stacking order.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       The `window` to query.
pub fn query_tree_unchecked<'a>(c     : &'a base::Connection,
                                window: Window)
        -> QueryTreeCookie<'a> {
    unsafe {
        let cookie = xcb_query_tree_unchecked(c.get_raw_conn(),
                                              window as xcb_window_t);  // 0
        QueryTreeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const INTERN_ATOM: u8 = 16;

pub type InternAtomCookie<'a> = base::Cookie<'a, xcb_intern_atom_cookie_t>;

impl<'a> InternAtomCookie<'a> {
    pub fn get_reply(&self) -> Result<InternAtomReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = InternAtomReply {
                    ptr: xcb_intern_atom_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( InternAtomReply {
                    ptr: xcb_intern_atom_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type InternAtomReply = base::Reply<xcb_intern_atom_reply_t>;

impl InternAtomReply {
    pub fn atom(&self) -> Atom {
        unsafe {
            (*self.ptr).atom
        }
    }
}

/// Get atom identifier by name
///
/// Retrieves the identifier (xcb_atom_t TODO) for the atom with the specified
/// name. Atoms are used in protocols like EWMH, for example to store window titles
/// (`_NET_WM_NAME` atom) as property of a window.
///
/// If `only_if_exists` is 0, the atom will be created if it does not already exist.
/// If `only_if_exists` is 1, `XCB_ATOM_NONE` will be returned if the atom does
/// not yet exist.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __only_if_exists__:
///       Return a valid atom id only if the atom already exists.
///
///   - __name__:
///       The name of the atom.
pub fn intern_atom<'a>(c             : &'a base::Connection,
                       only_if_exists: bool,
                       name          : &str)
        -> InternAtomCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_intern_atom(c.get_raw_conn(),
                                     only_if_exists as u8,  // 0
                                     name_len as u16,  // 1
                                     name_ptr as *const c_char);  // 2
        InternAtomCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// Get atom identifier by name
///
/// Retrieves the identifier (xcb_atom_t TODO) for the atom with the specified
/// name. Atoms are used in protocols like EWMH, for example to store window titles
/// (`_NET_WM_NAME` atom) as property of a window.
///
/// If `only_if_exists` is 0, the atom will be created if it does not already exist.
/// If `only_if_exists` is 1, `XCB_ATOM_NONE` will be returned if the atom does
/// not yet exist.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __only_if_exists__:
///       Return a valid atom id only if the atom already exists.
///
///   - __name__:
///       The name of the atom.
pub fn intern_atom_unchecked<'a>(c             : &'a base::Connection,
                                 only_if_exists: bool,
                                 name          : &str)
        -> InternAtomCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_intern_atom_unchecked(c.get_raw_conn(),
                                               only_if_exists as u8,  // 0
                                               name_len as u16,  // 1
                                               name_ptr as *const c_char);  // 2
        InternAtomCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_ATOM_NAME: u8 = 17;

pub type GetAtomNameCookie<'a> = base::Cookie<'a, xcb_get_atom_name_cookie_t>;

impl<'a> GetAtomNameCookie<'a> {
    pub fn get_reply(&self) -> Result<GetAtomNameReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetAtomNameReply {
                    ptr: xcb_get_atom_name_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetAtomNameReply {
                    ptr: xcb_get_atom_name_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetAtomNameReply = base::Reply<xcb_get_atom_name_reply_t>;

impl GetAtomNameReply {
    pub fn name_len(&self) -> u16 {
        unsafe {
            (*self.ptr).name_len
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_get_atom_name_name_length(field) as usize;
            let data = xcb_get_atom_name_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_atom_name<'a>(c   : &'a base::Connection,
                         atom: Atom)
        -> GetAtomNameCookie<'a> {
    unsafe {
        let cookie = xcb_get_atom_name(c.get_raw_conn(),
                                       atom as xcb_atom_t);  // 0
        GetAtomNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_atom_name_unchecked<'a>(c   : &'a base::Connection,
                                   atom: Atom)
        -> GetAtomNameCookie<'a> {
    unsafe {
        let cookie = xcb_get_atom_name_unchecked(c.get_raw_conn(),
                                                 atom as xcb_atom_t);  // 0
        GetAtomNameCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_PROPERTY: u8 = 18;

/// Changes a window property
///
/// Sets or updates a property on the specified `window`. Properties are for
/// example the window title (`WM_NAME`) or its minimum size (`WM_NORMAL_HINTS`).
/// Protocols such as EWMH also use properties - for example EWMH defines the
/// window title, encoded as UTF-8 string, in the `_NET_WM_NAME` property.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __mode__:
///
///
///   - __window__:
///       The window whose property you want to change.
///
///   - __property__:
///       The property you want to change (an atom).
///
///   - __type__:
///       The type of the property you want to change (an atom).
///
///   - __format__:
///       Specifies whether the data should be viewed as a list of 8-bit, 16-bit or
///       32-bit quantities. Possible values are 8, 16 and 32. This information allows
///       the X server to correctly perform byte-swap operations as necessary.
///
///   - __data__:
///       The property data.
pub fn change_property<'a, T>(c       : &'a base::Connection,
                              mode    : u8,
                              window  : Window,
                              property: Atom,
                              type_   : Atom,
                              format  : u8,
                              data    : &[T])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_change_property(c.get_raw_conn(),
                                         mode as u8,  // 0
                                         window as xcb_window_t,  // 1
                                         property as xcb_atom_t,  // 2
                                         type_ as xcb_atom_t,  // 3
                                         format as u8,  // 4
                                         data_len as u32,  // 5
                                         data_ptr as *const c_void);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Changes a window property
///
/// Sets or updates a property on the specified `window`. Properties are for
/// example the window title (`WM_NAME`) or its minimum size (`WM_NORMAL_HINTS`).
/// Protocols such as EWMH also use properties - for example EWMH defines the
/// window title, encoded as UTF-8 string, in the `_NET_WM_NAME` property.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __mode__:
///
///
///   - __window__:
///       The window whose property you want to change.
///
///   - __property__:
///       The property you want to change (an atom).
///
///   - __type__:
///       The type of the property you want to change (an atom).
///
///   - __format__:
///       Specifies whether the data should be viewed as a list of 8-bit, 16-bit or
///       32-bit quantities. Possible values are 8, 16 and 32. This information allows
///       the X server to correctly perform byte-swap operations as necessary.
///
///   - __data__:
///       The property data.
pub fn change_property_checked<'a, T>(c       : &'a base::Connection,
                                      mode    : u8,
                                      window  : Window,
                                      property: Atom,
                                      type_   : Atom,
                                      format  : u8,
                                      data    : &[T])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_change_property_checked(c.get_raw_conn(),
                                                 mode as u8,  // 0
                                                 window as xcb_window_t,  // 1
                                                 property as xcb_atom_t,  // 2
                                                 type_ as xcb_atom_t,  // 3
                                                 format as u8,  // 4
                                                 data_len as u32,  // 5
                                                 data_ptr as *const c_void);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_PROPERTY: u8 = 19;

pub fn delete_property<'a>(c       : &'a base::Connection,
                           window  : Window,
                           property: Atom)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_delete_property(c.get_raw_conn(),
                                         window as xcb_window_t,  // 0
                                         property as xcb_atom_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_property_checked<'a>(c       : &'a base::Connection,
                                   window  : Window,
                                   property: Atom)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_delete_property_checked(c.get_raw_conn(),
                                                 window as xcb_window_t,  // 0
                                                 property as xcb_atom_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_PROPERTY: u8 = 20;

pub type GetPropertyCookie<'a> = base::Cookie<'a, xcb_get_property_cookie_t>;

impl<'a> GetPropertyCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPropertyReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPropertyReply {
                    ptr: xcb_get_property_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPropertyReply {
                    ptr: xcb_get_property_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPropertyReply = base::Reply<xcb_get_property_reply_t>;

impl GetPropertyReply {
    pub fn format(&self) -> u8 {
        unsafe {
            (*self.ptr).format
        }
    }
    pub fn type_(&self) -> Atom {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn bytes_after(&self) -> u32 {
        unsafe {
            (*self.ptr).bytes_after
        }
    }
    pub fn value_len(&self) -> u32 {
        unsafe {
            (*self.ptr).value_len
        }
    }
    pub fn value<T>(&self) -> &[T] {
        unsafe {
            let field = self.ptr;
            let len = xcb_get_property_value_length(field) as usize;
            let data = xcb_get_property_value(field);
            debug_assert_eq!(len % std::mem::size_of::<T>(), 0);
            std::slice::from_raw_parts(data as *const T, len / std::mem::size_of::<T>())
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __delete__:
///       Whether the property should actually be deleted. For deleting a property, the
///       specified `type` has to match the actual property type.
///
///   - __window__:
///       The window whose property you want to get.
///
///   - __property__:
///       The property you want to get (an atom).
///
///   - __type__:
///       The type of the property you want to get (an atom).
///
///   - __long_offset__:
///       Specifies the offset (in 32-bit multiples) in the specified property where the
///       data is to be retrieved.
///
///   - __long_length__:
///       Specifies how many 32-bit multiples of data should be retrieved (e.g. if you
///       set `long_length` to 4, you will receive 16 bytes of data).
pub fn get_property<'a>(c          : &'a base::Connection,
                        delete     : bool,
                        window     : Window,
                        property   : Atom,
                        type_      : Atom,
                        long_offset: u32,
                        long_length: u32)
        -> GetPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_get_property(c.get_raw_conn(),
                                      delete as u8,  // 0
                                      window as xcb_window_t,  // 1
                                      property as xcb_atom_t,  // 2
                                      type_ as xcb_atom_t,  // 3
                                      long_offset as u32,  // 4
                                      long_length as u32);  // 5
        GetPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __delete__:
///       Whether the property should actually be deleted. For deleting a property, the
///       specified `type` has to match the actual property type.
///
///   - __window__:
///       The window whose property you want to get.
///
///   - __property__:
///       The property you want to get (an atom).
///
///   - __type__:
///       The type of the property you want to get (an atom).
///
///   - __long_offset__:
///       Specifies the offset (in 32-bit multiples) in the specified property where the
///       data is to be retrieved.
///
///   - __long_length__:
///       Specifies how many 32-bit multiples of data should be retrieved (e.g. if you
///       set `long_length` to 4, you will receive 16 bytes of data).
pub fn get_property_unchecked<'a>(c          : &'a base::Connection,
                                  delete     : bool,
                                  window     : Window,
                                  property   : Atom,
                                  type_      : Atom,
                                  long_offset: u32,
                                  long_length: u32)
        -> GetPropertyCookie<'a> {
    unsafe {
        let cookie = xcb_get_property_unchecked(c.get_raw_conn(),
                                                delete as u8,  // 0
                                                window as xcb_window_t,  // 1
                                                property as xcb_atom_t,  // 2
                                                type_ as xcb_atom_t,  // 3
                                                long_offset as u32,  // 4
                                                long_length as u32);  // 5
        GetPropertyCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_PROPERTIES: u8 = 21;

pub type ListPropertiesCookie<'a> = base::Cookie<'a, xcb_list_properties_cookie_t>;

impl<'a> ListPropertiesCookie<'a> {
    pub fn get_reply(&self) -> Result<ListPropertiesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListPropertiesReply {
                    ptr: xcb_list_properties_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListPropertiesReply {
                    ptr: xcb_list_properties_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListPropertiesReply = base::Reply<xcb_list_properties_reply_t>;

impl ListPropertiesReply {
    pub fn atoms_len(&self) -> u16 {
        unsafe {
            (*self.ptr).atoms_len
        }
    }
    pub fn atoms(&self) -> &[Atom] {
        unsafe {
            let field = self.ptr;
            let len = xcb_list_properties_atoms_length(field) as usize;
            let data = xcb_list_properties_atoms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn list_properties<'a>(c     : &'a base::Connection,
                           window: Window)
        -> ListPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_list_properties(c.get_raw_conn(),
                                         window as xcb_window_t);  // 0
        ListPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_properties_unchecked<'a>(c     : &'a base::Connection,
                                     window: Window)
        -> ListPropertiesCookie<'a> {
    unsafe {
        let cookie = xcb_list_properties_unchecked(c.get_raw_conn(),
                                                   window as xcb_window_t);  // 0
        ListPropertiesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_SELECTION_OWNER: u8 = 22;

/// Sets the owner of a selection
///
/// Makes `window` the owner of the selection `selection` and updates the
/// last-change time of the specified selection.
///
/// TODO: briefly explain what a selection is.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner__:
///       The new owner of the selection.
///
///       The special value `XCB_NONE` means that the selection will have no owner.
///
///   - __selection__:
///       The selection.
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The selection will not be changed if `time` is earlier than the current
///       last-change time of the `selection` or is later than the current X server time.
///       Otherwise, the last-change time is set to the specified time.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
pub fn set_selection_owner<'a>(c        : &'a base::Connection,
                               owner    : Window,
                               selection: Atom,
                               time     : Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_selection_owner(c.get_raw_conn(),
                                             owner as xcb_window_t,  // 0
                                             selection as xcb_atom_t,  // 1
                                             time as xcb_timestamp_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Sets the owner of a selection
///
/// Makes `window` the owner of the selection `selection` and updates the
/// last-change time of the specified selection.
///
/// TODO: briefly explain what a selection is.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner__:
///       The new owner of the selection.
///
///       The special value `XCB_NONE` means that the selection will have no owner.
///
///   - __selection__:
///       The selection.
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The selection will not be changed if `time` is earlier than the current
///       last-change time of the `selection` or is later than the current X server time.
///       Otherwise, the last-change time is set to the specified time.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
pub fn set_selection_owner_checked<'a>(c        : &'a base::Connection,
                                       owner    : Window,
                                       selection: Atom,
                                       time     : Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_selection_owner_checked(c.get_raw_conn(),
                                                     owner as xcb_window_t,  // 0
                                                     selection as xcb_atom_t,  // 1
                                                     time as xcb_timestamp_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_SELECTION_OWNER: u8 = 23;

pub type GetSelectionOwnerCookie<'a> = base::Cookie<'a, xcb_get_selection_owner_cookie_t>;

impl<'a> GetSelectionOwnerCookie<'a> {
    pub fn get_reply(&self) -> Result<GetSelectionOwnerReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetSelectionOwnerReply {
                    ptr: xcb_get_selection_owner_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetSelectionOwnerReply {
                    ptr: xcb_get_selection_owner_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetSelectionOwnerReply = base::Reply<xcb_get_selection_owner_reply_t>;

impl GetSelectionOwnerReply {
    pub fn owner(&self) -> Window {
        unsafe {
            (*self.ptr).owner
        }
    }
}

/// Gets the owner of a selection
///
/// Gets the owner of the specified selection.
///
/// TODO: briefly explain what a selection is.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __selection__:
///       The selection.
pub fn get_selection_owner<'a>(c        : &'a base::Connection,
                               selection: Atom)
        -> GetSelectionOwnerCookie<'a> {
    unsafe {
        let cookie = xcb_get_selection_owner(c.get_raw_conn(),
                                             selection as xcb_atom_t);  // 0
        GetSelectionOwnerCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// Gets the owner of a selection
///
/// Gets the owner of the specified selection.
///
/// TODO: briefly explain what a selection is.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __selection__:
///       The selection.
pub fn get_selection_owner_unchecked<'a>(c        : &'a base::Connection,
                                         selection: Atom)
        -> GetSelectionOwnerCookie<'a> {
    unsafe {
        let cookie = xcb_get_selection_owner_unchecked(c.get_raw_conn(),
                                                       selection as xcb_atom_t);  // 0
        GetSelectionOwnerCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CONVERT_SELECTION: u8 = 24;

pub fn convert_selection<'a>(c        : &'a base::Connection,
                             requestor: Window,
                             selection: Atom,
                             target   : Atom,
                             property : Atom,
                             time     : Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_convert_selection(c.get_raw_conn(),
                                           requestor as xcb_window_t,  // 0
                                           selection as xcb_atom_t,  // 1
                                           target as xcb_atom_t,  // 2
                                           property as xcb_atom_t,  // 3
                                           time as xcb_timestamp_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn convert_selection_checked<'a>(c        : &'a base::Connection,
                                     requestor: Window,
                                     selection: Atom,
                                     target   : Atom,
                                     property : Atom,
                                     time     : Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_convert_selection_checked(c.get_raw_conn(),
                                                   requestor as xcb_window_t,  // 0
                                                   selection as xcb_atom_t,  // 1
                                                   target as xcb_atom_t,  // 2
                                                   property as xcb_atom_t,  // 3
                                                   time as xcb_timestamp_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SEND_EVENT: u8 = 25;

/// send an event
///
/// Identifies the `destination` window, determines which clients should receive
/// the specified event and ignores any active grabs.
///
/// The `event` must be one of the core events or an event defined by an extension,
/// so that the X server can correctly byte-swap the contents as necessary. The
/// contents of `event` are otherwise unaltered and unchecked except for the
/// `send_event` field which is forced to 'true'.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __propagate__:
///       If `propagate` is true and no clients have selected any event on `destination`,
///       the destination is replaced with the closest ancestor of `destination` for
///       which some client has selected a type in `event_mask` and for which no
///       intervening window has that type in its do-not-propagate-mask. If no such
///       window exists or if the window is an ancestor of the focus window and
///       `InputFocus` was originally specified as the destination, the event is not sent
///       to any clients. Otherwise, the event is reported to every client selecting on
///       the final destination any of the types specified in `event_mask`.
///
///   - __destination__:
///       The window to send this event to. Every client which selects any event within
///       `event_mask` on `destination` will get the event.
///
///       The special value `XCB_SEND_EVENT_DEST_POINTER_WINDOW` refers to the window
///       that contains the mouse pointer.
///
///       The special value `XCB_SEND_EVENT_DEST_ITEM_FOCUS` refers to the window which
///       has the keyboard focus.
///
///   - __event_mask__:
///       Event_mask for determining which clients should receive the specified event.
///       See `destination` and `propagate`.
///
///   - __event__:
///       The event to send to the specified `destination`.
pub fn send_event<'a, T>(c          : &'a base::Connection,
                         propagate  : bool,
                         destination: Window,
                         event_mask : u32,
                         event      : &base::Event<T>)
        -> base::VoidCookie<'a> {
    unsafe {
        let event_ptr = std::mem::transmute(event.ptr);
        let cookie = xcb_send_event(c.get_raw_conn(),
                                    propagate as u8,  // 0
                                    destination as xcb_window_t,  // 1
                                    event_mask as u32,  // 2
                                    event_ptr);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// send an event
///
/// Identifies the `destination` window, determines which clients should receive
/// the specified event and ignores any active grabs.
///
/// The `event` must be one of the core events or an event defined by an extension,
/// so that the X server can correctly byte-swap the contents as necessary. The
/// contents of `event` are otherwise unaltered and unchecked except for the
/// `send_event` field which is forced to 'true'.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __propagate__:
///       If `propagate` is true and no clients have selected any event on `destination`,
///       the destination is replaced with the closest ancestor of `destination` for
///       which some client has selected a type in `event_mask` and for which no
///       intervening window has that type in its do-not-propagate-mask. If no such
///       window exists or if the window is an ancestor of the focus window and
///       `InputFocus` was originally specified as the destination, the event is not sent
///       to any clients. Otherwise, the event is reported to every client selecting on
///       the final destination any of the types specified in `event_mask`.
///
///   - __destination__:
///       The window to send this event to. Every client which selects any event within
///       `event_mask` on `destination` will get the event.
///
///       The special value `XCB_SEND_EVENT_DEST_POINTER_WINDOW` refers to the window
///       that contains the mouse pointer.
///
///       The special value `XCB_SEND_EVENT_DEST_ITEM_FOCUS` refers to the window which
///       has the keyboard focus.
///
///   - __event_mask__:
///       Event_mask for determining which clients should receive the specified event.
///       See `destination` and `propagate`.
///
///   - __event__:
///       The event to send to the specified `destination`.
pub fn send_event_checked<'a, T>(c          : &'a base::Connection,
                                 propagate  : bool,
                                 destination: Window,
                                 event_mask : u32,
                                 event      : &base::Event<T>)
        -> base::VoidCookie<'a> {
    unsafe {
        let event_ptr = std::mem::transmute(event.ptr);
        let cookie = xcb_send_event_checked(c.get_raw_conn(),
                                            propagate as u8,  // 0
                                            destination as xcb_window_t,  // 1
                                            event_mask as u32,  // 2
                                            event_ptr);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GRAB_POINTER: u8 = 26;

pub type GrabPointerCookie<'a> = base::Cookie<'a, xcb_grab_pointer_cookie_t>;

impl<'a> GrabPointerCookie<'a> {
    pub fn get_reply(&self) -> Result<GrabPointerReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GrabPointerReply {
                    ptr: xcb_grab_pointer_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GrabPointerReply {
                    ptr: xcb_grab_pointer_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GrabPointerReply = base::Reply<xcb_grab_pointer_reply_t>;

impl GrabPointerReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

/// Grab the pointer
///
/// Actively grabs control of the pointer. Further pointer events are reported only to the grabbing client. Overrides any active pointer grab by this client.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner_events__:
///       If 1, the `grab_window` will still get the pointer events. If 0, events are not
///       reported to the `grab_window`.
///
///   - __grab_window__:
///       Specifies the window on which the pointer should be grabbed.
///
///   - __event_mask__:
///       Specifies which pointer events are reported to the client.
///
///       TODO: which values?
///
///   - __pointer_mode__:
///
///
///   - __keyboard_mode__:
///
///
///   - __confine_to__:
///       Specifies the window to confine the pointer in (the user will not be able to
///       move the pointer out of that window).
///
///       The special value `XCB_NONE` means don't confine the pointer.
///
///   - __cursor__:
///       Specifies the cursor that should be displayed or `XCB_NONE` to not change the
///       cursor.
///
///   - __time__:
///       The time argument allows you to avoid certain circumstances that come up if
///       applications take a long time to respond or if there are long network delays.
///       Consider a situation where you have two applications, both of which normally
///       grab the pointer when clicked on. If both applications specify the timestamp
///       from the event, the second application may wake up faster and successfully grab
///       the pointer before the first application. The first application then will get
///       an indication that the other application grabbed the pointer before its request
///       was processed.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
pub fn grab_pointer<'a>(c            : &'a base::Connection,
                        owner_events : bool,
                        grab_window  : Window,
                        event_mask   : u16,
                        pointer_mode : u8,
                        keyboard_mode: u8,
                        confine_to   : Window,
                        cursor       : Cursor,
                        time         : Timestamp)
        -> GrabPointerCookie<'a> {
    unsafe {
        let cookie = xcb_grab_pointer(c.get_raw_conn(),
                                      owner_events as u8,  // 0
                                      grab_window as xcb_window_t,  // 1
                                      event_mask as u16,  // 2
                                      pointer_mode as u8,  // 3
                                      keyboard_mode as u8,  // 4
                                      confine_to as xcb_window_t,  // 5
                                      cursor as xcb_cursor_t,  // 6
                                      time as xcb_timestamp_t);  // 7
        GrabPointerCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// Grab the pointer
///
/// Actively grabs control of the pointer. Further pointer events are reported only to the grabbing client. Overrides any active pointer grab by this client.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner_events__:
///       If 1, the `grab_window` will still get the pointer events. If 0, events are not
///       reported to the `grab_window`.
///
///   - __grab_window__:
///       Specifies the window on which the pointer should be grabbed.
///
///   - __event_mask__:
///       Specifies which pointer events are reported to the client.
///
///       TODO: which values?
///
///   - __pointer_mode__:
///
///
///   - __keyboard_mode__:
///
///
///   - __confine_to__:
///       Specifies the window to confine the pointer in (the user will not be able to
///       move the pointer out of that window).
///
///       The special value `XCB_NONE` means don't confine the pointer.
///
///   - __cursor__:
///       Specifies the cursor that should be displayed or `XCB_NONE` to not change the
///       cursor.
///
///   - __time__:
///       The time argument allows you to avoid certain circumstances that come up if
///       applications take a long time to respond or if there are long network delays.
///       Consider a situation where you have two applications, both of which normally
///       grab the pointer when clicked on. If both applications specify the timestamp
///       from the event, the second application may wake up faster and successfully grab
///       the pointer before the first application. The first application then will get
///       an indication that the other application grabbed the pointer before its request
///       was processed.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
pub fn grab_pointer_unchecked<'a>(c            : &'a base::Connection,
                                  owner_events : bool,
                                  grab_window  : Window,
                                  event_mask   : u16,
                                  pointer_mode : u8,
                                  keyboard_mode: u8,
                                  confine_to   : Window,
                                  cursor       : Cursor,
                                  time         : Timestamp)
        -> GrabPointerCookie<'a> {
    unsafe {
        let cookie = xcb_grab_pointer_unchecked(c.get_raw_conn(),
                                                owner_events as u8,  // 0
                                                grab_window as xcb_window_t,  // 1
                                                event_mask as u16,  // 2
                                                pointer_mode as u8,  // 3
                                                keyboard_mode as u8,  // 4
                                                confine_to as xcb_window_t,  // 5
                                                cursor as xcb_cursor_t,  // 6
                                                time as xcb_timestamp_t);  // 7
        GrabPointerCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const UNGRAB_POINTER: u8 = 27;

/// release the pointer
///
/// Releases the pointer and any queued events if you actively grabbed the pointer
/// before using `xcb_grab_pointer`, `xcb_grab_button` or within a normal button
/// press.
///
/// EnterNotify and LeaveNotify events are generated.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The pointer will not be released if `time` is earlier than the
///       last-pointer-grab time or later than the current X server time.
pub fn ungrab_pointer<'a>(c   : &'a base::Connection,
                          time: Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_pointer(c.get_raw_conn(),
                                        time as xcb_timestamp_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// release the pointer
///
/// Releases the pointer and any queued events if you actively grabbed the pointer
/// before using `xcb_grab_pointer`, `xcb_grab_button` or within a normal button
/// press.
///
/// EnterNotify and LeaveNotify events are generated.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The pointer will not be released if `time` is earlier than the
///       last-pointer-grab time or later than the current X server time.
pub fn ungrab_pointer_checked<'a>(c   : &'a base::Connection,
                                  time: Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_pointer_checked(c.get_raw_conn(),
                                                time as xcb_timestamp_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GRAB_BUTTON: u8 = 28;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner_events__:
///       If 1, the `grab_window` will still get the pointer events. If 0, events are not
///       reported to the `grab_window`.
///
///   - __grab_window__:
///       Specifies the window on which the pointer should be grabbed.
///
///   - __event_mask__:
///       Specifies which pointer events are reported to the client.
///
///       TODO: which values?
///
///   - __pointer_mode__:
///
///
///   - __keyboard_mode__:
///
///
///   - __confine_to__:
///       Specifies the window to confine the pointer in (the user will not be able to
///       move the pointer out of that window).
///
///       The special value `XCB_NONE` means don't confine the pointer.
///
///   - __cursor__:
///       Specifies the cursor that should be displayed or `XCB_NONE` to not change the
///       cursor.
///
///   - __button__:
///
///
///   - __modifiers__:
///       The modifiers to grab.
///
///       Using the special value `XCB_MOD_MASK_ANY` means grab the pointer with all
///       possible modifier combinations.
pub fn grab_button<'a>(c            : &'a base::Connection,
                       owner_events : bool,
                       grab_window  : Window,
                       event_mask   : u16,
                       pointer_mode : u8,
                       keyboard_mode: u8,
                       confine_to   : Window,
                       cursor       : Cursor,
                       button       : u8,
                       modifiers    : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_grab_button(c.get_raw_conn(),
                                     owner_events as u8,  // 0
                                     grab_window as xcb_window_t,  // 1
                                     event_mask as u16,  // 2
                                     pointer_mode as u8,  // 3
                                     keyboard_mode as u8,  // 4
                                     confine_to as xcb_window_t,  // 5
                                     cursor as xcb_cursor_t,  // 6
                                     button as u8,  // 7
                                     modifiers as u16);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner_events__:
///       If 1, the `grab_window` will still get the pointer events. If 0, events are not
///       reported to the `grab_window`.
///
///   - __grab_window__:
///       Specifies the window on which the pointer should be grabbed.
///
///   - __event_mask__:
///       Specifies which pointer events are reported to the client.
///
///       TODO: which values?
///
///   - __pointer_mode__:
///
///
///   - __keyboard_mode__:
///
///
///   - __confine_to__:
///       Specifies the window to confine the pointer in (the user will not be able to
///       move the pointer out of that window).
///
///       The special value `XCB_NONE` means don't confine the pointer.
///
///   - __cursor__:
///       Specifies the cursor that should be displayed or `XCB_NONE` to not change the
///       cursor.
///
///   - __button__:
///
///
///   - __modifiers__:
///       The modifiers to grab.
///
///       Using the special value `XCB_MOD_MASK_ANY` means grab the pointer with all
///       possible modifier combinations.
pub fn grab_button_checked<'a>(c            : &'a base::Connection,
                               owner_events : bool,
                               grab_window  : Window,
                               event_mask   : u16,
                               pointer_mode : u8,
                               keyboard_mode: u8,
                               confine_to   : Window,
                               cursor       : Cursor,
                               button       : u8,
                               modifiers    : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_grab_button_checked(c.get_raw_conn(),
                                             owner_events as u8,  // 0
                                             grab_window as xcb_window_t,  // 1
                                             event_mask as u16,  // 2
                                             pointer_mode as u8,  // 3
                                             keyboard_mode as u8,  // 4
                                             confine_to as xcb_window_t,  // 5
                                             cursor as xcb_cursor_t,  // 6
                                             button as u8,  // 7
                                             modifiers as u16);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNGRAB_BUTTON: u8 = 29;

pub fn ungrab_button<'a>(c          : &'a base::Connection,
                         button     : u8,
                         grab_window: Window,
                         modifiers  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_button(c.get_raw_conn(),
                                       button as u8,  // 0
                                       grab_window as xcb_window_t,  // 1
                                       modifiers as u16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn ungrab_button_checked<'a>(c          : &'a base::Connection,
                                 button     : u8,
                                 grab_window: Window,
                                 modifiers  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_button_checked(c.get_raw_conn(),
                                               button as u8,  // 0
                                               grab_window as xcb_window_t,  // 1
                                               modifiers as u16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_ACTIVE_POINTER_GRAB: u8 = 30;

pub fn change_active_pointer_grab<'a>(c         : &'a base::Connection,
                                      cursor    : Cursor,
                                      time      : Timestamp,
                                      event_mask: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_change_active_pointer_grab(c.get_raw_conn(),
                                                    cursor as xcb_cursor_t,  // 0
                                                    time as xcb_timestamp_t,  // 1
                                                    event_mask as u16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_active_pointer_grab_checked<'a>(c         : &'a base::Connection,
                                              cursor    : Cursor,
                                              time      : Timestamp,
                                              event_mask: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_change_active_pointer_grab_checked(c.get_raw_conn(),
                                                            cursor as xcb_cursor_t,  // 0
                                                            time as xcb_timestamp_t,  // 1
                                                            event_mask as u16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GRAB_KEYBOARD: u8 = 31;

pub type GrabKeyboardCookie<'a> = base::Cookie<'a, xcb_grab_keyboard_cookie_t>;

impl<'a> GrabKeyboardCookie<'a> {
    pub fn get_reply(&self) -> Result<GrabKeyboardReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GrabKeyboardReply {
                    ptr: xcb_grab_keyboard_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GrabKeyboardReply {
                    ptr: xcb_grab_keyboard_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GrabKeyboardReply = base::Reply<xcb_grab_keyboard_reply_t>;

impl GrabKeyboardReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner_events__:
///       If 1, the `grab_window` will still get the pointer events. If 0, events are not
///       reported to the `grab_window`.
///
///   - __grab_window__:
///       Specifies the window on which the pointer should be grabbed.
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
///
///   - __pointer_mode__:
///
///
///   - __keyboard_mode__:
///
pub fn grab_keyboard<'a>(c            : &'a base::Connection,
                         owner_events : bool,
                         grab_window  : Window,
                         time         : Timestamp,
                         pointer_mode : u8,
                         keyboard_mode: u8)
        -> GrabKeyboardCookie<'a> {
    unsafe {
        let cookie = xcb_grab_keyboard(c.get_raw_conn(),
                                       owner_events as u8,  // 0
                                       grab_window as xcb_window_t,  // 1
                                       time as xcb_timestamp_t,  // 2
                                       pointer_mode as u8,  // 3
                                       keyboard_mode as u8);  // 4
        GrabKeyboardCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner_events__:
///       If 1, the `grab_window` will still get the pointer events. If 0, events are not
///       reported to the `grab_window`.
///
///   - __grab_window__:
///       Specifies the window on which the pointer should be grabbed.
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
///
///   - __pointer_mode__:
///
///
///   - __keyboard_mode__:
///
pub fn grab_keyboard_unchecked<'a>(c            : &'a base::Connection,
                                   owner_events : bool,
                                   grab_window  : Window,
                                   time         : Timestamp,
                                   pointer_mode : u8,
                                   keyboard_mode: u8)
        -> GrabKeyboardCookie<'a> {
    unsafe {
        let cookie = xcb_grab_keyboard_unchecked(c.get_raw_conn(),
                                                 owner_events as u8,  // 0
                                                 grab_window as xcb_window_t,  // 1
                                                 time as xcb_timestamp_t,  // 2
                                                 pointer_mode as u8,  // 3
                                                 keyboard_mode as u8);  // 4
        GrabKeyboardCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const UNGRAB_KEYBOARD: u8 = 32;

pub fn ungrab_keyboard<'a>(c   : &'a base::Connection,
                           time: Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_keyboard(c.get_raw_conn(),
                                         time as xcb_timestamp_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn ungrab_keyboard_checked<'a>(c   : &'a base::Connection,
                                   time: Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_keyboard_checked(c.get_raw_conn(),
                                                 time as xcb_timestamp_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GRAB_KEY: u8 = 33;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner_events__:
///       If 1, the `grab_window` will still get the pointer events. If 0, events are not
///       reported to the `grab_window`.
///
///   - __grab_window__:
///       Specifies the window on which the pointer should be grabbed.
///
///   - __modifiers__:
///       The modifiers to grab.
///
///       Using the special value `XCB_MOD_MASK_ANY` means grab the pointer with all
///       possible modifier combinations.
///
///   - __key__:
///       The keycode of the key to grab.
///
///       The special value `XCB_GRAB_ANY` means grab any key.
///
///   - __pointer_mode__:
///
///
///   - __keyboard_mode__:
///
pub fn grab_key<'a>(c            : &'a base::Connection,
                    owner_events : bool,
                    grab_window  : Window,
                    modifiers    : u16,
                    key          : Keycode,
                    pointer_mode : u8,
                    keyboard_mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_grab_key(c.get_raw_conn(),
                                  owner_events as u8,  // 0
                                  grab_window as xcb_window_t,  // 1
                                  modifiers as u16,  // 2
                                  key as xcb_keycode_t,  // 3
                                  pointer_mode as u8,  // 4
                                  keyboard_mode as u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __owner_events__:
///       If 1, the `grab_window` will still get the pointer events. If 0, events are not
///       reported to the `grab_window`.
///
///   - __grab_window__:
///       Specifies the window on which the pointer should be grabbed.
///
///   - __modifiers__:
///       The modifiers to grab.
///
///       Using the special value `XCB_MOD_MASK_ANY` means grab the pointer with all
///       possible modifier combinations.
///
///   - __key__:
///       The keycode of the key to grab.
///
///       The special value `XCB_GRAB_ANY` means grab any key.
///
///   - __pointer_mode__:
///
///
///   - __keyboard_mode__:
///
pub fn grab_key_checked<'a>(c            : &'a base::Connection,
                            owner_events : bool,
                            grab_window  : Window,
                            modifiers    : u16,
                            key          : Keycode,
                            pointer_mode : u8,
                            keyboard_mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_grab_key_checked(c.get_raw_conn(),
                                          owner_events as u8,  // 0
                                          grab_window as xcb_window_t,  // 1
                                          modifiers as u16,  // 2
                                          key as xcb_keycode_t,  // 3
                                          pointer_mode as u8,  // 4
                                          keyboard_mode as u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNGRAB_KEY: u8 = 34;

/// release a key combination
///
/// Releases the key combination on `grab_window` if you grabbed it using
/// `xcb_grab_key` before.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __key__:
///       The keycode of the specified key combination.
///
///       Using the special value `XCB_GRAB_ANY` means releasing all possible key codes.
///
///   - __grab_window__:
///       The window on which the grabbed key combination will be released.
///
///   - __modifiers__:
///       The modifiers of the specified key combination.
///
///       Using the special value `XCB_MOD_MASK_ANY` means releasing the key combination
///       with every possible modifier combination.
pub fn ungrab_key<'a>(c          : &'a base::Connection,
                      key        : Keycode,
                      grab_window: Window,
                      modifiers  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_key(c.get_raw_conn(),
                                    key as xcb_keycode_t,  // 0
                                    grab_window as xcb_window_t,  // 1
                                    modifiers as u16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// release a key combination
///
/// Releases the key combination on `grab_window` if you grabbed it using
/// `xcb_grab_key` before.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __key__:
///       The keycode of the specified key combination.
///
///       Using the special value `XCB_GRAB_ANY` means releasing all possible key codes.
///
///   - __grab_window__:
///       The window on which the grabbed key combination will be released.
///
///   - __modifiers__:
///       The modifiers of the specified key combination.
///
///       Using the special value `XCB_MOD_MASK_ANY` means releasing the key combination
///       with every possible modifier combination.
pub fn ungrab_key_checked<'a>(c          : &'a base::Connection,
                              key        : Keycode,
                              grab_window: Window,
                              modifiers  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_key_checked(c.get_raw_conn(),
                                            key as xcb_keycode_t,  // 0
                                            grab_window as xcb_window_t,  // 1
                                            modifiers as u16);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ALLOW_EVENTS: u8 = 35;

/// release queued events
///
/// Releases queued events if the client has caused a device (pointer/keyboard) to
/// freeze due to grabbing it actively. This request has no effect if `time` is
/// earlier than the last-grab time of the most recent active grab for this client
/// or if `time` is later than the current X server time.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __mode__:
///
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
pub fn allow_events<'a>(c   : &'a base::Connection,
                        mode: u8,
                        time: Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_allow_events(c.get_raw_conn(),
                                      mode as u8,  // 0
                                      time as xcb_timestamp_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// release queued events
///
/// Releases queued events if the client has caused a device (pointer/keyboard) to
/// freeze due to grabbing it actively. This request has no effect if `time` is
/// earlier than the last-grab time of the most recent active grab for this client
/// or if `time` is later than the current X server time.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __mode__:
///
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
pub fn allow_events_checked<'a>(c   : &'a base::Connection,
                                mode: u8,
                                time: Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_allow_events_checked(c.get_raw_conn(),
                                              mode as u8,  // 0
                                              time as xcb_timestamp_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GRAB_SERVER: u8 = 36;

pub fn grab_server<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_grab_server(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn grab_server_checked<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_grab_server_checked(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNGRAB_SERVER: u8 = 37;

pub fn ungrab_server<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_server(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn ungrab_server_checked<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_ungrab_server_checked(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_POINTER: u8 = 38;

pub type QueryPointerCookie<'a> = base::Cookie<'a, xcb_query_pointer_cookie_t>;

impl<'a> QueryPointerCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryPointerReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryPointerReply {
                    ptr: xcb_query_pointer_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryPointerReply {
                    ptr: xcb_query_pointer_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryPointerReply = base::Reply<xcb_query_pointer_reply_t>;

impl QueryPointerReply {
    pub fn same_screen(&self) -> bool {
        unsafe {
            (*self.ptr).same_screen != 0
        }
    }
    pub fn root(&self) -> Window {
        unsafe {
            (*self.ptr).root
        }
    }
    pub fn child(&self) -> Window {
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
    pub fn win_x(&self) -> i16 {
        unsafe {
            (*self.ptr).win_x
        }
    }
    pub fn win_y(&self) -> i16 {
        unsafe {
            (*self.ptr).win_y
        }
    }
    pub fn mask(&self) -> u16 {
        unsafe {
            (*self.ptr).mask
        }
    }
}

/// get pointer coordinates
///
/// Gets the root window the pointer is logically on and the pointer coordinates
/// relative to the root window's origin.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       A window to check if the pointer is on the same screen as `window` (see the
///       `same_screen` field in the reply).
pub fn query_pointer<'a>(c     : &'a base::Connection,
                         window: Window)
        -> QueryPointerCookie<'a> {
    unsafe {
        let cookie = xcb_query_pointer(c.get_raw_conn(),
                                       window as xcb_window_t);  // 0
        QueryPointerCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// get pointer coordinates
///
/// Gets the root window the pointer is logically on and the pointer coordinates
/// relative to the root window's origin.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __window__:
///       A window to check if the pointer is on the same screen as `window` (see the
///       `same_screen` field in the reply).
pub fn query_pointer_unchecked<'a>(c     : &'a base::Connection,
                                   window: Window)
        -> QueryPointerCookie<'a> {
    unsafe {
        let cookie = xcb_query_pointer_unchecked(c.get_raw_conn(),
                                                 window as xcb_window_t);  // 0
        QueryPointerCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

#[derive(Copy, Clone)]
pub struct Timecoord {
    pub base: xcb_timecoord_t,
}

impl Timecoord {
    #[allow(unused_unsafe)]
    pub fn new(time: Timestamp,
               x:    i16,
               y:    i16)
            -> Timecoord {
        unsafe {
            Timecoord {
                base: xcb_timecoord_t {
                    time: time,
                    x:    x,
                    y:    y,
                }
            }
        }
    }
    pub fn time(&self) -> Timestamp {
        unsafe {
            self.base.time
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
}

pub type TimecoordIterator = xcb_timecoord_iterator_t;

impl Iterator for TimecoordIterator {
    type Item = Timecoord;
    fn next(&mut self) -> std::option::Option<Timecoord> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_timecoord_iterator_t;
                let data = (*iter).data;
                xcb_timecoord_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const GET_MOTION_EVENTS: u8 = 39;

pub type GetMotionEventsCookie<'a> = base::Cookie<'a, xcb_get_motion_events_cookie_t>;

impl<'a> GetMotionEventsCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMotionEventsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMotionEventsReply {
                    ptr: xcb_get_motion_events_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMotionEventsReply {
                    ptr: xcb_get_motion_events_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMotionEventsReply = base::Reply<xcb_get_motion_events_reply_t>;

impl GetMotionEventsReply {
    pub fn events_len(&self) -> u32 {
        unsafe {
            (*self.ptr).events_len
        }
    }
    pub fn events(&self) -> TimecoordIterator {
        unsafe {
            xcb_get_motion_events_events_iterator(self.ptr)
        }
    }
}

pub fn get_motion_events<'a>(c     : &'a base::Connection,
                             window: Window,
                             start : Timestamp,
                             stop  : Timestamp)
        -> GetMotionEventsCookie<'a> {
    unsafe {
        let cookie = xcb_get_motion_events(c.get_raw_conn(),
                                           window as xcb_window_t,  // 0
                                           start as xcb_timestamp_t,  // 1
                                           stop as xcb_timestamp_t);  // 2
        GetMotionEventsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_motion_events_unchecked<'a>(c     : &'a base::Connection,
                                       window: Window,
                                       start : Timestamp,
                                       stop  : Timestamp)
        -> GetMotionEventsCookie<'a> {
    unsafe {
        let cookie = xcb_get_motion_events_unchecked(c.get_raw_conn(),
                                                     window as xcb_window_t,  // 0
                                                     start as xcb_timestamp_t,  // 1
                                                     stop as xcb_timestamp_t);  // 2
        GetMotionEventsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const TRANSLATE_COORDINATES: u8 = 40;

pub type TranslateCoordinatesCookie<'a> = base::Cookie<'a, xcb_translate_coordinates_cookie_t>;

impl<'a> TranslateCoordinatesCookie<'a> {
    pub fn get_reply(&self) -> Result<TranslateCoordinatesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = TranslateCoordinatesReply {
                    ptr: xcb_translate_coordinates_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( TranslateCoordinatesReply {
                    ptr: xcb_translate_coordinates_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type TranslateCoordinatesReply = base::Reply<xcb_translate_coordinates_reply_t>;

impl TranslateCoordinatesReply {
    pub fn same_screen(&self) -> bool {
        unsafe {
            (*self.ptr).same_screen != 0
        }
    }
    pub fn child(&self) -> Window {
        unsafe {
            (*self.ptr).child
        }
    }
    pub fn dst_x(&self) -> i16 {
        unsafe {
            (*self.ptr).dst_x
        }
    }
    pub fn dst_y(&self) -> i16 {
        unsafe {
            (*self.ptr).dst_y
        }
    }
}

pub fn translate_coordinates<'a>(c         : &'a base::Connection,
                                 src_window: Window,
                                 dst_window: Window,
                                 src_x     : i16,
                                 src_y     : i16)
        -> TranslateCoordinatesCookie<'a> {
    unsafe {
        let cookie = xcb_translate_coordinates(c.get_raw_conn(),
                                               src_window as xcb_window_t,  // 0
                                               dst_window as xcb_window_t,  // 1
                                               src_x as i16,  // 2
                                               src_y as i16);  // 3
        TranslateCoordinatesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn translate_coordinates_unchecked<'a>(c         : &'a base::Connection,
                                           src_window: Window,
                                           dst_window: Window,
                                           src_x     : i16,
                                           src_y     : i16)
        -> TranslateCoordinatesCookie<'a> {
    unsafe {
        let cookie = xcb_translate_coordinates_unchecked(c.get_raw_conn(),
                                                         src_window as xcb_window_t,  // 0
                                                         dst_window as xcb_window_t,  // 1
                                                         src_x as i16,  // 2
                                                         src_y as i16);  // 3
        TranslateCoordinatesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const WARP_POINTER: u8 = 41;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __src_window__:
///       If `src_window` is not `XCB_NONE` (TODO), the move will only take place if the
///       pointer is inside `src_window` and within the rectangle specified by (`src_x`,
///       `src_y`, `src_width`, `src_height`). The rectangle coordinates are relative to
///       `src_window`.
///
///   - __dst_window__:
///       If `dst_window` is not `XCB_NONE` (TODO), the pointer will be moved to the
///       offsets (`dst_x`, `dst_y`) relative to `dst_window`. If `dst_window` is
///       `XCB_NONE` (TODO), the pointer will be moved by the offsets (`dst_x`, `dst_y`)
///       relative to the current position of the pointer.
///
///   - __src_x__:
///
///   - __src_y__:
///
///   - __src_width__:
///
///   - __src_height__:
///
///   - __dst_x__:
///
///   - __dst_y__:
pub fn warp_pointer<'a>(c         : &'a base::Connection,
                        src_window: Window,
                        dst_window: Window,
                        src_x     : i16,
                        src_y     : i16,
                        src_width : u16,
                        src_height: u16,
                        dst_x     : i16,
                        dst_y     : i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_warp_pointer(c.get_raw_conn(),
                                      src_window as xcb_window_t,  // 0
                                      dst_window as xcb_window_t,  // 1
                                      src_x as i16,  // 2
                                      src_y as i16,  // 3
                                      src_width as u16,  // 4
                                      src_height as u16,  // 5
                                      dst_x as i16,  // 6
                                      dst_y as i16);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __src_window__:
///       If `src_window` is not `XCB_NONE` (TODO), the move will only take place if the
///       pointer is inside `src_window` and within the rectangle specified by (`src_x`,
///       `src_y`, `src_width`, `src_height`). The rectangle coordinates are relative to
///       `src_window`.
///
///   - __dst_window__:
///       If `dst_window` is not `XCB_NONE` (TODO), the pointer will be moved to the
///       offsets (`dst_x`, `dst_y`) relative to `dst_window`. If `dst_window` is
///       `XCB_NONE` (TODO), the pointer will be moved by the offsets (`dst_x`, `dst_y`)
///       relative to the current position of the pointer.
///
///   - __src_x__:
///
///   - __src_y__:
///
///   - __src_width__:
///
///   - __src_height__:
///
///   - __dst_x__:
///
///   - __dst_y__:
pub fn warp_pointer_checked<'a>(c         : &'a base::Connection,
                                src_window: Window,
                                dst_window: Window,
                                src_x     : i16,
                                src_y     : i16,
                                src_width : u16,
                                src_height: u16,
                                dst_x     : i16,
                                dst_y     : i16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_warp_pointer_checked(c.get_raw_conn(),
                                              src_window as xcb_window_t,  // 0
                                              dst_window as xcb_window_t,  // 1
                                              src_x as i16,  // 2
                                              src_y as i16,  // 3
                                              src_width as u16,  // 4
                                              src_height as u16,  // 5
                                              dst_x as i16,  // 6
                                              dst_y as i16);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_INPUT_FOCUS: u8 = 42;

/// Sets input focus
///
/// Changes the input focus and the last-focus-change time. If the specified `time`
/// is earlier than the current last-focus-change time, the request is ignored (to
/// avoid race conditions when running X over the network).
///
/// A FocusIn and FocusOut event is generated when focus is changed.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __revert_to__:
///       Specifies what happens when the `focus` window becomes unviewable (if `focus`
///       is neither `XCB_NONE` nor `XCB_POINTER_ROOT`).
///
///   - __focus__:
///       The window to focus. All keyboard events will be reported to this window. The
///       window must be viewable (TODO), or a `xcb_match_error_t` occurs (TODO).
///
///       If `focus` is `XCB_NONE` (TODO), all keyboard events are
///       discarded until a new focus window is set.
///
///       If `focus` is `XCB_POINTER_ROOT` (TODO), focus is on the root window of the
///       screen on which the pointer is on currently.
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
pub fn set_input_focus<'a>(c        : &'a base::Connection,
                           revert_to: u8,
                           focus    : Window,
                           time     : Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_input_focus(c.get_raw_conn(),
                                         revert_to as u8,  // 0
                                         focus as xcb_window_t,  // 1
                                         time as xcb_timestamp_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Sets input focus
///
/// Changes the input focus and the last-focus-change time. If the specified `time`
/// is earlier than the current last-focus-change time, the request is ignored (to
/// avoid race conditions when running X over the network).
///
/// A FocusIn and FocusOut event is generated when focus is changed.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __revert_to__:
///       Specifies what happens when the `focus` window becomes unviewable (if `focus`
///       is neither `XCB_NONE` nor `XCB_POINTER_ROOT`).
///
///   - __focus__:
///       The window to focus. All keyboard events will be reported to this window. The
///       window must be viewable (TODO), or a `xcb_match_error_t` occurs (TODO).
///
///       If `focus` is `XCB_NONE` (TODO), all keyboard events are
///       discarded until a new focus window is set.
///
///       If `focus` is `XCB_POINTER_ROOT` (TODO), focus is on the root window of the
///       screen on which the pointer is on currently.
///
///   - __time__:
///       Timestamp to avoid race conditions when running X over the network.
///
///       The special value `XCB_CURRENT_TIME` will be replaced with the current server
///       time.
pub fn set_input_focus_checked<'a>(c        : &'a base::Connection,
                                   revert_to: u8,
                                   focus    : Window,
                                   time     : Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_input_focus_checked(c.get_raw_conn(),
                                                 revert_to as u8,  // 0
                                                 focus as xcb_window_t,  // 1
                                                 time as xcb_timestamp_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_INPUT_FOCUS: u8 = 43;

pub type GetInputFocusCookie<'a> = base::Cookie<'a, xcb_get_input_focus_cookie_t>;

impl<'a> GetInputFocusCookie<'a> {
    pub fn get_reply(&self) -> Result<GetInputFocusReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetInputFocusReply {
                    ptr: xcb_get_input_focus_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetInputFocusReply {
                    ptr: xcb_get_input_focus_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetInputFocusReply = base::Reply<xcb_get_input_focus_reply_t>;

impl GetInputFocusReply {
    pub fn revert_to(&self) -> u8 {
        unsafe {
            (*self.ptr).revert_to
        }
    }
    pub fn focus(&self) -> Window {
        unsafe {
            (*self.ptr).focus
        }
    }
}

pub fn get_input_focus<'a>(c: &'a base::Connection)
        -> GetInputFocusCookie<'a> {
    unsafe {
        let cookie = xcb_get_input_focus(c.get_raw_conn());
        GetInputFocusCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_input_focus_unchecked<'a>(c: &'a base::Connection)
        -> GetInputFocusCookie<'a> {
    unsafe {
        let cookie = xcb_get_input_focus_unchecked(c.get_raw_conn());
        GetInputFocusCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_KEYMAP: u8 = 44;

pub type QueryKeymapCookie<'a> = base::Cookie<'a, xcb_query_keymap_cookie_t>;

impl<'a> QueryKeymapCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryKeymapReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryKeymapReply {
                    ptr: xcb_query_keymap_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryKeymapReply {
                    ptr: xcb_query_keymap_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryKeymapReply = base::Reply<xcb_query_keymap_reply_t>;

impl QueryKeymapReply {
    pub fn keys(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).keys
        }
    }
}

pub fn query_keymap<'a>(c: &'a base::Connection)
        -> QueryKeymapCookie<'a> {
    unsafe {
        let cookie = xcb_query_keymap(c.get_raw_conn());
        QueryKeymapCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_keymap_unchecked<'a>(c: &'a base::Connection)
        -> QueryKeymapCookie<'a> {
    unsafe {
        let cookie = xcb_query_keymap_unchecked(c.get_raw_conn());
        QueryKeymapCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const OPEN_FONT: u8 = 45;

/// opens a font
///
/// Opens any X core font matching the given `name` (for example "-misc-fixed-*").
///
/// Note that X core fonts are deprecated (but still supported) in favor of
/// client-side rendering using Xft.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __fid__:
///       The ID with which you will refer to the font, created by `xcb_generate_id`.
///
///   - __name__:
///       A pattern describing an X core font.
pub fn open_font<'a>(c   : &'a base::Connection,
                     fid : Font,
                     name: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_open_font(c.get_raw_conn(),
                                   fid as xcb_font_t,  // 0
                                   name_len as u16,  // 1
                                   name_ptr as *const c_char);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// opens a font
///
/// Opens any X core font matching the given `name` (for example "-misc-fixed-*").
///
/// Note that X core fonts are deprecated (but still supported) in favor of
/// client-side rendering using Xft.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __fid__:
///       The ID with which you will refer to the font, created by `xcb_generate_id`.
///
///   - __name__:
///       A pattern describing an X core font.
pub fn open_font_checked<'a>(c   : &'a base::Connection,
                             fid : Font,
                             name: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_open_font_checked(c.get_raw_conn(),
                                           fid as xcb_font_t,  // 0
                                           name_len as u16,  // 1
                                           name_ptr as *const c_char);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CLOSE_FONT: u8 = 46;

pub fn close_font<'a>(c   : &'a base::Connection,
                      font: Font)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_close_font(c.get_raw_conn(),
                                    font as xcb_font_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn close_font_checked<'a>(c   : &'a base::Connection,
                              font: Font)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_close_font_checked(c.get_raw_conn(),
                                            font as xcb_font_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct Fontprop {
    pub base: xcb_fontprop_t,
}

impl Fontprop {
    #[allow(unused_unsafe)]
    pub fn new(name:  Atom,
               value: u32)
            -> Fontprop {
        unsafe {
            Fontprop {
                base: xcb_fontprop_t {
                    name:  name,
                    value: value,
                }
            }
        }
    }
    pub fn name(&self) -> Atom {
        unsafe {
            self.base.name
        }
    }
    pub fn value(&self) -> u32 {
        unsafe {
            self.base.value
        }
    }
}

pub type FontpropIterator = xcb_fontprop_iterator_t;

impl Iterator for FontpropIterator {
    type Item = Fontprop;
    fn next(&mut self) -> std::option::Option<Fontprop> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_fontprop_iterator_t;
                let data = (*iter).data;
                xcb_fontprop_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Charinfo {
    pub base: xcb_charinfo_t,
}

impl Charinfo {
    #[allow(unused_unsafe)]
    pub fn new(left_side_bearing:  i16,
               right_side_bearing: i16,
               character_width:    i16,
               ascent:             i16,
               descent:            i16,
               attributes:         u16)
            -> Charinfo {
        unsafe {
            Charinfo {
                base: xcb_charinfo_t {
                    left_side_bearing:  left_side_bearing,
                    right_side_bearing: right_side_bearing,
                    character_width:    character_width,
                    ascent:             ascent,
                    descent:            descent,
                    attributes:         attributes,
                }
            }
        }
    }
    pub fn left_side_bearing(&self) -> i16 {
        unsafe {
            self.base.left_side_bearing
        }
    }
    pub fn right_side_bearing(&self) -> i16 {
        unsafe {
            self.base.right_side_bearing
        }
    }
    pub fn character_width(&self) -> i16 {
        unsafe {
            self.base.character_width
        }
    }
    pub fn ascent(&self) -> i16 {
        unsafe {
            self.base.ascent
        }
    }
    pub fn descent(&self) -> i16 {
        unsafe {
            self.base.descent
        }
    }
    pub fn attributes(&self) -> u16 {
        unsafe {
            self.base.attributes
        }
    }
}

pub type CharinfoIterator = xcb_charinfo_iterator_t;

impl Iterator for CharinfoIterator {
    type Item = Charinfo;
    fn next(&mut self) -> std::option::Option<Charinfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_charinfo_iterator_t;
                let data = (*iter).data;
                xcb_charinfo_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const QUERY_FONT: u8 = 47;

pub type QueryFontCookie<'a> = base::Cookie<'a, xcb_query_font_cookie_t>;

impl<'a> QueryFontCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryFontReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryFontReply {
                    ptr: xcb_query_font_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryFontReply {
                    ptr: xcb_query_font_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryFontReply = base::Reply<xcb_query_font_reply_t>;

impl QueryFontReply {
    pub fn min_bounds(&self) -> Charinfo {
        unsafe {
            std::mem::transmute((*self.ptr).min_bounds)
        }
    }
    pub fn max_bounds(&self) -> Charinfo {
        unsafe {
            std::mem::transmute((*self.ptr).max_bounds)
        }
    }
    pub fn min_char_or_byte2(&self) -> u16 {
        unsafe {
            (*self.ptr).min_char_or_byte2
        }
    }
    pub fn max_char_or_byte2(&self) -> u16 {
        unsafe {
            (*self.ptr).max_char_or_byte2
        }
    }
    pub fn default_char(&self) -> u16 {
        unsafe {
            (*self.ptr).default_char
        }
    }
    pub fn properties_len(&self) -> u16 {
        unsafe {
            (*self.ptr).properties_len
        }
    }
    pub fn draw_direction(&self) -> u8 {
        unsafe {
            (*self.ptr).draw_direction
        }
    }
    pub fn min_byte1(&self) -> u8 {
        unsafe {
            (*self.ptr).min_byte1
        }
    }
    pub fn max_byte1(&self) -> u8 {
        unsafe {
            (*self.ptr).max_byte1
        }
    }
    pub fn all_chars_exist(&self) -> bool {
        unsafe {
            (*self.ptr).all_chars_exist != 0
        }
    }
    pub fn font_ascent(&self) -> i16 {
        unsafe {
            (*self.ptr).font_ascent
        }
    }
    pub fn font_descent(&self) -> i16 {
        unsafe {
            (*self.ptr).font_descent
        }
    }
    pub fn char_infos_len(&self) -> u32 {
        unsafe {
            (*self.ptr).char_infos_len
        }
    }
    pub fn properties(&self) -> FontpropIterator {
        unsafe {
            xcb_query_font_properties_iterator(self.ptr)
        }
    }
    pub fn char_infos(&self) -> CharinfoIterator {
        unsafe {
            xcb_query_font_char_infos_iterator(self.ptr)
        }
    }
}

/// query font metrics
///
/// Queries information associated with the font.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __font__:
///       The fontable (Font or Graphics Context) to query.
pub fn query_font<'a>(c   : &'a base::Connection,
                      font: Fontable)
        -> QueryFontCookie<'a> {
    unsafe {
        let cookie = xcb_query_font(c.get_raw_conn(),
                                    font as xcb_fontable_t);  // 0
        QueryFontCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// query font metrics
///
/// Queries information associated with the font.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __font__:
///       The fontable (Font or Graphics Context) to query.
pub fn query_font_unchecked<'a>(c   : &'a base::Connection,
                                font: Fontable)
        -> QueryFontCookie<'a> {
    unsafe {
        let cookie = xcb_query_font_unchecked(c.get_raw_conn(),
                                              font as xcb_fontable_t);  // 0
        QueryFontCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_TEXT_EXTENTS: u8 = 48;

pub type QueryTextExtentsCookie<'a> = base::Cookie<'a, xcb_query_text_extents_cookie_t>;

impl<'a> QueryTextExtentsCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryTextExtentsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryTextExtentsReply {
                    ptr: xcb_query_text_extents_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryTextExtentsReply {
                    ptr: xcb_query_text_extents_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryTextExtentsReply = base::Reply<xcb_query_text_extents_reply_t>;

impl QueryTextExtentsReply {
    pub fn draw_direction(&self) -> u8 {
        unsafe {
            (*self.ptr).draw_direction
        }
    }
    pub fn font_ascent(&self) -> i16 {
        unsafe {
            (*self.ptr).font_ascent
        }
    }
    pub fn font_descent(&self) -> i16 {
        unsafe {
            (*self.ptr).font_descent
        }
    }
    pub fn overall_ascent(&self) -> i16 {
        unsafe {
            (*self.ptr).overall_ascent
        }
    }
    pub fn overall_descent(&self) -> i16 {
        unsafe {
            (*self.ptr).overall_descent
        }
    }
    pub fn overall_width(&self) -> i32 {
        unsafe {
            (*self.ptr).overall_width
        }
    }
    pub fn overall_left(&self) -> i32 {
        unsafe {
            (*self.ptr).overall_left
        }
    }
    pub fn overall_right(&self) -> i32 {
        unsafe {
            (*self.ptr).overall_right
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __font__:
///       The `font` to calculate text extents in. You can also pass a graphics context.
///
///   - __string__:
///       The text to get text extents for.
pub fn query_text_extents<'a>(c     : &'a base::Connection,
                              font  : Fontable,
                              string: &[Char2b])
        -> QueryTextExtentsCookie<'a> {
    unsafe {
        let string_len = string.len();
        let string_ptr = string.as_ptr();
        let cookie = xcb_query_text_extents(c.get_raw_conn(),
                                            font as xcb_fontable_t,  // 0
                                            string_len as u32,  // 1
                                            string_ptr as *const xcb_char2b_t);  // 2
        QueryTextExtentsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __font__:
///       The `font` to calculate text extents in. You can also pass a graphics context.
///
///   - __string__:
///       The text to get text extents for.
pub fn query_text_extents_unchecked<'a>(c     : &'a base::Connection,
                                        font  : Fontable,
                                        string: &[Char2b])
        -> QueryTextExtentsCookie<'a> {
    unsafe {
        let string_len = string.len();
        let string_ptr = string.as_ptr();
        let cookie = xcb_query_text_extents_unchecked(c.get_raw_conn(),
                                                      font as xcb_fontable_t,  // 0
                                                      string_len as u32,  // 1
                                                      string_ptr as *const xcb_char2b_t);  // 2
        QueryTextExtentsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub type Str<'a> = base::StructPtr<'a, xcb_str_t>;

impl<'a> Str<'a> {
    pub fn name_len(&self) -> u8 {
        unsafe {
            (*self.ptr).name_len
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_str_name_length(field) as usize;
            let data = xcb_str_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type StrIterator<'a> = xcb_str_iterator_t<'a>;

impl<'a> Iterator for StrIterator<'a> {
    type Item = Str<'a>;
    fn next(&mut self) -> std::option::Option<Str<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_str_iterator_t;
                let data = (*iter).data;
                xcb_str_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const LIST_FONTS: u8 = 49;

pub type ListFontsCookie<'a> = base::Cookie<'a, xcb_list_fonts_cookie_t>;

impl<'a> ListFontsCookie<'a> {
    pub fn get_reply(&self) -> Result<ListFontsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListFontsReply {
                    ptr: xcb_list_fonts_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListFontsReply {
                    ptr: xcb_list_fonts_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListFontsReply = base::Reply<xcb_list_fonts_reply_t>;

impl ListFontsReply {
    pub fn names_len(&self) -> u16 {
        unsafe {
            (*self.ptr).names_len
        }
    }
    pub fn names(&self) -> StrIterator {
        unsafe {
            xcb_list_fonts_names_iterator(self.ptr)
        }
    }
}

/// get matching font names
///
/// Gets a list of available font names which match the given `pattern`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __max_names__:
///       The maximum number of fonts to be returned.
///
///   - __pattern__:
///       A font pattern, for example "-misc-fixed-*".
///
///       The asterisk (*) is a wildcard for any number of characters. The question mark
///       (?) is a wildcard for a single character. Use of uppercase or lowercase does
///       not matter.
pub fn list_fonts<'a>(c        : &'a base::Connection,
                      max_names: u16,
                      pattern  : &str)
        -> ListFontsCookie<'a> {
    unsafe {
        let pattern = pattern.as_bytes();
        let pattern_len = pattern.len();
        let pattern_ptr = pattern.as_ptr();
        let cookie = xcb_list_fonts(c.get_raw_conn(),
                                    max_names as u16,  // 0
                                    pattern_len as u16,  // 1
                                    pattern_ptr as *const c_char);  // 2
        ListFontsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// get matching font names
///
/// Gets a list of available font names which match the given `pattern`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __max_names__:
///       The maximum number of fonts to be returned.
///
///   - __pattern__:
///       A font pattern, for example "-misc-fixed-*".
///
///       The asterisk (*) is a wildcard for any number of characters. The question mark
///       (?) is a wildcard for a single character. Use of uppercase or lowercase does
///       not matter.
pub fn list_fonts_unchecked<'a>(c        : &'a base::Connection,
                                max_names: u16,
                                pattern  : &str)
        -> ListFontsCookie<'a> {
    unsafe {
        let pattern = pattern.as_bytes();
        let pattern_len = pattern.len();
        let pattern_ptr = pattern.as_ptr();
        let cookie = xcb_list_fonts_unchecked(c.get_raw_conn(),
                                              max_names as u16,  // 0
                                              pattern_len as u16,  // 1
                                              pattern_ptr as *const c_char);  // 2
        ListFontsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_FONTS_WITH_INFO: u8 = 50;

pub type ListFontsWithInfoCookie<'a> = base::Cookie<'a, xcb_list_fonts_with_info_cookie_t>;

impl<'a> ListFontsWithInfoCookie<'a> {
    pub fn get_reply(&self) -> Result<ListFontsWithInfoReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListFontsWithInfoReply {
                    ptr: xcb_list_fonts_with_info_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListFontsWithInfoReply {
                    ptr: xcb_list_fonts_with_info_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListFontsWithInfoReply = base::Reply<xcb_list_fonts_with_info_reply_t>;

impl ListFontsWithInfoReply {
    pub fn name_len(&self) -> u8 {
        unsafe {
            (*self.ptr).name_len
        }
    }
    pub fn min_bounds(&self) -> Charinfo {
        unsafe {
            std::mem::transmute((*self.ptr).min_bounds)
        }
    }
    pub fn max_bounds(&self) -> Charinfo {
        unsafe {
            std::mem::transmute((*self.ptr).max_bounds)
        }
    }
    pub fn min_char_or_byte2(&self) -> u16 {
        unsafe {
            (*self.ptr).min_char_or_byte2
        }
    }
    pub fn max_char_or_byte2(&self) -> u16 {
        unsafe {
            (*self.ptr).max_char_or_byte2
        }
    }
    pub fn default_char(&self) -> u16 {
        unsafe {
            (*self.ptr).default_char
        }
    }
    pub fn properties_len(&self) -> u16 {
        unsafe {
            (*self.ptr).properties_len
        }
    }
    pub fn draw_direction(&self) -> u8 {
        unsafe {
            (*self.ptr).draw_direction
        }
    }
    pub fn min_byte1(&self) -> u8 {
        unsafe {
            (*self.ptr).min_byte1
        }
    }
    pub fn max_byte1(&self) -> u8 {
        unsafe {
            (*self.ptr).max_byte1
        }
    }
    pub fn all_chars_exist(&self) -> bool {
        unsafe {
            (*self.ptr).all_chars_exist != 0
        }
    }
    pub fn font_ascent(&self) -> i16 {
        unsafe {
            (*self.ptr).font_ascent
        }
    }
    pub fn font_descent(&self) -> i16 {
        unsafe {
            (*self.ptr).font_descent
        }
    }
    pub fn replies_hint(&self) -> u32 {
        unsafe {
            (*self.ptr).replies_hint
        }
    }
    pub fn properties(&self) -> FontpropIterator {
        unsafe {
            xcb_list_fonts_with_info_properties_iterator(self.ptr)
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_list_fonts_with_info_name_length(field) as usize;
            let data = xcb_list_fonts_with_info_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

/// get matching font names and information
///
/// Gets a list of available font names which match the given `pattern`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __max_names__:
///       The maximum number of fonts to be returned.
///
///   - __pattern__:
///       A font pattern, for example "-misc-fixed-*".
///
///       The asterisk (*) is a wildcard for any number of characters. The question mark
///       (?) is a wildcard for a single character. Use of uppercase or lowercase does
///       not matter.
pub fn list_fonts_with_info<'a>(c        : &'a base::Connection,
                                max_names: u16,
                                pattern  : &str)
        -> ListFontsWithInfoCookie<'a> {
    unsafe {
        let pattern = pattern.as_bytes();
        let pattern_len = pattern.len();
        let pattern_ptr = pattern.as_ptr();
        let cookie = xcb_list_fonts_with_info(c.get_raw_conn(),
                                              max_names as u16,  // 0
                                              pattern_len as u16,  // 1
                                              pattern_ptr as *const c_char);  // 2
        ListFontsWithInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// get matching font names and information
///
/// Gets a list of available font names which match the given `pattern`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __max_names__:
///       The maximum number of fonts to be returned.
///
///   - __pattern__:
///       A font pattern, for example "-misc-fixed-*".
///
///       The asterisk (*) is a wildcard for any number of characters. The question mark
///       (?) is a wildcard for a single character. Use of uppercase or lowercase does
///       not matter.
pub fn list_fonts_with_info_unchecked<'a>(c        : &'a base::Connection,
                                          max_names: u16,
                                          pattern  : &str)
        -> ListFontsWithInfoCookie<'a> {
    unsafe {
        let pattern = pattern.as_bytes();
        let pattern_len = pattern.len();
        let pattern_ptr = pattern.as_ptr();
        let cookie = xcb_list_fonts_with_info_unchecked(c.get_raw_conn(),
                                                        max_names as u16,  // 0
                                                        pattern_len as u16,  // 1
                                                        pattern_ptr as *const c_char);  // 2
        ListFontsWithInfoCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_FONT_PATH: u8 = 51;

pub fn set_font_path<'a>(c   : &'a base::Connection,
                         font: &[Str])
        -> base::VoidCookie<'a> {
    unsafe {
        let font_len = font.len();
        let font_ptr = font.as_ptr();
        let cookie = xcb_set_font_path(c.get_raw_conn(),
                                       font_len as u16,  // 0
                                       font_ptr as *const xcb_str_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_font_path_checked<'a>(c   : &'a base::Connection,
                                 font: &[Str])
        -> base::VoidCookie<'a> {
    unsafe {
        let font_len = font.len();
        let font_ptr = font.as_ptr();
        let cookie = xcb_set_font_path_checked(c.get_raw_conn(),
                                               font_len as u16,  // 0
                                               font_ptr as *const xcb_str_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_FONT_PATH: u8 = 52;

pub type GetFontPathCookie<'a> = base::Cookie<'a, xcb_get_font_path_cookie_t>;

impl<'a> GetFontPathCookie<'a> {
    pub fn get_reply(&self) -> Result<GetFontPathReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetFontPathReply {
                    ptr: xcb_get_font_path_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetFontPathReply {
                    ptr: xcb_get_font_path_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetFontPathReply = base::Reply<xcb_get_font_path_reply_t>;

impl GetFontPathReply {
    pub fn path_len(&self) -> u16 {
        unsafe {
            (*self.ptr).path_len
        }
    }
    pub fn path(&self) -> StrIterator {
        unsafe {
            xcb_get_font_path_path_iterator(self.ptr)
        }
    }
}

pub fn get_font_path<'a>(c: &'a base::Connection)
        -> GetFontPathCookie<'a> {
    unsafe {
        let cookie = xcb_get_font_path(c.get_raw_conn());
        GetFontPathCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_font_path_unchecked<'a>(c: &'a base::Connection)
        -> GetFontPathCookie<'a> {
    unsafe {
        let cookie = xcb_get_font_path_unchecked(c.get_raw_conn());
        GetFontPathCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_PIXMAP: u8 = 53;

/// Creates a pixmap
///
/// Creates a pixmap. The pixmap can only be used on the same screen as `drawable`
/// is on and only with drawables of the same `depth`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __depth__:
///       TODO
///
///   - __pid__:
///       The ID with which you will refer to the new pixmap, created by
///       `xcb_generate_id`.
///
///   - __drawable__:
///       Drawable to get the screen from.
///
///   - __width__:
///       The width of the new pixmap.
///
///   - __height__:
///       The height of the new pixmap.
pub fn create_pixmap<'a>(c       : &'a base::Connection,
                         depth   : u8,
                         pid     : Pixmap,
                         drawable: Drawable,
                         width   : u16,
                         height  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_create_pixmap(c.get_raw_conn(),
                                       depth as u8,  // 0
                                       pid as xcb_pixmap_t,  // 1
                                       drawable as xcb_drawable_t,  // 2
                                       width as u16,  // 3
                                       height as u16);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Creates a pixmap
///
/// Creates a pixmap. The pixmap can only be used on the same screen as `drawable`
/// is on and only with drawables of the same `depth`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __depth__:
///       TODO
///
///   - __pid__:
///       The ID with which you will refer to the new pixmap, created by
///       `xcb_generate_id`.
///
///   - __drawable__:
///       Drawable to get the screen from.
///
///   - __width__:
///       The width of the new pixmap.
///
///   - __height__:
///       The height of the new pixmap.
pub fn create_pixmap_checked<'a>(c       : &'a base::Connection,
                                 depth   : u8,
                                 pid     : Pixmap,
                                 drawable: Drawable,
                                 width   : u16,
                                 height  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_create_pixmap_checked(c.get_raw_conn(),
                                               depth as u8,  // 0
                                               pid as xcb_pixmap_t,  // 1
                                               drawable as xcb_drawable_t,  // 2
                                               width as u16,  // 3
                                               height as u16);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FREE_PIXMAP: u8 = 54;

/// Destroys a pixmap
///
/// Deletes the association between the pixmap ID and the pixmap. The pixmap
/// storage will be freed when there are no more references to it.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __pixmap__:
///       The pixmap to destroy.
pub fn free_pixmap<'a>(c     : &'a base::Connection,
                       pixmap: Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_free_pixmap(c.get_raw_conn(),
                                     pixmap as xcb_pixmap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Destroys a pixmap
///
/// Deletes the association between the pixmap ID and the pixmap. The pixmap
/// storage will be freed when there are no more references to it.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __pixmap__:
///       The pixmap to destroy.
pub fn free_pixmap_checked<'a>(c     : &'a base::Connection,
                               pixmap: Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_free_pixmap_checked(c.get_raw_conn(),
                                             pixmap as xcb_pixmap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_GC: u8 = 55;

/// Creates a graphics context
///
/// Creates a graphics context. The graphics context can be used with any drawable
/// that has the same root and depth as the specified drawable.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __cid__:
///       The ID with which you will refer to the graphics context, created by
///       `xcb_generate_id`.
///
///   - __drawable__:
///       Drawable to get the root/depth from.
///
///   - __value_list__:
pub fn create_gc<'a>(c         : &'a base::Connection,
                     cid       : Gcontext,
                     drawable  : Drawable,
                     value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_create_gc(c.get_raw_conn(),
                                   cid as xcb_gcontext_t,  // 0
                                   drawable as xcb_drawable_t,  // 1
                                   value_list_mask as u32,  // 2
                                   value_list_ptr as *const u32);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Creates a graphics context
///
/// Creates a graphics context. The graphics context can be used with any drawable
/// that has the same root and depth as the specified drawable.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __cid__:
///       The ID with which you will refer to the graphics context, created by
///       `xcb_generate_id`.
///
///   - __drawable__:
///       Drawable to get the root/depth from.
///
///   - __value_list__:
pub fn create_gc_checked<'a>(c         : &'a base::Connection,
                             cid       : Gcontext,
                             drawable  : Drawable,
                             value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_create_gc_checked(c.get_raw_conn(),
                                           cid as xcb_gcontext_t,  // 0
                                           drawable as xcb_drawable_t,  // 1
                                           value_list_mask as u32,  // 2
                                           value_list_ptr as *const u32);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_GC: u8 = 56;

/// change graphics context components
///
/// Changes the components specified by `value_mask` for the specified graphics context.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __gc__:
///       The graphics context to change.
///
///   - __value_list__:
///       Values for each of the components specified in the bitmask `value_mask`. The
///       order has to correspond to the order of possible `value_mask` bits. See the
///       example.
pub fn change_gc<'a>(c         : &'a base::Connection,
                     gc        : Gcontext,
                     value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_change_gc(c.get_raw_conn(),
                                   gc as xcb_gcontext_t,  // 0
                                   value_list_mask as u32,  // 1
                                   value_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// change graphics context components
///
/// Changes the components specified by `value_mask` for the specified graphics context.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __gc__:
///       The graphics context to change.
///
///   - __value_list__:
///       Values for each of the components specified in the bitmask `value_mask`. The
///       order has to correspond to the order of possible `value_mask` bits. See the
///       example.
pub fn change_gc_checked<'a>(c         : &'a base::Connection,
                             gc        : Gcontext,
                             value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_change_gc_checked(c.get_raw_conn(),
                                           gc as xcb_gcontext_t,  // 0
                                           value_list_mask as u32,  // 1
                                           value_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COPY_GC: u8 = 57;

pub fn copy_gc<'a>(c         : &'a base::Connection,
                   src_gc    : Gcontext,
                   dst_gc    : Gcontext,
                   value_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_copy_gc(c.get_raw_conn(),
                                 src_gc as xcb_gcontext_t,  // 0
                                 dst_gc as xcb_gcontext_t,  // 1
                                 value_mask as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn copy_gc_checked<'a>(c         : &'a base::Connection,
                           src_gc    : Gcontext,
                           dst_gc    : Gcontext,
                           value_mask: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_copy_gc_checked(c.get_raw_conn(),
                                         src_gc as xcb_gcontext_t,  // 0
                                         dst_gc as xcb_gcontext_t,  // 1
                                         value_mask as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_DASHES: u8 = 58;

pub fn set_dashes<'a>(c          : &'a base::Connection,
                      gc         : Gcontext,
                      dash_offset: u16,
                      dashes     : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let dashes_len = dashes.len();
        let dashes_ptr = dashes.as_ptr();
        let cookie = xcb_set_dashes(c.get_raw_conn(),
                                    gc as xcb_gcontext_t,  // 0
                                    dash_offset as u16,  // 1
                                    dashes_len as u16,  // 2
                                    dashes_ptr as *const u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_dashes_checked<'a>(c          : &'a base::Connection,
                              gc         : Gcontext,
                              dash_offset: u16,
                              dashes     : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let dashes_len = dashes.len();
        let dashes_ptr = dashes.as_ptr();
        let cookie = xcb_set_dashes_checked(c.get_raw_conn(),
                                            gc as xcb_gcontext_t,  // 0
                                            dash_offset as u16,  // 1
                                            dashes_len as u16,  // 2
                                            dashes_ptr as *const u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_CLIP_RECTANGLES: u8 = 59;

pub fn set_clip_rectangles<'a>(c            : &'a base::Connection,
                               ordering     : u8,
                               gc           : Gcontext,
                               clip_x_origin: i16,
                               clip_y_origin: i16,
                               rectangles   : &[Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_set_clip_rectangles(c.get_raw_conn(),
                                             ordering as u8,  // 0
                                             gc as xcb_gcontext_t,  // 1
                                             clip_x_origin as i16,  // 2
                                             clip_y_origin as i16,  // 3
                                             rectangles_len as u32,  // 4
                                             rectangles_ptr as *const xcb_rectangle_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_clip_rectangles_checked<'a>(c            : &'a base::Connection,
                                       ordering     : u8,
                                       gc           : Gcontext,
                                       clip_x_origin: i16,
                                       clip_y_origin: i16,
                                       rectangles   : &[Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_set_clip_rectangles_checked(c.get_raw_conn(),
                                                     ordering as u8,  // 0
                                                     gc as xcb_gcontext_t,  // 1
                                                     clip_x_origin as i16,  // 2
                                                     clip_y_origin as i16,  // 3
                                                     rectangles_len as u32,  // 4
                                                     rectangles_ptr as *const xcb_rectangle_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FREE_GC: u8 = 60;

/// Destroys a graphics context
///
/// Destroys the specified `gc` and all associated storage.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __gc__:
///       The graphics context to destroy.
pub fn free_gc<'a>(c : &'a base::Connection,
                   gc: Gcontext)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_free_gc(c.get_raw_conn(),
                                 gc as xcb_gcontext_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Destroys a graphics context
///
/// Destroys the specified `gc` and all associated storage.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __gc__:
///       The graphics context to destroy.
pub fn free_gc_checked<'a>(c : &'a base::Connection,
                           gc: Gcontext)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_free_gc_checked(c.get_raw_conn(),
                                         gc as xcb_gcontext_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CLEAR_AREA: u8 = 61;

pub fn clear_area<'a>(c        : &'a base::Connection,
                      exposures: bool,
                      window   : Window,
                      x        : i16,
                      y        : i16,
                      width    : u16,
                      height   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_clear_area(c.get_raw_conn(),
                                    exposures as u8,  // 0
                                    window as xcb_window_t,  // 1
                                    x as i16,  // 2
                                    y as i16,  // 3
                                    width as u16,  // 4
                                    height as u16);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn clear_area_checked<'a>(c        : &'a base::Connection,
                              exposures: bool,
                              window   : Window,
                              x        : i16,
                              y        : i16,
                              width    : u16,
                              height   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_clear_area_checked(c.get_raw_conn(),
                                            exposures as u8,  // 0
                                            window as xcb_window_t,  // 1
                                            x as i16,  // 2
                                            y as i16,  // 3
                                            width as u16,  // 4
                                            height as u16);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COPY_AREA: u8 = 62;

/// copy areas
///
/// Copies the specified rectangle from `src_drawable` to `dst_drawable`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __src_drawable__:
///       The source drawable (Window or Pixmap).
///
///   - __dst_drawable__:
///       The destination drawable (Window or Pixmap).
///
///   - __gc__:
///       The graphics context to use.
///
///   - __src_x__:
///       The source X coordinate.
///
///   - __src_y__:
///       The source Y coordinate.
///
///   - __dst_x__:
///       The destination X coordinate.
///
///   - __dst_y__:
///       The destination Y coordinate.
///
///   - __width__:
///       The width of the area to copy (in pixels).
///
///   - __height__:
///       The height of the area to copy (in pixels).
pub fn copy_area<'a>(c           : &'a base::Connection,
                     src_drawable: Drawable,
                     dst_drawable: Drawable,
                     gc          : Gcontext,
                     src_x       : i16,
                     src_y       : i16,
                     dst_x       : i16,
                     dst_y       : i16,
                     width       : u16,
                     height      : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_copy_area(c.get_raw_conn(),
                                   src_drawable as xcb_drawable_t,  // 0
                                   dst_drawable as xcb_drawable_t,  // 1
                                   gc as xcb_gcontext_t,  // 2
                                   src_x as i16,  // 3
                                   src_y as i16,  // 4
                                   dst_x as i16,  // 5
                                   dst_y as i16,  // 6
                                   width as u16,  // 7
                                   height as u16);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// copy areas
///
/// Copies the specified rectangle from `src_drawable` to `dst_drawable`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __src_drawable__:
///       The source drawable (Window or Pixmap).
///
///   - __dst_drawable__:
///       The destination drawable (Window or Pixmap).
///
///   - __gc__:
///       The graphics context to use.
///
///   - __src_x__:
///       The source X coordinate.
///
///   - __src_y__:
///       The source Y coordinate.
///
///   - __dst_x__:
///       The destination X coordinate.
///
///   - __dst_y__:
///       The destination Y coordinate.
///
///   - __width__:
///       The width of the area to copy (in pixels).
///
///   - __height__:
///       The height of the area to copy (in pixels).
pub fn copy_area_checked<'a>(c           : &'a base::Connection,
                             src_drawable: Drawable,
                             dst_drawable: Drawable,
                             gc          : Gcontext,
                             src_x       : i16,
                             src_y       : i16,
                             dst_x       : i16,
                             dst_y       : i16,
                             width       : u16,
                             height      : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_copy_area_checked(c.get_raw_conn(),
                                           src_drawable as xcb_drawable_t,  // 0
                                           dst_drawable as xcb_drawable_t,  // 1
                                           gc as xcb_gcontext_t,  // 2
                                           src_x as i16,  // 3
                                           src_y as i16,  // 4
                                           dst_x as i16,  // 5
                                           dst_y as i16,  // 6
                                           width as u16,  // 7
                                           height as u16);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COPY_PLANE: u8 = 63;

pub fn copy_plane<'a>(c           : &'a base::Connection,
                      src_drawable: Drawable,
                      dst_drawable: Drawable,
                      gc          : Gcontext,
                      src_x       : i16,
                      src_y       : i16,
                      dst_x       : i16,
                      dst_y       : i16,
                      width       : u16,
                      height      : u16,
                      bit_plane   : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_copy_plane(c.get_raw_conn(),
                                    src_drawable as xcb_drawable_t,  // 0
                                    dst_drawable as xcb_drawable_t,  // 1
                                    gc as xcb_gcontext_t,  // 2
                                    src_x as i16,  // 3
                                    src_y as i16,  // 4
                                    dst_x as i16,  // 5
                                    dst_y as i16,  // 6
                                    width as u16,  // 7
                                    height as u16,  // 8
                                    bit_plane as u32);  // 9
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn copy_plane_checked<'a>(c           : &'a base::Connection,
                              src_drawable: Drawable,
                              dst_drawable: Drawable,
                              gc          : Gcontext,
                              src_x       : i16,
                              src_y       : i16,
                              dst_x       : i16,
                              dst_y       : i16,
                              width       : u16,
                              height      : u16,
                              bit_plane   : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_copy_plane_checked(c.get_raw_conn(),
                                            src_drawable as xcb_drawable_t,  // 0
                                            dst_drawable as xcb_drawable_t,  // 1
                                            gc as xcb_gcontext_t,  // 2
                                            src_x as i16,  // 3
                                            src_y as i16,  // 4
                                            dst_x as i16,  // 5
                                            dst_y as i16,  // 6
                                            width as u16,  // 7
                                            height as u16,  // 8
                                            bit_plane as u32);  // 9
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const POLY_POINT: u8 = 64;

pub fn poly_point<'a>(c              : &'a base::Connection,
                      coordinate_mode: u8,
                      drawable       : Drawable,
                      gc             : Gcontext,
                      points         : &[Point])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_poly_point(c.get_raw_conn(),
                                    coordinate_mode as u8,  // 0
                                    drawable as xcb_drawable_t,  // 1
                                    gc as xcb_gcontext_t,  // 2
                                    points_len as u32,  // 3
                                    points_ptr as *const xcb_point_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn poly_point_checked<'a>(c              : &'a base::Connection,
                              coordinate_mode: u8,
                              drawable       : Drawable,
                              gc             : Gcontext,
                              points         : &[Point])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_poly_point_checked(c.get_raw_conn(),
                                            coordinate_mode as u8,  // 0
                                            drawable as xcb_drawable_t,  // 1
                                            gc as xcb_gcontext_t,  // 2
                                            points_len as u32,  // 3
                                            points_ptr as *const xcb_point_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const POLY_LINE: u8 = 65;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __coordinate_mode__:
///
///
///   - __drawable__:
///       The drawable to draw the line(s) on.
///
///   - __gc__:
///       The graphics context to use.
///
///   - __points__:
///       An array of points.
pub fn poly_line<'a>(c              : &'a base::Connection,
                     coordinate_mode: u8,
                     drawable       : Drawable,
                     gc             : Gcontext,
                     points         : &[Point])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_poly_line(c.get_raw_conn(),
                                   coordinate_mode as u8,  // 0
                                   drawable as xcb_drawable_t,  // 1
                                   gc as xcb_gcontext_t,  // 2
                                   points_len as u32,  // 3
                                   points_ptr as *const xcb_point_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __coordinate_mode__:
///
///
///   - __drawable__:
///       The drawable to draw the line(s) on.
///
///   - __gc__:
///       The graphics context to use.
///
///   - __points__:
///       An array of points.
pub fn poly_line_checked<'a>(c              : &'a base::Connection,
                             coordinate_mode: u8,
                             drawable       : Drawable,
                             gc             : Gcontext,
                             points         : &[Point])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_poly_line_checked(c.get_raw_conn(),
                                           coordinate_mode as u8,  // 0
                                           drawable as xcb_drawable_t,  // 1
                                           gc as xcb_gcontext_t,  // 2
                                           points_len as u32,  // 3
                                           points_ptr as *const xcb_point_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct Segment {
    pub base: xcb_segment_t,
}

impl Segment {
    #[allow(unused_unsafe)]
    pub fn new(x1: i16,
               y1: i16,
               x2: i16,
               y2: i16)
            -> Segment {
        unsafe {
            Segment {
                base: xcb_segment_t {
                    x1: x1,
                    y1: y1,
                    x2: x2,
                    y2: y2,
                }
            }
        }
    }
    pub fn x1(&self) -> i16 {
        unsafe {
            self.base.x1
        }
    }
    pub fn y1(&self) -> i16 {
        unsafe {
            self.base.y1
        }
    }
    pub fn x2(&self) -> i16 {
        unsafe {
            self.base.x2
        }
    }
    pub fn y2(&self) -> i16 {
        unsafe {
            self.base.y2
        }
    }
}

pub type SegmentIterator = xcb_segment_iterator_t;

impl Iterator for SegmentIterator {
    type Item = Segment;
    fn next(&mut self) -> std::option::Option<Segment> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_segment_iterator_t;
                let data = (*iter).data;
                xcb_segment_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const POLY_SEGMENT: u8 = 66;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       A drawable (Window or Pixmap) to draw on.
///
///   - __gc__:
///       The graphics context to use.
///
///       TODO: document which attributes of a gc are used
///
///   - __segments__:
///       An array of `xcb_segment_t` structures.
pub fn poly_segment<'a>(c       : &'a base::Connection,
                        drawable: Drawable,
                        gc      : Gcontext,
                        segments: &[Segment])
        -> base::VoidCookie<'a> {
    unsafe {
        let segments_len = segments.len();
        let segments_ptr = segments.as_ptr();
        let cookie = xcb_poly_segment(c.get_raw_conn(),
                                      drawable as xcb_drawable_t,  // 0
                                      gc as xcb_gcontext_t,  // 1
                                      segments_len as u32,  // 2
                                      segments_ptr as *const xcb_segment_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       A drawable (Window or Pixmap) to draw on.
///
///   - __gc__:
///       The graphics context to use.
///
///       TODO: document which attributes of a gc are used
///
///   - __segments__:
///       An array of `xcb_segment_t` structures.
pub fn poly_segment_checked<'a>(c       : &'a base::Connection,
                                drawable: Drawable,
                                gc      : Gcontext,
                                segments: &[Segment])
        -> base::VoidCookie<'a> {
    unsafe {
        let segments_len = segments.len();
        let segments_ptr = segments.as_ptr();
        let cookie = xcb_poly_segment_checked(c.get_raw_conn(),
                                              drawable as xcb_drawable_t,  // 0
                                              gc as xcb_gcontext_t,  // 1
                                              segments_len as u32,  // 2
                                              segments_ptr as *const xcb_segment_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const POLY_RECTANGLE: u8 = 67;

pub fn poly_rectangle<'a>(c         : &'a base::Connection,
                          drawable  : Drawable,
                          gc        : Gcontext,
                          rectangles: &[Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_poly_rectangle(c.get_raw_conn(),
                                        drawable as xcb_drawable_t,  // 0
                                        gc as xcb_gcontext_t,  // 1
                                        rectangles_len as u32,  // 2
                                        rectangles_ptr as *const xcb_rectangle_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn poly_rectangle_checked<'a>(c         : &'a base::Connection,
                                  drawable  : Drawable,
                                  gc        : Gcontext,
                                  rectangles: &[Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_poly_rectangle_checked(c.get_raw_conn(),
                                                drawable as xcb_drawable_t,  // 0
                                                gc as xcb_gcontext_t,  // 1
                                                rectangles_len as u32,  // 2
                                                rectangles_ptr as *const xcb_rectangle_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const POLY_ARC: u8 = 68;

pub fn poly_arc<'a>(c       : &'a base::Connection,
                    drawable: Drawable,
                    gc      : Gcontext,
                    arcs    : &[Arc])
        -> base::VoidCookie<'a> {
    unsafe {
        let arcs_len = arcs.len();
        let arcs_ptr = arcs.as_ptr();
        let cookie = xcb_poly_arc(c.get_raw_conn(),
                                  drawable as xcb_drawable_t,  // 0
                                  gc as xcb_gcontext_t,  // 1
                                  arcs_len as u32,  // 2
                                  arcs_ptr as *const xcb_arc_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn poly_arc_checked<'a>(c       : &'a base::Connection,
                            drawable: Drawable,
                            gc      : Gcontext,
                            arcs    : &[Arc])
        -> base::VoidCookie<'a> {
    unsafe {
        let arcs_len = arcs.len();
        let arcs_ptr = arcs.as_ptr();
        let cookie = xcb_poly_arc_checked(c.get_raw_conn(),
                                          drawable as xcb_drawable_t,  // 0
                                          gc as xcb_gcontext_t,  // 1
                                          arcs_len as u32,  // 2
                                          arcs_ptr as *const xcb_arc_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FILL_POLY: u8 = 69;

pub fn fill_poly<'a>(c              : &'a base::Connection,
                     drawable       : Drawable,
                     gc             : Gcontext,
                     shape          : u8,
                     coordinate_mode: u8,
                     points         : &[Point])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_fill_poly(c.get_raw_conn(),
                                   drawable as xcb_drawable_t,  // 0
                                   gc as xcb_gcontext_t,  // 1
                                   shape as u8,  // 2
                                   coordinate_mode as u8,  // 3
                                   points_len as u32,  // 4
                                   points_ptr as *const xcb_point_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn fill_poly_checked<'a>(c              : &'a base::Connection,
                             drawable       : Drawable,
                             gc             : Gcontext,
                             shape          : u8,
                             coordinate_mode: u8,
                             points         : &[Point])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_fill_poly_checked(c.get_raw_conn(),
                                           drawable as xcb_drawable_t,  // 0
                                           gc as xcb_gcontext_t,  // 1
                                           shape as u8,  // 2
                                           coordinate_mode as u8,  // 3
                                           points_len as u32,  // 4
                                           points_ptr as *const xcb_point_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const POLY_FILL_RECTANGLE: u8 = 70;

/// Fills rectangles
///
/// Fills the specified rectangle(s) in the order listed in the array. For any
/// given rectangle, each pixel is not drawn more than once. If rectangles
/// intersect, the intersecting pixels are drawn multiple times.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       The drawable (Window or Pixmap) to draw on.
///
///   - __gc__:
///       The graphics context to use.
///
///       The following graphics context components are used: function, plane-mask,
///       fill-style, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
///
///       The following graphics context mode-dependent components are used:
///       foreground, background, tile, stipple, tile-stipple-x-origin, and
///       tile-stipple-y-origin.
///
///   - __rectangles__:
///       The rectangles to fill.
pub fn poly_fill_rectangle<'a>(c         : &'a base::Connection,
                               drawable  : Drawable,
                               gc        : Gcontext,
                               rectangles: &[Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_poly_fill_rectangle(c.get_raw_conn(),
                                             drawable as xcb_drawable_t,  // 0
                                             gc as xcb_gcontext_t,  // 1
                                             rectangles_len as u32,  // 2
                                             rectangles_ptr as *const xcb_rectangle_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Fills rectangles
///
/// Fills the specified rectangle(s) in the order listed in the array. For any
/// given rectangle, each pixel is not drawn more than once. If rectangles
/// intersect, the intersecting pixels are drawn multiple times.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       The drawable (Window or Pixmap) to draw on.
///
///   - __gc__:
///       The graphics context to use.
///
///       The following graphics context components are used: function, plane-mask,
///       fill-style, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
///
///       The following graphics context mode-dependent components are used:
///       foreground, background, tile, stipple, tile-stipple-x-origin, and
///       tile-stipple-y-origin.
///
///   - __rectangles__:
///       The rectangles to fill.
pub fn poly_fill_rectangle_checked<'a>(c         : &'a base::Connection,
                                       drawable  : Drawable,
                                       gc        : Gcontext,
                                       rectangles: &[Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_poly_fill_rectangle_checked(c.get_raw_conn(),
                                                     drawable as xcb_drawable_t,  // 0
                                                     gc as xcb_gcontext_t,  // 1
                                                     rectangles_len as u32,  // 2
                                                     rectangles_ptr as *const xcb_rectangle_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const POLY_FILL_ARC: u8 = 71;

pub fn poly_fill_arc<'a>(c       : &'a base::Connection,
                         drawable: Drawable,
                         gc      : Gcontext,
                         arcs    : &[Arc])
        -> base::VoidCookie<'a> {
    unsafe {
        let arcs_len = arcs.len();
        let arcs_ptr = arcs.as_ptr();
        let cookie = xcb_poly_fill_arc(c.get_raw_conn(),
                                       drawable as xcb_drawable_t,  // 0
                                       gc as xcb_gcontext_t,  // 1
                                       arcs_len as u32,  // 2
                                       arcs_ptr as *const xcb_arc_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn poly_fill_arc_checked<'a>(c       : &'a base::Connection,
                                 drawable: Drawable,
                                 gc      : Gcontext,
                                 arcs    : &[Arc])
        -> base::VoidCookie<'a> {
    unsafe {
        let arcs_len = arcs.len();
        let arcs_ptr = arcs.as_ptr();
        let cookie = xcb_poly_fill_arc_checked(c.get_raw_conn(),
                                               drawable as xcb_drawable_t,  // 0
                                               gc as xcb_gcontext_t,  // 1
                                               arcs_len as u32,  // 2
                                               arcs_ptr as *const xcb_arc_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PUT_IMAGE: u8 = 72;

pub fn put_image<'a>(c       : &'a base::Connection,
                     format  : u8,
                     drawable: Drawable,
                     gc      : Gcontext,
                     width   : u16,
                     height  : u16,
                     dst_x   : i16,
                     dst_y   : i16,
                     left_pad: u8,
                     depth   : u8,
                     data    : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_put_image(c.get_raw_conn(),
                                   format as u8,  // 0
                                   drawable as xcb_drawable_t,  // 1
                                   gc as xcb_gcontext_t,  // 2
                                   width as u16,  // 3
                                   height as u16,  // 4
                                   dst_x as i16,  // 5
                                   dst_y as i16,  // 6
                                   left_pad as u8,  // 7
                                   depth as u8,  // 8
                                   data_len as u32,  // 9
                                   data_ptr as *const u8);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn put_image_checked<'a>(c       : &'a base::Connection,
                             format  : u8,
                             drawable: Drawable,
                             gc      : Gcontext,
                             width   : u16,
                             height  : u16,
                             dst_x   : i16,
                             dst_y   : i16,
                             left_pad: u8,
                             depth   : u8,
                             data    : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_put_image_checked(c.get_raw_conn(),
                                           format as u8,  // 0
                                           drawable as xcb_drawable_t,  // 1
                                           gc as xcb_gcontext_t,  // 2
                                           width as u16,  // 3
                                           height as u16,  // 4
                                           dst_x as i16,  // 5
                                           dst_y as i16,  // 6
                                           left_pad as u8,  // 7
                                           depth as u8,  // 8
                                           data_len as u32,  // 9
                                           data_ptr as *const u8);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_IMAGE: u8 = 73;

pub type GetImageCookie<'a> = base::Cookie<'a, xcb_get_image_cookie_t>;

impl<'a> GetImageCookie<'a> {
    pub fn get_reply(&self) -> Result<GetImageReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetImageReply {
                    ptr: xcb_get_image_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetImageReply {
                    ptr: xcb_get_image_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetImageReply = base::Reply<xcb_get_image_reply_t>;

impl GetImageReply {
    pub fn depth(&self) -> u8 {
        unsafe {
            (*self.ptr).depth
        }
    }
    pub fn visual(&self) -> Visualid {
        unsafe {
            (*self.ptr).visual
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_get_image_data_length(field) as usize;
            let data = xcb_get_image_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_image<'a>(c         : &'a base::Connection,
                     format    : u8,
                     drawable  : Drawable,
                     x         : i16,
                     y         : i16,
                     width     : u16,
                     height    : u16,
                     plane_mask: u32)
        -> GetImageCookie<'a> {
    unsafe {
        let cookie = xcb_get_image(c.get_raw_conn(),
                                   format as u8,  // 0
                                   drawable as xcb_drawable_t,  // 1
                                   x as i16,  // 2
                                   y as i16,  // 3
                                   width as u16,  // 4
                                   height as u16,  // 5
                                   plane_mask as u32);  // 6
        GetImageCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_image_unchecked<'a>(c         : &'a base::Connection,
                               format    : u8,
                               drawable  : Drawable,
                               x         : i16,
                               y         : i16,
                               width     : u16,
                               height    : u16,
                               plane_mask: u32)
        -> GetImageCookie<'a> {
    unsafe {
        let cookie = xcb_get_image_unchecked(c.get_raw_conn(),
                                             format as u8,  // 0
                                             drawable as xcb_drawable_t,  // 1
                                             x as i16,  // 2
                                             y as i16,  // 3
                                             width as u16,  // 4
                                             height as u16,  // 5
                                             plane_mask as u32);  // 6
        GetImageCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const POLY_TEXT_8: u8 = 74;

pub fn poly_text_8<'a>(c       : &'a base::Connection,
                       drawable: Drawable,
                       gc      : Gcontext,
                       x       : i16,
                       y       : i16,
                       items   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let items_len = items.len();
        let items_ptr = items.as_ptr();
        let cookie = xcb_poly_text_8(c.get_raw_conn(),
                                     drawable as xcb_drawable_t,  // 0
                                     gc as xcb_gcontext_t,  // 1
                                     x as i16,  // 2
                                     y as i16,  // 3
                                     items_len as u32,  // 4
                                     items_ptr as *const u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn poly_text_8_checked<'a>(c       : &'a base::Connection,
                               drawable: Drawable,
                               gc      : Gcontext,
                               x       : i16,
                               y       : i16,
                               items   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let items_len = items.len();
        let items_ptr = items.as_ptr();
        let cookie = xcb_poly_text_8_checked(c.get_raw_conn(),
                                             drawable as xcb_drawable_t,  // 0
                                             gc as xcb_gcontext_t,  // 1
                                             x as i16,  // 2
                                             y as i16,  // 3
                                             items_len as u32,  // 4
                                             items_ptr as *const u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const POLY_TEXT_16: u8 = 75;

pub fn poly_text_16<'a>(c       : &'a base::Connection,
                        drawable: Drawable,
                        gc      : Gcontext,
                        x       : i16,
                        y       : i16,
                        items   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let items_len = items.len();
        let items_ptr = items.as_ptr();
        let cookie = xcb_poly_text_16(c.get_raw_conn(),
                                      drawable as xcb_drawable_t,  // 0
                                      gc as xcb_gcontext_t,  // 1
                                      x as i16,  // 2
                                      y as i16,  // 3
                                      items_len as u32,  // 4
                                      items_ptr as *const u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn poly_text_16_checked<'a>(c       : &'a base::Connection,
                                drawable: Drawable,
                                gc      : Gcontext,
                                x       : i16,
                                y       : i16,
                                items   : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let items_len = items.len();
        let items_ptr = items.as_ptr();
        let cookie = xcb_poly_text_16_checked(c.get_raw_conn(),
                                              drawable as xcb_drawable_t,  // 0
                                              gc as xcb_gcontext_t,  // 1
                                              x as i16,  // 2
                                              y as i16,  // 3
                                              items_len as u32,  // 4
                                              items_ptr as *const u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const IMAGE_TEXT_8: u8 = 76;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       The drawable (Window or Pixmap) to draw text on.
///
///   - __gc__:
///       The graphics context to use.
///
///       The following graphics context components are used: plane-mask, foreground,
///       background, font, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
///
///   - __x__:
///       The x coordinate of the first character, relative to the origin of `drawable`.
///
///   - __y__:
///       The y coordinate of the first character, relative to the origin of `drawable`.
///
///   - __string__:
///       The string to draw. Only the first 255 characters are relevant due to the data
///       type of `string_len`.
pub fn image_text_8<'a>(c       : &'a base::Connection,
                        drawable: Drawable,
                        gc      : Gcontext,
                        x       : i16,
                        y       : i16,
                        string  : &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let string = string.as_bytes();
        let string_len = string.len();
        let string_ptr = string.as_ptr();
        let cookie = xcb_image_text_8(c.get_raw_conn(),
                                      string_len as u8,  // 0
                                      drawable as xcb_drawable_t,  // 1
                                      gc as xcb_gcontext_t,  // 2
                                      x as i16,  // 3
                                      y as i16,  // 4
                                      string_ptr as *const c_char);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       The drawable (Window or Pixmap) to draw text on.
///
///   - __gc__:
///       The graphics context to use.
///
///       The following graphics context components are used: plane-mask, foreground,
///       background, font, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
///
///   - __x__:
///       The x coordinate of the first character, relative to the origin of `drawable`.
///
///   - __y__:
///       The y coordinate of the first character, relative to the origin of `drawable`.
///
///   - __string__:
///       The string to draw. Only the first 255 characters are relevant due to the data
///       type of `string_len`.
pub fn image_text_8_checked<'a>(c       : &'a base::Connection,
                                drawable: Drawable,
                                gc      : Gcontext,
                                x       : i16,
                                y       : i16,
                                string  : &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let string = string.as_bytes();
        let string_len = string.len();
        let string_ptr = string.as_ptr();
        let cookie = xcb_image_text_8_checked(c.get_raw_conn(),
                                              string_len as u8,  // 0
                                              drawable as xcb_drawable_t,  // 1
                                              gc as xcb_gcontext_t,  // 2
                                              x as i16,  // 3
                                              y as i16,  // 4
                                              string_ptr as *const c_char);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const IMAGE_TEXT_16: u8 = 77;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       The drawable (Window or Pixmap) to draw text on.
///
///   - __gc__:
///       The graphics context to use.
///
///       The following graphics context components are used: plane-mask, foreground,
///       background, font, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
///
///   - __x__:
///       The x coordinate of the first character, relative to the origin of `drawable`.
///
///   - __y__:
///       The y coordinate of the first character, relative to the origin of `drawable`.
///
///   - __string__:
///       The string to draw. Only the first 255 characters are relevant due to the data
///       type of `string_len`. Every character uses 2 bytes (hence the 16 in this
///       request's name).
pub fn image_text_16<'a>(c       : &'a base::Connection,
                         drawable: Drawable,
                         gc      : Gcontext,
                         x       : i16,
                         y       : i16,
                         string  : &[Char2b])
        -> base::VoidCookie<'a> {
    unsafe {
        let string_len = string.len();
        let string_ptr = string.as_ptr();
        let cookie = xcb_image_text_16(c.get_raw_conn(),
                                       string_len as u8,  // 0
                                       drawable as xcb_drawable_t,  // 1
                                       gc as xcb_gcontext_t,  // 2
                                       x as i16,  // 3
                                       y as i16,  // 4
                                       string_ptr as *const xcb_char2b_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __drawable__:
///       The drawable (Window or Pixmap) to draw text on.
///
///   - __gc__:
///       The graphics context to use.
///
///       The following graphics context components are used: plane-mask, foreground,
///       background, font, subwindow-mode, clip-x-origin, clip-y-origin, and clip-mask.
///
///   - __x__:
///       The x coordinate of the first character, relative to the origin of `drawable`.
///
///   - __y__:
///       The y coordinate of the first character, relative to the origin of `drawable`.
///
///   - __string__:
///       The string to draw. Only the first 255 characters are relevant due to the data
///       type of `string_len`. Every character uses 2 bytes (hence the 16 in this
///       request's name).
pub fn image_text_16_checked<'a>(c       : &'a base::Connection,
                                 drawable: Drawable,
                                 gc      : Gcontext,
                                 x       : i16,
                                 y       : i16,
                                 string  : &[Char2b])
        -> base::VoidCookie<'a> {
    unsafe {
        let string_len = string.len();
        let string_ptr = string.as_ptr();
        let cookie = xcb_image_text_16_checked(c.get_raw_conn(),
                                               string_len as u8,  // 0
                                               drawable as xcb_drawable_t,  // 1
                                               gc as xcb_gcontext_t,  // 2
                                               x as i16,  // 3
                                               y as i16,  // 4
                                               string_ptr as *const xcb_char2b_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_COLORMAP: u8 = 78;

pub fn create_colormap<'a>(c     : &'a base::Connection,
                           alloc : u8,
                           mid   : Colormap,
                           window: Window,
                           visual: Visualid)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_create_colormap(c.get_raw_conn(),
                                         alloc as u8,  // 0
                                         mid as xcb_colormap_t,  // 1
                                         window as xcb_window_t,  // 2
                                         visual as xcb_visualid_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_colormap_checked<'a>(c     : &'a base::Connection,
                                   alloc : u8,
                                   mid   : Colormap,
                                   window: Window,
                                   visual: Visualid)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_create_colormap_checked(c.get_raw_conn(),
                                                 alloc as u8,  // 0
                                                 mid as xcb_colormap_t,  // 1
                                                 window as xcb_window_t,  // 2
                                                 visual as xcb_visualid_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FREE_COLORMAP: u8 = 79;

pub fn free_colormap<'a>(c   : &'a base::Connection,
                         cmap: Colormap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_free_colormap(c.get_raw_conn(),
                                       cmap as xcb_colormap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn free_colormap_checked<'a>(c   : &'a base::Connection,
                                 cmap: Colormap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_free_colormap_checked(c.get_raw_conn(),
                                               cmap as xcb_colormap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COPY_COLORMAP_AND_FREE: u8 = 80;

pub fn copy_colormap_and_free<'a>(c       : &'a base::Connection,
                                  mid     : Colormap,
                                  src_cmap: Colormap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_copy_colormap_and_free(c.get_raw_conn(),
                                                mid as xcb_colormap_t,  // 0
                                                src_cmap as xcb_colormap_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn copy_colormap_and_free_checked<'a>(c       : &'a base::Connection,
                                          mid     : Colormap,
                                          src_cmap: Colormap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_copy_colormap_and_free_checked(c.get_raw_conn(),
                                                        mid as xcb_colormap_t,  // 0
                                                        src_cmap as xcb_colormap_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const INSTALL_COLORMAP: u8 = 81;

pub fn install_colormap<'a>(c   : &'a base::Connection,
                            cmap: Colormap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_install_colormap(c.get_raw_conn(),
                                          cmap as xcb_colormap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn install_colormap_checked<'a>(c   : &'a base::Connection,
                                    cmap: Colormap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_install_colormap_checked(c.get_raw_conn(),
                                                  cmap as xcb_colormap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const UNINSTALL_COLORMAP: u8 = 82;

pub fn uninstall_colormap<'a>(c   : &'a base::Connection,
                              cmap: Colormap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_uninstall_colormap(c.get_raw_conn(),
                                            cmap as xcb_colormap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn uninstall_colormap_checked<'a>(c   : &'a base::Connection,
                                      cmap: Colormap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_uninstall_colormap_checked(c.get_raw_conn(),
                                                    cmap as xcb_colormap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const LIST_INSTALLED_COLORMAPS: u8 = 83;

pub type ListInstalledColormapsCookie<'a> = base::Cookie<'a, xcb_list_installed_colormaps_cookie_t>;

impl<'a> ListInstalledColormapsCookie<'a> {
    pub fn get_reply(&self) -> Result<ListInstalledColormapsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListInstalledColormapsReply {
                    ptr: xcb_list_installed_colormaps_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListInstalledColormapsReply {
                    ptr: xcb_list_installed_colormaps_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListInstalledColormapsReply = base::Reply<xcb_list_installed_colormaps_reply_t>;

impl ListInstalledColormapsReply {
    pub fn cmaps_len(&self) -> u16 {
        unsafe {
            (*self.ptr).cmaps_len
        }
    }
    pub fn cmaps(&self) -> &[Colormap] {
        unsafe {
            let field = self.ptr;
            let len = xcb_list_installed_colormaps_cmaps_length(field) as usize;
            let data = xcb_list_installed_colormaps_cmaps(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn list_installed_colormaps<'a>(c     : &'a base::Connection,
                                    window: Window)
        -> ListInstalledColormapsCookie<'a> {
    unsafe {
        let cookie = xcb_list_installed_colormaps(c.get_raw_conn(),
                                                  window as xcb_window_t);  // 0
        ListInstalledColormapsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_installed_colormaps_unchecked<'a>(c     : &'a base::Connection,
                                              window: Window)
        -> ListInstalledColormapsCookie<'a> {
    unsafe {
        let cookie = xcb_list_installed_colormaps_unchecked(c.get_raw_conn(),
                                                            window as xcb_window_t);  // 0
        ListInstalledColormapsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const ALLOC_COLOR: u8 = 84;

pub type AllocColorCookie<'a> = base::Cookie<'a, xcb_alloc_color_cookie_t>;

impl<'a> AllocColorCookie<'a> {
    pub fn get_reply(&self) -> Result<AllocColorReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = AllocColorReply {
                    ptr: xcb_alloc_color_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( AllocColorReply {
                    ptr: xcb_alloc_color_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type AllocColorReply = base::Reply<xcb_alloc_color_reply_t>;

impl AllocColorReply {
    pub fn red(&self) -> u16 {
        unsafe {
            (*self.ptr).red
        }
    }
    pub fn green(&self) -> u16 {
        unsafe {
            (*self.ptr).green
        }
    }
    pub fn blue(&self) -> u16 {
        unsafe {
            (*self.ptr).blue
        }
    }
    pub fn pixel(&self) -> u32 {
        unsafe {
            (*self.ptr).pixel
        }
    }
}

/// Allocate a color
///
/// Allocates a read-only colormap entry corresponding to the closest RGB value
/// supported by the hardware. If you are using TrueColor, you can take a shortcut
/// and directly calculate the color pixel value to avoid the round trip. But, for
/// example, on 16-bit color setups (VNC), you can easily get the closest supported
/// RGB value to the RGB value you are specifying.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __cmap__:
///       TODO
///
///   - __red__:
///       The red value of your color.
///
///   - __green__:
///       The green value of your color.
///
///   - __blue__:
///       The blue value of your color.
pub fn alloc_color<'a>(c    : &'a base::Connection,
                       cmap : Colormap,
                       red  : u16,
                       green: u16,
                       blue : u16)
        -> AllocColorCookie<'a> {
    unsafe {
        let cookie = xcb_alloc_color(c.get_raw_conn(),
                                     cmap as xcb_colormap_t,  // 0
                                     red as u16,  // 1
                                     green as u16,  // 2
                                     blue as u16);  // 3
        AllocColorCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

/// Allocate a color
///
/// Allocates a read-only colormap entry corresponding to the closest RGB value
/// supported by the hardware. If you are using TrueColor, you can take a shortcut
/// and directly calculate the color pixel value to avoid the round trip. But, for
/// example, on 16-bit color setups (VNC), you can easily get the closest supported
/// RGB value to the RGB value you are specifying.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __cmap__:
///       TODO
///
///   - __red__:
///       The red value of your color.
///
///   - __green__:
///       The green value of your color.
///
///   - __blue__:
///       The blue value of your color.
pub fn alloc_color_unchecked<'a>(c    : &'a base::Connection,
                                 cmap : Colormap,
                                 red  : u16,
                                 green: u16,
                                 blue : u16)
        -> AllocColorCookie<'a> {
    unsafe {
        let cookie = xcb_alloc_color_unchecked(c.get_raw_conn(),
                                               cmap as xcb_colormap_t,  // 0
                                               red as u16,  // 1
                                               green as u16,  // 2
                                               blue as u16);  // 3
        AllocColorCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const ALLOC_NAMED_COLOR: u8 = 85;

pub type AllocNamedColorCookie<'a> = base::Cookie<'a, xcb_alloc_named_color_cookie_t>;

impl<'a> AllocNamedColorCookie<'a> {
    pub fn get_reply(&self) -> Result<AllocNamedColorReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = AllocNamedColorReply {
                    ptr: xcb_alloc_named_color_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( AllocNamedColorReply {
                    ptr: xcb_alloc_named_color_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type AllocNamedColorReply = base::Reply<xcb_alloc_named_color_reply_t>;

impl AllocNamedColorReply {
    pub fn pixel(&self) -> u32 {
        unsafe {
            (*self.ptr).pixel
        }
    }
    pub fn exact_red(&self) -> u16 {
        unsafe {
            (*self.ptr).exact_red
        }
    }
    pub fn exact_green(&self) -> u16 {
        unsafe {
            (*self.ptr).exact_green
        }
    }
    pub fn exact_blue(&self) -> u16 {
        unsafe {
            (*self.ptr).exact_blue
        }
    }
    pub fn visual_red(&self) -> u16 {
        unsafe {
            (*self.ptr).visual_red
        }
    }
    pub fn visual_green(&self) -> u16 {
        unsafe {
            (*self.ptr).visual_green
        }
    }
    pub fn visual_blue(&self) -> u16 {
        unsafe {
            (*self.ptr).visual_blue
        }
    }
}

pub fn alloc_named_color<'a>(c   : &'a base::Connection,
                             cmap: Colormap,
                             name: &str)
        -> AllocNamedColorCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_alloc_named_color(c.get_raw_conn(),
                                           cmap as xcb_colormap_t,  // 0
                                           name_len as u16,  // 1
                                           name_ptr as *const c_char);  // 2
        AllocNamedColorCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn alloc_named_color_unchecked<'a>(c   : &'a base::Connection,
                                       cmap: Colormap,
                                       name: &str)
        -> AllocNamedColorCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_alloc_named_color_unchecked(c.get_raw_conn(),
                                                     cmap as xcb_colormap_t,  // 0
                                                     name_len as u16,  // 1
                                                     name_ptr as *const c_char);  // 2
        AllocNamedColorCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const ALLOC_COLOR_CELLS: u8 = 86;

pub type AllocColorCellsCookie<'a> = base::Cookie<'a, xcb_alloc_color_cells_cookie_t>;

impl<'a> AllocColorCellsCookie<'a> {
    pub fn get_reply(&self) -> Result<AllocColorCellsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = AllocColorCellsReply {
                    ptr: xcb_alloc_color_cells_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( AllocColorCellsReply {
                    ptr: xcb_alloc_color_cells_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type AllocColorCellsReply = base::Reply<xcb_alloc_color_cells_reply_t>;

impl AllocColorCellsReply {
    pub fn pixels_len(&self) -> u16 {
        unsafe {
            (*self.ptr).pixels_len
        }
    }
    pub fn masks_len(&self) -> u16 {
        unsafe {
            (*self.ptr).masks_len
        }
    }
    pub fn pixels(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_alloc_color_cells_pixels_length(field) as usize;
            let data = xcb_alloc_color_cells_pixels(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn masks(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_alloc_color_cells_masks_length(field) as usize;
            let data = xcb_alloc_color_cells_masks(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn alloc_color_cells<'a>(c         : &'a base::Connection,
                             contiguous: bool,
                             cmap      : Colormap,
                             colors    : u16,
                             planes    : u16)
        -> AllocColorCellsCookie<'a> {
    unsafe {
        let cookie = xcb_alloc_color_cells(c.get_raw_conn(),
                                           contiguous as u8,  // 0
                                           cmap as xcb_colormap_t,  // 1
                                           colors as u16,  // 2
                                           planes as u16);  // 3
        AllocColorCellsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn alloc_color_cells_unchecked<'a>(c         : &'a base::Connection,
                                       contiguous: bool,
                                       cmap      : Colormap,
                                       colors    : u16,
                                       planes    : u16)
        -> AllocColorCellsCookie<'a> {
    unsafe {
        let cookie = xcb_alloc_color_cells_unchecked(c.get_raw_conn(),
                                                     contiguous as u8,  // 0
                                                     cmap as xcb_colormap_t,  // 1
                                                     colors as u16,  // 2
                                                     planes as u16);  // 3
        AllocColorCellsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const ALLOC_COLOR_PLANES: u8 = 87;

pub type AllocColorPlanesCookie<'a> = base::Cookie<'a, xcb_alloc_color_planes_cookie_t>;

impl<'a> AllocColorPlanesCookie<'a> {
    pub fn get_reply(&self) -> Result<AllocColorPlanesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = AllocColorPlanesReply {
                    ptr: xcb_alloc_color_planes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( AllocColorPlanesReply {
                    ptr: xcb_alloc_color_planes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type AllocColorPlanesReply = base::Reply<xcb_alloc_color_planes_reply_t>;

impl AllocColorPlanesReply {
    pub fn pixels_len(&self) -> u16 {
        unsafe {
            (*self.ptr).pixels_len
        }
    }
    pub fn red_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).red_mask
        }
    }
    pub fn green_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).green_mask
        }
    }
    pub fn blue_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).blue_mask
        }
    }
    pub fn pixels(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_alloc_color_planes_pixels_length(field) as usize;
            let data = xcb_alloc_color_planes_pixels(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn alloc_color_planes<'a>(c         : &'a base::Connection,
                              contiguous: bool,
                              cmap      : Colormap,
                              colors    : u16,
                              reds      : u16,
                              greens    : u16,
                              blues     : u16)
        -> AllocColorPlanesCookie<'a> {
    unsafe {
        let cookie = xcb_alloc_color_planes(c.get_raw_conn(),
                                            contiguous as u8,  // 0
                                            cmap as xcb_colormap_t,  // 1
                                            colors as u16,  // 2
                                            reds as u16,  // 3
                                            greens as u16,  // 4
                                            blues as u16);  // 5
        AllocColorPlanesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn alloc_color_planes_unchecked<'a>(c         : &'a base::Connection,
                                        contiguous: bool,
                                        cmap      : Colormap,
                                        colors    : u16,
                                        reds      : u16,
                                        greens    : u16,
                                        blues     : u16)
        -> AllocColorPlanesCookie<'a> {
    unsafe {
        let cookie = xcb_alloc_color_planes_unchecked(c.get_raw_conn(),
                                                      contiguous as u8,  // 0
                                                      cmap as xcb_colormap_t,  // 1
                                                      colors as u16,  // 2
                                                      reds as u16,  // 3
                                                      greens as u16,  // 4
                                                      blues as u16);  // 5
        AllocColorPlanesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const FREE_COLORS: u8 = 88;

pub fn free_colors<'a>(c         : &'a base::Connection,
                       cmap      : Colormap,
                       plane_mask: u32,
                       pixels    : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let pixels_len = pixels.len();
        let pixels_ptr = pixels.as_ptr();
        let cookie = xcb_free_colors(c.get_raw_conn(),
                                     cmap as xcb_colormap_t,  // 0
                                     plane_mask as u32,  // 1
                                     pixels_len as u32,  // 2
                                     pixels_ptr as *const u32);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn free_colors_checked<'a>(c         : &'a base::Connection,
                               cmap      : Colormap,
                               plane_mask: u32,
                               pixels    : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let pixels_len = pixels.len();
        let pixels_ptr = pixels.as_ptr();
        let cookie = xcb_free_colors_checked(c.get_raw_conn(),
                                             cmap as xcb_colormap_t,  // 0
                                             plane_mask as u32,  // 1
                                             pixels_len as u32,  // 2
                                             pixels_ptr as *const u32);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct Coloritem {
    pub base: xcb_coloritem_t,
}

impl Coloritem {
    #[allow(unused_unsafe)]
    pub fn new(pixel: u32,
               red:   u16,
               green: u16,
               blue:  u16,
               flags: u8)
            -> Coloritem {
        unsafe {
            Coloritem {
                base: xcb_coloritem_t {
                    pixel: pixel,
                    red:   red,
                    green: green,
                    blue:  blue,
                    flags: flags,
                    pad0:  0,
                }
            }
        }
    }
    pub fn pixel(&self) -> u32 {
        unsafe {
            self.base.pixel
        }
    }
    pub fn red(&self) -> u16 {
        unsafe {
            self.base.red
        }
    }
    pub fn green(&self) -> u16 {
        unsafe {
            self.base.green
        }
    }
    pub fn blue(&self) -> u16 {
        unsafe {
            self.base.blue
        }
    }
    pub fn flags(&self) -> u8 {
        unsafe {
            self.base.flags
        }
    }
}

pub type ColoritemIterator = xcb_coloritem_iterator_t;

impl Iterator for ColoritemIterator {
    type Item = Coloritem;
    fn next(&mut self) -> std::option::Option<Coloritem> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_coloritem_iterator_t;
                let data = (*iter).data;
                xcb_coloritem_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const STORE_COLORS: u8 = 89;

pub fn store_colors<'a>(c    : &'a base::Connection,
                        cmap : Colormap,
                        items: &[Coloritem])
        -> base::VoidCookie<'a> {
    unsafe {
        let items_len = items.len();
        let items_ptr = items.as_ptr();
        let cookie = xcb_store_colors(c.get_raw_conn(),
                                      cmap as xcb_colormap_t,  // 0
                                      items_len as u32,  // 1
                                      items_ptr as *const xcb_coloritem_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn store_colors_checked<'a>(c    : &'a base::Connection,
                                cmap : Colormap,
                                items: &[Coloritem])
        -> base::VoidCookie<'a> {
    unsafe {
        let items_len = items.len();
        let items_ptr = items.as_ptr();
        let cookie = xcb_store_colors_checked(c.get_raw_conn(),
                                              cmap as xcb_colormap_t,  // 0
                                              items_len as u32,  // 1
                                              items_ptr as *const xcb_coloritem_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const STORE_NAMED_COLOR: u8 = 90;

pub fn store_named_color<'a>(c    : &'a base::Connection,
                             flags: u8,
                             cmap : Colormap,
                             pixel: u32,
                             name : &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_store_named_color(c.get_raw_conn(),
                                           flags as u8,  // 0
                                           cmap as xcb_colormap_t,  // 1
                                           pixel as u32,  // 2
                                           name_len as u16,  // 3
                                           name_ptr as *const c_char);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn store_named_color_checked<'a>(c    : &'a base::Connection,
                                     flags: u8,
                                     cmap : Colormap,
                                     pixel: u32,
                                     name : &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_store_named_color_checked(c.get_raw_conn(),
                                                   flags as u8,  // 0
                                                   cmap as xcb_colormap_t,  // 1
                                                   pixel as u32,  // 2
                                                   name_len as u16,  // 3
                                                   name_ptr as *const c_char);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct Rgb {
    pub base: xcb_rgb_t,
}

impl Rgb {
    #[allow(unused_unsafe)]
    pub fn new(red:   u16,
               green: u16,
               blue:  u16)
            -> Rgb {
        unsafe {
            Rgb {
                base: xcb_rgb_t {
                    red:   red,
                    green: green,
                    blue:  blue,
                    pad0:  [0; 2],
                }
            }
        }
    }
    pub fn red(&self) -> u16 {
        unsafe {
            self.base.red
        }
    }
    pub fn green(&self) -> u16 {
        unsafe {
            self.base.green
        }
    }
    pub fn blue(&self) -> u16 {
        unsafe {
            self.base.blue
        }
    }
}

pub type RgbIterator = xcb_rgb_iterator_t;

impl Iterator for RgbIterator {
    type Item = Rgb;
    fn next(&mut self) -> std::option::Option<Rgb> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_rgb_iterator_t;
                let data = (*iter).data;
                xcb_rgb_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const QUERY_COLORS: u8 = 91;

pub type QueryColorsCookie<'a> = base::Cookie<'a, xcb_query_colors_cookie_t>;

impl<'a> QueryColorsCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryColorsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryColorsReply {
                    ptr: xcb_query_colors_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryColorsReply {
                    ptr: xcb_query_colors_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryColorsReply = base::Reply<xcb_query_colors_reply_t>;

impl QueryColorsReply {
    pub fn colors_len(&self) -> u16 {
        unsafe {
            (*self.ptr).colors_len
        }
    }
    pub fn colors(&self) -> RgbIterator {
        unsafe {
            xcb_query_colors_colors_iterator(self.ptr)
        }
    }
}

pub fn query_colors<'a>(c     : &'a base::Connection,
                        cmap  : Colormap,
                        pixels: &[u32])
        -> QueryColorsCookie<'a> {
    unsafe {
        let pixels_len = pixels.len();
        let pixels_ptr = pixels.as_ptr();
        let cookie = xcb_query_colors(c.get_raw_conn(),
                                      cmap as xcb_colormap_t,  // 0
                                      pixels_len as u32,  // 1
                                      pixels_ptr as *const u32);  // 2
        QueryColorsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_colors_unchecked<'a>(c     : &'a base::Connection,
                                  cmap  : Colormap,
                                  pixels: &[u32])
        -> QueryColorsCookie<'a> {
    unsafe {
        let pixels_len = pixels.len();
        let pixels_ptr = pixels.as_ptr();
        let cookie = xcb_query_colors_unchecked(c.get_raw_conn(),
                                                cmap as xcb_colormap_t,  // 0
                                                pixels_len as u32,  // 1
                                                pixels_ptr as *const u32);  // 2
        QueryColorsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LOOKUP_COLOR: u8 = 92;

pub type LookupColorCookie<'a> = base::Cookie<'a, xcb_lookup_color_cookie_t>;

impl<'a> LookupColorCookie<'a> {
    pub fn get_reply(&self) -> Result<LookupColorReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = LookupColorReply {
                    ptr: xcb_lookup_color_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( LookupColorReply {
                    ptr: xcb_lookup_color_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type LookupColorReply = base::Reply<xcb_lookup_color_reply_t>;

impl LookupColorReply {
    pub fn exact_red(&self) -> u16 {
        unsafe {
            (*self.ptr).exact_red
        }
    }
    pub fn exact_green(&self) -> u16 {
        unsafe {
            (*self.ptr).exact_green
        }
    }
    pub fn exact_blue(&self) -> u16 {
        unsafe {
            (*self.ptr).exact_blue
        }
    }
    pub fn visual_red(&self) -> u16 {
        unsafe {
            (*self.ptr).visual_red
        }
    }
    pub fn visual_green(&self) -> u16 {
        unsafe {
            (*self.ptr).visual_green
        }
    }
    pub fn visual_blue(&self) -> u16 {
        unsafe {
            (*self.ptr).visual_blue
        }
    }
}

pub fn lookup_color<'a>(c   : &'a base::Connection,
                        cmap: Colormap,
                        name: &str)
        -> LookupColorCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_lookup_color(c.get_raw_conn(),
                                      cmap as xcb_colormap_t,  // 0
                                      name_len as u16,  // 1
                                      name_ptr as *const c_char);  // 2
        LookupColorCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn lookup_color_unchecked<'a>(c   : &'a base::Connection,
                                  cmap: Colormap,
                                  name: &str)
        -> LookupColorCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_lookup_color_unchecked(c.get_raw_conn(),
                                                cmap as xcb_colormap_t,  // 0
                                                name_len as u16,  // 1
                                                name_ptr as *const c_char);  // 2
        LookupColorCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_CURSOR: u8 = 93;

pub fn create_cursor<'a>(c         : &'a base::Connection,
                         cid       : Cursor,
                         source    : Pixmap,
                         mask      : Pixmap,
                         fore_red  : u16,
                         fore_green: u16,
                         fore_blue : u16,
                         back_red  : u16,
                         back_green: u16,
                         back_blue : u16,
                         x         : u16,
                         y         : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_create_cursor(c.get_raw_conn(),
                                       cid as xcb_cursor_t,  // 0
                                       source as xcb_pixmap_t,  // 1
                                       mask as xcb_pixmap_t,  // 2
                                       fore_red as u16,  // 3
                                       fore_green as u16,  // 4
                                       fore_blue as u16,  // 5
                                       back_red as u16,  // 6
                                       back_green as u16,  // 7
                                       back_blue as u16,  // 8
                                       x as u16,  // 9
                                       y as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_cursor_checked<'a>(c         : &'a base::Connection,
                                 cid       : Cursor,
                                 source    : Pixmap,
                                 mask      : Pixmap,
                                 fore_red  : u16,
                                 fore_green: u16,
                                 fore_blue : u16,
                                 back_red  : u16,
                                 back_green: u16,
                                 back_blue : u16,
                                 x         : u16,
                                 y         : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_create_cursor_checked(c.get_raw_conn(),
                                               cid as xcb_cursor_t,  // 0
                                               source as xcb_pixmap_t,  // 1
                                               mask as xcb_pixmap_t,  // 2
                                               fore_red as u16,  // 3
                                               fore_green as u16,  // 4
                                               fore_blue as u16,  // 5
                                               back_red as u16,  // 6
                                               back_green as u16,  // 7
                                               back_blue as u16,  // 8
                                               x as u16,  // 9
                                               y as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_GLYPH_CURSOR: u8 = 94;

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __cid__:
///       The ID with which you will refer to the cursor, created by `xcb_generate_id`.
///
///   - __source_font__:
///       In which font to look for the cursor glyph.
///
///   - __mask_font__:
///       In which font to look for the mask glyph.
///
///   - __source_char__:
///       The glyph of `source_font` to use.
///
///   - __mask_char__:
///       The glyph of `mask_font` to use as a mask: Pixels which are set to 1 define
///       which source pixels are displayed. All pixels which are set to 0 are not
///       displayed.
///
///   - __fore_red__:
///       The red value of the foreground color.
///
///   - __fore_green__:
///       The green value of the foreground color.
///
///   - __fore_blue__:
///       The blue value of the foreground color.
///
///   - __back_red__:
///       The red value of the background color.
///
///   - __back_green__:
///       The green value of the background color.
///
///   - __back_blue__:
///       The blue value of the background color.
pub fn create_glyph_cursor<'a>(c          : &'a base::Connection,
                               cid        : Cursor,
                               source_font: Font,
                               mask_font  : Font,
                               source_char: u16,
                               mask_char  : u16,
                               fore_red   : u16,
                               fore_green : u16,
                               fore_blue  : u16,
                               back_red   : u16,
                               back_green : u16,
                               back_blue  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_create_glyph_cursor(c.get_raw_conn(),
                                             cid as xcb_cursor_t,  // 0
                                             source_font as xcb_font_t,  // 1
                                             mask_font as xcb_font_t,  // 2
                                             source_char as u16,  // 3
                                             mask_char as u16,  // 4
                                             fore_red as u16,  // 5
                                             fore_green as u16,  // 6
                                             fore_blue as u16,  // 7
                                             back_red as u16,  // 8
                                             back_green as u16,  // 9
                                             back_blue as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __cid__:
///       The ID with which you will refer to the cursor, created by `xcb_generate_id`.
///
///   - __source_font__:
///       In which font to look for the cursor glyph.
///
///   - __mask_font__:
///       In which font to look for the mask glyph.
///
///   - __source_char__:
///       The glyph of `source_font` to use.
///
///   - __mask_char__:
///       The glyph of `mask_font` to use as a mask: Pixels which are set to 1 define
///       which source pixels are displayed. All pixels which are set to 0 are not
///       displayed.
///
///   - __fore_red__:
///       The red value of the foreground color.
///
///   - __fore_green__:
///       The green value of the foreground color.
///
///   - __fore_blue__:
///       The blue value of the foreground color.
///
///   - __back_red__:
///       The red value of the background color.
///
///   - __back_green__:
///       The green value of the background color.
///
///   - __back_blue__:
///       The blue value of the background color.
pub fn create_glyph_cursor_checked<'a>(c          : &'a base::Connection,
                                       cid        : Cursor,
                                       source_font: Font,
                                       mask_font  : Font,
                                       source_char: u16,
                                       mask_char  : u16,
                                       fore_red   : u16,
                                       fore_green : u16,
                                       fore_blue  : u16,
                                       back_red   : u16,
                                       back_green : u16,
                                       back_blue  : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_create_glyph_cursor_checked(c.get_raw_conn(),
                                                     cid as xcb_cursor_t,  // 0
                                                     source_font as xcb_font_t,  // 1
                                                     mask_font as xcb_font_t,  // 2
                                                     source_char as u16,  // 3
                                                     mask_char as u16,  // 4
                                                     fore_red as u16,  // 5
                                                     fore_green as u16,  // 6
                                                     fore_blue as u16,  // 7
                                                     back_red as u16,  // 8
                                                     back_green as u16,  // 9
                                                     back_blue as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FREE_CURSOR: u8 = 95;

/// Deletes a cursor
///
/// Deletes the association between the cursor resource ID and the specified
/// cursor. The cursor is freed when no other resource references it.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __cursor__:
///       The cursor to destroy.
pub fn free_cursor<'a>(c     : &'a base::Connection,
                       cursor: Cursor)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_free_cursor(c.get_raw_conn(),
                                     cursor as xcb_cursor_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// Deletes a cursor
///
/// Deletes the association between the cursor resource ID and the specified
/// cursor. The cursor is freed when no other resource references it.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __cursor__:
///       The cursor to destroy.
pub fn free_cursor_checked<'a>(c     : &'a base::Connection,
                               cursor: Cursor)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_free_cursor_checked(c.get_raw_conn(),
                                             cursor as xcb_cursor_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const RECOLOR_CURSOR: u8 = 96;

pub fn recolor_cursor<'a>(c         : &'a base::Connection,
                          cursor    : Cursor,
                          fore_red  : u16,
                          fore_green: u16,
                          fore_blue : u16,
                          back_red  : u16,
                          back_green: u16,
                          back_blue : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_recolor_cursor(c.get_raw_conn(),
                                        cursor as xcb_cursor_t,  // 0
                                        fore_red as u16,  // 1
                                        fore_green as u16,  // 2
                                        fore_blue as u16,  // 3
                                        back_red as u16,  // 4
                                        back_green as u16,  // 5
                                        back_blue as u16);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn recolor_cursor_checked<'a>(c         : &'a base::Connection,
                                  cursor    : Cursor,
                                  fore_red  : u16,
                                  fore_green: u16,
                                  fore_blue : u16,
                                  back_red  : u16,
                                  back_green: u16,
                                  back_blue : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_recolor_cursor_checked(c.get_raw_conn(),
                                                cursor as xcb_cursor_t,  // 0
                                                fore_red as u16,  // 1
                                                fore_green as u16,  // 2
                                                fore_blue as u16,  // 3
                                                back_red as u16,  // 4
                                                back_green as u16,  // 5
                                                back_blue as u16);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_BEST_SIZE: u8 = 97;

pub type QueryBestSizeCookie<'a> = base::Cookie<'a, xcb_query_best_size_cookie_t>;

impl<'a> QueryBestSizeCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryBestSizeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryBestSizeReply {
                    ptr: xcb_query_best_size_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryBestSizeReply {
                    ptr: xcb_query_best_size_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryBestSizeReply = base::Reply<xcb_query_best_size_reply_t>;

impl QueryBestSizeReply {
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
}

pub fn query_best_size<'a>(c       : &'a base::Connection,
                           class   : u8,
                           drawable: Drawable,
                           width   : u16,
                           height  : u16)
        -> QueryBestSizeCookie<'a> {
    unsafe {
        let cookie = xcb_query_best_size(c.get_raw_conn(),
                                         class as u8,  // 0
                                         drawable as xcb_drawable_t,  // 1
                                         width as u16,  // 2
                                         height as u16);  // 3
        QueryBestSizeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_best_size_unchecked<'a>(c       : &'a base::Connection,
                                     class   : u8,
                                     drawable: Drawable,
                                     width   : u16,
                                     height  : u16)
        -> QueryBestSizeCookie<'a> {
    unsafe {
        let cookie = xcb_query_best_size_unchecked(c.get_raw_conn(),
                                                   class as u8,  // 0
                                                   drawable as xcb_drawable_t,  // 1
                                                   width as u16,  // 2
                                                   height as u16);  // 3
        QueryBestSizeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_EXTENSION: u8 = 98;

pub type QueryExtensionCookie<'a> = base::Cookie<'a, xcb_query_extension_cookie_t>;

impl<'a> QueryExtensionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryExtensionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryExtensionReply {
                    ptr: xcb_query_extension_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryExtensionReply {
                    ptr: xcb_query_extension_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryExtensionReply = base::Reply<xcb_query_extension_reply_t>;

impl QueryExtensionReply {
    pub fn present(&self) -> bool {
        unsafe {
            (*self.ptr).present != 0
        }
    }
    pub fn major_opcode(&self) -> u8 {
        unsafe {
            (*self.ptr).major_opcode
        }
    }
    pub fn first_event(&self) -> u8 {
        unsafe {
            (*self.ptr).first_event
        }
    }
    pub fn first_error(&self) -> u8 {
        unsafe {
            (*self.ptr).first_error
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __name__:
///       The name of the extension to query, for example "RANDR". This is case
///       sensitive!
pub fn query_extension<'a>(c   : &'a base::Connection,
                           name: &str)
        -> QueryExtensionCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_query_extension(c.get_raw_conn(),
                                         name_len as u16,  // 0
                                         name_ptr as *const c_char);  // 1
        QueryExtensionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

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
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __name__:
///       The name of the extension to query, for example "RANDR". This is case
///       sensitive!
pub fn query_extension_unchecked<'a>(c   : &'a base::Connection,
                                     name: &str)
        -> QueryExtensionCookie<'a> {
    unsafe {
        let name = name.as_bytes();
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_query_extension_unchecked(c.get_raw_conn(),
                                                   name_len as u16,  // 0
                                                   name_ptr as *const c_char);  // 1
        QueryExtensionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_EXTENSIONS: u8 = 99;

pub type ListExtensionsCookie<'a> = base::Cookie<'a, xcb_list_extensions_cookie_t>;

impl<'a> ListExtensionsCookie<'a> {
    pub fn get_reply(&self) -> Result<ListExtensionsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListExtensionsReply {
                    ptr: xcb_list_extensions_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListExtensionsReply {
                    ptr: xcb_list_extensions_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListExtensionsReply = base::Reply<xcb_list_extensions_reply_t>;

impl ListExtensionsReply {
    pub fn names_len(&self) -> u8 {
        unsafe {
            (*self.ptr).names_len
        }
    }
    pub fn names(&self) -> StrIterator {
        unsafe {
            xcb_list_extensions_names_iterator(self.ptr)
        }
    }
}

pub fn list_extensions<'a>(c: &'a base::Connection)
        -> ListExtensionsCookie<'a> {
    unsafe {
        let cookie = xcb_list_extensions(c.get_raw_conn());
        ListExtensionsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_extensions_unchecked<'a>(c: &'a base::Connection)
        -> ListExtensionsCookie<'a> {
    unsafe {
        let cookie = xcb_list_extensions_unchecked(c.get_raw_conn());
        ListExtensionsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_KEYBOARD_MAPPING: u8 = 100;

pub fn change_keyboard_mapping<'a>(c                  : &'a base::Connection,
                                   first_keycode      : Keycode,
                                   keysyms_per_keycode: u8,
                                   keysyms            : &[Keysym])
        -> base::VoidCookie<'a> {
    unsafe {
        let keysyms_len = keysyms.len();
        let keysyms_ptr = keysyms.as_ptr();
        let cookie = xcb_change_keyboard_mapping(c.get_raw_conn(),
                                                 keysyms_len as u8,  // 0
                                                 first_keycode as xcb_keycode_t,  // 1
                                                 keysyms_per_keycode as u8,  // 2
                                                 keysyms_ptr as *const xcb_keysym_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_keyboard_mapping_checked<'a>(c                  : &'a base::Connection,
                                           first_keycode      : Keycode,
                                           keysyms_per_keycode: u8,
                                           keysyms            : &[Keysym])
        -> base::VoidCookie<'a> {
    unsafe {
        let keysyms_len = keysyms.len();
        let keysyms_ptr = keysyms.as_ptr();
        let cookie = xcb_change_keyboard_mapping_checked(c.get_raw_conn(),
                                                         keysyms_len as u8,  // 0
                                                         first_keycode as xcb_keycode_t,  // 1
                                                         keysyms_per_keycode as u8,  // 2
                                                         keysyms_ptr as *const xcb_keysym_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_KEYBOARD_MAPPING: u8 = 101;

pub type GetKeyboardMappingCookie<'a> = base::Cookie<'a, xcb_get_keyboard_mapping_cookie_t>;

impl<'a> GetKeyboardMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<GetKeyboardMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetKeyboardMappingReply {
                    ptr: xcb_get_keyboard_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetKeyboardMappingReply {
                    ptr: xcb_get_keyboard_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetKeyboardMappingReply = base::Reply<xcb_get_keyboard_mapping_reply_t>;

impl GetKeyboardMappingReply {
    pub fn keysyms_per_keycode(&self) -> u8 {
        unsafe {
            (*self.ptr).keysyms_per_keycode
        }
    }
    pub fn keysyms(&self) -> &[Keysym] {
        unsafe {
            let field = self.ptr;
            let len = xcb_get_keyboard_mapping_keysyms_length(field) as usize;
            let data = xcb_get_keyboard_mapping_keysyms(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_keyboard_mapping<'a>(c            : &'a base::Connection,
                                first_keycode: Keycode,
                                count        : u8)
        -> GetKeyboardMappingCookie<'a> {
    unsafe {
        let cookie = xcb_get_keyboard_mapping(c.get_raw_conn(),
                                              first_keycode as xcb_keycode_t,  // 0
                                              count as u8);  // 1
        GetKeyboardMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_keyboard_mapping_unchecked<'a>(c            : &'a base::Connection,
                                          first_keycode: Keycode,
                                          count        : u8)
        -> GetKeyboardMappingCookie<'a> {
    unsafe {
        let cookie = xcb_get_keyboard_mapping_unchecked(c.get_raw_conn(),
                                                        first_keycode as xcb_keycode_t,  // 0
                                                        count as u8);  // 1
        GetKeyboardMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_KEYBOARD_CONTROL: u8 = 102;

pub fn change_keyboard_control<'a>(c         : &'a base::Connection,
                                   value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_change_keyboard_control(c.get_raw_conn(),
                                                 value_list_mask as u32,  // 0
                                                 value_list_ptr as *const u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_keyboard_control_checked<'a>(c         : &'a base::Connection,
                                           value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_change_keyboard_control_checked(c.get_raw_conn(),
                                                         value_list_mask as u32,  // 0
                                                         value_list_ptr as *const u32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_KEYBOARD_CONTROL: u8 = 103;

pub type GetKeyboardControlCookie<'a> = base::Cookie<'a, xcb_get_keyboard_control_cookie_t>;

impl<'a> GetKeyboardControlCookie<'a> {
    pub fn get_reply(&self) -> Result<GetKeyboardControlReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetKeyboardControlReply {
                    ptr: xcb_get_keyboard_control_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetKeyboardControlReply {
                    ptr: xcb_get_keyboard_control_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetKeyboardControlReply = base::Reply<xcb_get_keyboard_control_reply_t>;

impl GetKeyboardControlReply {
    pub fn global_auto_repeat(&self) -> u8 {
        unsafe {
            (*self.ptr).global_auto_repeat
        }
    }
    pub fn led_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).led_mask
        }
    }
    pub fn key_click_percent(&self) -> u8 {
        unsafe {
            (*self.ptr).key_click_percent
        }
    }
    pub fn bell_percent(&self) -> u8 {
        unsafe {
            (*self.ptr).bell_percent
        }
    }
    pub fn bell_pitch(&self) -> u16 {
        unsafe {
            (*self.ptr).bell_pitch
        }
    }
    pub fn bell_duration(&self) -> u16 {
        unsafe {
            (*self.ptr).bell_duration
        }
    }
    pub fn auto_repeats(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).auto_repeats
        }
    }
}

pub fn get_keyboard_control<'a>(c: &'a base::Connection)
        -> GetKeyboardControlCookie<'a> {
    unsafe {
        let cookie = xcb_get_keyboard_control(c.get_raw_conn());
        GetKeyboardControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_keyboard_control_unchecked<'a>(c: &'a base::Connection)
        -> GetKeyboardControlCookie<'a> {
    unsafe {
        let cookie = xcb_get_keyboard_control_unchecked(c.get_raw_conn());
        GetKeyboardControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const BELL: u8 = 104;

pub fn bell<'a>(c      : &'a base::Connection,
                percent: i8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_bell(c.get_raw_conn(),
                              percent as i8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn bell_checked<'a>(c      : &'a base::Connection,
                        percent: i8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_bell_checked(c.get_raw_conn(),
                                      percent as i8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_POINTER_CONTROL: u8 = 105;

pub fn change_pointer_control<'a>(c                       : &'a base::Connection,
                                  acceleration_numerator  : i16,
                                  acceleration_denominator: i16,
                                  threshold               : i16,
                                  do_acceleration         : bool,
                                  do_threshold            : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_change_pointer_control(c.get_raw_conn(),
                                                acceleration_numerator as i16,  // 0
                                                acceleration_denominator as i16,  // 1
                                                threshold as i16,  // 2
                                                do_acceleration as u8,  // 3
                                                do_threshold as u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_pointer_control_checked<'a>(c                       : &'a base::Connection,
                                          acceleration_numerator  : i16,
                                          acceleration_denominator: i16,
                                          threshold               : i16,
                                          do_acceleration         : bool,
                                          do_threshold            : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_change_pointer_control_checked(c.get_raw_conn(),
                                                        acceleration_numerator as i16,  // 0
                                                        acceleration_denominator as i16,  // 1
                                                        threshold as i16,  // 2
                                                        do_acceleration as u8,  // 3
                                                        do_threshold as u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_POINTER_CONTROL: u8 = 106;

pub type GetPointerControlCookie<'a> = base::Cookie<'a, xcb_get_pointer_control_cookie_t>;

impl<'a> GetPointerControlCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPointerControlReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPointerControlReply {
                    ptr: xcb_get_pointer_control_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPointerControlReply {
                    ptr: xcb_get_pointer_control_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPointerControlReply = base::Reply<xcb_get_pointer_control_reply_t>;

impl GetPointerControlReply {
    pub fn acceleration_numerator(&self) -> u16 {
        unsafe {
            (*self.ptr).acceleration_numerator
        }
    }
    pub fn acceleration_denominator(&self) -> u16 {
        unsafe {
            (*self.ptr).acceleration_denominator
        }
    }
    pub fn threshold(&self) -> u16 {
        unsafe {
            (*self.ptr).threshold
        }
    }
}

pub fn get_pointer_control<'a>(c: &'a base::Connection)
        -> GetPointerControlCookie<'a> {
    unsafe {
        let cookie = xcb_get_pointer_control(c.get_raw_conn());
        GetPointerControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_pointer_control_unchecked<'a>(c: &'a base::Connection)
        -> GetPointerControlCookie<'a> {
    unsafe {
        let cookie = xcb_get_pointer_control_unchecked(c.get_raw_conn());
        GetPointerControlCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_SCREEN_SAVER: u8 = 107;

pub fn set_screen_saver<'a>(c              : &'a base::Connection,
                            timeout        : i16,
                            interval       : i16,
                            prefer_blanking: u8,
                            allow_exposures: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_screen_saver(c.get_raw_conn(),
                                          timeout as i16,  // 0
                                          interval as i16,  // 1
                                          prefer_blanking as u8,  // 2
                                          allow_exposures as u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_screen_saver_checked<'a>(c              : &'a base::Connection,
                                    timeout        : i16,
                                    interval       : i16,
                                    prefer_blanking: u8,
                                    allow_exposures: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_screen_saver_checked(c.get_raw_conn(),
                                                  timeout as i16,  // 0
                                                  interval as i16,  // 1
                                                  prefer_blanking as u8,  // 2
                                                  allow_exposures as u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_SCREEN_SAVER: u8 = 108;

pub type GetScreenSaverCookie<'a> = base::Cookie<'a, xcb_get_screen_saver_cookie_t>;

impl<'a> GetScreenSaverCookie<'a> {
    pub fn get_reply(&self) -> Result<GetScreenSaverReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetScreenSaverReply {
                    ptr: xcb_get_screen_saver_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetScreenSaverReply {
                    ptr: xcb_get_screen_saver_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetScreenSaverReply = base::Reply<xcb_get_screen_saver_reply_t>;

impl GetScreenSaverReply {
    pub fn timeout(&self) -> u16 {
        unsafe {
            (*self.ptr).timeout
        }
    }
    pub fn interval(&self) -> u16 {
        unsafe {
            (*self.ptr).interval
        }
    }
    pub fn prefer_blanking(&self) -> u8 {
        unsafe {
            (*self.ptr).prefer_blanking
        }
    }
    pub fn allow_exposures(&self) -> u8 {
        unsafe {
            (*self.ptr).allow_exposures
        }
    }
}

pub fn get_screen_saver<'a>(c: &'a base::Connection)
        -> GetScreenSaverCookie<'a> {
    unsafe {
        let cookie = xcb_get_screen_saver(c.get_raw_conn());
        GetScreenSaverCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_screen_saver_unchecked<'a>(c: &'a base::Connection)
        -> GetScreenSaverCookie<'a> {
    unsafe {
        let cookie = xcb_get_screen_saver_unchecked(c.get_raw_conn());
        GetScreenSaverCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_HOSTS: u8 = 109;

pub fn change_hosts<'a>(c      : &'a base::Connection,
                        mode   : u8,
                        family : u8,
                        address: &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let address_len = address.len();
        let address_ptr = address.as_ptr();
        let cookie = xcb_change_hosts(c.get_raw_conn(),
                                      mode as u8,  // 0
                                      family as u8,  // 1
                                      address_len as u16,  // 2
                                      address_ptr as *const u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_hosts_checked<'a>(c      : &'a base::Connection,
                                mode   : u8,
                                family : u8,
                                address: &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let address_len = address.len();
        let address_ptr = address.as_ptr();
        let cookie = xcb_change_hosts_checked(c.get_raw_conn(),
                                              mode as u8,  // 0
                                              family as u8,  // 1
                                              address_len as u16,  // 2
                                              address_ptr as *const u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub type Host<'a> = base::StructPtr<'a, xcb_host_t>;

impl<'a> Host<'a> {
    pub fn family(&self) -> u8 {
        unsafe {
            (*self.ptr).family
        }
    }
    pub fn address_len(&self) -> u16 {
        unsafe {
            (*self.ptr).address_len
        }
    }
    pub fn address(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_host_address_length(field) as usize;
            let data = xcb_host_address(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type HostIterator<'a> = xcb_host_iterator_t<'a>;

impl<'a> Iterator for HostIterator<'a> {
    type Item = Host<'a>;
    fn next(&mut self) -> std::option::Option<Host<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_host_iterator_t;
                let data = (*iter).data;
                xcb_host_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const LIST_HOSTS: u8 = 110;

pub type ListHostsCookie<'a> = base::Cookie<'a, xcb_list_hosts_cookie_t>;

impl<'a> ListHostsCookie<'a> {
    pub fn get_reply(&self) -> Result<ListHostsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListHostsReply {
                    ptr: xcb_list_hosts_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListHostsReply {
                    ptr: xcb_list_hosts_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListHostsReply = base::Reply<xcb_list_hosts_reply_t>;

impl ListHostsReply {
    pub fn mode(&self) -> u8 {
        unsafe {
            (*self.ptr).mode
        }
    }
    pub fn hosts_len(&self) -> u16 {
        unsafe {
            (*self.ptr).hosts_len
        }
    }
    pub fn hosts(&self) -> HostIterator {
        unsafe {
            xcb_list_hosts_hosts_iterator(self.ptr)
        }
    }
}

pub fn list_hosts<'a>(c: &'a base::Connection)
        -> ListHostsCookie<'a> {
    unsafe {
        let cookie = xcb_list_hosts(c.get_raw_conn());
        ListHostsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_hosts_unchecked<'a>(c: &'a base::Connection)
        -> ListHostsCookie<'a> {
    unsafe {
        let cookie = xcb_list_hosts_unchecked(c.get_raw_conn());
        ListHostsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_ACCESS_CONTROL: u8 = 111;

pub fn set_access_control<'a>(c   : &'a base::Connection,
                              mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_access_control(c.get_raw_conn(),
                                            mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_access_control_checked<'a>(c   : &'a base::Connection,
                                      mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_access_control_checked(c.get_raw_conn(),
                                                    mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_CLOSE_DOWN_MODE: u8 = 112;

pub fn set_close_down_mode<'a>(c   : &'a base::Connection,
                               mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_close_down_mode(c.get_raw_conn(),
                                             mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_close_down_mode_checked<'a>(c   : &'a base::Connection,
                                       mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_set_close_down_mode_checked(c.get_raw_conn(),
                                                     mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const KILL_CLIENT: u8 = 113;

/// kills a client
///
/// Forces a close down of the client that created the specified `resource`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __resource__:
///       Any resource belonging to the client (for example a Window), used to identify
///       the client connection.
///
///       The special value of `XCB_KILL_ALL_TEMPORARY`, the resources of all clients
///       that have terminated in `RetainTemporary` (TODO) are destroyed.
pub fn kill_client<'a>(c       : &'a base::Connection,
                       resource: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_kill_client(c.get_raw_conn(),
                                     resource as u32);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

/// kills a client
///
/// Forces a close down of the client that created the specified `resource`.
///
/// parameters:
///
///   - __c__:
///       The connection object to the server
///
///   - __resource__:
///       Any resource belonging to the client (for example a Window), used to identify
///       the client connection.
///
///       The special value of `XCB_KILL_ALL_TEMPORARY`, the resources of all clients
///       that have terminated in `RetainTemporary` (TODO) are destroyed.
pub fn kill_client_checked<'a>(c       : &'a base::Connection,
                               resource: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_kill_client_checked(c.get_raw_conn(),
                                             resource as u32);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ROTATE_PROPERTIES: u8 = 114;

pub fn rotate_properties<'a>(c     : &'a base::Connection,
                             window: Window,
                             delta : i16,
                             atoms : &[Atom])
        -> base::VoidCookie<'a> {
    unsafe {
        let atoms_len = atoms.len();
        let atoms_ptr = atoms.as_ptr();
        let cookie = xcb_rotate_properties(c.get_raw_conn(),
                                           window as xcb_window_t,  // 0
                                           atoms_len as u16,  // 1
                                           delta as i16,  // 2
                                           atoms_ptr as *const xcb_atom_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn rotate_properties_checked<'a>(c     : &'a base::Connection,
                                     window: Window,
                                     delta : i16,
                                     atoms : &[Atom])
        -> base::VoidCookie<'a> {
    unsafe {
        let atoms_len = atoms.len();
        let atoms_ptr = atoms.as_ptr();
        let cookie = xcb_rotate_properties_checked(c.get_raw_conn(),
                                                   window as xcb_window_t,  // 0
                                                   atoms_len as u16,  // 1
                                                   delta as i16,  // 2
                                                   atoms_ptr as *const xcb_atom_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FORCE_SCREEN_SAVER: u8 = 115;

pub fn force_screen_saver<'a>(c   : &'a base::Connection,
                              mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_force_screen_saver(c.get_raw_conn(),
                                            mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn force_screen_saver_checked<'a>(c   : &'a base::Connection,
                                      mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_force_screen_saver_checked(c.get_raw_conn(),
                                                    mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_POINTER_MAPPING: u8 = 116;

pub type SetPointerMappingCookie<'a> = base::Cookie<'a, xcb_set_pointer_mapping_cookie_t>;

impl<'a> SetPointerMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<SetPointerMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetPointerMappingReply {
                    ptr: xcb_set_pointer_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetPointerMappingReply {
                    ptr: xcb_set_pointer_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetPointerMappingReply = base::Reply<xcb_set_pointer_mapping_reply_t>;

impl SetPointerMappingReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn set_pointer_mapping<'a>(c  : &'a base::Connection,
                               map: &[u8])
        -> SetPointerMappingCookie<'a> {
    unsafe {
        let map_len = map.len();
        let map_ptr = map.as_ptr();
        let cookie = xcb_set_pointer_mapping(c.get_raw_conn(),
                                             map_len as u8,  // 0
                                             map_ptr as *const u8);  // 1
        SetPointerMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_pointer_mapping_unchecked<'a>(c  : &'a base::Connection,
                                         map: &[u8])
        -> SetPointerMappingCookie<'a> {
    unsafe {
        let map_len = map.len();
        let map_ptr = map.as_ptr();
        let cookie = xcb_set_pointer_mapping_unchecked(c.get_raw_conn(),
                                                       map_len as u8,  // 0
                                                       map_ptr as *const u8);  // 1
        SetPointerMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_POINTER_MAPPING: u8 = 117;

pub type GetPointerMappingCookie<'a> = base::Cookie<'a, xcb_get_pointer_mapping_cookie_t>;

impl<'a> GetPointerMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPointerMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPointerMappingReply {
                    ptr: xcb_get_pointer_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPointerMappingReply {
                    ptr: xcb_get_pointer_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPointerMappingReply = base::Reply<xcb_get_pointer_mapping_reply_t>;

impl GetPointerMappingReply {
    pub fn map_len(&self) -> u8 {
        unsafe {
            (*self.ptr).map_len
        }
    }
    pub fn map(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_get_pointer_mapping_map_length(field) as usize;
            let data = xcb_get_pointer_mapping_map(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_pointer_mapping<'a>(c: &'a base::Connection)
        -> GetPointerMappingCookie<'a> {
    unsafe {
        let cookie = xcb_get_pointer_mapping(c.get_raw_conn());
        GetPointerMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_pointer_mapping_unchecked<'a>(c: &'a base::Connection)
        -> GetPointerMappingCookie<'a> {
    unsafe {
        let cookie = xcb_get_pointer_mapping_unchecked(c.get_raw_conn());
        GetPointerMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_MODIFIER_MAPPING: u8 = 118;

pub type SetModifierMappingCookie<'a> = base::Cookie<'a, xcb_set_modifier_mapping_cookie_t>;

impl<'a> SetModifierMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<SetModifierMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = SetModifierMappingReply {
                    ptr: xcb_set_modifier_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( SetModifierMappingReply {
                    ptr: xcb_set_modifier_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type SetModifierMappingReply = base::Reply<xcb_set_modifier_mapping_reply_t>;

impl SetModifierMappingReply {
    pub fn status(&self) -> u8 {
        unsafe {
            (*self.ptr).status
        }
    }
}

pub fn set_modifier_mapping<'a>(c       : &'a base::Connection,
                                keycodes: &[Keycode])
        -> SetModifierMappingCookie<'a> {
    unsafe {
        let keycodes_len = keycodes.len();
        let keycodes_ptr = keycodes.as_ptr();
        let cookie = xcb_set_modifier_mapping(c.get_raw_conn(),
                                              keycodes_len as u8,  // 0
                                              keycodes_ptr as *const xcb_keycode_t);  // 1
        SetModifierMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn set_modifier_mapping_unchecked<'a>(c       : &'a base::Connection,
                                          keycodes: &[Keycode])
        -> SetModifierMappingCookie<'a> {
    unsafe {
        let keycodes_len = keycodes.len();
        let keycodes_ptr = keycodes.as_ptr();
        let cookie = xcb_set_modifier_mapping_unchecked(c.get_raw_conn(),
                                                        keycodes_len as u8,  // 0
                                                        keycodes_ptr as *const xcb_keycode_t);  // 1
        SetModifierMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MODIFIER_MAPPING: u8 = 119;

pub type GetModifierMappingCookie<'a> = base::Cookie<'a, xcb_get_modifier_mapping_cookie_t>;

impl<'a> GetModifierMappingCookie<'a> {
    pub fn get_reply(&self) -> Result<GetModifierMappingReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetModifierMappingReply {
                    ptr: xcb_get_modifier_mapping_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetModifierMappingReply {
                    ptr: xcb_get_modifier_mapping_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetModifierMappingReply = base::Reply<xcb_get_modifier_mapping_reply_t>;

impl GetModifierMappingReply {
    pub fn keycodes_per_modifier(&self) -> u8 {
        unsafe {
            (*self.ptr).keycodes_per_modifier
        }
    }
    pub fn keycodes(&self) -> &[Keycode] {
        unsafe {
            let field = self.ptr;
            let len = xcb_get_modifier_mapping_keycodes_length(field) as usize;
            let data = xcb_get_modifier_mapping_keycodes(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_modifier_mapping<'a>(c: &'a base::Connection)
        -> GetModifierMappingCookie<'a> {
    unsafe {
        let cookie = xcb_get_modifier_mapping(c.get_raw_conn());
        GetModifierMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_modifier_mapping_unchecked<'a>(c: &'a base::Connection)
        -> GetModifierMappingCookie<'a> {
    unsafe {
        let cookie = xcb_get_modifier_mapping_unchecked(c.get_raw_conn());
        GetModifierMappingCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const NO_OPERATION: u8 = 127;

pub fn no_operation<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_no_operation(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn no_operation_checked<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_no_operation_checked(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}
