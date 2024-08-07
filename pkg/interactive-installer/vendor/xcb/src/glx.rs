// Generated automatically from glx.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::glx::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_glx_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 4;

pub type Pixmap = xcb_glx_pixmap_t;

pub type Context = xcb_glx_context_t;

pub type Pbuffer = xcb_glx_pbuffer_t;

pub type Window = xcb_glx_window_t;

pub type Fbconfig = xcb_glx_fbconfig_t;

pub type Drawable = xcb_glx_drawable_t;

pub type Float32 = xcb_glx_float32_t;

pub type Float64 = xcb_glx_float64_t;

pub type Bool32 = xcb_glx_bool32_t;

pub type ContextTag = xcb_glx_context_tag_t;

pub struct GenericError {
    pub base: base::Error<xcb_glx_generic_error_t>
}

pub struct BadContextError {
    pub base: base::Error<xcb_glx_bad_context_error_t>
}

pub struct BadContextStateError {
    pub base: base::Error<xcb_glx_bad_context_state_error_t>
}

pub struct BadDrawableError {
    pub base: base::Error<xcb_glx_bad_drawable_error_t>
}

pub struct BadPixmapError {
    pub base: base::Error<xcb_glx_bad_pixmap_error_t>
}

pub struct BadContextTagError {
    pub base: base::Error<xcb_glx_bad_context_tag_error_t>
}

pub struct BadCurrentWindowError {
    pub base: base::Error<xcb_glx_bad_current_window_error_t>
}

pub struct BadRenderRequestError {
    pub base: base::Error<xcb_glx_bad_render_request_error_t>
}

pub struct BadLargeRequestError {
    pub base: base::Error<xcb_glx_bad_large_request_error_t>
}

pub struct UnsupportedPrivateRequestError {
    pub base: base::Error<xcb_glx_unsupported_private_request_error_t>
}

pub struct BadFbConfigError {
    pub base: base::Error<xcb_glx_bad_fb_config_error_t>
}

pub struct BadPbufferError {
    pub base: base::Error<xcb_glx_bad_pbuffer_error_t>
}

pub struct BadCurrentDrawableError {
    pub base: base::Error<xcb_glx_bad_current_drawable_error_t>
}

pub struct BadWindowError {
    pub base: base::Error<xcb_glx_bad_window_error_t>
}

pub struct GlxBadProfileArbError {
    pub base: base::Error<xcb_glx_glx_bad_profile_arb_error_t>
}

pub type Pbcet = u32;
pub const PBCET_DAMAGED: Pbcet = 0x8017;
pub const PBCET_SAVED  : Pbcet = 0x8018;

pub type Pbcdt = u32;
pub const PBCDT_WINDOW : Pbcdt = 0x8019;
pub const PBCDT_PBUFFER: Pbcdt = 0x801a;

pub type Gc = u32;
pub const GC_GL_CURRENT_BIT        : Gc =     0x01;
pub const GC_GL_POINT_BIT          : Gc =     0x02;
pub const GC_GL_LINE_BIT           : Gc =     0x04;
pub const GC_GL_POLYGON_BIT        : Gc =     0x08;
pub const GC_GL_POLYGON_STIPPLE_BIT: Gc =     0x10;
pub const GC_GL_PIXEL_MODE_BIT     : Gc =     0x20;
pub const GC_GL_LIGHTING_BIT       : Gc =     0x40;
pub const GC_GL_FOG_BIT            : Gc =     0x80;
pub const GC_GL_DEPTH_BUFFER_BIT   : Gc =    0x100;
pub const GC_GL_ACCUM_BUFFER_BIT   : Gc =    0x200;
pub const GC_GL_STENCIL_BUFFER_BIT : Gc =    0x400;
pub const GC_GL_VIEWPORT_BIT       : Gc =    0x800;
pub const GC_GL_TRANSFORM_BIT      : Gc =   0x1000;
pub const GC_GL_ENABLE_BIT         : Gc =   0x2000;
pub const GC_GL_COLOR_BUFFER_BIT   : Gc =   0x4000;
pub const GC_GL_HINT_BIT           : Gc =   0x8000;
pub const GC_GL_EVAL_BIT           : Gc =  0x10000;
pub const GC_GL_LIST_BIT           : Gc =  0x20000;
pub const GC_GL_TEXTURE_BIT        : Gc =  0x40000;
pub const GC_GL_SCISSOR_BIT        : Gc =  0x80000;
pub const GC_GL_ALL_ATTRIB_BITS    : Gc = 0xffffff;

pub type Rm = u32;
pub const RM_GL_RENDER  : Rm = 0x1c00;
pub const RM_GL_FEEDBACK: Rm = 0x1c01;
pub const RM_GL_SELECT  : Rm = 0x1c02;



pub const GENERIC: i8 = -1;

pub const BAD_CONTEXT: u8 = 0;

pub const BAD_CONTEXT_STATE: u8 = 1;

pub const BAD_DRAWABLE: u8 = 2;

pub const BAD_PIXMAP: u8 = 3;

pub const BAD_CONTEXT_TAG: u8 = 4;

pub const BAD_CURRENT_WINDOW: u8 = 5;

pub const BAD_RENDER_REQUEST: u8 = 6;

pub const BAD_LARGE_REQUEST: u8 = 7;

pub const UNSUPPORTED_PRIVATE_REQUEST: u8 = 8;

pub const BAD_FB_CONFIG: u8 = 9;

pub const BAD_PBUFFER: u8 = 10;

pub const BAD_CURRENT_DRAWABLE: u8 = 11;

pub const BAD_WINDOW: u8 = 12;

pub const GLX_BAD_PROFILE_ARB: u8 = 13;

pub const PBUFFER_CLOBBER: u8 = 0;

pub type PbufferClobberEvent = base::Event<xcb_glx_pbuffer_clobber_event_t>;

impl PbufferClobberEvent {
    pub fn event_type(&self) -> u16 {
        unsafe {
            (*self.ptr).event_type
        }
    }
    pub fn draw_type(&self) -> u16 {
        unsafe {
            (*self.ptr).draw_type
        }
    }
    pub fn drawable(&self) -> Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    pub fn b_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).b_mask
        }
    }
    pub fn aux_buffer(&self) -> u16 {
        unsafe {
            (*self.ptr).aux_buffer
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
    pub fn count(&self) -> u16 {
        unsafe {
            (*self.ptr).count
        }
    }
    /// Constructs a new PbufferClobberEvent
    /// `response_type` will be set automatically to PBUFFER_CLOBBER
    pub fn new(event_type: u16,
               draw_type: u16,
               drawable: Drawable,
               b_mask: u32,
               aux_buffer: u16,
               x: u16,
               y: u16,
               width: u16,
               height: u16,
               count: u16)
            -> PbufferClobberEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_glx_pbuffer_clobber_event_t;
            (*raw).response_type = PBUFFER_CLOBBER;
            (*raw).event_type = event_type;
            (*raw).draw_type = draw_type;
            (*raw).drawable = drawable;
            (*raw).b_mask = b_mask;
            (*raw).aux_buffer = aux_buffer;
            (*raw).x = x;
            (*raw).y = y;
            (*raw).width = width;
            (*raw).height = height;
            (*raw).count = count;
            PbufferClobberEvent {
                ptr: raw
            }
        }
    }
}

pub const BUFFER_SWAP_COMPLETE: u8 = 1;

pub type BufferSwapCompleteEvent = base::Event<xcb_glx_buffer_swap_complete_event_t>;

impl BufferSwapCompleteEvent {
    pub fn event_type(&self) -> u16 {
        unsafe {
            (*self.ptr).event_type
        }
    }
    pub fn drawable(&self) -> Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    pub fn ust_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_hi
        }
    }
    pub fn ust_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).ust_lo
        }
    }
    pub fn msc_hi(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_hi
        }
    }
    pub fn msc_lo(&self) -> u32 {
        unsafe {
            (*self.ptr).msc_lo
        }
    }
    pub fn sbc(&self) -> u32 {
        unsafe {
            (*self.ptr).sbc
        }
    }
    /// Constructs a new BufferSwapCompleteEvent
    /// `response_type` will be set automatically to BUFFER_SWAP_COMPLETE
    pub fn new(event_type: u16,
               drawable: Drawable,
               ust_hi: u32,
               ust_lo: u32,
               msc_hi: u32,
               msc_lo: u32,
               sbc: u32)
            -> BufferSwapCompleteEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_glx_buffer_swap_complete_event_t;
            (*raw).response_type = BUFFER_SWAP_COMPLETE;
            (*raw).event_type = event_type;
            (*raw).drawable = drawable;
            (*raw).ust_hi = ust_hi;
            (*raw).ust_lo = ust_lo;
            (*raw).msc_hi = msc_hi;
            (*raw).msc_lo = msc_lo;
            (*raw).sbc = sbc;
            BufferSwapCompleteEvent {
                ptr: raw
            }
        }
    }
}

pub const RENDER: u8 = 1;

pub fn render<'a>(c          : &'a base::Connection,
                  context_tag: ContextTag,
                  data       : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_glx_render(c.get_raw_conn(),
                                    context_tag as xcb_glx_context_tag_t,  // 0
                                    data_len as u32,  // 1
                                    data_ptr as *const u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn render_checked<'a>(c          : &'a base::Connection,
                          context_tag: ContextTag,
                          data       : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_glx_render_checked(c.get_raw_conn(),
                                            context_tag as xcb_glx_context_tag_t,  // 0
                                            data_len as u32,  // 1
                                            data_ptr as *const u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const RENDER_LARGE: u8 = 2;

pub fn render_large<'a>(c            : &'a base::Connection,
                        context_tag  : ContextTag,
                        request_num  : u16,
                        request_total: u16,
                        data         : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_glx_render_large(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          request_num as u16,  // 1
                                          request_total as u16,  // 2
                                          data_len as u32,  // 3
                                          data_ptr as *const u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn render_large_checked<'a>(c            : &'a base::Connection,
                                context_tag  : ContextTag,
                                request_num  : u16,
                                request_total: u16,
                                data         : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_glx_render_large_checked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  request_num as u16,  // 1
                                                  request_total as u16,  // 2
                                                  data_len as u32,  // 3
                                                  data_ptr as *const u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_CONTEXT: u8 = 3;

pub fn create_context<'a>(c         : &'a base::Connection,
                          context   : Context,
                          visual    : xproto::Visualid,
                          screen    : u32,
                          share_list: Context,
                          is_direct : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_create_context(c.get_raw_conn(),
                                            context as xcb_glx_context_t,  // 0
                                            visual as xcb_visualid_t,  // 1
                                            screen as u32,  // 2
                                            share_list as xcb_glx_context_t,  // 3
                                            is_direct as u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_context_checked<'a>(c         : &'a base::Connection,
                                  context   : Context,
                                  visual    : xproto::Visualid,
                                  screen    : u32,
                                  share_list: Context,
                                  is_direct : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_create_context_checked(c.get_raw_conn(),
                                                    context as xcb_glx_context_t,  // 0
                                                    visual as xcb_visualid_t,  // 1
                                                    screen as u32,  // 2
                                                    share_list as xcb_glx_context_t,  // 3
                                                    is_direct as u8);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_CONTEXT: u8 = 4;

pub fn destroy_context<'a>(c      : &'a base::Connection,
                           context: Context)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_destroy_context(c.get_raw_conn(),
                                             context as xcb_glx_context_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_context_checked<'a>(c      : &'a base::Connection,
                                   context: Context)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_destroy_context_checked(c.get_raw_conn(),
                                                     context as xcb_glx_context_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const MAKE_CURRENT: u8 = 5;

pub type MakeCurrentCookie<'a> = base::Cookie<'a, xcb_glx_make_current_cookie_t>;

impl<'a> MakeCurrentCookie<'a> {
    pub fn get_reply(&self) -> Result<MakeCurrentReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = MakeCurrentReply {
                    ptr: xcb_glx_make_current_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( MakeCurrentReply {
                    ptr: xcb_glx_make_current_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type MakeCurrentReply = base::Reply<xcb_glx_make_current_reply_t>;

impl MakeCurrentReply {
    pub fn context_tag(&self) -> ContextTag {
        unsafe {
            (*self.ptr).context_tag
        }
    }
}

pub fn make_current<'a>(c              : &'a base::Connection,
                        drawable       : Drawable,
                        context        : Context,
                        old_context_tag: ContextTag)
        -> MakeCurrentCookie<'a> {
    unsafe {
        let cookie = xcb_glx_make_current(c.get_raw_conn(),
                                          drawable as xcb_glx_drawable_t,  // 0
                                          context as xcb_glx_context_t,  // 1
                                          old_context_tag as xcb_glx_context_tag_t);  // 2
        MakeCurrentCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn make_current_unchecked<'a>(c              : &'a base::Connection,
                                  drawable       : Drawable,
                                  context        : Context,
                                  old_context_tag: ContextTag)
        -> MakeCurrentCookie<'a> {
    unsafe {
        let cookie = xcb_glx_make_current_unchecked(c.get_raw_conn(),
                                                    drawable as xcb_glx_drawable_t,  // 0
                                                    context as xcb_glx_context_t,  // 1
                                                    old_context_tag as xcb_glx_context_tag_t);  // 2
        MakeCurrentCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const IS_DIRECT: u8 = 6;

pub type IsDirectCookie<'a> = base::Cookie<'a, xcb_glx_is_direct_cookie_t>;

impl<'a> IsDirectCookie<'a> {
    pub fn get_reply(&self) -> Result<IsDirectReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = IsDirectReply {
                    ptr: xcb_glx_is_direct_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( IsDirectReply {
                    ptr: xcb_glx_is_direct_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type IsDirectReply = base::Reply<xcb_glx_is_direct_reply_t>;

impl IsDirectReply {
    pub fn is_direct(&self) -> bool {
        unsafe {
            (*self.ptr).is_direct != 0
        }
    }
}

pub fn is_direct<'a>(c      : &'a base::Connection,
                     context: Context)
        -> IsDirectCookie<'a> {
    unsafe {
        let cookie = xcb_glx_is_direct(c.get_raw_conn(),
                                       context as xcb_glx_context_t);  // 0
        IsDirectCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn is_direct_unchecked<'a>(c      : &'a base::Connection,
                               context: Context)
        -> IsDirectCookie<'a> {
    unsafe {
        let cookie = xcb_glx_is_direct_unchecked(c.get_raw_conn(),
                                                 context as xcb_glx_context_t);  // 0
        IsDirectCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_VERSION: u8 = 7;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_glx_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_glx_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_glx_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_glx_query_version_reply_t>;

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
        let cookie = xcb_glx_query_version(c.get_raw_conn(),
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
        let cookie = xcb_glx_query_version_unchecked(c.get_raw_conn(),
                                                     major_version as u32,  // 0
                                                     minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const WAIT_GL: u8 = 8;

pub fn wait_gl<'a>(c          : &'a base::Connection,
                   context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_wait_gl(c.get_raw_conn(),
                                     context_tag as xcb_glx_context_tag_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn wait_gl_checked<'a>(c          : &'a base::Connection,
                           context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_wait_gl_checked(c.get_raw_conn(),
                                             context_tag as xcb_glx_context_tag_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const WAIT_X: u8 = 9;

pub fn wait_x<'a>(c          : &'a base::Connection,
                  context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_wait_x(c.get_raw_conn(),
                                    context_tag as xcb_glx_context_tag_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn wait_x_checked<'a>(c          : &'a base::Connection,
                          context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_wait_x_checked(c.get_raw_conn(),
                                            context_tag as xcb_glx_context_tag_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COPY_CONTEXT: u8 = 10;

pub fn copy_context<'a>(c              : &'a base::Connection,
                        src            : Context,
                        dest           : Context,
                        mask           : u32,
                        src_context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_copy_context(c.get_raw_conn(),
                                          src as xcb_glx_context_t,  // 0
                                          dest as xcb_glx_context_t,  // 1
                                          mask as u32,  // 2
                                          src_context_tag as xcb_glx_context_tag_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn copy_context_checked<'a>(c              : &'a base::Connection,
                                src            : Context,
                                dest           : Context,
                                mask           : u32,
                                src_context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_copy_context_checked(c.get_raw_conn(),
                                                  src as xcb_glx_context_t,  // 0
                                                  dest as xcb_glx_context_t,  // 1
                                                  mask as u32,  // 2
                                                  src_context_tag as xcb_glx_context_tag_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SWAP_BUFFERS: u8 = 11;

pub fn swap_buffers<'a>(c          : &'a base::Connection,
                        context_tag: ContextTag,
                        drawable   : Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_swap_buffers(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          drawable as xcb_glx_drawable_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn swap_buffers_checked<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                drawable   : Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_swap_buffers_checked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  drawable as xcb_glx_drawable_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const USE_X_FONT: u8 = 12;

pub fn use_x_font<'a>(c          : &'a base::Connection,
                      context_tag: ContextTag,
                      font       : xproto::Font,
                      first      : u32,
                      count      : u32,
                      list_base  : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_use_x_font(c.get_raw_conn(),
                                        context_tag as xcb_glx_context_tag_t,  // 0
                                        font as xcb_font_t,  // 1
                                        first as u32,  // 2
                                        count as u32,  // 3
                                        list_base as u32);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn use_x_font_checked<'a>(c          : &'a base::Connection,
                              context_tag: ContextTag,
                              font       : xproto::Font,
                              first      : u32,
                              count      : u32,
                              list_base  : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_use_x_font_checked(c.get_raw_conn(),
                                                context_tag as xcb_glx_context_tag_t,  // 0
                                                font as xcb_font_t,  // 1
                                                first as u32,  // 2
                                                count as u32,  // 3
                                                list_base as u32);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_GLX_PIXMAP: u8 = 13;

pub fn create_glx_pixmap<'a>(c         : &'a base::Connection,
                             screen    : u32,
                             visual    : xproto::Visualid,
                             pixmap    : xproto::Pixmap,
                             glx_pixmap: Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_create_glx_pixmap(c.get_raw_conn(),
                                               screen as u32,  // 0
                                               visual as xcb_visualid_t,  // 1
                                               pixmap as xcb_pixmap_t,  // 2
                                               glx_pixmap as xcb_glx_pixmap_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_glx_pixmap_checked<'a>(c         : &'a base::Connection,
                                     screen    : u32,
                                     visual    : xproto::Visualid,
                                     pixmap    : xproto::Pixmap,
                                     glx_pixmap: Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_create_glx_pixmap_checked(c.get_raw_conn(),
                                                       screen as u32,  // 0
                                                       visual as xcb_visualid_t,  // 1
                                                       pixmap as xcb_pixmap_t,  // 2
                                                       glx_pixmap as xcb_glx_pixmap_t);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_VISUAL_CONFIGS: u8 = 14;

pub type GetVisualConfigsCookie<'a> = base::Cookie<'a, xcb_glx_get_visual_configs_cookie_t>;

impl<'a> GetVisualConfigsCookie<'a> {
    pub fn get_reply(&self) -> Result<GetVisualConfigsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetVisualConfigsReply {
                    ptr: xcb_glx_get_visual_configs_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetVisualConfigsReply {
                    ptr: xcb_glx_get_visual_configs_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetVisualConfigsReply = base::Reply<xcb_glx_get_visual_configs_reply_t>;

impl GetVisualConfigsReply {
    pub fn num_visuals(&self) -> u32 {
        unsafe {
            (*self.ptr).num_visuals
        }
    }
    pub fn num_properties(&self) -> u32 {
        unsafe {
            (*self.ptr).num_properties
        }
    }
    pub fn property_list(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_visual_configs_property_list_length(field) as usize;
            let data = xcb_glx_get_visual_configs_property_list(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_visual_configs<'a>(c     : &'a base::Connection,
                              screen: u32)
        -> GetVisualConfigsCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_visual_configs(c.get_raw_conn(),
                                                screen as u32);  // 0
        GetVisualConfigsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_visual_configs_unchecked<'a>(c     : &'a base::Connection,
                                        screen: u32)
        -> GetVisualConfigsCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_visual_configs_unchecked(c.get_raw_conn(),
                                                          screen as u32);  // 0
        GetVisualConfigsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DESTROY_GLX_PIXMAP: u8 = 15;

pub fn destroy_glx_pixmap<'a>(c         : &'a base::Connection,
                              glx_pixmap: Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_destroy_glx_pixmap(c.get_raw_conn(),
                                                glx_pixmap as xcb_glx_pixmap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_glx_pixmap_checked<'a>(c         : &'a base::Connection,
                                      glx_pixmap: Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_destroy_glx_pixmap_checked(c.get_raw_conn(),
                                                        glx_pixmap as xcb_glx_pixmap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const VENDOR_PRIVATE: u8 = 16;

pub fn vendor_private<'a>(c          : &'a base::Connection,
                          vendor_code: u32,
                          context_tag: ContextTag,
                          data       : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_glx_vendor_private(c.get_raw_conn(),
                                            vendor_code as u32,  // 0
                                            context_tag as xcb_glx_context_tag_t,  // 1
                                            data_len as u32,  // 2
                                            data_ptr as *const u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn vendor_private_checked<'a>(c          : &'a base::Connection,
                                  vendor_code: u32,
                                  context_tag: ContextTag,
                                  data       : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_glx_vendor_private_checked(c.get_raw_conn(),
                                                    vendor_code as u32,  // 0
                                                    context_tag as xcb_glx_context_tag_t,  // 1
                                                    data_len as u32,  // 2
                                                    data_ptr as *const u8);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const VENDOR_PRIVATE_WITH_REPLY: u8 = 17;

pub type VendorPrivateWithReplyCookie<'a> = base::Cookie<'a, xcb_glx_vendor_private_with_reply_cookie_t>;

impl<'a> VendorPrivateWithReplyCookie<'a> {
    pub fn get_reply(&self) -> Result<VendorPrivateWithReplyReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = VendorPrivateWithReplyReply {
                    ptr: xcb_glx_vendor_private_with_reply_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( VendorPrivateWithReplyReply {
                    ptr: xcb_glx_vendor_private_with_reply_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type VendorPrivateWithReplyReply = base::Reply<xcb_glx_vendor_private_with_reply_reply_t>;

impl VendorPrivateWithReplyReply {
    pub fn retval(&self) -> u32 {
        unsafe {
            (*self.ptr).retval
        }
    }
    pub fn data1(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).data1
        }
    }
    pub fn data2(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_vendor_private_with_reply_data_2_length(field) as usize;
            let data = xcb_glx_vendor_private_with_reply_data_2(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn vendor_private_with_reply<'a>(c          : &'a base::Connection,
                                     vendor_code: u32,
                                     context_tag: ContextTag,
                                     data       : &[u8])
        -> VendorPrivateWithReplyCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_glx_vendor_private_with_reply(c.get_raw_conn(),
                                                       vendor_code as u32,  // 0
                                                       context_tag as xcb_glx_context_tag_t,  // 1
                                                       data_len as u32,  // 2
                                                       data_ptr as *const u8);  // 3
        VendorPrivateWithReplyCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn vendor_private_with_reply_unchecked<'a>(c          : &'a base::Connection,
                                               vendor_code: u32,
                                               context_tag: ContextTag,
                                               data       : &[u8])
        -> VendorPrivateWithReplyCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_glx_vendor_private_with_reply_unchecked(c.get_raw_conn(),
                                                                 vendor_code as u32,  // 0
                                                                 context_tag as xcb_glx_context_tag_t,  // 1
                                                                 data_len as u32,  // 2
                                                                 data_ptr as *const u8);  // 3
        VendorPrivateWithReplyCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_EXTENSIONS_STRING: u8 = 18;

pub type QueryExtensionsStringCookie<'a> = base::Cookie<'a, xcb_glx_query_extensions_string_cookie_t>;

impl<'a> QueryExtensionsStringCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryExtensionsStringReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryExtensionsStringReply {
                    ptr: xcb_glx_query_extensions_string_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryExtensionsStringReply {
                    ptr: xcb_glx_query_extensions_string_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryExtensionsStringReply = base::Reply<xcb_glx_query_extensions_string_reply_t>;

impl QueryExtensionsStringReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
}

pub fn query_extensions_string<'a>(c     : &'a base::Connection,
                                   screen: u32)
        -> QueryExtensionsStringCookie<'a> {
    unsafe {
        let cookie = xcb_glx_query_extensions_string(c.get_raw_conn(),
                                                     screen as u32);  // 0
        QueryExtensionsStringCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_extensions_string_unchecked<'a>(c     : &'a base::Connection,
                                             screen: u32)
        -> QueryExtensionsStringCookie<'a> {
    unsafe {
        let cookie = xcb_glx_query_extensions_string_unchecked(c.get_raw_conn(),
                                                               screen as u32);  // 0
        QueryExtensionsStringCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_SERVER_STRING: u8 = 19;

pub type QueryServerStringCookie<'a> = base::Cookie<'a, xcb_glx_query_server_string_cookie_t>;

impl<'a> QueryServerStringCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryServerStringReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryServerStringReply {
                    ptr: xcb_glx_query_server_string_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryServerStringReply {
                    ptr: xcb_glx_query_server_string_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryServerStringReply = base::Reply<xcb_glx_query_server_string_reply_t>;

impl QueryServerStringReply {
    pub fn str_len(&self) -> u32 {
        unsafe {
            (*self.ptr).str_len
        }
    }
    pub fn string(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_query_server_string_string_length(field) as usize;
            let data = xcb_glx_query_server_string_string(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn query_server_string<'a>(c     : &'a base::Connection,
                               screen: u32,
                               name  : u32)
        -> QueryServerStringCookie<'a> {
    unsafe {
        let cookie = xcb_glx_query_server_string(c.get_raw_conn(),
                                                 screen as u32,  // 0
                                                 name as u32);  // 1
        QueryServerStringCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_server_string_unchecked<'a>(c     : &'a base::Connection,
                                         screen: u32,
                                         name  : u32)
        -> QueryServerStringCookie<'a> {
    unsafe {
        let cookie = xcb_glx_query_server_string_unchecked(c.get_raw_conn(),
                                                           screen as u32,  // 0
                                                           name as u32);  // 1
        QueryServerStringCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CLIENT_INFO: u8 = 20;

pub fn client_info<'a>(c            : &'a base::Connection,
                       major_version: u32,
                       minor_version: u32,
                       string       : &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let string = string.as_bytes();
        let string_len = string.len();
        let string_ptr = string.as_ptr();
        let cookie = xcb_glx_client_info(c.get_raw_conn(),
                                         major_version as u32,  // 0
                                         minor_version as u32,  // 1
                                         string_len as u32,  // 2
                                         string_ptr as *const c_char);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn client_info_checked<'a>(c            : &'a base::Connection,
                               major_version: u32,
                               minor_version: u32,
                               string       : &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let string = string.as_bytes();
        let string_len = string.len();
        let string_ptr = string.as_ptr();
        let cookie = xcb_glx_client_info_checked(c.get_raw_conn(),
                                                 major_version as u32,  // 0
                                                 minor_version as u32,  // 1
                                                 string_len as u32,  // 2
                                                 string_ptr as *const c_char);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_FB_CONFIGS: u8 = 21;

pub type GetFbConfigsCookie<'a> = base::Cookie<'a, xcb_glx_get_fb_configs_cookie_t>;

impl<'a> GetFbConfigsCookie<'a> {
    pub fn get_reply(&self) -> Result<GetFbConfigsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetFbConfigsReply {
                    ptr: xcb_glx_get_fb_configs_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetFbConfigsReply {
                    ptr: xcb_glx_get_fb_configs_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetFbConfigsReply = base::Reply<xcb_glx_get_fb_configs_reply_t>;

impl GetFbConfigsReply {
    pub fn num__f_b_configs(&self) -> u32 {
        unsafe {
            (*self.ptr).num_FB_configs
        }
    }
    pub fn num_properties(&self) -> u32 {
        unsafe {
            (*self.ptr).num_properties
        }
    }
    pub fn property_list(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_fb_configs_property_list_length(field) as usize;
            let data = xcb_glx_get_fb_configs_property_list(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_fb_configs<'a>(c     : &'a base::Connection,
                          screen: u32)
        -> GetFbConfigsCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_fb_configs(c.get_raw_conn(),
                                            screen as u32);  // 0
        GetFbConfigsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_fb_configs_unchecked<'a>(c     : &'a base::Connection,
                                    screen: u32)
        -> GetFbConfigsCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_fb_configs_unchecked(c.get_raw_conn(),
                                                      screen as u32);  // 0
        GetFbConfigsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_PIXMAP: u8 = 22;

pub fn create_pixmap<'a>(c         : &'a base::Connection,
                         screen    : u32,
                         fbconfig  : Fbconfig,
                         pixmap    : xproto::Pixmap,
                         glx_pixmap: Pixmap,
                         attribs   : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_create_pixmap(c.get_raw_conn(),
                                           screen as u32,  // 0
                                           fbconfig as xcb_glx_fbconfig_t,  // 1
                                           pixmap as xcb_pixmap_t,  // 2
                                           glx_pixmap as xcb_glx_pixmap_t,  // 3
                                           attribs_len as u32,  // 4
                                           attribs_ptr as *const u32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_pixmap_checked<'a>(c         : &'a base::Connection,
                                 screen    : u32,
                                 fbconfig  : Fbconfig,
                                 pixmap    : xproto::Pixmap,
                                 glx_pixmap: Pixmap,
                                 attribs   : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_create_pixmap_checked(c.get_raw_conn(),
                                                   screen as u32,  // 0
                                                   fbconfig as xcb_glx_fbconfig_t,  // 1
                                                   pixmap as xcb_pixmap_t,  // 2
                                                   glx_pixmap as xcb_glx_pixmap_t,  // 3
                                                   attribs_len as u32,  // 4
                                                   attribs_ptr as *const u32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_PIXMAP: u8 = 23;

pub fn destroy_pixmap<'a>(c         : &'a base::Connection,
                          glx_pixmap: Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_destroy_pixmap(c.get_raw_conn(),
                                            glx_pixmap as xcb_glx_pixmap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_pixmap_checked<'a>(c         : &'a base::Connection,
                                  glx_pixmap: Pixmap)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_destroy_pixmap_checked(c.get_raw_conn(),
                                                    glx_pixmap as xcb_glx_pixmap_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_NEW_CONTEXT: u8 = 24;

pub fn create_new_context<'a>(c          : &'a base::Connection,
                              context    : Context,
                              fbconfig   : Fbconfig,
                              screen     : u32,
                              render_type: u32,
                              share_list : Context,
                              is_direct  : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_create_new_context(c.get_raw_conn(),
                                                context as xcb_glx_context_t,  // 0
                                                fbconfig as xcb_glx_fbconfig_t,  // 1
                                                screen as u32,  // 2
                                                render_type as u32,  // 3
                                                share_list as xcb_glx_context_t,  // 4
                                                is_direct as u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_new_context_checked<'a>(c          : &'a base::Connection,
                                      context    : Context,
                                      fbconfig   : Fbconfig,
                                      screen     : u32,
                                      render_type: u32,
                                      share_list : Context,
                                      is_direct  : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_create_new_context_checked(c.get_raw_conn(),
                                                        context as xcb_glx_context_t,  // 0
                                                        fbconfig as xcb_glx_fbconfig_t,  // 1
                                                        screen as u32,  // 2
                                                        render_type as u32,  // 3
                                                        share_list as xcb_glx_context_t,  // 4
                                                        is_direct as u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_CONTEXT: u8 = 25;

pub type QueryContextCookie<'a> = base::Cookie<'a, xcb_glx_query_context_cookie_t>;

impl<'a> QueryContextCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryContextReply {
                    ptr: xcb_glx_query_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryContextReply {
                    ptr: xcb_glx_query_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryContextReply = base::Reply<xcb_glx_query_context_reply_t>;

impl QueryContextReply {
    pub fn num_attribs(&self) -> u32 {
        unsafe {
            (*self.ptr).num_attribs
        }
    }
    pub fn attribs(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_query_context_attribs_length(field) as usize;
            let data = xcb_glx_query_context_attribs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn query_context<'a>(c      : &'a base::Connection,
                         context: Context)
        -> QueryContextCookie<'a> {
    unsafe {
        let cookie = xcb_glx_query_context(c.get_raw_conn(),
                                           context as xcb_glx_context_t);  // 0
        QueryContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_context_unchecked<'a>(c      : &'a base::Connection,
                                   context: Context)
        -> QueryContextCookie<'a> {
    unsafe {
        let cookie = xcb_glx_query_context_unchecked(c.get_raw_conn(),
                                                     context as xcb_glx_context_t);  // 0
        QueryContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const MAKE_CONTEXT_CURRENT: u8 = 26;

pub type MakeContextCurrentCookie<'a> = base::Cookie<'a, xcb_glx_make_context_current_cookie_t>;

impl<'a> MakeContextCurrentCookie<'a> {
    pub fn get_reply(&self) -> Result<MakeContextCurrentReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = MakeContextCurrentReply {
                    ptr: xcb_glx_make_context_current_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( MakeContextCurrentReply {
                    ptr: xcb_glx_make_context_current_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type MakeContextCurrentReply = base::Reply<xcb_glx_make_context_current_reply_t>;

impl MakeContextCurrentReply {
    pub fn context_tag(&self) -> ContextTag {
        unsafe {
            (*self.ptr).context_tag
        }
    }
}

pub fn make_context_current<'a>(c              : &'a base::Connection,
                                old_context_tag: ContextTag,
                                drawable       : Drawable,
                                read_drawable  : Drawable,
                                context        : Context)
        -> MakeContextCurrentCookie<'a> {
    unsafe {
        let cookie = xcb_glx_make_context_current(c.get_raw_conn(),
                                                  old_context_tag as xcb_glx_context_tag_t,  // 0
                                                  drawable as xcb_glx_drawable_t,  // 1
                                                  read_drawable as xcb_glx_drawable_t,  // 2
                                                  context as xcb_glx_context_t);  // 3
        MakeContextCurrentCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn make_context_current_unchecked<'a>(c              : &'a base::Connection,
                                          old_context_tag: ContextTag,
                                          drawable       : Drawable,
                                          read_drawable  : Drawable,
                                          context        : Context)
        -> MakeContextCurrentCookie<'a> {
    unsafe {
        let cookie = xcb_glx_make_context_current_unchecked(c.get_raw_conn(),
                                                            old_context_tag as xcb_glx_context_tag_t,  // 0
                                                            drawable as xcb_glx_drawable_t,  // 1
                                                            read_drawable as xcb_glx_drawable_t,  // 2
                                                            context as xcb_glx_context_t);  // 3
        MakeContextCurrentCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_PBUFFER: u8 = 27;

pub fn create_pbuffer<'a>(c       : &'a base::Connection,
                          screen  : u32,
                          fbconfig: Fbconfig,
                          pbuffer : Pbuffer,
                          attribs : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_create_pbuffer(c.get_raw_conn(),
                                            screen as u32,  // 0
                                            fbconfig as xcb_glx_fbconfig_t,  // 1
                                            pbuffer as xcb_glx_pbuffer_t,  // 2
                                            attribs_len as u32,  // 3
                                            attribs_ptr as *const u32);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_pbuffer_checked<'a>(c       : &'a base::Connection,
                                  screen  : u32,
                                  fbconfig: Fbconfig,
                                  pbuffer : Pbuffer,
                                  attribs : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_create_pbuffer_checked(c.get_raw_conn(),
                                                    screen as u32,  // 0
                                                    fbconfig as xcb_glx_fbconfig_t,  // 1
                                                    pbuffer as xcb_glx_pbuffer_t,  // 2
                                                    attribs_len as u32,  // 3
                                                    attribs_ptr as *const u32);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_PBUFFER: u8 = 28;

pub fn destroy_pbuffer<'a>(c      : &'a base::Connection,
                           pbuffer: Pbuffer)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_destroy_pbuffer(c.get_raw_conn(),
                                             pbuffer as xcb_glx_pbuffer_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_pbuffer_checked<'a>(c      : &'a base::Connection,
                                   pbuffer: Pbuffer)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_destroy_pbuffer_checked(c.get_raw_conn(),
                                                     pbuffer as xcb_glx_pbuffer_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_DRAWABLE_ATTRIBUTES: u8 = 29;

pub type GetDrawableAttributesCookie<'a> = base::Cookie<'a, xcb_glx_get_drawable_attributes_cookie_t>;

impl<'a> GetDrawableAttributesCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDrawableAttributesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDrawableAttributesReply {
                    ptr: xcb_glx_get_drawable_attributes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDrawableAttributesReply {
                    ptr: xcb_glx_get_drawable_attributes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDrawableAttributesReply = base::Reply<xcb_glx_get_drawable_attributes_reply_t>;

impl GetDrawableAttributesReply {
    pub fn num_attribs(&self) -> u32 {
        unsafe {
            (*self.ptr).num_attribs
        }
    }
    pub fn attribs(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_drawable_attributes_attribs_length(field) as usize;
            let data = xcb_glx_get_drawable_attributes_attribs(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_drawable_attributes<'a>(c       : &'a base::Connection,
                                   drawable: Drawable)
        -> GetDrawableAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_drawable_attributes(c.get_raw_conn(),
                                                     drawable as xcb_glx_drawable_t);  // 0
        GetDrawableAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_drawable_attributes_unchecked<'a>(c       : &'a base::Connection,
                                             drawable: Drawable)
        -> GetDrawableAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_drawable_attributes_unchecked(c.get_raw_conn(),
                                                               drawable as xcb_glx_drawable_t);  // 0
        GetDrawableAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CHANGE_DRAWABLE_ATTRIBUTES: u8 = 30;

pub fn change_drawable_attributes<'a>(c       : &'a base::Connection,
                                      drawable: Drawable,
                                      attribs : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_change_drawable_attributes(c.get_raw_conn(),
                                                        drawable as xcb_glx_drawable_t,  // 0
                                                        attribs_len as u32,  // 1
                                                        attribs_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_drawable_attributes_checked<'a>(c       : &'a base::Connection,
                                              drawable: Drawable,
                                              attribs : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_change_drawable_attributes_checked(c.get_raw_conn(),
                                                                drawable as xcb_glx_drawable_t,  // 0
                                                                attribs_len as u32,  // 1
                                                                attribs_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_WINDOW: u8 = 31;

pub fn create_window<'a>(c         : &'a base::Connection,
                         screen    : u32,
                         fbconfig  : Fbconfig,
                         window    : xproto::Window,
                         glx_window: Window,
                         attribs   : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_create_window(c.get_raw_conn(),
                                           screen as u32,  // 0
                                           fbconfig as xcb_glx_fbconfig_t,  // 1
                                           window as xcb_window_t,  // 2
                                           glx_window as xcb_glx_window_t,  // 3
                                           attribs_len as u32,  // 4
                                           attribs_ptr as *const u32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_window_checked<'a>(c         : &'a base::Connection,
                                 screen    : u32,
                                 fbconfig  : Fbconfig,
                                 window    : xproto::Window,
                                 glx_window: Window,
                                 attribs   : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_create_window_checked(c.get_raw_conn(),
                                                   screen as u32,  // 0
                                                   fbconfig as xcb_glx_fbconfig_t,  // 1
                                                   window as xcb_window_t,  // 2
                                                   glx_window as xcb_glx_window_t,  // 3
                                                   attribs_len as u32,  // 4
                                                   attribs_ptr as *const u32);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_WINDOW: u8 = 32;

pub fn delete_window<'a>(c        : &'a base::Connection,
                         glxwindow: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_delete_window(c.get_raw_conn(),
                                           glxwindow as xcb_glx_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_window_checked<'a>(c        : &'a base::Connection,
                                 glxwindow: Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_delete_window_checked(c.get_raw_conn(),
                                                   glxwindow as xcb_glx_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_CLIENT_INFO_ARB: u8 = 33;

pub fn set_client_info_arb<'a>(c                   : &'a base::Connection,
                               major_version       : u32,
                               minor_version       : u32,
                               gl_versions         : &[u32],
                               gl_extension_string : &str,
                               glx_extension_string: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let gl_versions_len = gl_versions.len();
        let gl_versions_ptr = gl_versions.as_ptr();
        let gl_extension_string = gl_extension_string.as_bytes();
        let gl_extension_string_len = gl_extension_string.len();
        let gl_extension_string_ptr = gl_extension_string.as_ptr();
        let glx_extension_string = glx_extension_string.as_bytes();
        let glx_extension_string_len = glx_extension_string.len();
        let glx_extension_string_ptr = glx_extension_string.as_ptr();
        let cookie = xcb_glx_set_client_info_arb(c.get_raw_conn(),
                                                 major_version as u32,  // 0
                                                 minor_version as u32,  // 1
                                                 gl_versions_len as u32,  // 2
                                                 gl_extension_string_len as u32,  // 3
                                                 glx_extension_string_len as u32,  // 4
                                                 gl_versions_ptr as *const u32,  // 5
                                                 gl_extension_string_ptr as *const c_char,  // 6
                                                 glx_extension_string_ptr as *const c_char);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_client_info_arb_checked<'a>(c                   : &'a base::Connection,
                                       major_version       : u32,
                                       minor_version       : u32,
                                       gl_versions         : &[u32],
                                       gl_extension_string : &str,
                                       glx_extension_string: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let gl_versions_len = gl_versions.len();
        let gl_versions_ptr = gl_versions.as_ptr();
        let gl_extension_string = gl_extension_string.as_bytes();
        let gl_extension_string_len = gl_extension_string.len();
        let gl_extension_string_ptr = gl_extension_string.as_ptr();
        let glx_extension_string = glx_extension_string.as_bytes();
        let glx_extension_string_len = glx_extension_string.len();
        let glx_extension_string_ptr = glx_extension_string.as_ptr();
        let cookie = xcb_glx_set_client_info_arb_checked(c.get_raw_conn(),
                                                         major_version as u32,  // 0
                                                         minor_version as u32,  // 1
                                                         gl_versions_len as u32,  // 2
                                                         gl_extension_string_len as u32,  // 3
                                                         glx_extension_string_len as u32,  // 4
                                                         gl_versions_ptr as *const u32,  // 5
                                                         gl_extension_string_ptr as *const c_char,  // 6
                                                         glx_extension_string_ptr as *const c_char);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_CONTEXT_ATTRIBS_ARB: u8 = 34;

pub fn create_context_attribs_arb<'a>(c         : &'a base::Connection,
                                      context   : Context,
                                      fbconfig  : Fbconfig,
                                      screen    : u32,
                                      share_list: Context,
                                      is_direct : bool,
                                      attribs   : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_create_context_attribs_arb(c.get_raw_conn(),
                                                        context as xcb_glx_context_t,  // 0
                                                        fbconfig as xcb_glx_fbconfig_t,  // 1
                                                        screen as u32,  // 2
                                                        share_list as xcb_glx_context_t,  // 3
                                                        is_direct as u8,  // 4
                                                        attribs_len as u32,  // 5
                                                        attribs_ptr as *const u32);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_context_attribs_arb_checked<'a>(c         : &'a base::Connection,
                                              context   : Context,
                                              fbconfig  : Fbconfig,
                                              screen    : u32,
                                              share_list: Context,
                                              is_direct : bool,
                                              attribs   : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let attribs_len = attribs.len();
        let attribs_ptr = attribs.as_ptr();
        let cookie = xcb_glx_create_context_attribs_arb_checked(c.get_raw_conn(),
                                                                context as xcb_glx_context_t,  // 0
                                                                fbconfig as xcb_glx_fbconfig_t,  // 1
                                                                screen as u32,  // 2
                                                                share_list as xcb_glx_context_t,  // 3
                                                                is_direct as u8,  // 4
                                                                attribs_len as u32,  // 5
                                                                attribs_ptr as *const u32);  // 6
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_CLIENT_INFO_2ARB: u8 = 35;

pub fn set_client_info_2arb<'a>(c                   : &'a base::Connection,
                                major_version       : u32,
                                minor_version       : u32,
                                gl_versions         : &[u32],
                                gl_extension_string : &str,
                                glx_extension_string: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let gl_versions_len = gl_versions.len();
        let gl_versions_ptr = gl_versions.as_ptr();
        let gl_extension_string = gl_extension_string.as_bytes();
        let gl_extension_string_len = gl_extension_string.len();
        let gl_extension_string_ptr = gl_extension_string.as_ptr();
        let glx_extension_string = glx_extension_string.as_bytes();
        let glx_extension_string_len = glx_extension_string.len();
        let glx_extension_string_ptr = glx_extension_string.as_ptr();
        let cookie = xcb_glx_set_client_info_2arb(c.get_raw_conn(),
                                                  major_version as u32,  // 0
                                                  minor_version as u32,  // 1
                                                  gl_versions_len as u32,  // 2
                                                  gl_extension_string_len as u32,  // 3
                                                  glx_extension_string_len as u32,  // 4
                                                  gl_versions_ptr as *const u32,  // 5
                                                  gl_extension_string_ptr as *const c_char,  // 6
                                                  glx_extension_string_ptr as *const c_char);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_client_info_2arb_checked<'a>(c                   : &'a base::Connection,
                                        major_version       : u32,
                                        minor_version       : u32,
                                        gl_versions         : &[u32],
                                        gl_extension_string : &str,
                                        glx_extension_string: &str)
        -> base::VoidCookie<'a> {
    unsafe {
        let gl_versions_len = gl_versions.len();
        let gl_versions_ptr = gl_versions.as_ptr();
        let gl_extension_string = gl_extension_string.as_bytes();
        let gl_extension_string_len = gl_extension_string.len();
        let gl_extension_string_ptr = gl_extension_string.as_ptr();
        let glx_extension_string = glx_extension_string.as_bytes();
        let glx_extension_string_len = glx_extension_string.len();
        let glx_extension_string_ptr = glx_extension_string.as_ptr();
        let cookie = xcb_glx_set_client_info_2arb_checked(c.get_raw_conn(),
                                                          major_version as u32,  // 0
                                                          minor_version as u32,  // 1
                                                          gl_versions_len as u32,  // 2
                                                          gl_extension_string_len as u32,  // 3
                                                          glx_extension_string_len as u32,  // 4
                                                          gl_versions_ptr as *const u32,  // 5
                                                          gl_extension_string_ptr as *const c_char,  // 6
                                                          glx_extension_string_ptr as *const c_char);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const NEW_LIST: u8 = 101;

pub fn new_list<'a>(c          : &'a base::Connection,
                    context_tag: ContextTag,
                    list       : u32,
                    mode       : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_new_list(c.get_raw_conn(),
                                      context_tag as xcb_glx_context_tag_t,  // 0
                                      list as u32,  // 1
                                      mode as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn new_list_checked<'a>(c          : &'a base::Connection,
                            context_tag: ContextTag,
                            list       : u32,
                            mode       : u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_new_list_checked(c.get_raw_conn(),
                                              context_tag as xcb_glx_context_tag_t,  // 0
                                              list as u32,  // 1
                                              mode as u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const END_LIST: u8 = 102;

pub fn end_list<'a>(c          : &'a base::Connection,
                    context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_end_list(c.get_raw_conn(),
                                      context_tag as xcb_glx_context_tag_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn end_list_checked<'a>(c          : &'a base::Connection,
                            context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_end_list_checked(c.get_raw_conn(),
                                              context_tag as xcb_glx_context_tag_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DELETE_LISTS: u8 = 103;

pub fn delete_lists<'a>(c          : &'a base::Connection,
                        context_tag: ContextTag,
                        list       : u32,
                        range      : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_delete_lists(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          list as u32,  // 1
                                          range as i32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_lists_checked<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                list       : u32,
                                range      : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_delete_lists_checked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  list as u32,  // 1
                                                  range as i32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GEN_LISTS: u8 = 104;

pub type GenListsCookie<'a> = base::Cookie<'a, xcb_glx_gen_lists_cookie_t>;

impl<'a> GenListsCookie<'a> {
    pub fn get_reply(&self) -> Result<GenListsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GenListsReply {
                    ptr: xcb_glx_gen_lists_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GenListsReply {
                    ptr: xcb_glx_gen_lists_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GenListsReply = base::Reply<xcb_glx_gen_lists_reply_t>;

impl GenListsReply {
    pub fn ret_val(&self) -> u32 {
        unsafe {
            (*self.ptr).ret_val
        }
    }
}

pub fn gen_lists<'a>(c          : &'a base::Connection,
                     context_tag: ContextTag,
                     range      : i32)
        -> GenListsCookie<'a> {
    unsafe {
        let cookie = xcb_glx_gen_lists(c.get_raw_conn(),
                                       context_tag as xcb_glx_context_tag_t,  // 0
                                       range as i32);  // 1
        GenListsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn gen_lists_unchecked<'a>(c          : &'a base::Connection,
                               context_tag: ContextTag,
                               range      : i32)
        -> GenListsCookie<'a> {
    unsafe {
        let cookie = xcb_glx_gen_lists_unchecked(c.get_raw_conn(),
                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                 range as i32);  // 1
        GenListsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const FEEDBACK_BUFFER: u8 = 105;

pub fn feedback_buffer<'a>(c          : &'a base::Connection,
                           context_tag: ContextTag,
                           size       : i32,
                           type_      : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_feedback_buffer(c.get_raw_conn(),
                                             context_tag as xcb_glx_context_tag_t,  // 0
                                             size as i32,  // 1
                                             type_ as i32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn feedback_buffer_checked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   size       : i32,
                                   type_      : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_feedback_buffer_checked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     size as i32,  // 1
                                                     type_ as i32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SELECT_BUFFER: u8 = 106;

pub fn select_buffer<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag,
                         size       : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_select_buffer(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t,  // 0
                                           size as i32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_buffer_checked<'a>(c          : &'a base::Connection,
                                 context_tag: ContextTag,
                                 size       : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_select_buffer_checked(c.get_raw_conn(),
                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                   size as i32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const RENDER_MODE: u8 = 107;

pub type RenderModeCookie<'a> = base::Cookie<'a, xcb_glx_render_mode_cookie_t>;

impl<'a> RenderModeCookie<'a> {
    pub fn get_reply(&self) -> Result<RenderModeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = RenderModeReply {
                    ptr: xcb_glx_render_mode_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( RenderModeReply {
                    ptr: xcb_glx_render_mode_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type RenderModeReply = base::Reply<xcb_glx_render_mode_reply_t>;

impl RenderModeReply {
    pub fn ret_val(&self) -> u32 {
        unsafe {
            (*self.ptr).ret_val
        }
    }
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn new_mode(&self) -> u32 {
        unsafe {
            (*self.ptr).new_mode
        }
    }
    pub fn data(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_render_mode_data_length(field) as usize;
            let data = xcb_glx_render_mode_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn render_mode<'a>(c          : &'a base::Connection,
                       context_tag: ContextTag,
                       mode       : u32)
        -> RenderModeCookie<'a> {
    unsafe {
        let cookie = xcb_glx_render_mode(c.get_raw_conn(),
                                         context_tag as xcb_glx_context_tag_t,  // 0
                                         mode as u32);  // 1
        RenderModeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn render_mode_unchecked<'a>(c          : &'a base::Connection,
                                 context_tag: ContextTag,
                                 mode       : u32)
        -> RenderModeCookie<'a> {
    unsafe {
        let cookie = xcb_glx_render_mode_unchecked(c.get_raw_conn(),
                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                   mode as u32);  // 1
        RenderModeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const FINISH: u8 = 108;

pub type FinishCookie<'a> = base::Cookie<'a, xcb_glx_finish_cookie_t>;

impl<'a> FinishCookie<'a> {
    pub fn get_reply(&self) -> Result<FinishReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = FinishReply {
                    ptr: xcb_glx_finish_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( FinishReply {
                    ptr: xcb_glx_finish_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type FinishReply = base::Reply<xcb_glx_finish_reply_t>;

impl FinishReply {
}

pub fn finish<'a>(c          : &'a base::Connection,
                  context_tag: ContextTag)
        -> FinishCookie<'a> {
    unsafe {
        let cookie = xcb_glx_finish(c.get_raw_conn(),
                                    context_tag as xcb_glx_context_tag_t);  // 0
        FinishCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn finish_unchecked<'a>(c          : &'a base::Connection,
                            context_tag: ContextTag)
        -> FinishCookie<'a> {
    unsafe {
        let cookie = xcb_glx_finish_unchecked(c.get_raw_conn(),
                                              context_tag as xcb_glx_context_tag_t);  // 0
        FinishCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PIXEL_STOREF: u8 = 109;

pub fn pixel_storef<'a>(c          : &'a base::Connection,
                        context_tag: ContextTag,
                        pname      : u32,
                        datum      : Float32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_pixel_storef(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          pname as u32,  // 1
                                          datum as xcb_glx_float32_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn pixel_storef_checked<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                pname      : u32,
                                datum      : Float32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_pixel_storef_checked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  pname as u32,  // 1
                                                  datum as xcb_glx_float32_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PIXEL_STOREI: u8 = 110;

pub fn pixel_storei<'a>(c          : &'a base::Connection,
                        context_tag: ContextTag,
                        pname      : u32,
                        datum      : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_pixel_storei(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          pname as u32,  // 1
                                          datum as i32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn pixel_storei_checked<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                pname      : u32,
                                datum      : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_pixel_storei_checked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  pname as u32,  // 1
                                                  datum as i32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const READ_PIXELS: u8 = 111;

pub type ReadPixelsCookie<'a> = base::Cookie<'a, xcb_glx_read_pixels_cookie_t>;

impl<'a> ReadPixelsCookie<'a> {
    pub fn get_reply(&self) -> Result<ReadPixelsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ReadPixelsReply {
                    ptr: xcb_glx_read_pixels_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ReadPixelsReply {
                    ptr: xcb_glx_read_pixels_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ReadPixelsReply = base::Reply<xcb_glx_read_pixels_reply_t>;

impl ReadPixelsReply {
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_read_pixels_data_length(field) as usize;
            let data = xcb_glx_read_pixels_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn read_pixels<'a>(c          : &'a base::Connection,
                       context_tag: ContextTag,
                       x          : i32,
                       y          : i32,
                       width      : i32,
                       height     : i32,
                       format     : u32,
                       type_      : u32,
                       swap_bytes : bool,
                       lsb_first  : bool)
        -> ReadPixelsCookie<'a> {
    unsafe {
        let cookie = xcb_glx_read_pixels(c.get_raw_conn(),
                                         context_tag as xcb_glx_context_tag_t,  // 0
                                         x as i32,  // 1
                                         y as i32,  // 2
                                         width as i32,  // 3
                                         height as i32,  // 4
                                         format as u32,  // 5
                                         type_ as u32,  // 6
                                         swap_bytes as u8,  // 7
                                         lsb_first as u8);  // 8
        ReadPixelsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn read_pixels_unchecked<'a>(c          : &'a base::Connection,
                                 context_tag: ContextTag,
                                 x          : i32,
                                 y          : i32,
                                 width      : i32,
                                 height     : i32,
                                 format     : u32,
                                 type_      : u32,
                                 swap_bytes : bool,
                                 lsb_first  : bool)
        -> ReadPixelsCookie<'a> {
    unsafe {
        let cookie = xcb_glx_read_pixels_unchecked(c.get_raw_conn(),
                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                   x as i32,  // 1
                                                   y as i32,  // 2
                                                   width as i32,  // 3
                                                   height as i32,  // 4
                                                   format as u32,  // 5
                                                   type_ as u32,  // 6
                                                   swap_bytes as u8,  // 7
                                                   lsb_first as u8);  // 8
        ReadPixelsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_BOOLEANV: u8 = 112;

pub type GetBooleanvCookie<'a> = base::Cookie<'a, xcb_glx_get_booleanv_cookie_t>;

impl<'a> GetBooleanvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetBooleanvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetBooleanvReply {
                    ptr: xcb_glx_get_booleanv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetBooleanvReply {
                    ptr: xcb_glx_get_booleanv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetBooleanvReply = base::Reply<xcb_glx_get_booleanv_reply_t>;

impl GetBooleanvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> bool {
        unsafe {
            (*self.ptr).datum != 0
        }
    }
    pub fn data(&self) -> Vec<bool> {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_booleanv_data_length(field);
            let data = xcb_glx_get_booleanv_data(field);
            let slice = std::slice::from_raw_parts(data, len as usize);
            slice.iter().map(|el| if *el == 0 {false} else{true}).collect()
        }
    }
}

pub fn get_booleanv<'a>(c          : &'a base::Connection,
                        context_tag: ContextTag,
                        pname      : i32)
        -> GetBooleanvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_booleanv(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          pname as i32);  // 1
        GetBooleanvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_booleanv_unchecked<'a>(c          : &'a base::Connection,
                                  context_tag: ContextTag,
                                  pname      : i32)
        -> GetBooleanvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_booleanv_unchecked(c.get_raw_conn(),
                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                    pname as i32);  // 1
        GetBooleanvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_CLIP_PLANE: u8 = 113;

pub type GetClipPlaneCookie<'a> = base::Cookie<'a, xcb_glx_get_clip_plane_cookie_t>;

impl<'a> GetClipPlaneCookie<'a> {
    pub fn get_reply(&self) -> Result<GetClipPlaneReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetClipPlaneReply {
                    ptr: xcb_glx_get_clip_plane_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetClipPlaneReply {
                    ptr: xcb_glx_get_clip_plane_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetClipPlaneReply = base::Reply<xcb_glx_get_clip_plane_reply_t>;

impl GetClipPlaneReply {
    pub fn data(&self) -> &[Float64] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_clip_plane_data_length(field) as usize;
            let data = xcb_glx_get_clip_plane_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_clip_plane<'a>(c          : &'a base::Connection,
                          context_tag: ContextTag,
                          plane      : i32)
        -> GetClipPlaneCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_clip_plane(c.get_raw_conn(),
                                            context_tag as xcb_glx_context_tag_t,  // 0
                                            plane as i32);  // 1
        GetClipPlaneCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_clip_plane_unchecked<'a>(c          : &'a base::Connection,
                                    context_tag: ContextTag,
                                    plane      : i32)
        -> GetClipPlaneCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_clip_plane_unchecked(c.get_raw_conn(),
                                                      context_tag as xcb_glx_context_tag_t,  // 0
                                                      plane as i32);  // 1
        GetClipPlaneCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_DOUBLEV: u8 = 114;

pub type GetDoublevCookie<'a> = base::Cookie<'a, xcb_glx_get_doublev_cookie_t>;

impl<'a> GetDoublevCookie<'a> {
    pub fn get_reply(&self) -> Result<GetDoublevReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetDoublevReply {
                    ptr: xcb_glx_get_doublev_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetDoublevReply {
                    ptr: xcb_glx_get_doublev_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetDoublevReply = base::Reply<xcb_glx_get_doublev_reply_t>;

impl GetDoublevReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float64 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float64] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_doublev_data_length(field) as usize;
            let data = xcb_glx_get_doublev_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_doublev<'a>(c          : &'a base::Connection,
                       context_tag: ContextTag,
                       pname      : u32)
        -> GetDoublevCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_doublev(c.get_raw_conn(),
                                         context_tag as xcb_glx_context_tag_t,  // 0
                                         pname as u32);  // 1
        GetDoublevCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_doublev_unchecked<'a>(c          : &'a base::Connection,
                                 context_tag: ContextTag,
                                 pname      : u32)
        -> GetDoublevCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_doublev_unchecked(c.get_raw_conn(),
                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                   pname as u32);  // 1
        GetDoublevCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_ERROR: u8 = 115;

pub type GetErrorCookie<'a> = base::Cookie<'a, xcb_glx_get_error_cookie_t>;

impl<'a> GetErrorCookie<'a> {
    pub fn get_reply(&self) -> Result<GetErrorReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetErrorReply {
                    ptr: xcb_glx_get_error_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetErrorReply {
                    ptr: xcb_glx_get_error_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetErrorReply = base::Reply<xcb_glx_get_error_reply_t>;

impl GetErrorReply {
    pub fn error(&self) -> i32 {
        unsafe {
            (*self.ptr).error
        }
    }
}

pub fn get_error<'a>(c          : &'a base::Connection,
                     context_tag: ContextTag)
        -> GetErrorCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_error(c.get_raw_conn(),
                                       context_tag as xcb_glx_context_tag_t);  // 0
        GetErrorCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_error_unchecked<'a>(c          : &'a base::Connection,
                               context_tag: ContextTag)
        -> GetErrorCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_error_unchecked(c.get_raw_conn(),
                                                 context_tag as xcb_glx_context_tag_t);  // 0
        GetErrorCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_FLOATV: u8 = 116;

pub type GetFloatvCookie<'a> = base::Cookie<'a, xcb_glx_get_floatv_cookie_t>;

impl<'a> GetFloatvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetFloatvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetFloatvReply {
                    ptr: xcb_glx_get_floatv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetFloatvReply {
                    ptr: xcb_glx_get_floatv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetFloatvReply = base::Reply<xcb_glx_get_floatv_reply_t>;

impl GetFloatvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_floatv_data_length(field) as usize;
            let data = xcb_glx_get_floatv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_floatv<'a>(c          : &'a base::Connection,
                      context_tag: ContextTag,
                      pname      : u32)
        -> GetFloatvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_floatv(c.get_raw_conn(),
                                        context_tag as xcb_glx_context_tag_t,  // 0
                                        pname as u32);  // 1
        GetFloatvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_floatv_unchecked<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                pname      : u32)
        -> GetFloatvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_floatv_unchecked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  pname as u32);  // 1
        GetFloatvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_INTEGERV: u8 = 117;

pub type GetIntegervCookie<'a> = base::Cookie<'a, xcb_glx_get_integerv_cookie_t>;

impl<'a> GetIntegervCookie<'a> {
    pub fn get_reply(&self) -> Result<GetIntegervReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetIntegervReply {
                    ptr: xcb_glx_get_integerv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetIntegervReply {
                    ptr: xcb_glx_get_integerv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetIntegervReply = base::Reply<xcb_glx_get_integerv_reply_t>;

impl GetIntegervReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_integerv_data_length(field) as usize;
            let data = xcb_glx_get_integerv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_integerv<'a>(c          : &'a base::Connection,
                        context_tag: ContextTag,
                        pname      : u32)
        -> GetIntegervCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_integerv(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          pname as u32);  // 1
        GetIntegervCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_integerv_unchecked<'a>(c          : &'a base::Connection,
                                  context_tag: ContextTag,
                                  pname      : u32)
        -> GetIntegervCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_integerv_unchecked(c.get_raw_conn(),
                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                    pname as u32);  // 1
        GetIntegervCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_LIGHTFV: u8 = 118;

pub type GetLightfvCookie<'a> = base::Cookie<'a, xcb_glx_get_lightfv_cookie_t>;

impl<'a> GetLightfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetLightfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetLightfvReply {
                    ptr: xcb_glx_get_lightfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetLightfvReply {
                    ptr: xcb_glx_get_lightfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetLightfvReply = base::Reply<xcb_glx_get_lightfv_reply_t>;

impl GetLightfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_lightfv_data_length(field) as usize;
            let data = xcb_glx_get_lightfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_lightfv<'a>(c          : &'a base::Connection,
                       context_tag: ContextTag,
                       light      : u32,
                       pname      : u32)
        -> GetLightfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_lightfv(c.get_raw_conn(),
                                         context_tag as xcb_glx_context_tag_t,  // 0
                                         light as u32,  // 1
                                         pname as u32);  // 2
        GetLightfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_lightfv_unchecked<'a>(c          : &'a base::Connection,
                                 context_tag: ContextTag,
                                 light      : u32,
                                 pname      : u32)
        -> GetLightfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_lightfv_unchecked(c.get_raw_conn(),
                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                   light as u32,  // 1
                                                   pname as u32);  // 2
        GetLightfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_LIGHTIV: u8 = 119;

pub type GetLightivCookie<'a> = base::Cookie<'a, xcb_glx_get_lightiv_cookie_t>;

impl<'a> GetLightivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetLightivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetLightivReply {
                    ptr: xcb_glx_get_lightiv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetLightivReply {
                    ptr: xcb_glx_get_lightiv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetLightivReply = base::Reply<xcb_glx_get_lightiv_reply_t>;

impl GetLightivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_lightiv_data_length(field) as usize;
            let data = xcb_glx_get_lightiv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_lightiv<'a>(c          : &'a base::Connection,
                       context_tag: ContextTag,
                       light      : u32,
                       pname      : u32)
        -> GetLightivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_lightiv(c.get_raw_conn(),
                                         context_tag as xcb_glx_context_tag_t,  // 0
                                         light as u32,  // 1
                                         pname as u32);  // 2
        GetLightivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_lightiv_unchecked<'a>(c          : &'a base::Connection,
                                 context_tag: ContextTag,
                                 light      : u32,
                                 pname      : u32)
        -> GetLightivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_lightiv_unchecked(c.get_raw_conn(),
                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                   light as u32,  // 1
                                                   pname as u32);  // 2
        GetLightivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MAPDV: u8 = 120;

pub type GetMapdvCookie<'a> = base::Cookie<'a, xcb_glx_get_mapdv_cookie_t>;

impl<'a> GetMapdvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMapdvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMapdvReply {
                    ptr: xcb_glx_get_mapdv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMapdvReply {
                    ptr: xcb_glx_get_mapdv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMapdvReply = base::Reply<xcb_glx_get_mapdv_reply_t>;

impl GetMapdvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float64 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float64] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_mapdv_data_length(field) as usize;
            let data = xcb_glx_get_mapdv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_mapdv<'a>(c          : &'a base::Connection,
                     context_tag: ContextTag,
                     target     : u32,
                     query      : u32)
        -> GetMapdvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_mapdv(c.get_raw_conn(),
                                       context_tag as xcb_glx_context_tag_t,  // 0
                                       target as u32,  // 1
                                       query as u32);  // 2
        GetMapdvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_mapdv_unchecked<'a>(c          : &'a base::Connection,
                               context_tag: ContextTag,
                               target     : u32,
                               query      : u32)
        -> GetMapdvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_mapdv_unchecked(c.get_raw_conn(),
                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                 target as u32,  // 1
                                                 query as u32);  // 2
        GetMapdvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MAPFV: u8 = 121;

pub type GetMapfvCookie<'a> = base::Cookie<'a, xcb_glx_get_mapfv_cookie_t>;

impl<'a> GetMapfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMapfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMapfvReply {
                    ptr: xcb_glx_get_mapfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMapfvReply {
                    ptr: xcb_glx_get_mapfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMapfvReply = base::Reply<xcb_glx_get_mapfv_reply_t>;

impl GetMapfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_mapfv_data_length(field) as usize;
            let data = xcb_glx_get_mapfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_mapfv<'a>(c          : &'a base::Connection,
                     context_tag: ContextTag,
                     target     : u32,
                     query      : u32)
        -> GetMapfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_mapfv(c.get_raw_conn(),
                                       context_tag as xcb_glx_context_tag_t,  // 0
                                       target as u32,  // 1
                                       query as u32);  // 2
        GetMapfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_mapfv_unchecked<'a>(c          : &'a base::Connection,
                               context_tag: ContextTag,
                               target     : u32,
                               query      : u32)
        -> GetMapfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_mapfv_unchecked(c.get_raw_conn(),
                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                 target as u32,  // 1
                                                 query as u32);  // 2
        GetMapfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MAPIV: u8 = 122;

pub type GetMapivCookie<'a> = base::Cookie<'a, xcb_glx_get_mapiv_cookie_t>;

impl<'a> GetMapivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMapivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMapivReply {
                    ptr: xcb_glx_get_mapiv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMapivReply {
                    ptr: xcb_glx_get_mapiv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMapivReply = base::Reply<xcb_glx_get_mapiv_reply_t>;

impl GetMapivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_mapiv_data_length(field) as usize;
            let data = xcb_glx_get_mapiv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_mapiv<'a>(c          : &'a base::Connection,
                     context_tag: ContextTag,
                     target     : u32,
                     query      : u32)
        -> GetMapivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_mapiv(c.get_raw_conn(),
                                       context_tag as xcb_glx_context_tag_t,  // 0
                                       target as u32,  // 1
                                       query as u32);  // 2
        GetMapivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_mapiv_unchecked<'a>(c          : &'a base::Connection,
                               context_tag: ContextTag,
                               target     : u32,
                               query      : u32)
        -> GetMapivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_mapiv_unchecked(c.get_raw_conn(),
                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                 target as u32,  // 1
                                                 query as u32);  // 2
        GetMapivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MATERIALFV: u8 = 123;

pub type GetMaterialfvCookie<'a> = base::Cookie<'a, xcb_glx_get_materialfv_cookie_t>;

impl<'a> GetMaterialfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMaterialfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMaterialfvReply {
                    ptr: xcb_glx_get_materialfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMaterialfvReply {
                    ptr: xcb_glx_get_materialfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMaterialfvReply = base::Reply<xcb_glx_get_materialfv_reply_t>;

impl GetMaterialfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_materialfv_data_length(field) as usize;
            let data = xcb_glx_get_materialfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_materialfv<'a>(c          : &'a base::Connection,
                          context_tag: ContextTag,
                          face       : u32,
                          pname      : u32)
        -> GetMaterialfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_materialfv(c.get_raw_conn(),
                                            context_tag as xcb_glx_context_tag_t,  // 0
                                            face as u32,  // 1
                                            pname as u32);  // 2
        GetMaterialfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_materialfv_unchecked<'a>(c          : &'a base::Connection,
                                    context_tag: ContextTag,
                                    face       : u32,
                                    pname      : u32)
        -> GetMaterialfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_materialfv_unchecked(c.get_raw_conn(),
                                                      context_tag as xcb_glx_context_tag_t,  // 0
                                                      face as u32,  // 1
                                                      pname as u32);  // 2
        GetMaterialfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MATERIALIV: u8 = 124;

pub type GetMaterialivCookie<'a> = base::Cookie<'a, xcb_glx_get_materialiv_cookie_t>;

impl<'a> GetMaterialivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMaterialivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMaterialivReply {
                    ptr: xcb_glx_get_materialiv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMaterialivReply {
                    ptr: xcb_glx_get_materialiv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMaterialivReply = base::Reply<xcb_glx_get_materialiv_reply_t>;

impl GetMaterialivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_materialiv_data_length(field) as usize;
            let data = xcb_glx_get_materialiv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_materialiv<'a>(c          : &'a base::Connection,
                          context_tag: ContextTag,
                          face       : u32,
                          pname      : u32)
        -> GetMaterialivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_materialiv(c.get_raw_conn(),
                                            context_tag as xcb_glx_context_tag_t,  // 0
                                            face as u32,  // 1
                                            pname as u32);  // 2
        GetMaterialivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_materialiv_unchecked<'a>(c          : &'a base::Connection,
                                    context_tag: ContextTag,
                                    face       : u32,
                                    pname      : u32)
        -> GetMaterialivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_materialiv_unchecked(c.get_raw_conn(),
                                                      context_tag as xcb_glx_context_tag_t,  // 0
                                                      face as u32,  // 1
                                                      pname as u32);  // 2
        GetMaterialivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PIXEL_MAPFV: u8 = 125;

pub type GetPixelMapfvCookie<'a> = base::Cookie<'a, xcb_glx_get_pixel_mapfv_cookie_t>;

impl<'a> GetPixelMapfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPixelMapfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPixelMapfvReply {
                    ptr: xcb_glx_get_pixel_mapfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPixelMapfvReply {
                    ptr: xcb_glx_get_pixel_mapfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPixelMapfvReply = base::Reply<xcb_glx_get_pixel_mapfv_reply_t>;

impl GetPixelMapfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_pixel_mapfv_data_length(field) as usize;
            let data = xcb_glx_get_pixel_mapfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_pixel_mapfv<'a>(c          : &'a base::Connection,
                           context_tag: ContextTag,
                           map        : u32)
        -> GetPixelMapfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_pixel_mapfv(c.get_raw_conn(),
                                             context_tag as xcb_glx_context_tag_t,  // 0
                                             map as u32);  // 1
        GetPixelMapfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_pixel_mapfv_unchecked<'a>(c          : &'a base::Connection,
                                     context_tag: ContextTag,
                                     map        : u32)
        -> GetPixelMapfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_pixel_mapfv_unchecked(c.get_raw_conn(),
                                                       context_tag as xcb_glx_context_tag_t,  // 0
                                                       map as u32);  // 1
        GetPixelMapfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PIXEL_MAPUIV: u8 = 126;

pub type GetPixelMapuivCookie<'a> = base::Cookie<'a, xcb_glx_get_pixel_mapuiv_cookie_t>;

impl<'a> GetPixelMapuivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPixelMapuivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPixelMapuivReply {
                    ptr: xcb_glx_get_pixel_mapuiv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPixelMapuivReply {
                    ptr: xcb_glx_get_pixel_mapuiv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPixelMapuivReply = base::Reply<xcb_glx_get_pixel_mapuiv_reply_t>;

impl GetPixelMapuivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> u32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_pixel_mapuiv_data_length(field) as usize;
            let data = xcb_glx_get_pixel_mapuiv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_pixel_mapuiv<'a>(c          : &'a base::Connection,
                            context_tag: ContextTag,
                            map        : u32)
        -> GetPixelMapuivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_pixel_mapuiv(c.get_raw_conn(),
                                              context_tag as xcb_glx_context_tag_t,  // 0
                                              map as u32);  // 1
        GetPixelMapuivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_pixel_mapuiv_unchecked<'a>(c          : &'a base::Connection,
                                      context_tag: ContextTag,
                                      map        : u32)
        -> GetPixelMapuivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_pixel_mapuiv_unchecked(c.get_raw_conn(),
                                                        context_tag as xcb_glx_context_tag_t,  // 0
                                                        map as u32);  // 1
        GetPixelMapuivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_PIXEL_MAPUSV: u8 = 127;

pub type GetPixelMapusvCookie<'a> = base::Cookie<'a, xcb_glx_get_pixel_mapusv_cookie_t>;

impl<'a> GetPixelMapusvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPixelMapusvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPixelMapusvReply {
                    ptr: xcb_glx_get_pixel_mapusv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPixelMapusvReply {
                    ptr: xcb_glx_get_pixel_mapusv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPixelMapusvReply = base::Reply<xcb_glx_get_pixel_mapusv_reply_t>;

impl GetPixelMapusvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> u16 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_pixel_mapusv_data_length(field) as usize;
            let data = xcb_glx_get_pixel_mapusv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_pixel_mapusv<'a>(c          : &'a base::Connection,
                            context_tag: ContextTag,
                            map        : u32)
        -> GetPixelMapusvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_pixel_mapusv(c.get_raw_conn(),
                                              context_tag as xcb_glx_context_tag_t,  // 0
                                              map as u32);  // 1
        GetPixelMapusvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_pixel_mapusv_unchecked<'a>(c          : &'a base::Connection,
                                      context_tag: ContextTag,
                                      map        : u32)
        -> GetPixelMapusvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_pixel_mapusv_unchecked(c.get_raw_conn(),
                                                        context_tag as xcb_glx_context_tag_t,  // 0
                                                        map as u32);  // 1
        GetPixelMapusvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_POLYGON_STIPPLE: u8 = 128;

pub type GetPolygonStippleCookie<'a> = base::Cookie<'a, xcb_glx_get_polygon_stipple_cookie_t>;

impl<'a> GetPolygonStippleCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPolygonStippleReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPolygonStippleReply {
                    ptr: xcb_glx_get_polygon_stipple_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPolygonStippleReply {
                    ptr: xcb_glx_get_polygon_stipple_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPolygonStippleReply = base::Reply<xcb_glx_get_polygon_stipple_reply_t>;

impl GetPolygonStippleReply {
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_polygon_stipple_data_length(field) as usize;
            let data = xcb_glx_get_polygon_stipple_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_polygon_stipple<'a>(c          : &'a base::Connection,
                               context_tag: ContextTag,
                               lsb_first  : bool)
        -> GetPolygonStippleCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_polygon_stipple(c.get_raw_conn(),
                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                 lsb_first as u8);  // 1
        GetPolygonStippleCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_polygon_stipple_unchecked<'a>(c          : &'a base::Connection,
                                         context_tag: ContextTag,
                                         lsb_first  : bool)
        -> GetPolygonStippleCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_polygon_stipple_unchecked(c.get_raw_conn(),
                                                           context_tag as xcb_glx_context_tag_t,  // 0
                                                           lsb_first as u8);  // 1
        GetPolygonStippleCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_STRING: u8 = 129;

pub type GetStringCookie<'a> = base::Cookie<'a, xcb_glx_get_string_cookie_t>;

impl<'a> GetStringCookie<'a> {
    pub fn get_reply(&self) -> Result<GetStringReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetStringReply {
                    ptr: xcb_glx_get_string_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetStringReply {
                    ptr: xcb_glx_get_string_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetStringReply = base::Reply<xcb_glx_get_string_reply_t>;

impl GetStringReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn string(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_string_string_length(field) as usize;
            let data = xcb_glx_get_string_string(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub fn get_string<'a>(c          : &'a base::Connection,
                      context_tag: ContextTag,
                      name       : u32)
        -> GetStringCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_string(c.get_raw_conn(),
                                        context_tag as xcb_glx_context_tag_t,  // 0
                                        name as u32);  // 1
        GetStringCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_string_unchecked<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                name       : u32)
        -> GetStringCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_string_unchecked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  name as u32);  // 1
        GetStringCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_ENVFV: u8 = 130;

pub type GetTexEnvfvCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_envfv_cookie_t>;

impl<'a> GetTexEnvfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexEnvfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexEnvfvReply {
                    ptr: xcb_glx_get_tex_envfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexEnvfvReply {
                    ptr: xcb_glx_get_tex_envfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexEnvfvReply = base::Reply<xcb_glx_get_tex_envfv_reply_t>;

impl GetTexEnvfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_envfv_data_length(field) as usize;
            let data = xcb_glx_get_tex_envfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_envfv<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag,
                         target     : u32,
                         pname      : u32)
        -> GetTexEnvfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_envfv(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t,  // 0
                                           target as u32,  // 1
                                           pname as u32);  // 2
        GetTexEnvfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_envfv_unchecked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   target     : u32,
                                   pname      : u32)
        -> GetTexEnvfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_envfv_unchecked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     target as u32,  // 1
                                                     pname as u32);  // 2
        GetTexEnvfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_ENVIV: u8 = 131;

pub type GetTexEnvivCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_enviv_cookie_t>;

impl<'a> GetTexEnvivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexEnvivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexEnvivReply {
                    ptr: xcb_glx_get_tex_enviv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexEnvivReply {
                    ptr: xcb_glx_get_tex_enviv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexEnvivReply = base::Reply<xcb_glx_get_tex_enviv_reply_t>;

impl GetTexEnvivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_enviv_data_length(field) as usize;
            let data = xcb_glx_get_tex_enviv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_enviv<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag,
                         target     : u32,
                         pname      : u32)
        -> GetTexEnvivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_enviv(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t,  // 0
                                           target as u32,  // 1
                                           pname as u32);  // 2
        GetTexEnvivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_enviv_unchecked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   target     : u32,
                                   pname      : u32)
        -> GetTexEnvivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_enviv_unchecked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     target as u32,  // 1
                                                     pname as u32);  // 2
        GetTexEnvivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_GENDV: u8 = 132;

pub type GetTexGendvCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_gendv_cookie_t>;

impl<'a> GetTexGendvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexGendvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexGendvReply {
                    ptr: xcb_glx_get_tex_gendv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexGendvReply {
                    ptr: xcb_glx_get_tex_gendv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexGendvReply = base::Reply<xcb_glx_get_tex_gendv_reply_t>;

impl GetTexGendvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float64 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float64] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_gendv_data_length(field) as usize;
            let data = xcb_glx_get_tex_gendv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_gendv<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag,
                         coord      : u32,
                         pname      : u32)
        -> GetTexGendvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_gendv(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t,  // 0
                                           coord as u32,  // 1
                                           pname as u32);  // 2
        GetTexGendvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_gendv_unchecked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   coord      : u32,
                                   pname      : u32)
        -> GetTexGendvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_gendv_unchecked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     coord as u32,  // 1
                                                     pname as u32);  // 2
        GetTexGendvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_GENFV: u8 = 133;

pub type GetTexGenfvCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_genfv_cookie_t>;

impl<'a> GetTexGenfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexGenfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexGenfvReply {
                    ptr: xcb_glx_get_tex_genfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexGenfvReply {
                    ptr: xcb_glx_get_tex_genfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexGenfvReply = base::Reply<xcb_glx_get_tex_genfv_reply_t>;

impl GetTexGenfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_genfv_data_length(field) as usize;
            let data = xcb_glx_get_tex_genfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_genfv<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag,
                         coord      : u32,
                         pname      : u32)
        -> GetTexGenfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_genfv(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t,  // 0
                                           coord as u32,  // 1
                                           pname as u32);  // 2
        GetTexGenfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_genfv_unchecked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   coord      : u32,
                                   pname      : u32)
        -> GetTexGenfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_genfv_unchecked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     coord as u32,  // 1
                                                     pname as u32);  // 2
        GetTexGenfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_GENIV: u8 = 134;

pub type GetTexGenivCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_geniv_cookie_t>;

impl<'a> GetTexGenivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexGenivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexGenivReply {
                    ptr: xcb_glx_get_tex_geniv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexGenivReply {
                    ptr: xcb_glx_get_tex_geniv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexGenivReply = base::Reply<xcb_glx_get_tex_geniv_reply_t>;

impl GetTexGenivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_geniv_data_length(field) as usize;
            let data = xcb_glx_get_tex_geniv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_geniv<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag,
                         coord      : u32,
                         pname      : u32)
        -> GetTexGenivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_geniv(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t,  // 0
                                           coord as u32,  // 1
                                           pname as u32);  // 2
        GetTexGenivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_geniv_unchecked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   coord      : u32,
                                   pname      : u32)
        -> GetTexGenivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_geniv_unchecked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     coord as u32,  // 1
                                                     pname as u32);  // 2
        GetTexGenivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_IMAGE: u8 = 135;

pub type GetTexImageCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_image_cookie_t>;

impl<'a> GetTexImageCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexImageReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexImageReply {
                    ptr: xcb_glx_get_tex_image_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexImageReply {
                    ptr: xcb_glx_get_tex_image_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexImageReply = base::Reply<xcb_glx_get_tex_image_reply_t>;

impl GetTexImageReply {
    pub fn width(&self) -> i32 {
        unsafe {
            (*self.ptr).width
        }
    }
    pub fn height(&self) -> i32 {
        unsafe {
            (*self.ptr).height
        }
    }
    pub fn depth(&self) -> i32 {
        unsafe {
            (*self.ptr).depth
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_image_data_length(field) as usize;
            let data = xcb_glx_get_tex_image_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_image<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag,
                         target     : u32,
                         level      : i32,
                         format     : u32,
                         type_      : u32,
                         swap_bytes : bool)
        -> GetTexImageCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_image(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t,  // 0
                                           target as u32,  // 1
                                           level as i32,  // 2
                                           format as u32,  // 3
                                           type_ as u32,  // 4
                                           swap_bytes as u8);  // 5
        GetTexImageCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_image_unchecked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   target     : u32,
                                   level      : i32,
                                   format     : u32,
                                   type_      : u32,
                                   swap_bytes : bool)
        -> GetTexImageCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_image_unchecked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     target as u32,  // 1
                                                     level as i32,  // 2
                                                     format as u32,  // 3
                                                     type_ as u32,  // 4
                                                     swap_bytes as u8);  // 5
        GetTexImageCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_PARAMETERFV: u8 = 136;

pub type GetTexParameterfvCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_parameterfv_cookie_t>;

impl<'a> GetTexParameterfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexParameterfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexParameterfvReply {
                    ptr: xcb_glx_get_tex_parameterfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexParameterfvReply {
                    ptr: xcb_glx_get_tex_parameterfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexParameterfvReply = base::Reply<xcb_glx_get_tex_parameterfv_reply_t>;

impl GetTexParameterfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_parameterfv_data_length(field) as usize;
            let data = xcb_glx_get_tex_parameterfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_parameterfv<'a>(c          : &'a base::Connection,
                               context_tag: ContextTag,
                               target     : u32,
                               pname      : u32)
        -> GetTexParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_parameterfv(c.get_raw_conn(),
                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                 target as u32,  // 1
                                                 pname as u32);  // 2
        GetTexParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_parameterfv_unchecked<'a>(c          : &'a base::Connection,
                                         context_tag: ContextTag,
                                         target     : u32,
                                         pname      : u32)
        -> GetTexParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_parameterfv_unchecked(c.get_raw_conn(),
                                                           context_tag as xcb_glx_context_tag_t,  // 0
                                                           target as u32,  // 1
                                                           pname as u32);  // 2
        GetTexParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_PARAMETERIV: u8 = 137;

pub type GetTexParameterivCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_parameteriv_cookie_t>;

impl<'a> GetTexParameterivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexParameterivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexParameterivReply {
                    ptr: xcb_glx_get_tex_parameteriv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexParameterivReply {
                    ptr: xcb_glx_get_tex_parameteriv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexParameterivReply = base::Reply<xcb_glx_get_tex_parameteriv_reply_t>;

impl GetTexParameterivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_parameteriv_data_length(field) as usize;
            let data = xcb_glx_get_tex_parameteriv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_parameteriv<'a>(c          : &'a base::Connection,
                               context_tag: ContextTag,
                               target     : u32,
                               pname      : u32)
        -> GetTexParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_parameteriv(c.get_raw_conn(),
                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                 target as u32,  // 1
                                                 pname as u32);  // 2
        GetTexParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_parameteriv_unchecked<'a>(c          : &'a base::Connection,
                                         context_tag: ContextTag,
                                         target     : u32,
                                         pname      : u32)
        -> GetTexParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_parameteriv_unchecked(c.get_raw_conn(),
                                                           context_tag as xcb_glx_context_tag_t,  // 0
                                                           target as u32,  // 1
                                                           pname as u32);  // 2
        GetTexParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_LEVEL_PARAMETERFV: u8 = 138;

pub type GetTexLevelParameterfvCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_level_parameterfv_cookie_t>;

impl<'a> GetTexLevelParameterfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexLevelParameterfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexLevelParameterfvReply {
                    ptr: xcb_glx_get_tex_level_parameterfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexLevelParameterfvReply {
                    ptr: xcb_glx_get_tex_level_parameterfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexLevelParameterfvReply = base::Reply<xcb_glx_get_tex_level_parameterfv_reply_t>;

impl GetTexLevelParameterfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_level_parameterfv_data_length(field) as usize;
            let data = xcb_glx_get_tex_level_parameterfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_level_parameterfv<'a>(c          : &'a base::Connection,
                                     context_tag: ContextTag,
                                     target     : u32,
                                     level      : i32,
                                     pname      : u32)
        -> GetTexLevelParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_level_parameterfv(c.get_raw_conn(),
                                                       context_tag as xcb_glx_context_tag_t,  // 0
                                                       target as u32,  // 1
                                                       level as i32,  // 2
                                                       pname as u32);  // 3
        GetTexLevelParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_level_parameterfv_unchecked<'a>(c          : &'a base::Connection,
                                               context_tag: ContextTag,
                                               target     : u32,
                                               level      : i32,
                                               pname      : u32)
        -> GetTexLevelParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_level_parameterfv_unchecked(c.get_raw_conn(),
                                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                                 target as u32,  // 1
                                                                 level as i32,  // 2
                                                                 pname as u32);  // 3
        GetTexLevelParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_TEX_LEVEL_PARAMETERIV: u8 = 139;

pub type GetTexLevelParameterivCookie<'a> = base::Cookie<'a, xcb_glx_get_tex_level_parameteriv_cookie_t>;

impl<'a> GetTexLevelParameterivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetTexLevelParameterivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetTexLevelParameterivReply {
                    ptr: xcb_glx_get_tex_level_parameteriv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetTexLevelParameterivReply {
                    ptr: xcb_glx_get_tex_level_parameteriv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetTexLevelParameterivReply = base::Reply<xcb_glx_get_tex_level_parameteriv_reply_t>;

impl GetTexLevelParameterivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_tex_level_parameteriv_data_length(field) as usize;
            let data = xcb_glx_get_tex_level_parameteriv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_tex_level_parameteriv<'a>(c          : &'a base::Connection,
                                     context_tag: ContextTag,
                                     target     : u32,
                                     level      : i32,
                                     pname      : u32)
        -> GetTexLevelParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_level_parameteriv(c.get_raw_conn(),
                                                       context_tag as xcb_glx_context_tag_t,  // 0
                                                       target as u32,  // 1
                                                       level as i32,  // 2
                                                       pname as u32);  // 3
        GetTexLevelParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_tex_level_parameteriv_unchecked<'a>(c          : &'a base::Connection,
                                               context_tag: ContextTag,
                                               target     : u32,
                                               level      : i32,
                                               pname      : u32)
        -> GetTexLevelParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_tex_level_parameteriv_unchecked(c.get_raw_conn(),
                                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                                 target as u32,  // 1
                                                                 level as i32,  // 2
                                                                 pname as u32);  // 3
        GetTexLevelParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const IS_LIST: u8 = 141;

pub type IsListCookie<'a> = base::Cookie<'a, xcb_glx_is_list_cookie_t>;

impl<'a> IsListCookie<'a> {
    pub fn get_reply(&self) -> Result<IsListReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = IsListReply {
                    ptr: xcb_glx_is_list_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( IsListReply {
                    ptr: xcb_glx_is_list_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type IsListReply = base::Reply<xcb_glx_is_list_reply_t>;

impl IsListReply {
    pub fn ret_val(&self) -> Bool32 {
        unsafe {
            (*self.ptr).ret_val
        }
    }
}

pub fn is_list<'a>(c          : &'a base::Connection,
                   context_tag: ContextTag,
                   list       : u32)
        -> IsListCookie<'a> {
    unsafe {
        let cookie = xcb_glx_is_list(c.get_raw_conn(),
                                     context_tag as xcb_glx_context_tag_t,  // 0
                                     list as u32);  // 1
        IsListCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn is_list_unchecked<'a>(c          : &'a base::Connection,
                             context_tag: ContextTag,
                             list       : u32)
        -> IsListCookie<'a> {
    unsafe {
        let cookie = xcb_glx_is_list_unchecked(c.get_raw_conn(),
                                               context_tag as xcb_glx_context_tag_t,  // 0
                                               list as u32);  // 1
        IsListCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const FLUSH: u8 = 142;

pub fn flush<'a>(c          : &'a base::Connection,
                 context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_flush(c.get_raw_conn(),
                                   context_tag as xcb_glx_context_tag_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn flush_checked<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_glx_flush_checked(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ARE_TEXTURES_RESIDENT: u8 = 143;

pub type AreTexturesResidentCookie<'a> = base::Cookie<'a, xcb_glx_are_textures_resident_cookie_t>;

impl<'a> AreTexturesResidentCookie<'a> {
    pub fn get_reply(&self) -> Result<AreTexturesResidentReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = AreTexturesResidentReply {
                    ptr: xcb_glx_are_textures_resident_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( AreTexturesResidentReply {
                    ptr: xcb_glx_are_textures_resident_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type AreTexturesResidentReply = base::Reply<xcb_glx_are_textures_resident_reply_t>;

impl AreTexturesResidentReply {
    pub fn ret_val(&self) -> Bool32 {
        unsafe {
            (*self.ptr).ret_val
        }
    }
    pub fn data(&self) -> Vec<bool> {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_are_textures_resident_data_length(field);
            let data = xcb_glx_are_textures_resident_data(field);
            let slice = std::slice::from_raw_parts(data, len as usize);
            slice.iter().map(|el| if *el == 0 {false} else{true}).collect()
        }
    }
}

pub fn are_textures_resident<'a>(c          : &'a base::Connection,
                                 context_tag: ContextTag,
                                 textures   : &[u32])
        -> AreTexturesResidentCookie<'a> {
    unsafe {
        let textures_len = textures.len();
        let textures_ptr = textures.as_ptr();
        let cookie = xcb_glx_are_textures_resident(c.get_raw_conn(),
                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                   textures_len as i32,  // 1
                                                   textures_ptr as *const u32);  // 2
        AreTexturesResidentCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn are_textures_resident_unchecked<'a>(c          : &'a base::Connection,
                                           context_tag: ContextTag,
                                           textures   : &[u32])
        -> AreTexturesResidentCookie<'a> {
    unsafe {
        let textures_len = textures.len();
        let textures_ptr = textures.as_ptr();
        let cookie = xcb_glx_are_textures_resident_unchecked(c.get_raw_conn(),
                                                             context_tag as xcb_glx_context_tag_t,  // 0
                                                             textures_len as i32,  // 1
                                                             textures_ptr as *const u32);  // 2
        AreTexturesResidentCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DELETE_TEXTURES: u8 = 144;

pub fn delete_textures<'a>(c          : &'a base::Connection,
                           context_tag: ContextTag,
                           textures   : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let textures_len = textures.len();
        let textures_ptr = textures.as_ptr();
        let cookie = xcb_glx_delete_textures(c.get_raw_conn(),
                                             context_tag as xcb_glx_context_tag_t,  // 0
                                             textures_len as i32,  // 1
                                             textures_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_textures_checked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   textures   : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let textures_len = textures.len();
        let textures_ptr = textures.as_ptr();
        let cookie = xcb_glx_delete_textures_checked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     textures_len as i32,  // 1
                                                     textures_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GEN_TEXTURES: u8 = 145;

pub type GenTexturesCookie<'a> = base::Cookie<'a, xcb_glx_gen_textures_cookie_t>;

impl<'a> GenTexturesCookie<'a> {
    pub fn get_reply(&self) -> Result<GenTexturesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GenTexturesReply {
                    ptr: xcb_glx_gen_textures_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GenTexturesReply {
                    ptr: xcb_glx_gen_textures_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GenTexturesReply = base::Reply<xcb_glx_gen_textures_reply_t>;

impl GenTexturesReply {
    pub fn data(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_gen_textures_data_length(field) as usize;
            let data = xcb_glx_gen_textures_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn gen_textures<'a>(c          : &'a base::Connection,
                        context_tag: ContextTag,
                        n          : i32)
        -> GenTexturesCookie<'a> {
    unsafe {
        let cookie = xcb_glx_gen_textures(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          n as i32);  // 1
        GenTexturesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn gen_textures_unchecked<'a>(c          : &'a base::Connection,
                                  context_tag: ContextTag,
                                  n          : i32)
        -> GenTexturesCookie<'a> {
    unsafe {
        let cookie = xcb_glx_gen_textures_unchecked(c.get_raw_conn(),
                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                    n as i32);  // 1
        GenTexturesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const IS_TEXTURE: u8 = 146;

pub type IsTextureCookie<'a> = base::Cookie<'a, xcb_glx_is_texture_cookie_t>;

impl<'a> IsTextureCookie<'a> {
    pub fn get_reply(&self) -> Result<IsTextureReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = IsTextureReply {
                    ptr: xcb_glx_is_texture_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( IsTextureReply {
                    ptr: xcb_glx_is_texture_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type IsTextureReply = base::Reply<xcb_glx_is_texture_reply_t>;

impl IsTextureReply {
    pub fn ret_val(&self) -> Bool32 {
        unsafe {
            (*self.ptr).ret_val
        }
    }
}

pub fn is_texture<'a>(c          : &'a base::Connection,
                      context_tag: ContextTag,
                      texture    : u32)
        -> IsTextureCookie<'a> {
    unsafe {
        let cookie = xcb_glx_is_texture(c.get_raw_conn(),
                                        context_tag as xcb_glx_context_tag_t,  // 0
                                        texture as u32);  // 1
        IsTextureCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn is_texture_unchecked<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                texture    : u32)
        -> IsTextureCookie<'a> {
    unsafe {
        let cookie = xcb_glx_is_texture_unchecked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  texture as u32);  // 1
        IsTextureCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_COLOR_TABLE: u8 = 147;

pub type GetColorTableCookie<'a> = base::Cookie<'a, xcb_glx_get_color_table_cookie_t>;

impl<'a> GetColorTableCookie<'a> {
    pub fn get_reply(&self) -> Result<GetColorTableReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetColorTableReply {
                    ptr: xcb_glx_get_color_table_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetColorTableReply {
                    ptr: xcb_glx_get_color_table_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetColorTableReply = base::Reply<xcb_glx_get_color_table_reply_t>;

impl GetColorTableReply {
    pub fn width(&self) -> i32 {
        unsafe {
            (*self.ptr).width
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_color_table_data_length(field) as usize;
            let data = xcb_glx_get_color_table_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_color_table<'a>(c          : &'a base::Connection,
                           context_tag: ContextTag,
                           target     : u32,
                           format     : u32,
                           type_      : u32,
                           swap_bytes : bool)
        -> GetColorTableCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_color_table(c.get_raw_conn(),
                                             context_tag as xcb_glx_context_tag_t,  // 0
                                             target as u32,  // 1
                                             format as u32,  // 2
                                             type_ as u32,  // 3
                                             swap_bytes as u8);  // 4
        GetColorTableCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_color_table_unchecked<'a>(c          : &'a base::Connection,
                                     context_tag: ContextTag,
                                     target     : u32,
                                     format     : u32,
                                     type_      : u32,
                                     swap_bytes : bool)
        -> GetColorTableCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_color_table_unchecked(c.get_raw_conn(),
                                                       context_tag as xcb_glx_context_tag_t,  // 0
                                                       target as u32,  // 1
                                                       format as u32,  // 2
                                                       type_ as u32,  // 3
                                                       swap_bytes as u8);  // 4
        GetColorTableCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_COLOR_TABLE_PARAMETERFV: u8 = 148;

pub type GetColorTableParameterfvCookie<'a> = base::Cookie<'a, xcb_glx_get_color_table_parameterfv_cookie_t>;

impl<'a> GetColorTableParameterfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetColorTableParameterfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetColorTableParameterfvReply {
                    ptr: xcb_glx_get_color_table_parameterfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetColorTableParameterfvReply {
                    ptr: xcb_glx_get_color_table_parameterfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetColorTableParameterfvReply = base::Reply<xcb_glx_get_color_table_parameterfv_reply_t>;

impl GetColorTableParameterfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_color_table_parameterfv_data_length(field) as usize;
            let data = xcb_glx_get_color_table_parameterfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_color_table_parameterfv<'a>(c          : &'a base::Connection,
                                       context_tag: ContextTag,
                                       target     : u32,
                                       pname      : u32)
        -> GetColorTableParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_color_table_parameterfv(c.get_raw_conn(),
                                                         context_tag as xcb_glx_context_tag_t,  // 0
                                                         target as u32,  // 1
                                                         pname as u32);  // 2
        GetColorTableParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_color_table_parameterfv_unchecked<'a>(c          : &'a base::Connection,
                                                 context_tag: ContextTag,
                                                 target     : u32,
                                                 pname      : u32)
        -> GetColorTableParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_color_table_parameterfv_unchecked(c.get_raw_conn(),
                                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                                   target as u32,  // 1
                                                                   pname as u32);  // 2
        GetColorTableParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_COLOR_TABLE_PARAMETERIV: u8 = 149;

pub type GetColorTableParameterivCookie<'a> = base::Cookie<'a, xcb_glx_get_color_table_parameteriv_cookie_t>;

impl<'a> GetColorTableParameterivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetColorTableParameterivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetColorTableParameterivReply {
                    ptr: xcb_glx_get_color_table_parameteriv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetColorTableParameterivReply {
                    ptr: xcb_glx_get_color_table_parameteriv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetColorTableParameterivReply = base::Reply<xcb_glx_get_color_table_parameteriv_reply_t>;

impl GetColorTableParameterivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_color_table_parameteriv_data_length(field) as usize;
            let data = xcb_glx_get_color_table_parameteriv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_color_table_parameteriv<'a>(c          : &'a base::Connection,
                                       context_tag: ContextTag,
                                       target     : u32,
                                       pname      : u32)
        -> GetColorTableParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_color_table_parameteriv(c.get_raw_conn(),
                                                         context_tag as xcb_glx_context_tag_t,  // 0
                                                         target as u32,  // 1
                                                         pname as u32);  // 2
        GetColorTableParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_color_table_parameteriv_unchecked<'a>(c          : &'a base::Connection,
                                                 context_tag: ContextTag,
                                                 target     : u32,
                                                 pname      : u32)
        -> GetColorTableParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_color_table_parameteriv_unchecked(c.get_raw_conn(),
                                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                                   target as u32,  // 1
                                                                   pname as u32);  // 2
        GetColorTableParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_CONVOLUTION_FILTER: u8 = 150;

pub type GetConvolutionFilterCookie<'a> = base::Cookie<'a, xcb_glx_get_convolution_filter_cookie_t>;

impl<'a> GetConvolutionFilterCookie<'a> {
    pub fn get_reply(&self) -> Result<GetConvolutionFilterReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetConvolutionFilterReply {
                    ptr: xcb_glx_get_convolution_filter_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetConvolutionFilterReply {
                    ptr: xcb_glx_get_convolution_filter_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetConvolutionFilterReply = base::Reply<xcb_glx_get_convolution_filter_reply_t>;

impl GetConvolutionFilterReply {
    pub fn width(&self) -> i32 {
        unsafe {
            (*self.ptr).width
        }
    }
    pub fn height(&self) -> i32 {
        unsafe {
            (*self.ptr).height
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_convolution_filter_data_length(field) as usize;
            let data = xcb_glx_get_convolution_filter_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_convolution_filter<'a>(c          : &'a base::Connection,
                                  context_tag: ContextTag,
                                  target     : u32,
                                  format     : u32,
                                  type_      : u32,
                                  swap_bytes : bool)
        -> GetConvolutionFilterCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_convolution_filter(c.get_raw_conn(),
                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                    target as u32,  // 1
                                                    format as u32,  // 2
                                                    type_ as u32,  // 3
                                                    swap_bytes as u8);  // 4
        GetConvolutionFilterCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_convolution_filter_unchecked<'a>(c          : &'a base::Connection,
                                            context_tag: ContextTag,
                                            target     : u32,
                                            format     : u32,
                                            type_      : u32,
                                            swap_bytes : bool)
        -> GetConvolutionFilterCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_convolution_filter_unchecked(c.get_raw_conn(),
                                                              context_tag as xcb_glx_context_tag_t,  // 0
                                                              target as u32,  // 1
                                                              format as u32,  // 2
                                                              type_ as u32,  // 3
                                                              swap_bytes as u8);  // 4
        GetConvolutionFilterCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_CONVOLUTION_PARAMETERFV: u8 = 151;

pub type GetConvolutionParameterfvCookie<'a> = base::Cookie<'a, xcb_glx_get_convolution_parameterfv_cookie_t>;

impl<'a> GetConvolutionParameterfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetConvolutionParameterfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetConvolutionParameterfvReply {
                    ptr: xcb_glx_get_convolution_parameterfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetConvolutionParameterfvReply {
                    ptr: xcb_glx_get_convolution_parameterfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetConvolutionParameterfvReply = base::Reply<xcb_glx_get_convolution_parameterfv_reply_t>;

impl GetConvolutionParameterfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_convolution_parameterfv_data_length(field) as usize;
            let data = xcb_glx_get_convolution_parameterfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_convolution_parameterfv<'a>(c          : &'a base::Connection,
                                       context_tag: ContextTag,
                                       target     : u32,
                                       pname      : u32)
        -> GetConvolutionParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_convolution_parameterfv(c.get_raw_conn(),
                                                         context_tag as xcb_glx_context_tag_t,  // 0
                                                         target as u32,  // 1
                                                         pname as u32);  // 2
        GetConvolutionParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_convolution_parameterfv_unchecked<'a>(c          : &'a base::Connection,
                                                 context_tag: ContextTag,
                                                 target     : u32,
                                                 pname      : u32)
        -> GetConvolutionParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_convolution_parameterfv_unchecked(c.get_raw_conn(),
                                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                                   target as u32,  // 1
                                                                   pname as u32);  // 2
        GetConvolutionParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_CONVOLUTION_PARAMETERIV: u8 = 152;

pub type GetConvolutionParameterivCookie<'a> = base::Cookie<'a, xcb_glx_get_convolution_parameteriv_cookie_t>;

impl<'a> GetConvolutionParameterivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetConvolutionParameterivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetConvolutionParameterivReply {
                    ptr: xcb_glx_get_convolution_parameteriv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetConvolutionParameterivReply {
                    ptr: xcb_glx_get_convolution_parameteriv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetConvolutionParameterivReply = base::Reply<xcb_glx_get_convolution_parameteriv_reply_t>;

impl GetConvolutionParameterivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_convolution_parameteriv_data_length(field) as usize;
            let data = xcb_glx_get_convolution_parameteriv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_convolution_parameteriv<'a>(c          : &'a base::Connection,
                                       context_tag: ContextTag,
                                       target     : u32,
                                       pname      : u32)
        -> GetConvolutionParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_convolution_parameteriv(c.get_raw_conn(),
                                                         context_tag as xcb_glx_context_tag_t,  // 0
                                                         target as u32,  // 1
                                                         pname as u32);  // 2
        GetConvolutionParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_convolution_parameteriv_unchecked<'a>(c          : &'a base::Connection,
                                                 context_tag: ContextTag,
                                                 target     : u32,
                                                 pname      : u32)
        -> GetConvolutionParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_convolution_parameteriv_unchecked(c.get_raw_conn(),
                                                                   context_tag as xcb_glx_context_tag_t,  // 0
                                                                   target as u32,  // 1
                                                                   pname as u32);  // 2
        GetConvolutionParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_SEPARABLE_FILTER: u8 = 153;

pub type GetSeparableFilterCookie<'a> = base::Cookie<'a, xcb_glx_get_separable_filter_cookie_t>;

impl<'a> GetSeparableFilterCookie<'a> {
    pub fn get_reply(&self) -> Result<GetSeparableFilterReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetSeparableFilterReply {
                    ptr: xcb_glx_get_separable_filter_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetSeparableFilterReply {
                    ptr: xcb_glx_get_separable_filter_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetSeparableFilterReply = base::Reply<xcb_glx_get_separable_filter_reply_t>;

impl GetSeparableFilterReply {
    pub fn row_w(&self) -> i32 {
        unsafe {
            (*self.ptr).row_w
        }
    }
    pub fn col_h(&self) -> i32 {
        unsafe {
            (*self.ptr).col_h
        }
    }
    pub fn rows_and_cols(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_separable_filter_rows_and_cols_length(field) as usize;
            let data = xcb_glx_get_separable_filter_rows_and_cols(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_separable_filter<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                target     : u32,
                                format     : u32,
                                type_      : u32,
                                swap_bytes : bool)
        -> GetSeparableFilterCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_separable_filter(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  target as u32,  // 1
                                                  format as u32,  // 2
                                                  type_ as u32,  // 3
                                                  swap_bytes as u8);  // 4
        GetSeparableFilterCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_separable_filter_unchecked<'a>(c          : &'a base::Connection,
                                          context_tag: ContextTag,
                                          target     : u32,
                                          format     : u32,
                                          type_      : u32,
                                          swap_bytes : bool)
        -> GetSeparableFilterCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_separable_filter_unchecked(c.get_raw_conn(),
                                                            context_tag as xcb_glx_context_tag_t,  // 0
                                                            target as u32,  // 1
                                                            format as u32,  // 2
                                                            type_ as u32,  // 3
                                                            swap_bytes as u8);  // 4
        GetSeparableFilterCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_HISTOGRAM: u8 = 154;

pub type GetHistogramCookie<'a> = base::Cookie<'a, xcb_glx_get_histogram_cookie_t>;

impl<'a> GetHistogramCookie<'a> {
    pub fn get_reply(&self) -> Result<GetHistogramReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetHistogramReply {
                    ptr: xcb_glx_get_histogram_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetHistogramReply {
                    ptr: xcb_glx_get_histogram_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetHistogramReply = base::Reply<xcb_glx_get_histogram_reply_t>;

impl GetHistogramReply {
    pub fn width(&self) -> i32 {
        unsafe {
            (*self.ptr).width
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_histogram_data_length(field) as usize;
            let data = xcb_glx_get_histogram_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_histogram<'a>(c          : &'a base::Connection,
                         context_tag: ContextTag,
                         target     : u32,
                         format     : u32,
                         type_      : u32,
                         swap_bytes : bool,
                         reset      : bool)
        -> GetHistogramCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_histogram(c.get_raw_conn(),
                                           context_tag as xcb_glx_context_tag_t,  // 0
                                           target as u32,  // 1
                                           format as u32,  // 2
                                           type_ as u32,  // 3
                                           swap_bytes as u8,  // 4
                                           reset as u8);  // 5
        GetHistogramCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_histogram_unchecked<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   target     : u32,
                                   format     : u32,
                                   type_      : u32,
                                   swap_bytes : bool,
                                   reset      : bool)
        -> GetHistogramCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_histogram_unchecked(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     target as u32,  // 1
                                                     format as u32,  // 2
                                                     type_ as u32,  // 3
                                                     swap_bytes as u8,  // 4
                                                     reset as u8);  // 5
        GetHistogramCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_HISTOGRAM_PARAMETERFV: u8 = 155;

pub type GetHistogramParameterfvCookie<'a> = base::Cookie<'a, xcb_glx_get_histogram_parameterfv_cookie_t>;

impl<'a> GetHistogramParameterfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetHistogramParameterfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetHistogramParameterfvReply {
                    ptr: xcb_glx_get_histogram_parameterfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetHistogramParameterfvReply {
                    ptr: xcb_glx_get_histogram_parameterfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetHistogramParameterfvReply = base::Reply<xcb_glx_get_histogram_parameterfv_reply_t>;

impl GetHistogramParameterfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_histogram_parameterfv_data_length(field) as usize;
            let data = xcb_glx_get_histogram_parameterfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_histogram_parameterfv<'a>(c          : &'a base::Connection,
                                     context_tag: ContextTag,
                                     target     : u32,
                                     pname      : u32)
        -> GetHistogramParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_histogram_parameterfv(c.get_raw_conn(),
                                                       context_tag as xcb_glx_context_tag_t,  // 0
                                                       target as u32,  // 1
                                                       pname as u32);  // 2
        GetHistogramParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_histogram_parameterfv_unchecked<'a>(c          : &'a base::Connection,
                                               context_tag: ContextTag,
                                               target     : u32,
                                               pname      : u32)
        -> GetHistogramParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_histogram_parameterfv_unchecked(c.get_raw_conn(),
                                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                                 target as u32,  // 1
                                                                 pname as u32);  // 2
        GetHistogramParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_HISTOGRAM_PARAMETERIV: u8 = 156;

pub type GetHistogramParameterivCookie<'a> = base::Cookie<'a, xcb_glx_get_histogram_parameteriv_cookie_t>;

impl<'a> GetHistogramParameterivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetHistogramParameterivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetHistogramParameterivReply {
                    ptr: xcb_glx_get_histogram_parameteriv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetHistogramParameterivReply {
                    ptr: xcb_glx_get_histogram_parameteriv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetHistogramParameterivReply = base::Reply<xcb_glx_get_histogram_parameteriv_reply_t>;

impl GetHistogramParameterivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_histogram_parameteriv_data_length(field) as usize;
            let data = xcb_glx_get_histogram_parameteriv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_histogram_parameteriv<'a>(c          : &'a base::Connection,
                                     context_tag: ContextTag,
                                     target     : u32,
                                     pname      : u32)
        -> GetHistogramParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_histogram_parameteriv(c.get_raw_conn(),
                                                       context_tag as xcb_glx_context_tag_t,  // 0
                                                       target as u32,  // 1
                                                       pname as u32);  // 2
        GetHistogramParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_histogram_parameteriv_unchecked<'a>(c          : &'a base::Connection,
                                               context_tag: ContextTag,
                                               target     : u32,
                                               pname      : u32)
        -> GetHistogramParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_histogram_parameteriv_unchecked(c.get_raw_conn(),
                                                                 context_tag as xcb_glx_context_tag_t,  // 0
                                                                 target as u32,  // 1
                                                                 pname as u32);  // 2
        GetHistogramParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MINMAX: u8 = 157;

pub type GetMinmaxCookie<'a> = base::Cookie<'a, xcb_glx_get_minmax_cookie_t>;

impl<'a> GetMinmaxCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMinmaxReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMinmaxReply {
                    ptr: xcb_glx_get_minmax_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMinmaxReply {
                    ptr: xcb_glx_get_minmax_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMinmaxReply = base::Reply<xcb_glx_get_minmax_reply_t>;

impl GetMinmaxReply {
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_minmax_data_length(field) as usize;
            let data = xcb_glx_get_minmax_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_minmax<'a>(c          : &'a base::Connection,
                      context_tag: ContextTag,
                      target     : u32,
                      format     : u32,
                      type_      : u32,
                      swap_bytes : bool,
                      reset      : bool)
        -> GetMinmaxCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_minmax(c.get_raw_conn(),
                                        context_tag as xcb_glx_context_tag_t,  // 0
                                        target as u32,  // 1
                                        format as u32,  // 2
                                        type_ as u32,  // 3
                                        swap_bytes as u8,  // 4
                                        reset as u8);  // 5
        GetMinmaxCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_minmax_unchecked<'a>(c          : &'a base::Connection,
                                context_tag: ContextTag,
                                target     : u32,
                                format     : u32,
                                type_      : u32,
                                swap_bytes : bool,
                                reset      : bool)
        -> GetMinmaxCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_minmax_unchecked(c.get_raw_conn(),
                                                  context_tag as xcb_glx_context_tag_t,  // 0
                                                  target as u32,  // 1
                                                  format as u32,  // 2
                                                  type_ as u32,  // 3
                                                  swap_bytes as u8,  // 4
                                                  reset as u8);  // 5
        GetMinmaxCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MINMAX_PARAMETERFV: u8 = 158;

pub type GetMinmaxParameterfvCookie<'a> = base::Cookie<'a, xcb_glx_get_minmax_parameterfv_cookie_t>;

impl<'a> GetMinmaxParameterfvCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMinmaxParameterfvReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMinmaxParameterfvReply {
                    ptr: xcb_glx_get_minmax_parameterfv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMinmaxParameterfvReply {
                    ptr: xcb_glx_get_minmax_parameterfv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMinmaxParameterfvReply = base::Reply<xcb_glx_get_minmax_parameterfv_reply_t>;

impl GetMinmaxParameterfvReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> Float32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[Float32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_minmax_parameterfv_data_length(field) as usize;
            let data = xcb_glx_get_minmax_parameterfv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_minmax_parameterfv<'a>(c          : &'a base::Connection,
                                  context_tag: ContextTag,
                                  target     : u32,
                                  pname      : u32)
        -> GetMinmaxParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_minmax_parameterfv(c.get_raw_conn(),
                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                    target as u32,  // 1
                                                    pname as u32);  // 2
        GetMinmaxParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_minmax_parameterfv_unchecked<'a>(c          : &'a base::Connection,
                                            context_tag: ContextTag,
                                            target     : u32,
                                            pname      : u32)
        -> GetMinmaxParameterfvCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_minmax_parameterfv_unchecked(c.get_raw_conn(),
                                                              context_tag as xcb_glx_context_tag_t,  // 0
                                                              target as u32,  // 1
                                                              pname as u32);  // 2
        GetMinmaxParameterfvCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_MINMAX_PARAMETERIV: u8 = 159;

pub type GetMinmaxParameterivCookie<'a> = base::Cookie<'a, xcb_glx_get_minmax_parameteriv_cookie_t>;

impl<'a> GetMinmaxParameterivCookie<'a> {
    pub fn get_reply(&self) -> Result<GetMinmaxParameterivReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetMinmaxParameterivReply {
                    ptr: xcb_glx_get_minmax_parameteriv_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetMinmaxParameterivReply {
                    ptr: xcb_glx_get_minmax_parameteriv_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetMinmaxParameterivReply = base::Reply<xcb_glx_get_minmax_parameteriv_reply_t>;

impl GetMinmaxParameterivReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_minmax_parameteriv_data_length(field) as usize;
            let data = xcb_glx_get_minmax_parameteriv_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_minmax_parameteriv<'a>(c          : &'a base::Connection,
                                  context_tag: ContextTag,
                                  target     : u32,
                                  pname      : u32)
        -> GetMinmaxParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_minmax_parameteriv(c.get_raw_conn(),
                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                    target as u32,  // 1
                                                    pname as u32);  // 2
        GetMinmaxParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_minmax_parameteriv_unchecked<'a>(c          : &'a base::Connection,
                                            context_tag: ContextTag,
                                            target     : u32,
                                            pname      : u32)
        -> GetMinmaxParameterivCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_minmax_parameteriv_unchecked(c.get_raw_conn(),
                                                              context_tag as xcb_glx_context_tag_t,  // 0
                                                              target as u32,  // 1
                                                              pname as u32);  // 2
        GetMinmaxParameterivCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_COMPRESSED_TEX_IMAGE_ARB: u8 = 160;

pub type GetCompressedTexImageArbCookie<'a> = base::Cookie<'a, xcb_glx_get_compressed_tex_image_arb_cookie_t>;

impl<'a> GetCompressedTexImageArbCookie<'a> {
    pub fn get_reply(&self) -> Result<GetCompressedTexImageArbReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetCompressedTexImageArbReply {
                    ptr: xcb_glx_get_compressed_tex_image_arb_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetCompressedTexImageArbReply {
                    ptr: xcb_glx_get_compressed_tex_image_arb_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetCompressedTexImageArbReply = base::Reply<xcb_glx_get_compressed_tex_image_arb_reply_t>;

impl GetCompressedTexImageArbReply {
    pub fn size(&self) -> i32 {
        unsafe {
            (*self.ptr).size
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_compressed_tex_image_arb_data_length(field) as usize;
            let data = xcb_glx_get_compressed_tex_image_arb_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_compressed_tex_image_arb<'a>(c          : &'a base::Connection,
                                        context_tag: ContextTag,
                                        target     : u32,
                                        level      : i32)
        -> GetCompressedTexImageArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_compressed_tex_image_arb(c.get_raw_conn(),
                                                          context_tag as xcb_glx_context_tag_t,  // 0
                                                          target as u32,  // 1
                                                          level as i32);  // 2
        GetCompressedTexImageArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_compressed_tex_image_arb_unchecked<'a>(c          : &'a base::Connection,
                                                  context_tag: ContextTag,
                                                  target     : u32,
                                                  level      : i32)
        -> GetCompressedTexImageArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_compressed_tex_image_arb_unchecked(c.get_raw_conn(),
                                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                                    target as u32,  // 1
                                                                    level as i32);  // 2
        GetCompressedTexImageArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const DELETE_QUERIES_ARB: u8 = 161;

pub fn delete_queries_arb<'a>(c          : &'a base::Connection,
                              context_tag: ContextTag,
                              ids        : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let ids_len = ids.len();
        let ids_ptr = ids.as_ptr();
        let cookie = xcb_glx_delete_queries_arb(c.get_raw_conn(),
                                                context_tag as xcb_glx_context_tag_t,  // 0
                                                ids_len as i32,  // 1
                                                ids_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn delete_queries_arb_checked<'a>(c          : &'a base::Connection,
                                      context_tag: ContextTag,
                                      ids        : &[u32])
        -> base::VoidCookie<'a> {
    unsafe {
        let ids_len = ids.len();
        let ids_ptr = ids.as_ptr();
        let cookie = xcb_glx_delete_queries_arb_checked(c.get_raw_conn(),
                                                        context_tag as xcb_glx_context_tag_t,  // 0
                                                        ids_len as i32,  // 1
                                                        ids_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GEN_QUERIES_ARB: u8 = 162;

pub type GenQueriesArbCookie<'a> = base::Cookie<'a, xcb_glx_gen_queries_arb_cookie_t>;

impl<'a> GenQueriesArbCookie<'a> {
    pub fn get_reply(&self) -> Result<GenQueriesArbReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GenQueriesArbReply {
                    ptr: xcb_glx_gen_queries_arb_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GenQueriesArbReply {
                    ptr: xcb_glx_gen_queries_arb_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GenQueriesArbReply = base::Reply<xcb_glx_gen_queries_arb_reply_t>;

impl GenQueriesArbReply {
    pub fn data(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_gen_queries_arb_data_length(field) as usize;
            let data = xcb_glx_gen_queries_arb_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn gen_queries_arb<'a>(c          : &'a base::Connection,
                           context_tag: ContextTag,
                           n          : i32)
        -> GenQueriesArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_gen_queries_arb(c.get_raw_conn(),
                                             context_tag as xcb_glx_context_tag_t,  // 0
                                             n as i32);  // 1
        GenQueriesArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn gen_queries_arb_unchecked<'a>(c          : &'a base::Connection,
                                     context_tag: ContextTag,
                                     n          : i32)
        -> GenQueriesArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_gen_queries_arb_unchecked(c.get_raw_conn(),
                                                       context_tag as xcb_glx_context_tag_t,  // 0
                                                       n as i32);  // 1
        GenQueriesArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const IS_QUERY_ARB: u8 = 163;

pub type IsQueryArbCookie<'a> = base::Cookie<'a, xcb_glx_is_query_arb_cookie_t>;

impl<'a> IsQueryArbCookie<'a> {
    pub fn get_reply(&self) -> Result<IsQueryArbReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = IsQueryArbReply {
                    ptr: xcb_glx_is_query_arb_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( IsQueryArbReply {
                    ptr: xcb_glx_is_query_arb_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type IsQueryArbReply = base::Reply<xcb_glx_is_query_arb_reply_t>;

impl IsQueryArbReply {
    pub fn ret_val(&self) -> Bool32 {
        unsafe {
            (*self.ptr).ret_val
        }
    }
}

pub fn is_query_arb<'a>(c          : &'a base::Connection,
                        context_tag: ContextTag,
                        id         : u32)
        -> IsQueryArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_is_query_arb(c.get_raw_conn(),
                                          context_tag as xcb_glx_context_tag_t,  // 0
                                          id as u32);  // 1
        IsQueryArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn is_query_arb_unchecked<'a>(c          : &'a base::Connection,
                                  context_tag: ContextTag,
                                  id         : u32)
        -> IsQueryArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_is_query_arb_unchecked(c.get_raw_conn(),
                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                    id as u32);  // 1
        IsQueryArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_QUERYIV_ARB: u8 = 164;

pub type GetQueryivArbCookie<'a> = base::Cookie<'a, xcb_glx_get_queryiv_arb_cookie_t>;

impl<'a> GetQueryivArbCookie<'a> {
    pub fn get_reply(&self) -> Result<GetQueryivArbReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetQueryivArbReply {
                    ptr: xcb_glx_get_queryiv_arb_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetQueryivArbReply {
                    ptr: xcb_glx_get_queryiv_arb_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetQueryivArbReply = base::Reply<xcb_glx_get_queryiv_arb_reply_t>;

impl GetQueryivArbReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_queryiv_arb_data_length(field) as usize;
            let data = xcb_glx_get_queryiv_arb_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_queryiv_arb<'a>(c          : &'a base::Connection,
                           context_tag: ContextTag,
                           target     : u32,
                           pname      : u32)
        -> GetQueryivArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_queryiv_arb(c.get_raw_conn(),
                                             context_tag as xcb_glx_context_tag_t,  // 0
                                             target as u32,  // 1
                                             pname as u32);  // 2
        GetQueryivArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_queryiv_arb_unchecked<'a>(c          : &'a base::Connection,
                                     context_tag: ContextTag,
                                     target     : u32,
                                     pname      : u32)
        -> GetQueryivArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_queryiv_arb_unchecked(c.get_raw_conn(),
                                                       context_tag as xcb_glx_context_tag_t,  // 0
                                                       target as u32,  // 1
                                                       pname as u32);  // 2
        GetQueryivArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_QUERY_OBJECTIV_ARB: u8 = 165;

pub type GetQueryObjectivArbCookie<'a> = base::Cookie<'a, xcb_glx_get_query_objectiv_arb_cookie_t>;

impl<'a> GetQueryObjectivArbCookie<'a> {
    pub fn get_reply(&self) -> Result<GetQueryObjectivArbReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetQueryObjectivArbReply {
                    ptr: xcb_glx_get_query_objectiv_arb_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetQueryObjectivArbReply {
                    ptr: xcb_glx_get_query_objectiv_arb_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetQueryObjectivArbReply = base::Reply<xcb_glx_get_query_objectiv_arb_reply_t>;

impl GetQueryObjectivArbReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> i32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[i32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_query_objectiv_arb_data_length(field) as usize;
            let data = xcb_glx_get_query_objectiv_arb_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_query_objectiv_arb<'a>(c          : &'a base::Connection,
                                  context_tag: ContextTag,
                                  id         : u32,
                                  pname      : u32)
        -> GetQueryObjectivArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_query_objectiv_arb(c.get_raw_conn(),
                                                    context_tag as xcb_glx_context_tag_t,  // 0
                                                    id as u32,  // 1
                                                    pname as u32);  // 2
        GetQueryObjectivArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_query_objectiv_arb_unchecked<'a>(c          : &'a base::Connection,
                                            context_tag: ContextTag,
                                            id         : u32,
                                            pname      : u32)
        -> GetQueryObjectivArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_query_objectiv_arb_unchecked(c.get_raw_conn(),
                                                              context_tag as xcb_glx_context_tag_t,  // 0
                                                              id as u32,  // 1
                                                              pname as u32);  // 2
        GetQueryObjectivArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GET_QUERY_OBJECTUIV_ARB: u8 = 166;

pub type GetQueryObjectuivArbCookie<'a> = base::Cookie<'a, xcb_glx_get_query_objectuiv_arb_cookie_t>;

impl<'a> GetQueryObjectuivArbCookie<'a> {
    pub fn get_reply(&self) -> Result<GetQueryObjectuivArbReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetQueryObjectuivArbReply {
                    ptr: xcb_glx_get_query_objectuiv_arb_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetQueryObjectuivArbReply {
                    ptr: xcb_glx_get_query_objectuiv_arb_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetQueryObjectuivArbReply = base::Reply<xcb_glx_get_query_objectuiv_arb_reply_t>;

impl GetQueryObjectuivArbReply {
    pub fn n(&self) -> u32 {
        unsafe {
            (*self.ptr).n
        }
    }
    pub fn datum(&self) -> u32 {
        unsafe {
            (*self.ptr).datum
        }
    }
    pub fn data(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_glx_get_query_objectuiv_arb_data_length(field) as usize;
            let data = xcb_glx_get_query_objectuiv_arb_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn get_query_objectuiv_arb<'a>(c          : &'a base::Connection,
                                   context_tag: ContextTag,
                                   id         : u32,
                                   pname      : u32)
        -> GetQueryObjectuivArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_query_objectuiv_arb(c.get_raw_conn(),
                                                     context_tag as xcb_glx_context_tag_t,  // 0
                                                     id as u32,  // 1
                                                     pname as u32);  // 2
        GetQueryObjectuivArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_query_objectuiv_arb_unchecked<'a>(c          : &'a base::Connection,
                                             context_tag: ContextTag,
                                             id         : u32,
                                             pname      : u32)
        -> GetQueryObjectuivArbCookie<'a> {
    unsafe {
        let cookie = xcb_glx_get_query_objectuiv_arb_unchecked(c.get_raw_conn(),
                                                               context_tag as xcb_glx_context_tag_t,  // 0
                                                               id as u32,  // 1
                                                               pname as u32);  // 2
        GetQueryObjectuivArbCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}
