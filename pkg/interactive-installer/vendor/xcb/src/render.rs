// Generated automatically from render.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::render::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_render_id
    }
}

pub const MAJOR_VERSION: u32 = 0;
pub const MINOR_VERSION: u32 = 11;

pub type PictType = u32;
pub const PICT_TYPE_INDEXED: PictType = 0x00;
pub const PICT_TYPE_DIRECT : PictType = 0x01;

pub type PictureEnum = u32;
pub const PICTURE_NONE: PictureEnum = 0x00;

pub type PictOp = u32;
pub const PICT_OP_CLEAR                : PictOp = 0x00;
pub const PICT_OP_SRC                  : PictOp = 0x01;
pub const PICT_OP_DST                  : PictOp = 0x02;
pub const PICT_OP_OVER                 : PictOp = 0x03;
pub const PICT_OP_OVER_REVERSE         : PictOp = 0x04;
pub const PICT_OP_IN                   : PictOp = 0x05;
pub const PICT_OP_IN_REVERSE           : PictOp = 0x06;
pub const PICT_OP_OUT                  : PictOp = 0x07;
pub const PICT_OP_OUT_REVERSE          : PictOp = 0x08;
pub const PICT_OP_ATOP                 : PictOp = 0x09;
pub const PICT_OP_ATOP_REVERSE         : PictOp = 0x0a;
pub const PICT_OP_XOR                  : PictOp = 0x0b;
pub const PICT_OP_ADD                  : PictOp = 0x0c;
pub const PICT_OP_SATURATE             : PictOp = 0x0d;
pub const PICT_OP_DISJOINT_CLEAR       : PictOp = 0x10;
pub const PICT_OP_DISJOINT_SRC         : PictOp = 0x11;
pub const PICT_OP_DISJOINT_DST         : PictOp = 0x12;
pub const PICT_OP_DISJOINT_OVER        : PictOp = 0x13;
pub const PICT_OP_DISJOINT_OVER_REVERSE: PictOp = 0x14;
pub const PICT_OP_DISJOINT_IN          : PictOp = 0x15;
pub const PICT_OP_DISJOINT_IN_REVERSE  : PictOp = 0x16;
pub const PICT_OP_DISJOINT_OUT         : PictOp = 0x17;
pub const PICT_OP_DISJOINT_OUT_REVERSE : PictOp = 0x18;
pub const PICT_OP_DISJOINT_ATOP        : PictOp = 0x19;
pub const PICT_OP_DISJOINT_ATOP_REVERSE: PictOp = 0x1a;
pub const PICT_OP_DISJOINT_XOR         : PictOp = 0x1b;
pub const PICT_OP_CONJOINT_CLEAR       : PictOp = 0x20;
pub const PICT_OP_CONJOINT_SRC         : PictOp = 0x21;
pub const PICT_OP_CONJOINT_DST         : PictOp = 0x22;
pub const PICT_OP_CONJOINT_OVER        : PictOp = 0x23;
pub const PICT_OP_CONJOINT_OVER_REVERSE: PictOp = 0x24;
pub const PICT_OP_CONJOINT_IN          : PictOp = 0x25;
pub const PICT_OP_CONJOINT_IN_REVERSE  : PictOp = 0x26;
pub const PICT_OP_CONJOINT_OUT         : PictOp = 0x27;
pub const PICT_OP_CONJOINT_OUT_REVERSE : PictOp = 0x28;
pub const PICT_OP_CONJOINT_ATOP        : PictOp = 0x29;
pub const PICT_OP_CONJOINT_ATOP_REVERSE: PictOp = 0x2a;
pub const PICT_OP_CONJOINT_XOR         : PictOp = 0x2b;
pub const PICT_OP_MULTIPLY             : PictOp = 0x30;
pub const PICT_OP_SCREEN               : PictOp = 0x31;
pub const PICT_OP_OVERLAY              : PictOp = 0x32;
pub const PICT_OP_DARKEN               : PictOp = 0x33;
pub const PICT_OP_LIGHTEN              : PictOp = 0x34;
pub const PICT_OP_COLOR_DODGE          : PictOp = 0x35;
pub const PICT_OP_COLOR_BURN           : PictOp = 0x36;
pub const PICT_OP_HARD_LIGHT           : PictOp = 0x37;
pub const PICT_OP_SOFT_LIGHT           : PictOp = 0x38;
pub const PICT_OP_DIFFERENCE           : PictOp = 0x39;
pub const PICT_OP_EXCLUSION            : PictOp = 0x3a;
pub const PICT_OP_HSL_HUE              : PictOp = 0x3b;
pub const PICT_OP_HSL_SATURATION       : PictOp = 0x3c;
pub const PICT_OP_HSL_COLOR            : PictOp = 0x3d;
pub const PICT_OP_HSL_LUMINOSITY       : PictOp = 0x3e;

pub type PolyEdge = u32;
pub const POLY_EDGE_SHARP : PolyEdge = 0x00;
pub const POLY_EDGE_SMOOTH: PolyEdge = 0x01;

pub type PolyMode = u32;
pub const POLY_MODE_PRECISE  : PolyMode = 0x00;
pub const POLY_MODE_IMPRECISE: PolyMode = 0x01;

pub type Cp = u32;
pub const CP_REPEAT           : Cp =   0x01;
pub const CP_ALPHA_MAP        : Cp =   0x02;
pub const CP_ALPHA_X_ORIGIN   : Cp =   0x04;
pub const CP_ALPHA_Y_ORIGIN   : Cp =   0x08;
pub const CP_CLIP_X_ORIGIN    : Cp =   0x10;
pub const CP_CLIP_Y_ORIGIN    : Cp =   0x20;
pub const CP_CLIP_MASK        : Cp =   0x40;
pub const CP_GRAPHICS_EXPOSURE: Cp =   0x80;
pub const CP_SUBWINDOW_MODE   : Cp =  0x100;
pub const CP_POLY_EDGE        : Cp =  0x200;
pub const CP_POLY_MODE        : Cp =  0x400;
pub const CP_DITHER           : Cp =  0x800;
pub const CP_COMPONENT_ALPHA  : Cp = 0x1000;

pub type SubPixel = u32;
pub const SUB_PIXEL_UNKNOWN       : SubPixel = 0x00;
pub const SUB_PIXEL_HORIZONTAL_RGB: SubPixel = 0x01;
pub const SUB_PIXEL_HORIZONTAL_BGR: SubPixel = 0x02;
pub const SUB_PIXEL_VERTICAL_RGB  : SubPixel = 0x03;
pub const SUB_PIXEL_VERTICAL_BGR  : SubPixel = 0x04;
pub const SUB_PIXEL_NONE          : SubPixel = 0x05;

pub type Repeat = u32;
pub const REPEAT_NONE   : Repeat = 0x00;
pub const REPEAT_NORMAL : Repeat = 0x01;
pub const REPEAT_PAD    : Repeat = 0x02;
pub const REPEAT_REFLECT: Repeat = 0x03;

pub type Glyph = xcb_render_glyph_t;

pub type Glyphset = xcb_render_glyphset_t;

pub type Picture = xcb_render_picture_t;

pub type Pictformat = xcb_render_pictformat_t;

pub type Fixed = xcb_render_fixed_t;

pub struct PictFormatError {
    pub base: base::Error<xcb_render_pict_format_error_t>
}

pub struct PictureError {
    pub base: base::Error<xcb_render_picture_error_t>
}

pub struct PictOpError {
    pub base: base::Error<xcb_render_pict_op_error_t>
}

pub struct GlyphSetError {
    pub base: base::Error<xcb_render_glyph_set_error_t>
}

pub struct GlyphError {
    pub base: base::Error<xcb_render_glyph_error_t>
}



pub const PICT_FORMAT: u8 = 0;

pub const PICTURE: u8 = 1;

pub const PICT_OP: u8 = 2;

pub const GLYPH_SET: u8 = 3;

pub const GLYPH: u8 = 4;

#[derive(Copy, Clone)]
pub struct Directformat {
    pub base: xcb_render_directformat_t,
}

impl Directformat {
    #[allow(unused_unsafe)]
    pub fn new(red_shift:   u16,
               red_mask:    u16,
               green_shift: u16,
               green_mask:  u16,
               blue_shift:  u16,
               blue_mask:   u16,
               alpha_shift: u16,
               alpha_mask:  u16)
            -> Directformat {
        unsafe {
            Directformat {
                base: xcb_render_directformat_t {
                    red_shift:   red_shift,
                    red_mask:    red_mask,
                    green_shift: green_shift,
                    green_mask:  green_mask,
                    blue_shift:  blue_shift,
                    blue_mask:   blue_mask,
                    alpha_shift: alpha_shift,
                    alpha_mask:  alpha_mask,
                }
            }
        }
    }
    pub fn red_shift(&self) -> u16 {
        unsafe {
            self.base.red_shift
        }
    }
    pub fn red_mask(&self) -> u16 {
        unsafe {
            self.base.red_mask
        }
    }
    pub fn green_shift(&self) -> u16 {
        unsafe {
            self.base.green_shift
        }
    }
    pub fn green_mask(&self) -> u16 {
        unsafe {
            self.base.green_mask
        }
    }
    pub fn blue_shift(&self) -> u16 {
        unsafe {
            self.base.blue_shift
        }
    }
    pub fn blue_mask(&self) -> u16 {
        unsafe {
            self.base.blue_mask
        }
    }
    pub fn alpha_shift(&self) -> u16 {
        unsafe {
            self.base.alpha_shift
        }
    }
    pub fn alpha_mask(&self) -> u16 {
        unsafe {
            self.base.alpha_mask
        }
    }
}

pub type DirectformatIterator = xcb_render_directformat_iterator_t;

impl Iterator for DirectformatIterator {
    type Item = Directformat;
    fn next(&mut self) -> std::option::Option<Directformat> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_directformat_iterator_t;
                let data = (*iter).data;
                xcb_render_directformat_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Pictforminfo {
    pub base: xcb_render_pictforminfo_t,
}

impl Pictforminfo {
    #[allow(unused_unsafe)]
    pub fn new(id:       Pictformat,
               type_:    u8,
               depth:    u8,
               direct:   Directformat,
               colormap: xproto::Colormap)
            -> Pictforminfo {
        unsafe {
            Pictforminfo {
                base: xcb_render_pictforminfo_t {
                    id:       id,
                    type_:    type_,
                    depth:    depth,
                    pad0:     [0; 2],
                    direct:   std::mem::transmute(direct),
                    colormap: colormap,
                }
            }
        }
    }
    pub fn id(&self) -> Pictformat {
        unsafe {
            self.base.id
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            self.base.type_
        }
    }
    pub fn depth(&self) -> u8 {
        unsafe {
            self.base.depth
        }
    }
    pub fn direct(&self) -> Directformat {
        unsafe {
            std::mem::transmute(self.base.direct)
        }
    }
    pub fn colormap(&self) -> xproto::Colormap {
        unsafe {
            self.base.colormap
        }
    }
}

pub type PictforminfoIterator = xcb_render_pictforminfo_iterator_t;

impl Iterator for PictforminfoIterator {
    type Item = Pictforminfo;
    fn next(&mut self) -> std::option::Option<Pictforminfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_pictforminfo_iterator_t;
                let data = (*iter).data;
                xcb_render_pictforminfo_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Pictvisual {
    pub base: xcb_render_pictvisual_t,
}

impl Pictvisual {
    #[allow(unused_unsafe)]
    pub fn new(visual: xproto::Visualid,
               format: Pictformat)
            -> Pictvisual {
        unsafe {
            Pictvisual {
                base: xcb_render_pictvisual_t {
                    visual: visual,
                    format: format,
                }
            }
        }
    }
    pub fn visual(&self) -> xproto::Visualid {
        unsafe {
            self.base.visual
        }
    }
    pub fn format(&self) -> Pictformat {
        unsafe {
            self.base.format
        }
    }
}

pub type PictvisualIterator = xcb_render_pictvisual_iterator_t;

impl Iterator for PictvisualIterator {
    type Item = Pictvisual;
    fn next(&mut self) -> std::option::Option<Pictvisual> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_pictvisual_iterator_t;
                let data = (*iter).data;
                xcb_render_pictvisual_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type Pictdepth<'a> = base::StructPtr<'a, xcb_render_pictdepth_t>;

impl<'a> Pictdepth<'a> {
    pub fn depth(&self) -> u8 {
        unsafe {
            (*self.ptr).depth
        }
    }
    pub fn num_visuals(&self) -> u16 {
        unsafe {
            (*self.ptr).num_visuals
        }
    }
    pub fn visuals(&self) -> PictvisualIterator {
        unsafe {
            xcb_render_pictdepth_visuals_iterator(self.ptr)
        }
    }
}

pub type PictdepthIterator<'a> = xcb_render_pictdepth_iterator_t<'a>;

impl<'a> Iterator for PictdepthIterator<'a> {
    type Item = Pictdepth<'a>;
    fn next(&mut self) -> std::option::Option<Pictdepth<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_pictdepth_iterator_t;
                let data = (*iter).data;
                xcb_render_pictdepth_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Pictscreen<'a> = base::StructPtr<'a, xcb_render_pictscreen_t>;

impl<'a> Pictscreen<'a> {
    pub fn num_depths(&self) -> u32 {
        unsafe {
            (*self.ptr).num_depths
        }
    }
    pub fn fallback(&self) -> Pictformat {
        unsafe {
            (*self.ptr).fallback
        }
    }
    pub fn depths(&self) -> PictdepthIterator<'a> {
        unsafe {
            xcb_render_pictscreen_depths_iterator(self.ptr)
        }
    }
}

pub type PictscreenIterator<'a> = xcb_render_pictscreen_iterator_t<'a>;

impl<'a> Iterator for PictscreenIterator<'a> {
    type Item = Pictscreen<'a>;
    fn next(&mut self) -> std::option::Option<Pictscreen<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_pictscreen_iterator_t;
                let data = (*iter).data;
                xcb_render_pictscreen_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Indexvalue {
    pub base: xcb_render_indexvalue_t,
}

impl Indexvalue {
    #[allow(unused_unsafe)]
    pub fn new(pixel: u32,
               red:   u16,
               green: u16,
               blue:  u16,
               alpha: u16)
            -> Indexvalue {
        unsafe {
            Indexvalue {
                base: xcb_render_indexvalue_t {
                    pixel: pixel,
                    red:   red,
                    green: green,
                    blue:  blue,
                    alpha: alpha,
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
    pub fn alpha(&self) -> u16 {
        unsafe {
            self.base.alpha
        }
    }
}

pub type IndexvalueIterator = xcb_render_indexvalue_iterator_t;

impl Iterator for IndexvalueIterator {
    type Item = Indexvalue;
    fn next(&mut self) -> std::option::Option<Indexvalue> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_indexvalue_iterator_t;
                let data = (*iter).data;
                xcb_render_indexvalue_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Color {
    pub base: xcb_render_color_t,
}

impl Color {
    #[allow(unused_unsafe)]
    pub fn new(red:   u16,
               green: u16,
               blue:  u16,
               alpha: u16)
            -> Color {
        unsafe {
            Color {
                base: xcb_render_color_t {
                    red:   red,
                    green: green,
                    blue:  blue,
                    alpha: alpha,
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
    pub fn alpha(&self) -> u16 {
        unsafe {
            self.base.alpha
        }
    }
}

pub type ColorIterator = xcb_render_color_iterator_t;

impl Iterator for ColorIterator {
    type Item = Color;
    fn next(&mut self) -> std::option::Option<Color> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_color_iterator_t;
                let data = (*iter).data;
                xcb_render_color_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Pointfix {
    pub base: xcb_render_pointfix_t,
}

impl Pointfix {
    #[allow(unused_unsafe)]
    pub fn new(x: Fixed,
               y: Fixed)
            -> Pointfix {
        unsafe {
            Pointfix {
                base: xcb_render_pointfix_t {
                    x: x,
                    y: y,
                }
            }
        }
    }
    pub fn x(&self) -> Fixed {
        unsafe {
            self.base.x
        }
    }
    pub fn y(&self) -> Fixed {
        unsafe {
            self.base.y
        }
    }
}

pub type PointfixIterator = xcb_render_pointfix_iterator_t;

impl Iterator for PointfixIterator {
    type Item = Pointfix;
    fn next(&mut self) -> std::option::Option<Pointfix> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_pointfix_iterator_t;
                let data = (*iter).data;
                xcb_render_pointfix_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Linefix {
    pub base: xcb_render_linefix_t,
}

impl Linefix {
    #[allow(unused_unsafe)]
    pub fn new(p1: Pointfix,
               p2: Pointfix)
            -> Linefix {
        unsafe {
            Linefix {
                base: xcb_render_linefix_t {
                    p1: std::mem::transmute(p1),
                    p2: std::mem::transmute(p2),
                }
            }
        }
    }
    pub fn p1(&self) -> Pointfix {
        unsafe {
            std::mem::transmute(self.base.p1)
        }
    }
    pub fn p2(&self) -> Pointfix {
        unsafe {
            std::mem::transmute(self.base.p2)
        }
    }
}

pub type LinefixIterator = xcb_render_linefix_iterator_t;

impl Iterator for LinefixIterator {
    type Item = Linefix;
    fn next(&mut self) -> std::option::Option<Linefix> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_linefix_iterator_t;
                let data = (*iter).data;
                xcb_render_linefix_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Triangle {
    pub base: xcb_render_triangle_t,
}

impl Triangle {
    #[allow(unused_unsafe)]
    pub fn new(p1: Pointfix,
               p2: Pointfix,
               p3: Pointfix)
            -> Triangle {
        unsafe {
            Triangle {
                base: xcb_render_triangle_t {
                    p1: std::mem::transmute(p1),
                    p2: std::mem::transmute(p2),
                    p3: std::mem::transmute(p3),
                }
            }
        }
    }
    pub fn p1(&self) -> Pointfix {
        unsafe {
            std::mem::transmute(self.base.p1)
        }
    }
    pub fn p2(&self) -> Pointfix {
        unsafe {
            std::mem::transmute(self.base.p2)
        }
    }
    pub fn p3(&self) -> Pointfix {
        unsafe {
            std::mem::transmute(self.base.p3)
        }
    }
}

pub type TriangleIterator = xcb_render_triangle_iterator_t;

impl Iterator for TriangleIterator {
    type Item = Triangle;
    fn next(&mut self) -> std::option::Option<Triangle> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_triangle_iterator_t;
                let data = (*iter).data;
                xcb_render_triangle_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Trapezoid {
    pub base: xcb_render_trapezoid_t,
}

impl Trapezoid {
    #[allow(unused_unsafe)]
    pub fn new(top:    Fixed,
               bottom: Fixed,
               left:   Linefix,
               right:  Linefix)
            -> Trapezoid {
        unsafe {
            Trapezoid {
                base: xcb_render_trapezoid_t {
                    top:    top,
                    bottom: bottom,
                    left:   std::mem::transmute(left),
                    right:  std::mem::transmute(right),
                }
            }
        }
    }
    pub fn top(&self) -> Fixed {
        unsafe {
            self.base.top
        }
    }
    pub fn bottom(&self) -> Fixed {
        unsafe {
            self.base.bottom
        }
    }
    pub fn left(&self) -> Linefix {
        unsafe {
            std::mem::transmute(self.base.left)
        }
    }
    pub fn right(&self) -> Linefix {
        unsafe {
            std::mem::transmute(self.base.right)
        }
    }
}

pub type TrapezoidIterator = xcb_render_trapezoid_iterator_t;

impl Iterator for TrapezoidIterator {
    type Item = Trapezoid;
    fn next(&mut self) -> std::option::Option<Trapezoid> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_trapezoid_iterator_t;
                let data = (*iter).data;
                xcb_render_trapezoid_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Glyphinfo {
    pub base: xcb_render_glyphinfo_t,
}

impl Glyphinfo {
    #[allow(unused_unsafe)]
    pub fn new(width:  u16,
               height: u16,
               x:      i16,
               y:      i16,
               x_off:  i16,
               y_off:  i16)
            -> Glyphinfo {
        unsafe {
            Glyphinfo {
                base: xcb_render_glyphinfo_t {
                    width:  width,
                    height: height,
                    x:      x,
                    y:      y,
                    x_off:  x_off,
                    y_off:  y_off,
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
    pub fn x_off(&self) -> i16 {
        unsafe {
            self.base.x_off
        }
    }
    pub fn y_off(&self) -> i16 {
        unsafe {
            self.base.y_off
        }
    }
}

pub type GlyphinfoIterator = xcb_render_glyphinfo_iterator_t;

impl Iterator for GlyphinfoIterator {
    type Item = Glyphinfo;
    fn next(&mut self) -> std::option::Option<Glyphinfo> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_glyphinfo_iterator_t;
                let data = (*iter).data;
                xcb_render_glyphinfo_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const QUERY_VERSION: u8 = 0;

pub type QueryVersionCookie<'a> = base::Cookie<'a, xcb_render_query_version_cookie_t>;

impl<'a> QueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryVersionReply {
                    ptr: xcb_render_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryVersionReply {
                    ptr: xcb_render_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryVersionReply = base::Reply<xcb_render_query_version_reply_t>;

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

pub fn query_version<'a>(c                   : &'a base::Connection,
                         client_major_version: u32,
                         client_minor_version: u32)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_render_query_version(c.get_raw_conn(),
                                              client_major_version as u32,  // 0
                                              client_minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_version_unchecked<'a>(c                   : &'a base::Connection,
                                   client_major_version: u32,
                                   client_minor_version: u32)
        -> QueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_render_query_version_unchecked(c.get_raw_conn(),
                                                        client_major_version as u32,  // 0
                                                        client_minor_version as u32);  // 1
        QueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_PICT_FORMATS: u8 = 1;

pub type QueryPictFormatsCookie<'a> = base::Cookie<'a, xcb_render_query_pict_formats_cookie_t>;

impl<'a> QueryPictFormatsCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryPictFormatsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryPictFormatsReply {
                    ptr: xcb_render_query_pict_formats_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryPictFormatsReply {
                    ptr: xcb_render_query_pict_formats_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryPictFormatsReply = base::Reply<xcb_render_query_pict_formats_reply_t>;

impl QueryPictFormatsReply {
    pub fn num_formats(&self) -> u32 {
        unsafe {
            (*self.ptr).num_formats
        }
    }
    pub fn num_screens(&self) -> u32 {
        unsafe {
            (*self.ptr).num_screens
        }
    }
    pub fn num_depths(&self) -> u32 {
        unsafe {
            (*self.ptr).num_depths
        }
    }
    pub fn num_visuals(&self) -> u32 {
        unsafe {
            (*self.ptr).num_visuals
        }
    }
    pub fn num_subpixel(&self) -> u32 {
        unsafe {
            (*self.ptr).num_subpixel
        }
    }
    pub fn formats(&self) -> PictforminfoIterator {
        unsafe {
            xcb_render_query_pict_formats_formats_iterator(self.ptr)
        }
    }
    pub fn screens(&self) -> PictscreenIterator {
        unsafe {
            xcb_render_query_pict_formats_screens_iterator(self.ptr)
        }
    }
    pub fn subpixels(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_render_query_pict_formats_subpixels_length(field) as usize;
            let data = xcb_render_query_pict_formats_subpixels(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn query_pict_formats<'a>(c: &'a base::Connection)
        -> QueryPictFormatsCookie<'a> {
    unsafe {
        let cookie = xcb_render_query_pict_formats(c.get_raw_conn());
        QueryPictFormatsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_pict_formats_unchecked<'a>(c: &'a base::Connection)
        -> QueryPictFormatsCookie<'a> {
    unsafe {
        let cookie = xcb_render_query_pict_formats_unchecked(c.get_raw_conn());
        QueryPictFormatsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_PICT_INDEX_VALUES: u8 = 2;

pub type QueryPictIndexValuesCookie<'a> = base::Cookie<'a, xcb_render_query_pict_index_values_cookie_t>;

impl<'a> QueryPictIndexValuesCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryPictIndexValuesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryPictIndexValuesReply {
                    ptr: xcb_render_query_pict_index_values_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryPictIndexValuesReply {
                    ptr: xcb_render_query_pict_index_values_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryPictIndexValuesReply = base::Reply<xcb_render_query_pict_index_values_reply_t>;

impl QueryPictIndexValuesReply {
    pub fn num_values(&self) -> u32 {
        unsafe {
            (*self.ptr).num_values
        }
    }
    pub fn values(&self) -> IndexvalueIterator {
        unsafe {
            xcb_render_query_pict_index_values_values_iterator(self.ptr)
        }
    }
}

pub fn query_pict_index_values<'a>(c     : &'a base::Connection,
                                   format: Pictformat)
        -> QueryPictIndexValuesCookie<'a> {
    unsafe {
        let cookie = xcb_render_query_pict_index_values(c.get_raw_conn(),
                                                        format as xcb_render_pictformat_t);  // 0
        QueryPictIndexValuesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_pict_index_values_unchecked<'a>(c     : &'a base::Connection,
                                             format: Pictformat)
        -> QueryPictIndexValuesCookie<'a> {
    unsafe {
        let cookie = xcb_render_query_pict_index_values_unchecked(c.get_raw_conn(),
                                                                  format as xcb_render_pictformat_t);  // 0
        QueryPictIndexValuesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_PICTURE: u8 = 4;

pub fn create_picture<'a>(c         : &'a base::Connection,
                          pid       : Picture,
                          drawable  : xproto::Drawable,
                          format    : Pictformat,
                          value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_render_create_picture(c.get_raw_conn(),
                                               pid as xcb_render_picture_t,  // 0
                                               drawable as xcb_drawable_t,  // 1
                                               format as xcb_render_pictformat_t,  // 2
                                               value_list_mask as u32,  // 3
                                               value_list_ptr as *const u32);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_picture_checked<'a>(c         : &'a base::Connection,
                                  pid       : Picture,
                                  drawable  : xproto::Drawable,
                                  format    : Pictformat,
                                  value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_render_create_picture_checked(c.get_raw_conn(),
                                                       pid as xcb_render_picture_t,  // 0
                                                       drawable as xcb_drawable_t,  // 1
                                                       format as xcb_render_pictformat_t,  // 2
                                                       value_list_mask as u32,  // 3
                                                       value_list_ptr as *const u32);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_PICTURE: u8 = 5;

pub fn change_picture<'a>(c         : &'a base::Connection,
                          picture   : Picture,
                          value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_render_change_picture(c.get_raw_conn(),
                                               picture as xcb_render_picture_t,  // 0
                                               value_list_mask as u32,  // 1
                                               value_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_picture_checked<'a>(c         : &'a base::Connection,
                                  picture   : Picture,
                                  value_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut value_list_copy = value_list.to_vec();
        let (value_list_mask, value_list_vec) = base::pack_bitfield(&mut value_list_copy);
        let value_list_ptr = value_list_vec.as_ptr();
        let cookie = xcb_render_change_picture_checked(c.get_raw_conn(),
                                                       picture as xcb_render_picture_t,  // 0
                                                       value_list_mask as u32,  // 1
                                                       value_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_PICTURE_CLIP_RECTANGLES: u8 = 6;

pub fn set_picture_clip_rectangles<'a>(c            : &'a base::Connection,
                                       picture      : Picture,
                                       clip_x_origin: i16,
                                       clip_y_origin: i16,
                                       rectangles   : &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_render_set_picture_clip_rectangles(c.get_raw_conn(),
                                                            picture as xcb_render_picture_t,  // 0
                                                            clip_x_origin as i16,  // 1
                                                            clip_y_origin as i16,  // 2
                                                            rectangles_len as u32,  // 3
                                                            rectangles_ptr as *const xcb_rectangle_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_picture_clip_rectangles_checked<'a>(c            : &'a base::Connection,
                                               picture      : Picture,
                                               clip_x_origin: i16,
                                               clip_y_origin: i16,
                                               rectangles   : &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rectangles_len = rectangles.len();
        let rectangles_ptr = rectangles.as_ptr();
        let cookie = xcb_render_set_picture_clip_rectangles_checked(c.get_raw_conn(),
                                                                    picture as xcb_render_picture_t,  // 0
                                                                    clip_x_origin as i16,  // 1
                                                                    clip_y_origin as i16,  // 2
                                                                    rectangles_len as u32,  // 3
                                                                    rectangles_ptr as *const xcb_rectangle_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FREE_PICTURE: u8 = 7;

pub fn free_picture<'a>(c      : &'a base::Connection,
                        picture: Picture)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_free_picture(c.get_raw_conn(),
                                             picture as xcb_render_picture_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn free_picture_checked<'a>(c      : &'a base::Connection,
                                picture: Picture)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_free_picture_checked(c.get_raw_conn(),
                                                     picture as xcb_render_picture_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COMPOSITE: u8 = 8;

pub fn composite<'a>(c     : &'a base::Connection,
                     op    : u8,
                     src   : Picture,
                     mask  : Picture,
                     dst   : Picture,
                     src_x : i16,
                     src_y : i16,
                     mask_x: i16,
                     mask_y: i16,
                     dst_x : i16,
                     dst_y : i16,
                     width : u16,
                     height: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_composite(c.get_raw_conn(),
                                          op as u8,  // 0
                                          src as xcb_render_picture_t,  // 1
                                          mask as xcb_render_picture_t,  // 2
                                          dst as xcb_render_picture_t,  // 3
                                          src_x as i16,  // 4
                                          src_y as i16,  // 5
                                          mask_x as i16,  // 6
                                          mask_y as i16,  // 7
                                          dst_x as i16,  // 8
                                          dst_y as i16,  // 9
                                          width as u16,  // 10
                                          height as u16);  // 11
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn composite_checked<'a>(c     : &'a base::Connection,
                             op    : u8,
                             src   : Picture,
                             mask  : Picture,
                             dst   : Picture,
                             src_x : i16,
                             src_y : i16,
                             mask_x: i16,
                             mask_y: i16,
                             dst_x : i16,
                             dst_y : i16,
                             width : u16,
                             height: u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_composite_checked(c.get_raw_conn(),
                                                  op as u8,  // 0
                                                  src as xcb_render_picture_t,  // 1
                                                  mask as xcb_render_picture_t,  // 2
                                                  dst as xcb_render_picture_t,  // 3
                                                  src_x as i16,  // 4
                                                  src_y as i16,  // 5
                                                  mask_x as i16,  // 6
                                                  mask_y as i16,  // 7
                                                  dst_x as i16,  // 8
                                                  dst_y as i16,  // 9
                                                  width as u16,  // 10
                                                  height as u16);  // 11
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const TRAPEZOIDS: u8 = 10;

pub fn trapezoids<'a>(c          : &'a base::Connection,
                      op         : u8,
                      src        : Picture,
                      dst        : Picture,
                      mask_format: Pictformat,
                      src_x      : i16,
                      src_y      : i16,
                      traps      : &[Trapezoid])
        -> base::VoidCookie<'a> {
    unsafe {
        let traps_len = traps.len();
        let traps_ptr = traps.as_ptr();
        let cookie = xcb_render_trapezoids(c.get_raw_conn(),
                                           op as u8,  // 0
                                           src as xcb_render_picture_t,  // 1
                                           dst as xcb_render_picture_t,  // 2
                                           mask_format as xcb_render_pictformat_t,  // 3
                                           src_x as i16,  // 4
                                           src_y as i16,  // 5
                                           traps_len as u32,  // 6
                                           traps_ptr as *const xcb_render_trapezoid_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn trapezoids_checked<'a>(c          : &'a base::Connection,
                              op         : u8,
                              src        : Picture,
                              dst        : Picture,
                              mask_format: Pictformat,
                              src_x      : i16,
                              src_y      : i16,
                              traps      : &[Trapezoid])
        -> base::VoidCookie<'a> {
    unsafe {
        let traps_len = traps.len();
        let traps_ptr = traps.as_ptr();
        let cookie = xcb_render_trapezoids_checked(c.get_raw_conn(),
                                                   op as u8,  // 0
                                                   src as xcb_render_picture_t,  // 1
                                                   dst as xcb_render_picture_t,  // 2
                                                   mask_format as xcb_render_pictformat_t,  // 3
                                                   src_x as i16,  // 4
                                                   src_y as i16,  // 5
                                                   traps_len as u32,  // 6
                                                   traps_ptr as *const xcb_render_trapezoid_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const TRIANGLES: u8 = 11;

pub fn triangles<'a>(c          : &'a base::Connection,
                     op         : u8,
                     src        : Picture,
                     dst        : Picture,
                     mask_format: Pictformat,
                     src_x      : i16,
                     src_y      : i16,
                     triangles  : &[Triangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let triangles_len = triangles.len();
        let triangles_ptr = triangles.as_ptr();
        let cookie = xcb_render_triangles(c.get_raw_conn(),
                                          op as u8,  // 0
                                          src as xcb_render_picture_t,  // 1
                                          dst as xcb_render_picture_t,  // 2
                                          mask_format as xcb_render_pictformat_t,  // 3
                                          src_x as i16,  // 4
                                          src_y as i16,  // 5
                                          triangles_len as u32,  // 6
                                          triangles_ptr as *const xcb_render_triangle_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn triangles_checked<'a>(c          : &'a base::Connection,
                             op         : u8,
                             src        : Picture,
                             dst        : Picture,
                             mask_format: Pictformat,
                             src_x      : i16,
                             src_y      : i16,
                             triangles  : &[Triangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let triangles_len = triangles.len();
        let triangles_ptr = triangles.as_ptr();
        let cookie = xcb_render_triangles_checked(c.get_raw_conn(),
                                                  op as u8,  // 0
                                                  src as xcb_render_picture_t,  // 1
                                                  dst as xcb_render_picture_t,  // 2
                                                  mask_format as xcb_render_pictformat_t,  // 3
                                                  src_x as i16,  // 4
                                                  src_y as i16,  // 5
                                                  triangles_len as u32,  // 6
                                                  triangles_ptr as *const xcb_render_triangle_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const TRI_STRIP: u8 = 12;

pub fn tri_strip<'a>(c          : &'a base::Connection,
                     op         : u8,
                     src        : Picture,
                     dst        : Picture,
                     mask_format: Pictformat,
                     src_x      : i16,
                     src_y      : i16,
                     points     : &[Pointfix])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_render_tri_strip(c.get_raw_conn(),
                                          op as u8,  // 0
                                          src as xcb_render_picture_t,  // 1
                                          dst as xcb_render_picture_t,  // 2
                                          mask_format as xcb_render_pictformat_t,  // 3
                                          src_x as i16,  // 4
                                          src_y as i16,  // 5
                                          points_len as u32,  // 6
                                          points_ptr as *const xcb_render_pointfix_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn tri_strip_checked<'a>(c          : &'a base::Connection,
                             op         : u8,
                             src        : Picture,
                             dst        : Picture,
                             mask_format: Pictformat,
                             src_x      : i16,
                             src_y      : i16,
                             points     : &[Pointfix])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_render_tri_strip_checked(c.get_raw_conn(),
                                                  op as u8,  // 0
                                                  src as xcb_render_picture_t,  // 1
                                                  dst as xcb_render_picture_t,  // 2
                                                  mask_format as xcb_render_pictformat_t,  // 3
                                                  src_x as i16,  // 4
                                                  src_y as i16,  // 5
                                                  points_len as u32,  // 6
                                                  points_ptr as *const xcb_render_pointfix_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const TRI_FAN: u8 = 13;

pub fn tri_fan<'a>(c          : &'a base::Connection,
                   op         : u8,
                   src        : Picture,
                   dst        : Picture,
                   mask_format: Pictformat,
                   src_x      : i16,
                   src_y      : i16,
                   points     : &[Pointfix])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_render_tri_fan(c.get_raw_conn(),
                                        op as u8,  // 0
                                        src as xcb_render_picture_t,  // 1
                                        dst as xcb_render_picture_t,  // 2
                                        mask_format as xcb_render_pictformat_t,  // 3
                                        src_x as i16,  // 4
                                        src_y as i16,  // 5
                                        points_len as u32,  // 6
                                        points_ptr as *const xcb_render_pointfix_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn tri_fan_checked<'a>(c          : &'a base::Connection,
                           op         : u8,
                           src        : Picture,
                           dst        : Picture,
                           mask_format: Pictformat,
                           src_x      : i16,
                           src_y      : i16,
                           points     : &[Pointfix])
        -> base::VoidCookie<'a> {
    unsafe {
        let points_len = points.len();
        let points_ptr = points.as_ptr();
        let cookie = xcb_render_tri_fan_checked(c.get_raw_conn(),
                                                op as u8,  // 0
                                                src as xcb_render_picture_t,  // 1
                                                dst as xcb_render_picture_t,  // 2
                                                mask_format as xcb_render_pictformat_t,  // 3
                                                src_x as i16,  // 4
                                                src_y as i16,  // 5
                                                points_len as u32,  // 6
                                                points_ptr as *const xcb_render_pointfix_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_GLYPH_SET: u8 = 17;

pub fn create_glyph_set<'a>(c     : &'a base::Connection,
                            gsid  : Glyphset,
                            format: Pictformat)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_create_glyph_set(c.get_raw_conn(),
                                                 gsid as xcb_render_glyphset_t,  // 0
                                                 format as xcb_render_pictformat_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_glyph_set_checked<'a>(c     : &'a base::Connection,
                                    gsid  : Glyphset,
                                    format: Pictformat)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_create_glyph_set_checked(c.get_raw_conn(),
                                                         gsid as xcb_render_glyphset_t,  // 0
                                                         format as xcb_render_pictformat_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const REFERENCE_GLYPH_SET: u8 = 18;

pub fn reference_glyph_set<'a>(c       : &'a base::Connection,
                               gsid    : Glyphset,
                               existing: Glyphset)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_reference_glyph_set(c.get_raw_conn(),
                                                    gsid as xcb_render_glyphset_t,  // 0
                                                    existing as xcb_render_glyphset_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn reference_glyph_set_checked<'a>(c       : &'a base::Connection,
                                       gsid    : Glyphset,
                                       existing: Glyphset)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_reference_glyph_set_checked(c.get_raw_conn(),
                                                            gsid as xcb_render_glyphset_t,  // 0
                                                            existing as xcb_render_glyphset_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FREE_GLYPH_SET: u8 = 19;

pub fn free_glyph_set<'a>(c       : &'a base::Connection,
                          glyphset: Glyphset)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_free_glyph_set(c.get_raw_conn(),
                                               glyphset as xcb_render_glyphset_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn free_glyph_set_checked<'a>(c       : &'a base::Connection,
                                  glyphset: Glyphset)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_free_glyph_set_checked(c.get_raw_conn(),
                                                       glyphset as xcb_render_glyphset_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const ADD_GLYPHS: u8 = 20;

pub fn add_glyphs<'a>(c       : &'a base::Connection,
                      glyphset: Glyphset,
                      glyphids: &[u32],
                      glyphs  : &[Glyphinfo],
                      data    : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphids_len = glyphids.len();
        let glyphids_ptr = glyphids.as_ptr();
        let glyphs_ptr = glyphs.as_ptr();
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_render_add_glyphs(c.get_raw_conn(),
                                           glyphset as xcb_render_glyphset_t,  // 0
                                           glyphids_len as u32,  // 1
                                           glyphids_ptr as *const u32,  // 2
                                           glyphs_ptr as *const xcb_render_glyphinfo_t,  // 3
                                           data_len as u32,  // 4
                                           data_ptr as *const u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn add_glyphs_checked<'a>(c       : &'a base::Connection,
                              glyphset: Glyphset,
                              glyphids: &[u32],
                              glyphs  : &[Glyphinfo],
                              data    : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphids_len = glyphids.len();
        let glyphids_ptr = glyphids.as_ptr();
        let glyphs_ptr = glyphs.as_ptr();
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_render_add_glyphs_checked(c.get_raw_conn(),
                                                   glyphset as xcb_render_glyphset_t,  // 0
                                                   glyphids_len as u32,  // 1
                                                   glyphids_ptr as *const u32,  // 2
                                                   glyphs_ptr as *const xcb_render_glyphinfo_t,  // 3
                                                   data_len as u32,  // 4
                                                   data_ptr as *const u8);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FREE_GLYPHS: u8 = 22;

pub fn free_glyphs<'a>(c       : &'a base::Connection,
                       glyphset: Glyphset,
                       glyphs  : &[Glyph])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphs_len = glyphs.len();
        let glyphs_ptr = glyphs.as_ptr();
        let cookie = xcb_render_free_glyphs(c.get_raw_conn(),
                                            glyphset as xcb_render_glyphset_t,  // 0
                                            glyphs_len as u32,  // 1
                                            glyphs_ptr as *const xcb_render_glyph_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn free_glyphs_checked<'a>(c       : &'a base::Connection,
                               glyphset: Glyphset,
                               glyphs  : &[Glyph])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphs_len = glyphs.len();
        let glyphs_ptr = glyphs.as_ptr();
        let cookie = xcb_render_free_glyphs_checked(c.get_raw_conn(),
                                                    glyphset as xcb_render_glyphset_t,  // 0
                                                    glyphs_len as u32,  // 1
                                                    glyphs_ptr as *const xcb_render_glyph_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COMPOSITE_GLYPHS_8: u8 = 23;

pub fn composite_glyphs_8<'a>(c          : &'a base::Connection,
                              op         : u8,
                              src        : Picture,
                              dst        : Picture,
                              mask_format: Pictformat,
                              glyphset   : Glyphset,
                              src_x      : i16,
                              src_y      : i16,
                              glyphcmds  : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphcmds_len = glyphcmds.len();
        let glyphcmds_ptr = glyphcmds.as_ptr();
        let cookie = xcb_render_composite_glyphs_8(c.get_raw_conn(),
                                                   op as u8,  // 0
                                                   src as xcb_render_picture_t,  // 1
                                                   dst as xcb_render_picture_t,  // 2
                                                   mask_format as xcb_render_pictformat_t,  // 3
                                                   glyphset as xcb_render_glyphset_t,  // 4
                                                   src_x as i16,  // 5
                                                   src_y as i16,  // 6
                                                   glyphcmds_len as u32,  // 7
                                                   glyphcmds_ptr as *const u8);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn composite_glyphs_8_checked<'a>(c          : &'a base::Connection,
                                      op         : u8,
                                      src        : Picture,
                                      dst        : Picture,
                                      mask_format: Pictformat,
                                      glyphset   : Glyphset,
                                      src_x      : i16,
                                      src_y      : i16,
                                      glyphcmds  : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphcmds_len = glyphcmds.len();
        let glyphcmds_ptr = glyphcmds.as_ptr();
        let cookie = xcb_render_composite_glyphs_8_checked(c.get_raw_conn(),
                                                           op as u8,  // 0
                                                           src as xcb_render_picture_t,  // 1
                                                           dst as xcb_render_picture_t,  // 2
                                                           mask_format as xcb_render_pictformat_t,  // 3
                                                           glyphset as xcb_render_glyphset_t,  // 4
                                                           src_x as i16,  // 5
                                                           src_y as i16,  // 6
                                                           glyphcmds_len as u32,  // 7
                                                           glyphcmds_ptr as *const u8);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COMPOSITE_GLYPHS_16: u8 = 24;

pub fn composite_glyphs_16<'a>(c          : &'a base::Connection,
                               op         : u8,
                               src        : Picture,
                               dst        : Picture,
                               mask_format: Pictformat,
                               glyphset   : Glyphset,
                               src_x      : i16,
                               src_y      : i16,
                               glyphcmds  : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphcmds_len = glyphcmds.len();
        let glyphcmds_ptr = glyphcmds.as_ptr();
        let cookie = xcb_render_composite_glyphs_16(c.get_raw_conn(),
                                                    op as u8,  // 0
                                                    src as xcb_render_picture_t,  // 1
                                                    dst as xcb_render_picture_t,  // 2
                                                    mask_format as xcb_render_pictformat_t,  // 3
                                                    glyphset as xcb_render_glyphset_t,  // 4
                                                    src_x as i16,  // 5
                                                    src_y as i16,  // 6
                                                    glyphcmds_len as u32,  // 7
                                                    glyphcmds_ptr as *const u8);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn composite_glyphs_16_checked<'a>(c          : &'a base::Connection,
                                       op         : u8,
                                       src        : Picture,
                                       dst        : Picture,
                                       mask_format: Pictformat,
                                       glyphset   : Glyphset,
                                       src_x      : i16,
                                       src_y      : i16,
                                       glyphcmds  : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphcmds_len = glyphcmds.len();
        let glyphcmds_ptr = glyphcmds.as_ptr();
        let cookie = xcb_render_composite_glyphs_16_checked(c.get_raw_conn(),
                                                            op as u8,  // 0
                                                            src as xcb_render_picture_t,  // 1
                                                            dst as xcb_render_picture_t,  // 2
                                                            mask_format as xcb_render_pictformat_t,  // 3
                                                            glyphset as xcb_render_glyphset_t,  // 4
                                                            src_x as i16,  // 5
                                                            src_y as i16,  // 6
                                                            glyphcmds_len as u32,  // 7
                                                            glyphcmds_ptr as *const u8);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COMPOSITE_GLYPHS_32: u8 = 25;

pub fn composite_glyphs_32<'a>(c          : &'a base::Connection,
                               op         : u8,
                               src        : Picture,
                               dst        : Picture,
                               mask_format: Pictformat,
                               glyphset   : Glyphset,
                               src_x      : i16,
                               src_y      : i16,
                               glyphcmds  : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphcmds_len = glyphcmds.len();
        let glyphcmds_ptr = glyphcmds.as_ptr();
        let cookie = xcb_render_composite_glyphs_32(c.get_raw_conn(),
                                                    op as u8,  // 0
                                                    src as xcb_render_picture_t,  // 1
                                                    dst as xcb_render_picture_t,  // 2
                                                    mask_format as xcb_render_pictformat_t,  // 3
                                                    glyphset as xcb_render_glyphset_t,  // 4
                                                    src_x as i16,  // 5
                                                    src_y as i16,  // 6
                                                    glyphcmds_len as u32,  // 7
                                                    glyphcmds_ptr as *const u8);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn composite_glyphs_32_checked<'a>(c          : &'a base::Connection,
                                       op         : u8,
                                       src        : Picture,
                                       dst        : Picture,
                                       mask_format: Pictformat,
                                       glyphset   : Glyphset,
                                       src_x      : i16,
                                       src_y      : i16,
                                       glyphcmds  : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let glyphcmds_len = glyphcmds.len();
        let glyphcmds_ptr = glyphcmds.as_ptr();
        let cookie = xcb_render_composite_glyphs_32_checked(c.get_raw_conn(),
                                                            op as u8,  // 0
                                                            src as xcb_render_picture_t,  // 1
                                                            dst as xcb_render_picture_t,  // 2
                                                            mask_format as xcb_render_pictformat_t,  // 3
                                                            glyphset as xcb_render_glyphset_t,  // 4
                                                            src_x as i16,  // 5
                                                            src_y as i16,  // 6
                                                            glyphcmds_len as u32,  // 7
                                                            glyphcmds_ptr as *const u8);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const FILL_RECTANGLES: u8 = 26;

pub fn fill_rectangles<'a>(c    : &'a base::Connection,
                           op   : u8,
                           dst  : Picture,
                           color: Color,
                           rects: &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rects_len = rects.len();
        let rects_ptr = rects.as_ptr();
        let cookie = xcb_render_fill_rectangles(c.get_raw_conn(),
                                                op as u8,  // 0
                                                dst as xcb_render_picture_t,  // 1
                                                color.base,  // 2
                                                rects_len as u32,  // 3
                                                rects_ptr as *const xcb_rectangle_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn fill_rectangles_checked<'a>(c    : &'a base::Connection,
                                   op   : u8,
                                   dst  : Picture,
                                   color: Color,
                                   rects: &[xproto::Rectangle])
        -> base::VoidCookie<'a> {
    unsafe {
        let rects_len = rects.len();
        let rects_ptr = rects.as_ptr();
        let cookie = xcb_render_fill_rectangles_checked(c.get_raw_conn(),
                                                        op as u8,  // 0
                                                        dst as xcb_render_picture_t,  // 1
                                                        color.base,  // 2
                                                        rects_len as u32,  // 3
                                                        rects_ptr as *const xcb_rectangle_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_CURSOR: u8 = 27;

pub fn create_cursor<'a>(c     : &'a base::Connection,
                         cid   : xproto::Cursor,
                         source: Picture,
                         x     : u16,
                         y     : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_create_cursor(c.get_raw_conn(),
                                              cid as xcb_cursor_t,  // 0
                                              source as xcb_render_picture_t,  // 1
                                              x as u16,  // 2
                                              y as u16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_cursor_checked<'a>(c     : &'a base::Connection,
                                 cid   : xproto::Cursor,
                                 source: Picture,
                                 x     : u16,
                                 y     : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_create_cursor_checked(c.get_raw_conn(),
                                                      cid as xcb_cursor_t,  // 0
                                                      source as xcb_render_picture_t,  // 1
                                                      x as u16,  // 2
                                                      y as u16);  // 3
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct Transform {
    pub base: xcb_render_transform_t,
}

impl Transform {
    #[allow(unused_unsafe)]
    pub fn new(matrix11: Fixed,
               matrix12: Fixed,
               matrix13: Fixed,
               matrix21: Fixed,
               matrix22: Fixed,
               matrix23: Fixed,
               matrix31: Fixed,
               matrix32: Fixed,
               matrix33: Fixed)
            -> Transform {
        unsafe {
            Transform {
                base: xcb_render_transform_t {
                    matrix11: matrix11,
                    matrix12: matrix12,
                    matrix13: matrix13,
                    matrix21: matrix21,
                    matrix22: matrix22,
                    matrix23: matrix23,
                    matrix31: matrix31,
                    matrix32: matrix32,
                    matrix33: matrix33,
                }
            }
        }
    }
    pub fn matrix11(&self) -> Fixed {
        unsafe {
            self.base.matrix11
        }
    }
    pub fn matrix12(&self) -> Fixed {
        unsafe {
            self.base.matrix12
        }
    }
    pub fn matrix13(&self) -> Fixed {
        unsafe {
            self.base.matrix13
        }
    }
    pub fn matrix21(&self) -> Fixed {
        unsafe {
            self.base.matrix21
        }
    }
    pub fn matrix22(&self) -> Fixed {
        unsafe {
            self.base.matrix22
        }
    }
    pub fn matrix23(&self) -> Fixed {
        unsafe {
            self.base.matrix23
        }
    }
    pub fn matrix31(&self) -> Fixed {
        unsafe {
            self.base.matrix31
        }
    }
    pub fn matrix32(&self) -> Fixed {
        unsafe {
            self.base.matrix32
        }
    }
    pub fn matrix33(&self) -> Fixed {
        unsafe {
            self.base.matrix33
        }
    }
}

pub type TransformIterator = xcb_render_transform_iterator_t;

impl Iterator for TransformIterator {
    type Item = Transform;
    fn next(&mut self) -> std::option::Option<Transform> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_transform_iterator_t;
                let data = (*iter).data;
                xcb_render_transform_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const SET_PICTURE_TRANSFORM: u8 = 28;

pub fn set_picture_transform<'a>(c        : &'a base::Connection,
                                 picture  : Picture,
                                 transform: Transform)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_set_picture_transform(c.get_raw_conn(),
                                                      picture as xcb_render_picture_t,  // 0
                                                      transform.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_picture_transform_checked<'a>(c        : &'a base::Connection,
                                         picture  : Picture,
                                         transform: Transform)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_set_picture_transform_checked(c.get_raw_conn(),
                                                              picture as xcb_render_picture_t,  // 0
                                                              transform.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_FILTERS: u8 = 29;

pub type QueryFiltersCookie<'a> = base::Cookie<'a, xcb_render_query_filters_cookie_t>;

impl<'a> QueryFiltersCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryFiltersReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryFiltersReply {
                    ptr: xcb_render_query_filters_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryFiltersReply {
                    ptr: xcb_render_query_filters_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryFiltersReply = base::Reply<xcb_render_query_filters_reply_t>;

impl QueryFiltersReply {
    pub fn num_aliases(&self) -> u32 {
        unsafe {
            (*self.ptr).num_aliases
        }
    }
    pub fn num_filters(&self) -> u32 {
        unsafe {
            (*self.ptr).num_filters
        }
    }
    pub fn aliases(&self) -> &[u16] {
        unsafe {
            let field = self.ptr;
            let len = xcb_render_query_filters_aliases_length(field) as usize;
            let data = xcb_render_query_filters_aliases(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn filters(&self) -> xproto::StrIterator {
        unsafe {
            xcb_render_query_filters_filters_iterator(self.ptr)
        }
    }
}

pub fn query_filters<'a>(c       : &'a base::Connection,
                         drawable: xproto::Drawable)
        -> QueryFiltersCookie<'a> {
    unsafe {
        let cookie = xcb_render_query_filters(c.get_raw_conn(),
                                              drawable as xcb_drawable_t);  // 0
        QueryFiltersCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_filters_unchecked<'a>(c       : &'a base::Connection,
                                   drawable: xproto::Drawable)
        -> QueryFiltersCookie<'a> {
    unsafe {
        let cookie = xcb_render_query_filters_unchecked(c.get_raw_conn(),
                                                        drawable as xcb_drawable_t);  // 0
        QueryFiltersCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_PICTURE_FILTER: u8 = 30;

pub fn set_picture_filter<'a>(c      : &'a base::Connection,
                              picture: Picture,
                              filter : &str,
                              values : &[Fixed])
        -> base::VoidCookie<'a> {
    unsafe {
        let filter = filter.as_bytes();
        let filter_len = filter.len();
        let filter_ptr = filter.as_ptr();
        let values_len = values.len();
        let values_ptr = values.as_ptr();
        let cookie = xcb_render_set_picture_filter(c.get_raw_conn(),
                                                   picture as xcb_render_picture_t,  // 0
                                                   filter_len as u16,  // 1
                                                   filter_ptr as *const c_char,  // 2
                                                   values_len as u32,  // 3
                                                   values_ptr as *const xcb_render_fixed_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_picture_filter_checked<'a>(c      : &'a base::Connection,
                                      picture: Picture,
                                      filter : &str,
                                      values : &[Fixed])
        -> base::VoidCookie<'a> {
    unsafe {
        let filter = filter.as_bytes();
        let filter_len = filter.len();
        let filter_ptr = filter.as_ptr();
        let values_len = values.len();
        let values_ptr = values.as_ptr();
        let cookie = xcb_render_set_picture_filter_checked(c.get_raw_conn(),
                                                           picture as xcb_render_picture_t,  // 0
                                                           filter_len as u16,  // 1
                                                           filter_ptr as *const c_char,  // 2
                                                           values_len as u32,  // 3
                                                           values_ptr as *const xcb_render_fixed_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct Animcursorelt {
    pub base: xcb_render_animcursorelt_t,
}

impl Animcursorelt {
    #[allow(unused_unsafe)]
    pub fn new(cursor: xproto::Cursor,
               delay:  u32)
            -> Animcursorelt {
        unsafe {
            Animcursorelt {
                base: xcb_render_animcursorelt_t {
                    cursor: cursor,
                    delay:  delay,
                }
            }
        }
    }
    pub fn cursor(&self) -> xproto::Cursor {
        unsafe {
            self.base.cursor
        }
    }
    pub fn delay(&self) -> u32 {
        unsafe {
            self.base.delay
        }
    }
}

pub type AnimcursoreltIterator = xcb_render_animcursorelt_iterator_t;

impl Iterator for AnimcursoreltIterator {
    type Item = Animcursorelt;
    fn next(&mut self) -> std::option::Option<Animcursorelt> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_animcursorelt_iterator_t;
                let data = (*iter).data;
                xcb_render_animcursorelt_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const CREATE_ANIM_CURSOR: u8 = 31;

pub fn create_anim_cursor<'a>(c      : &'a base::Connection,
                              cid    : xproto::Cursor,
                              cursors: &[Animcursorelt])
        -> base::VoidCookie<'a> {
    unsafe {
        let cursors_len = cursors.len();
        let cursors_ptr = cursors.as_ptr();
        let cookie = xcb_render_create_anim_cursor(c.get_raw_conn(),
                                                   cid as xcb_cursor_t,  // 0
                                                   cursors_len as u32,  // 1
                                                   cursors_ptr as *const xcb_render_animcursorelt_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_anim_cursor_checked<'a>(c      : &'a base::Connection,
                                      cid    : xproto::Cursor,
                                      cursors: &[Animcursorelt])
        -> base::VoidCookie<'a> {
    unsafe {
        let cursors_len = cursors.len();
        let cursors_ptr = cursors.as_ptr();
        let cookie = xcb_render_create_anim_cursor_checked(c.get_raw_conn(),
                                                           cid as xcb_cursor_t,  // 0
                                                           cursors_len as u32,  // 1
                                                           cursors_ptr as *const xcb_render_animcursorelt_t);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

#[derive(Copy, Clone)]
pub struct Spanfix {
    pub base: xcb_render_spanfix_t,
}

impl Spanfix {
    #[allow(unused_unsafe)]
    pub fn new(l: Fixed,
               r: Fixed,
               y: Fixed)
            -> Spanfix {
        unsafe {
            Spanfix {
                base: xcb_render_spanfix_t {
                    l: l,
                    r: r,
                    y: y,
                }
            }
        }
    }
    pub fn l(&self) -> Fixed {
        unsafe {
            self.base.l
        }
    }
    pub fn r(&self) -> Fixed {
        unsafe {
            self.base.r
        }
    }
    pub fn y(&self) -> Fixed {
        unsafe {
            self.base.y
        }
    }
}

pub type SpanfixIterator = xcb_render_spanfix_iterator_t;

impl Iterator for SpanfixIterator {
    type Item = Spanfix;
    fn next(&mut self) -> std::option::Option<Spanfix> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_spanfix_iterator_t;
                let data = (*iter).data;
                xcb_render_spanfix_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Trap {
    pub base: xcb_render_trap_t,
}

impl Trap {
    #[allow(unused_unsafe)]
    pub fn new(top: Spanfix,
               bot: Spanfix)
            -> Trap {
        unsafe {
            Trap {
                base: xcb_render_trap_t {
                    top: std::mem::transmute(top),
                    bot: std::mem::transmute(bot),
                }
            }
        }
    }
    pub fn top(&self) -> Spanfix {
        unsafe {
            std::mem::transmute(self.base.top)
        }
    }
    pub fn bot(&self) -> Spanfix {
        unsafe {
            std::mem::transmute(self.base.bot)
        }
    }
}

pub type TrapIterator = xcb_render_trap_iterator_t;

impl Iterator for TrapIterator {
    type Item = Trap;
    fn next(&mut self) -> std::option::Option<Trap> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_render_trap_iterator_t;
                let data = (*iter).data;
                xcb_render_trap_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const ADD_TRAPS: u8 = 32;

pub fn add_traps<'a>(c      : &'a base::Connection,
                     picture: Picture,
                     x_off  : i16,
                     y_off  : i16,
                     traps  : &[Trap])
        -> base::VoidCookie<'a> {
    unsafe {
        let traps_len = traps.len();
        let traps_ptr = traps.as_ptr();
        let cookie = xcb_render_add_traps(c.get_raw_conn(),
                                          picture as xcb_render_picture_t,  // 0
                                          x_off as i16,  // 1
                                          y_off as i16,  // 2
                                          traps_len as u32,  // 3
                                          traps_ptr as *const xcb_render_trap_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn add_traps_checked<'a>(c      : &'a base::Connection,
                             picture: Picture,
                             x_off  : i16,
                             y_off  : i16,
                             traps  : &[Trap])
        -> base::VoidCookie<'a> {
    unsafe {
        let traps_len = traps.len();
        let traps_ptr = traps.as_ptr();
        let cookie = xcb_render_add_traps_checked(c.get_raw_conn(),
                                                  picture as xcb_render_picture_t,  // 0
                                                  x_off as i16,  // 1
                                                  y_off as i16,  // 2
                                                  traps_len as u32,  // 3
                                                  traps_ptr as *const xcb_render_trap_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_SOLID_FILL: u8 = 33;

pub fn create_solid_fill<'a>(c      : &'a base::Connection,
                             picture: Picture,
                             color  : Color)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_create_solid_fill(c.get_raw_conn(),
                                                  picture as xcb_render_picture_t,  // 0
                                                  color.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_solid_fill_checked<'a>(c      : &'a base::Connection,
                                     picture: Picture,
                                     color  : Color)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_render_create_solid_fill_checked(c.get_raw_conn(),
                                                          picture as xcb_render_picture_t,  // 0
                                                          color.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_LINEAR_GRADIENT: u8 = 34;

pub fn create_linear_gradient<'a>(c      : &'a base::Connection,
                                  picture: Picture,
                                  p1     : Pointfix,
                                  p2     : Pointfix,
                                  stops  : &[Fixed],
                                  colors : &[Color])
        -> base::VoidCookie<'a> {
    unsafe {
        let stops_len = stops.len();
        let stops_ptr = stops.as_ptr();
        let colors_ptr = colors.as_ptr();
        let cookie = xcb_render_create_linear_gradient(c.get_raw_conn(),
                                                       picture as xcb_render_picture_t,  // 0
                                                       p1.base,  // 1
                                                       p2.base,  // 2
                                                       stops_len as u32,  // 3
                                                       stops_ptr as *const xcb_render_fixed_t,  // 4
                                                       colors_ptr as *const xcb_render_color_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_linear_gradient_checked<'a>(c      : &'a base::Connection,
                                          picture: Picture,
                                          p1     : Pointfix,
                                          p2     : Pointfix,
                                          stops  : &[Fixed],
                                          colors : &[Color])
        -> base::VoidCookie<'a> {
    unsafe {
        let stops_len = stops.len();
        let stops_ptr = stops.as_ptr();
        let colors_ptr = colors.as_ptr();
        let cookie = xcb_render_create_linear_gradient_checked(c.get_raw_conn(),
                                                               picture as xcb_render_picture_t,  // 0
                                                               p1.base,  // 1
                                                               p2.base,  // 2
                                                               stops_len as u32,  // 3
                                                               stops_ptr as *const xcb_render_fixed_t,  // 4
                                                               colors_ptr as *const xcb_render_color_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_RADIAL_GRADIENT: u8 = 35;

pub fn create_radial_gradient<'a>(c           : &'a base::Connection,
                                  picture     : Picture,
                                  inner       : Pointfix,
                                  outer       : Pointfix,
                                  inner_radius: Fixed,
                                  outer_radius: Fixed,
                                  stops       : &[Fixed],
                                  colors      : &[Color])
        -> base::VoidCookie<'a> {
    unsafe {
        let stops_len = stops.len();
        let stops_ptr = stops.as_ptr();
        let colors_ptr = colors.as_ptr();
        let cookie = xcb_render_create_radial_gradient(c.get_raw_conn(),
                                                       picture as xcb_render_picture_t,  // 0
                                                       inner.base,  // 1
                                                       outer.base,  // 2
                                                       inner_radius as xcb_render_fixed_t,  // 3
                                                       outer_radius as xcb_render_fixed_t,  // 4
                                                       stops_len as u32,  // 5
                                                       stops_ptr as *const xcb_render_fixed_t,  // 6
                                                       colors_ptr as *const xcb_render_color_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_radial_gradient_checked<'a>(c           : &'a base::Connection,
                                          picture     : Picture,
                                          inner       : Pointfix,
                                          outer       : Pointfix,
                                          inner_radius: Fixed,
                                          outer_radius: Fixed,
                                          stops       : &[Fixed],
                                          colors      : &[Color])
        -> base::VoidCookie<'a> {
    unsafe {
        let stops_len = stops.len();
        let stops_ptr = stops.as_ptr();
        let colors_ptr = colors.as_ptr();
        let cookie = xcb_render_create_radial_gradient_checked(c.get_raw_conn(),
                                                               picture as xcb_render_picture_t,  // 0
                                                               inner.base,  // 1
                                                               outer.base,  // 2
                                                               inner_radius as xcb_render_fixed_t,  // 3
                                                               outer_radius as xcb_render_fixed_t,  // 4
                                                               stops_len as u32,  // 5
                                                               stops_ptr as *const xcb_render_fixed_t,  // 6
                                                               colors_ptr as *const xcb_render_color_t);  // 7
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_CONICAL_GRADIENT: u8 = 36;

pub fn create_conical_gradient<'a>(c      : &'a base::Connection,
                                   picture: Picture,
                                   center : Pointfix,
                                   angle  : Fixed,
                                   stops  : &[Fixed],
                                   colors : &[Color])
        -> base::VoidCookie<'a> {
    unsafe {
        let stops_len = stops.len();
        let stops_ptr = stops.as_ptr();
        let colors_ptr = colors.as_ptr();
        let cookie = xcb_render_create_conical_gradient(c.get_raw_conn(),
                                                        picture as xcb_render_picture_t,  // 0
                                                        center.base,  // 1
                                                        angle as xcb_render_fixed_t,  // 2
                                                        stops_len as u32,  // 3
                                                        stops_ptr as *const xcb_render_fixed_t,  // 4
                                                        colors_ptr as *const xcb_render_color_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_conical_gradient_checked<'a>(c      : &'a base::Connection,
                                           picture: Picture,
                                           center : Pointfix,
                                           angle  : Fixed,
                                           stops  : &[Fixed],
                                           colors : &[Color])
        -> base::VoidCookie<'a> {
    unsafe {
        let stops_len = stops.len();
        let stops_ptr = stops.as_ptr();
        let colors_ptr = colors.as_ptr();
        let cookie = xcb_render_create_conical_gradient_checked(c.get_raw_conn(),
                                                                picture as xcb_render_picture_t,  // 0
                                                                center.base,  // 1
                                                                angle as xcb_render_fixed_t,  // 2
                                                                stops_len as u32,  // 3
                                                                stops_ptr as *const xcb_render_fixed_t,  // 4
                                                                colors_ptr as *const xcb_render_color_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}
