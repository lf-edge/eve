// Generated automatically from xv.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use shm;
use ffi::base::*;
use ffi::xv::*;
use ffi::xproto::*;
use ffi::shm::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_xv_id
    }
}

pub const MAJOR_VERSION: u32 = 2;
pub const MINOR_VERSION: u32 = 2;

pub type Port = xcb_xv_port_t;

pub type Encoding = xcb_xv_encoding_t;

pub type Type = u32;
pub const TYPE_INPUT_MASK : Type = 0x01;
pub const TYPE_OUTPUT_MASK: Type = 0x02;
pub const TYPE_VIDEO_MASK : Type = 0x04;
pub const TYPE_STILL_MASK : Type = 0x08;
pub const TYPE_IMAGE_MASK : Type = 0x10;

pub type ImageFormatInfoType = u32;
pub const IMAGE_FORMAT_INFO_TYPE_RGB: ImageFormatInfoType = 0x00;
pub const IMAGE_FORMAT_INFO_TYPE_YUV: ImageFormatInfoType = 0x01;

pub type ImageFormatInfoFormat = u32;
pub const IMAGE_FORMAT_INFO_FORMAT_PACKED: ImageFormatInfoFormat = 0x00;
pub const IMAGE_FORMAT_INFO_FORMAT_PLANAR: ImageFormatInfoFormat = 0x01;

pub type AttributeFlag = u32;
pub const ATTRIBUTE_FLAG_GETTABLE: AttributeFlag = 0x01;
pub const ATTRIBUTE_FLAG_SETTABLE: AttributeFlag = 0x02;

pub type VideoNotifyReason = u32;
pub const VIDEO_NOTIFY_REASON_STARTED   : VideoNotifyReason = 0x00;
pub const VIDEO_NOTIFY_REASON_STOPPED   : VideoNotifyReason = 0x01;
pub const VIDEO_NOTIFY_REASON_BUSY      : VideoNotifyReason = 0x02;
pub const VIDEO_NOTIFY_REASON_PREEMPTED : VideoNotifyReason = 0x03;
pub const VIDEO_NOTIFY_REASON_HARD_ERROR: VideoNotifyReason = 0x04;

pub type ScanlineOrder = u32;
pub const SCANLINE_ORDER_TOP_TO_BOTTOM: ScanlineOrder = 0x00;
pub const SCANLINE_ORDER_BOTTOM_TO_TOP: ScanlineOrder = 0x01;

pub type GrabPortStatus = u32;
pub const GRAB_PORT_STATUS_SUCCESS        : GrabPortStatus = 0x00;
pub const GRAB_PORT_STATUS_BAD_EXTENSION  : GrabPortStatus = 0x01;
pub const GRAB_PORT_STATUS_ALREADY_GRABBED: GrabPortStatus = 0x02;
pub const GRAB_PORT_STATUS_INVALID_TIME   : GrabPortStatus = 0x03;
pub const GRAB_PORT_STATUS_BAD_REPLY      : GrabPortStatus = 0x04;
pub const GRAB_PORT_STATUS_BAD_ALLOC      : GrabPortStatus = 0x05;

pub struct BadPortError {
    pub base: base::Error<xcb_xv_bad_port_error_t>
}

pub struct BadEncodingError {
    pub base: base::Error<xcb_xv_bad_encoding_error_t>
}

pub struct BadControlError {
    pub base: base::Error<xcb_xv_bad_control_error_t>
}



#[derive(Copy, Clone)]
pub struct Rational {
    pub base: xcb_xv_rational_t,
}

impl Rational {
    #[allow(unused_unsafe)]
    pub fn new(numerator:   i32,
               denominator: i32)
            -> Rational {
        unsafe {
            Rational {
                base: xcb_xv_rational_t {
                    numerator:   numerator,
                    denominator: denominator,
                }
            }
        }
    }
    pub fn numerator(&self) -> i32 {
        unsafe {
            self.base.numerator
        }
    }
    pub fn denominator(&self) -> i32 {
        unsafe {
            self.base.denominator
        }
    }
}

pub type RationalIterator = xcb_xv_rational_iterator_t;

impl Iterator for RationalIterator {
    type Item = Rational;
    fn next(&mut self) -> std::option::Option<Rational> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xv_rational_iterator_t;
                let data = (*iter).data;
                xcb_xv_rational_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Format {
    pub base: xcb_xv_format_t,
}

impl Format {
    #[allow(unused_unsafe)]
    pub fn new(visual: xproto::Visualid,
               depth:  u8)
            -> Format {
        unsafe {
            Format {
                base: xcb_xv_format_t {
                    visual: visual,
                    depth:  depth,
                    pad0:   [0; 3],
                }
            }
        }
    }
    pub fn visual(&self) -> xproto::Visualid {
        unsafe {
            self.base.visual
        }
    }
    pub fn depth(&self) -> u8 {
        unsafe {
            self.base.depth
        }
    }
}

pub type FormatIterator = xcb_xv_format_iterator_t;

impl Iterator for FormatIterator {
    type Item = Format;
    fn next(&mut self) -> std::option::Option<Format> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xv_format_iterator_t;
                let data = (*iter).data;
                xcb_xv_format_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type AdaptorInfo<'a> = base::StructPtr<'a, xcb_xv_adaptor_info_t>;

impl<'a> AdaptorInfo<'a> {
    pub fn base_id(&self) -> Port {
        unsafe {
            (*self.ptr).base_id
        }
    }
    pub fn name_size(&self) -> u16 {
        unsafe {
            (*self.ptr).name_size
        }
    }
    pub fn num_ports(&self) -> u16 {
        unsafe {
            (*self.ptr).num_ports
        }
    }
    pub fn num_formats(&self) -> u16 {
        unsafe {
            (*self.ptr).num_formats
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xv_adaptor_info_name_length(field) as usize;
            let data = xcb_xv_adaptor_info_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
    pub fn formats(&self) -> FormatIterator {
        unsafe {
            xcb_xv_adaptor_info_formats_iterator(self.ptr)
        }
    }
}

pub type AdaptorInfoIterator<'a> = xcb_xv_adaptor_info_iterator_t<'a>;

impl<'a> Iterator for AdaptorInfoIterator<'a> {
    type Item = AdaptorInfo<'a>;
    fn next(&mut self) -> std::option::Option<AdaptorInfo<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xv_adaptor_info_iterator_t;
                let data = (*iter).data;
                xcb_xv_adaptor_info_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type EncodingInfo<'a> = base::StructPtr<'a, xcb_xv_encoding_info_t>;

impl<'a> EncodingInfo<'a> {
    pub fn encoding(&self) -> Encoding {
        unsafe {
            (*self.ptr).encoding
        }
    }
    pub fn name_size(&self) -> u16 {
        unsafe {
            (*self.ptr).name_size
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
    pub fn rate(&self) -> Rational {
        unsafe {
            std::mem::transmute((*self.ptr).rate)
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xv_encoding_info_name_length(field) as usize;
            let data = xcb_xv_encoding_info_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type EncodingInfoIterator<'a> = xcb_xv_encoding_info_iterator_t<'a>;

impl<'a> Iterator for EncodingInfoIterator<'a> {
    type Item = EncodingInfo<'a>;
    fn next(&mut self) -> std::option::Option<EncodingInfo<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xv_encoding_info_iterator_t;
                let data = (*iter).data;
                xcb_xv_encoding_info_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type Image<'a> = base::StructPtr<'a, xcb_xv_image_t>;

impl<'a> Image<'a> {
    pub fn id(&self) -> u32 {
        unsafe {
            (*self.ptr).id
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
    pub fn data_size(&self) -> u32 {
        unsafe {
            (*self.ptr).data_size
        }
    }
    pub fn num_planes(&self) -> u32 {
        unsafe {
            (*self.ptr).num_planes
        }
    }
    pub fn pitches(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xv_image_pitches_length(field) as usize;
            let data = xcb_xv_image_pitches(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn offsets(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xv_image_offsets_length(field) as usize;
            let data = xcb_xv_image_offsets(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xv_image_data_length(field) as usize;
            let data = xcb_xv_image_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type ImageIterator<'a> = xcb_xv_image_iterator_t<'a>;

impl<'a> Iterator for ImageIterator<'a> {
    type Item = Image<'a>;
    fn next(&mut self) -> std::option::Option<Image<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xv_image_iterator_t;
                let data = (*iter).data;
                xcb_xv_image_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type AttributeInfo<'a> = base::StructPtr<'a, xcb_xv_attribute_info_t>;

impl<'a> AttributeInfo<'a> {
    pub fn flags(&self) -> u32 {
        unsafe {
            (*self.ptr).flags
        }
    }
    pub fn min(&self) -> i32 {
        unsafe {
            (*self.ptr).min
        }
    }
    pub fn max(&self) -> i32 {
        unsafe {
            (*self.ptr).max
        }
    }
    pub fn size(&self) -> u32 {
        unsafe {
            (*self.ptr).size
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_xv_attribute_info_name_length(field) as usize;
            let data = xcb_xv_attribute_info_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type AttributeInfoIterator<'a> = xcb_xv_attribute_info_iterator_t<'a>;

impl<'a> Iterator for AttributeInfoIterator<'a> {
    type Item = AttributeInfo<'a>;
    fn next(&mut self) -> std::option::Option<AttributeInfo<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xv_attribute_info_iterator_t;
                let data = (*iter).data;
                xcb_xv_attribute_info_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub type ImageFormatInfo<'a> = base::StructPtr<'a, xcb_xv_image_format_info_t>;

impl<'a> ImageFormatInfo<'a> {
    pub fn id(&self) -> u32 {
        unsafe {
            (*self.ptr).id
        }
    }
    pub fn type_(&self) -> u8 {
        unsafe {
            (*self.ptr).type_
        }
    }
    pub fn byte_order(&self) -> u8 {
        unsafe {
            (*self.ptr).byte_order
        }
    }
    pub fn guid(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).guid
        }
    }
    pub fn bpp(&self) -> u8 {
        unsafe {
            (*self.ptr).bpp
        }
    }
    pub fn num_planes(&self) -> u8 {
        unsafe {
            (*self.ptr).num_planes
        }
    }
    pub fn depth(&self) -> u8 {
        unsafe {
            (*self.ptr).depth
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
    pub fn format(&self) -> u8 {
        unsafe {
            (*self.ptr).format
        }
    }
    pub fn y_sample_bits(&self) -> u32 {
        unsafe {
            (*self.ptr).y_sample_bits
        }
    }
    pub fn u_sample_bits(&self) -> u32 {
        unsafe {
            (*self.ptr).u_sample_bits
        }
    }
    pub fn v_sample_bits(&self) -> u32 {
        unsafe {
            (*self.ptr).v_sample_bits
        }
    }
    pub fn vhorz_y_period(&self) -> u32 {
        unsafe {
            (*self.ptr).vhorz_y_period
        }
    }
    pub fn vhorz_u_period(&self) -> u32 {
        unsafe {
            (*self.ptr).vhorz_u_period
        }
    }
    pub fn vhorz_v_period(&self) -> u32 {
        unsafe {
            (*self.ptr).vhorz_v_period
        }
    }
    pub fn vvert_y_period(&self) -> u32 {
        unsafe {
            (*self.ptr).vvert_y_period
        }
    }
    pub fn vvert_u_period(&self) -> u32 {
        unsafe {
            (*self.ptr).vvert_u_period
        }
    }
    pub fn vvert_v_period(&self) -> u32 {
        unsafe {
            (*self.ptr).vvert_v_period
        }
    }
    pub fn vcomp_order(&self) -> &[u8] {
        unsafe {
            &(*self.ptr).vcomp_order
        }
    }
    pub fn vscanline_order(&self) -> u8 {
        unsafe {
            (*self.ptr).vscanline_order
        }
    }
}

pub type ImageFormatInfoIterator<'a> = xcb_xv_image_format_info_iterator_t<'a>;

impl<'a> Iterator for ImageFormatInfoIterator<'a> {
    type Item = ImageFormatInfo<'a>;
    fn next(&mut self) -> std::option::Option<ImageFormatInfo<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_xv_image_format_info_iterator_t;
                let data = (*iter).data;
                xcb_xv_image_format_info_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const BAD_PORT: u8 = 0;

pub const BAD_ENCODING: u8 = 1;

pub const BAD_CONTROL: u8 = 2;

pub const VIDEO_NOTIFY: u8 = 0;

pub type VideoNotifyEvent = base::Event<xcb_xv_video_notify_event_t>;

impl VideoNotifyEvent {
    pub fn reason(&self) -> u8 {
        unsafe {
            (*self.ptr).reason
        }
    }
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn drawable(&self) -> xproto::Drawable {
        unsafe {
            (*self.ptr).drawable
        }
    }
    pub fn port(&self) -> Port {
        unsafe {
            (*self.ptr).port
        }
    }
    /// Constructs a new VideoNotifyEvent
    /// `response_type` will be set automatically to VIDEO_NOTIFY
    pub fn new(reason: u8,
               time: xproto::Timestamp,
               drawable: xproto::Drawable,
               port: Port)
            -> VideoNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xv_video_notify_event_t;
            (*raw).response_type = VIDEO_NOTIFY;
            (*raw).reason = reason;
            (*raw).time = time;
            (*raw).drawable = drawable;
            (*raw).port = port;
            VideoNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const PORT_NOTIFY: u8 = 1;

pub type PortNotifyEvent = base::Event<xcb_xv_port_notify_event_t>;

impl PortNotifyEvent {
    pub fn time(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).time
        }
    }
    pub fn port(&self) -> Port {
        unsafe {
            (*self.ptr).port
        }
    }
    pub fn attribute(&self) -> xproto::Atom {
        unsafe {
            (*self.ptr).attribute
        }
    }
    pub fn value(&self) -> i32 {
        unsafe {
            (*self.ptr).value
        }
    }
    /// Constructs a new PortNotifyEvent
    /// `response_type` will be set automatically to PORT_NOTIFY
    pub fn new(time: xproto::Timestamp,
               port: Port,
               attribute: xproto::Atom,
               value: i32)
            -> PortNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_xv_port_notify_event_t;
            (*raw).response_type = PORT_NOTIFY;
            (*raw).time = time;
            (*raw).port = port;
            (*raw).attribute = attribute;
            (*raw).value = value;
            PortNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const QUERY_EXTENSION: u8 = 0;

pub type QueryExtensionCookie<'a> = base::Cookie<'a, xcb_xv_query_extension_cookie_t>;

impl<'a> QueryExtensionCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryExtensionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryExtensionReply {
                    ptr: xcb_xv_query_extension_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryExtensionReply {
                    ptr: xcb_xv_query_extension_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryExtensionReply = base::Reply<xcb_xv_query_extension_reply_t>;

impl QueryExtensionReply {
    pub fn major(&self) -> u16 {
        unsafe {
            (*self.ptr).major
        }
    }
    pub fn minor(&self) -> u16 {
        unsafe {
            (*self.ptr).minor
        }
    }
}

pub fn query_extension<'a>(c: &'a base::Connection)
        -> QueryExtensionCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_extension(c.get_raw_conn());
        QueryExtensionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_extension_unchecked<'a>(c: &'a base::Connection)
        -> QueryExtensionCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_extension_unchecked(c.get_raw_conn());
        QueryExtensionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_ADAPTORS: u8 = 1;

pub type QueryAdaptorsCookie<'a> = base::Cookie<'a, xcb_xv_query_adaptors_cookie_t>;

impl<'a> QueryAdaptorsCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryAdaptorsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryAdaptorsReply {
                    ptr: xcb_xv_query_adaptors_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryAdaptorsReply {
                    ptr: xcb_xv_query_adaptors_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryAdaptorsReply = base::Reply<xcb_xv_query_adaptors_reply_t>;

impl QueryAdaptorsReply {
    pub fn num_adaptors(&self) -> u16 {
        unsafe {
            (*self.ptr).num_adaptors
        }
    }
    pub fn info(&self) -> AdaptorInfoIterator {
        unsafe {
            xcb_xv_query_adaptors_info_iterator(self.ptr)
        }
    }
}

pub fn query_adaptors<'a>(c     : &'a base::Connection,
                          window: xproto::Window)
        -> QueryAdaptorsCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_adaptors(c.get_raw_conn(),
                                           window as xcb_window_t);  // 0
        QueryAdaptorsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_adaptors_unchecked<'a>(c     : &'a base::Connection,
                                    window: xproto::Window)
        -> QueryAdaptorsCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_adaptors_unchecked(c.get_raw_conn(),
                                                     window as xcb_window_t);  // 0
        QueryAdaptorsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_ENCODINGS: u8 = 2;

pub type QueryEncodingsCookie<'a> = base::Cookie<'a, xcb_xv_query_encodings_cookie_t>;

impl<'a> QueryEncodingsCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryEncodingsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryEncodingsReply {
                    ptr: xcb_xv_query_encodings_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryEncodingsReply {
                    ptr: xcb_xv_query_encodings_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryEncodingsReply = base::Reply<xcb_xv_query_encodings_reply_t>;

impl QueryEncodingsReply {
    pub fn num_encodings(&self) -> u16 {
        unsafe {
            (*self.ptr).num_encodings
        }
    }
    pub fn info(&self) -> EncodingInfoIterator {
        unsafe {
            xcb_xv_query_encodings_info_iterator(self.ptr)
        }
    }
}

pub fn query_encodings<'a>(c   : &'a base::Connection,
                           port: Port)
        -> QueryEncodingsCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_encodings(c.get_raw_conn(),
                                            port as xcb_xv_port_t);  // 0
        QueryEncodingsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_encodings_unchecked<'a>(c   : &'a base::Connection,
                                     port: Port)
        -> QueryEncodingsCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_encodings_unchecked(c.get_raw_conn(),
                                                      port as xcb_xv_port_t);  // 0
        QueryEncodingsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const GRAB_PORT: u8 = 3;

pub type GrabPortCookie<'a> = base::Cookie<'a, xcb_xv_grab_port_cookie_t>;

impl<'a> GrabPortCookie<'a> {
    pub fn get_reply(&self) -> Result<GrabPortReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GrabPortReply {
                    ptr: xcb_xv_grab_port_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GrabPortReply {
                    ptr: xcb_xv_grab_port_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GrabPortReply = base::Reply<xcb_xv_grab_port_reply_t>;

impl GrabPortReply {
    pub fn result(&self) -> u8 {
        unsafe {
            (*self.ptr).result
        }
    }
}

pub fn grab_port<'a>(c   : &'a base::Connection,
                     port: Port,
                     time: xproto::Timestamp)
        -> GrabPortCookie<'a> {
    unsafe {
        let cookie = xcb_xv_grab_port(c.get_raw_conn(),
                                      port as xcb_xv_port_t,  // 0
                                      time as xcb_timestamp_t);  // 1
        GrabPortCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn grab_port_unchecked<'a>(c   : &'a base::Connection,
                               port: Port,
                               time: xproto::Timestamp)
        -> GrabPortCookie<'a> {
    unsafe {
        let cookie = xcb_xv_grab_port_unchecked(c.get_raw_conn(),
                                                port as xcb_xv_port_t,  // 0
                                                time as xcb_timestamp_t);  // 1
        GrabPortCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const UNGRAB_PORT: u8 = 4;

pub fn ungrab_port<'a>(c   : &'a base::Connection,
                       port: Port,
                       time: xproto::Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_ungrab_port(c.get_raw_conn(),
                                        port as xcb_xv_port_t,  // 0
                                        time as xcb_timestamp_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn ungrab_port_checked<'a>(c   : &'a base::Connection,
                               port: Port,
                               time: xproto::Timestamp)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_ungrab_port_checked(c.get_raw_conn(),
                                                port as xcb_xv_port_t,  // 0
                                                time as xcb_timestamp_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PUT_VIDEO: u8 = 5;

pub fn put_video<'a>(c       : &'a base::Connection,
                     port    : Port,
                     drawable: xproto::Drawable,
                     gc      : xproto::Gcontext,
                     vid_x   : i16,
                     vid_y   : i16,
                     vid_w   : u16,
                     vid_h   : u16,
                     drw_x   : i16,
                     drw_y   : i16,
                     drw_w   : u16,
                     drw_h   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_put_video(c.get_raw_conn(),
                                      port as xcb_xv_port_t,  // 0
                                      drawable as xcb_drawable_t,  // 1
                                      gc as xcb_gcontext_t,  // 2
                                      vid_x as i16,  // 3
                                      vid_y as i16,  // 4
                                      vid_w as u16,  // 5
                                      vid_h as u16,  // 6
                                      drw_x as i16,  // 7
                                      drw_y as i16,  // 8
                                      drw_w as u16,  // 9
                                      drw_h as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn put_video_checked<'a>(c       : &'a base::Connection,
                             port    : Port,
                             drawable: xproto::Drawable,
                             gc      : xproto::Gcontext,
                             vid_x   : i16,
                             vid_y   : i16,
                             vid_w   : u16,
                             vid_h   : u16,
                             drw_x   : i16,
                             drw_y   : i16,
                             drw_w   : u16,
                             drw_h   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_put_video_checked(c.get_raw_conn(),
                                              port as xcb_xv_port_t,  // 0
                                              drawable as xcb_drawable_t,  // 1
                                              gc as xcb_gcontext_t,  // 2
                                              vid_x as i16,  // 3
                                              vid_y as i16,  // 4
                                              vid_w as u16,  // 5
                                              vid_h as u16,  // 6
                                              drw_x as i16,  // 7
                                              drw_y as i16,  // 8
                                              drw_w as u16,  // 9
                                              drw_h as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PUT_STILL: u8 = 6;

pub fn put_still<'a>(c       : &'a base::Connection,
                     port    : Port,
                     drawable: xproto::Drawable,
                     gc      : xproto::Gcontext,
                     vid_x   : i16,
                     vid_y   : i16,
                     vid_w   : u16,
                     vid_h   : u16,
                     drw_x   : i16,
                     drw_y   : i16,
                     drw_w   : u16,
                     drw_h   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_put_still(c.get_raw_conn(),
                                      port as xcb_xv_port_t,  // 0
                                      drawable as xcb_drawable_t,  // 1
                                      gc as xcb_gcontext_t,  // 2
                                      vid_x as i16,  // 3
                                      vid_y as i16,  // 4
                                      vid_w as u16,  // 5
                                      vid_h as u16,  // 6
                                      drw_x as i16,  // 7
                                      drw_y as i16,  // 8
                                      drw_w as u16,  // 9
                                      drw_h as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn put_still_checked<'a>(c       : &'a base::Connection,
                             port    : Port,
                             drawable: xproto::Drawable,
                             gc      : xproto::Gcontext,
                             vid_x   : i16,
                             vid_y   : i16,
                             vid_w   : u16,
                             vid_h   : u16,
                             drw_x   : i16,
                             drw_y   : i16,
                             drw_w   : u16,
                             drw_h   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_put_still_checked(c.get_raw_conn(),
                                              port as xcb_xv_port_t,  // 0
                                              drawable as xcb_drawable_t,  // 1
                                              gc as xcb_gcontext_t,  // 2
                                              vid_x as i16,  // 3
                                              vid_y as i16,  // 4
                                              vid_w as u16,  // 5
                                              vid_h as u16,  // 6
                                              drw_x as i16,  // 7
                                              drw_y as i16,  // 8
                                              drw_w as u16,  // 9
                                              drw_h as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_VIDEO: u8 = 7;

pub fn get_video<'a>(c       : &'a base::Connection,
                     port    : Port,
                     drawable: xproto::Drawable,
                     gc      : xproto::Gcontext,
                     vid_x   : i16,
                     vid_y   : i16,
                     vid_w   : u16,
                     vid_h   : u16,
                     drw_x   : i16,
                     drw_y   : i16,
                     drw_w   : u16,
                     drw_h   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_get_video(c.get_raw_conn(),
                                      port as xcb_xv_port_t,  // 0
                                      drawable as xcb_drawable_t,  // 1
                                      gc as xcb_gcontext_t,  // 2
                                      vid_x as i16,  // 3
                                      vid_y as i16,  // 4
                                      vid_w as u16,  // 5
                                      vid_h as u16,  // 6
                                      drw_x as i16,  // 7
                                      drw_y as i16,  // 8
                                      drw_w as u16,  // 9
                                      drw_h as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn get_video_checked<'a>(c       : &'a base::Connection,
                             port    : Port,
                             drawable: xproto::Drawable,
                             gc      : xproto::Gcontext,
                             vid_x   : i16,
                             vid_y   : i16,
                             vid_w   : u16,
                             vid_h   : u16,
                             drw_x   : i16,
                             drw_y   : i16,
                             drw_w   : u16,
                             drw_h   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_get_video_checked(c.get_raw_conn(),
                                              port as xcb_xv_port_t,  // 0
                                              drawable as xcb_drawable_t,  // 1
                                              gc as xcb_gcontext_t,  // 2
                                              vid_x as i16,  // 3
                                              vid_y as i16,  // 4
                                              vid_w as u16,  // 5
                                              vid_h as u16,  // 6
                                              drw_x as i16,  // 7
                                              drw_y as i16,  // 8
                                              drw_w as u16,  // 9
                                              drw_h as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_STILL: u8 = 8;

pub fn get_still<'a>(c       : &'a base::Connection,
                     port    : Port,
                     drawable: xproto::Drawable,
                     gc      : xproto::Gcontext,
                     vid_x   : i16,
                     vid_y   : i16,
                     vid_w   : u16,
                     vid_h   : u16,
                     drw_x   : i16,
                     drw_y   : i16,
                     drw_w   : u16,
                     drw_h   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_get_still(c.get_raw_conn(),
                                      port as xcb_xv_port_t,  // 0
                                      drawable as xcb_drawable_t,  // 1
                                      gc as xcb_gcontext_t,  // 2
                                      vid_x as i16,  // 3
                                      vid_y as i16,  // 4
                                      vid_w as u16,  // 5
                                      vid_h as u16,  // 6
                                      drw_x as i16,  // 7
                                      drw_y as i16,  // 8
                                      drw_w as u16,  // 9
                                      drw_h as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn get_still_checked<'a>(c       : &'a base::Connection,
                             port    : Port,
                             drawable: xproto::Drawable,
                             gc      : xproto::Gcontext,
                             vid_x   : i16,
                             vid_y   : i16,
                             vid_w   : u16,
                             vid_h   : u16,
                             drw_x   : i16,
                             drw_y   : i16,
                             drw_w   : u16,
                             drw_h   : u16)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_get_still_checked(c.get_raw_conn(),
                                              port as xcb_xv_port_t,  // 0
                                              drawable as xcb_drawable_t,  // 1
                                              gc as xcb_gcontext_t,  // 2
                                              vid_x as i16,  // 3
                                              vid_y as i16,  // 4
                                              vid_w as u16,  // 5
                                              vid_h as u16,  // 6
                                              drw_x as i16,  // 7
                                              drw_y as i16,  // 8
                                              drw_w as u16,  // 9
                                              drw_h as u16);  // 10
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const STOP_VIDEO: u8 = 9;

pub fn stop_video<'a>(c       : &'a base::Connection,
                      port    : Port,
                      drawable: xproto::Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_stop_video(c.get_raw_conn(),
                                       port as xcb_xv_port_t,  // 0
                                       drawable as xcb_drawable_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn stop_video_checked<'a>(c       : &'a base::Connection,
                              port    : Port,
                              drawable: xproto::Drawable)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_stop_video_checked(c.get_raw_conn(),
                                               port as xcb_xv_port_t,  // 0
                                               drawable as xcb_drawable_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SELECT_VIDEO_NOTIFY: u8 = 10;

pub fn select_video_notify<'a>(c       : &'a base::Connection,
                               drawable: xproto::Drawable,
                               onoff   : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_select_video_notify(c.get_raw_conn(),
                                                drawable as xcb_drawable_t,  // 0
                                                onoff as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_video_notify_checked<'a>(c       : &'a base::Connection,
                                       drawable: xproto::Drawable,
                                       onoff   : bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_select_video_notify_checked(c.get_raw_conn(),
                                                        drawable as xcb_drawable_t,  // 0
                                                        onoff as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SELECT_PORT_NOTIFY: u8 = 11;

pub fn select_port_notify<'a>(c    : &'a base::Connection,
                              port : Port,
                              onoff: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_select_port_notify(c.get_raw_conn(),
                                               port as xcb_xv_port_t,  // 0
                                               onoff as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn select_port_notify_checked<'a>(c    : &'a base::Connection,
                                      port : Port,
                                      onoff: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_select_port_notify_checked(c.get_raw_conn(),
                                                       port as xcb_xv_port_t,  // 0
                                                       onoff as u8);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_BEST_SIZE: u8 = 12;

pub type QueryBestSizeCookie<'a> = base::Cookie<'a, xcb_xv_query_best_size_cookie_t>;

impl<'a> QueryBestSizeCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryBestSizeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryBestSizeReply {
                    ptr: xcb_xv_query_best_size_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryBestSizeReply {
                    ptr: xcb_xv_query_best_size_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryBestSizeReply = base::Reply<xcb_xv_query_best_size_reply_t>;

impl QueryBestSizeReply {
    pub fn actual_width(&self) -> u16 {
        unsafe {
            (*self.ptr).actual_width
        }
    }
    pub fn actual_height(&self) -> u16 {
        unsafe {
            (*self.ptr).actual_height
        }
    }
}

pub fn query_best_size<'a>(c     : &'a base::Connection,
                           port  : Port,
                           vid_w : u16,
                           vid_h : u16,
                           drw_w : u16,
                           drw_h : u16,
                           motion: bool)
        -> QueryBestSizeCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_best_size(c.get_raw_conn(),
                                            port as xcb_xv_port_t,  // 0
                                            vid_w as u16,  // 1
                                            vid_h as u16,  // 2
                                            drw_w as u16,  // 3
                                            drw_h as u16,  // 4
                                            motion as u8);  // 5
        QueryBestSizeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_best_size_unchecked<'a>(c     : &'a base::Connection,
                                     port  : Port,
                                     vid_w : u16,
                                     vid_h : u16,
                                     drw_w : u16,
                                     drw_h : u16,
                                     motion: bool)
        -> QueryBestSizeCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_best_size_unchecked(c.get_raw_conn(),
                                                      port as xcb_xv_port_t,  // 0
                                                      vid_w as u16,  // 1
                                                      vid_h as u16,  // 2
                                                      drw_w as u16,  // 3
                                                      drw_h as u16,  // 4
                                                      motion as u8);  // 5
        QueryBestSizeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_PORT_ATTRIBUTE: u8 = 13;

pub fn set_port_attribute<'a>(c        : &'a base::Connection,
                              port     : Port,
                              attribute: xproto::Atom,
                              value    : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_set_port_attribute(c.get_raw_conn(),
                                               port as xcb_xv_port_t,  // 0
                                               attribute as xcb_atom_t,  // 1
                                               value as i32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_port_attribute_checked<'a>(c        : &'a base::Connection,
                                      port     : Port,
                                      attribute: xproto::Atom,
                                      value    : i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_set_port_attribute_checked(c.get_raw_conn(),
                                                       port as xcb_xv_port_t,  // 0
                                                       attribute as xcb_atom_t,  // 1
                                                       value as i32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_PORT_ATTRIBUTE: u8 = 14;

pub type GetPortAttributeCookie<'a> = base::Cookie<'a, xcb_xv_get_port_attribute_cookie_t>;

impl<'a> GetPortAttributeCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPortAttributeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPortAttributeReply {
                    ptr: xcb_xv_get_port_attribute_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPortAttributeReply {
                    ptr: xcb_xv_get_port_attribute_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPortAttributeReply = base::Reply<xcb_xv_get_port_attribute_reply_t>;

impl GetPortAttributeReply {
    pub fn value(&self) -> i32 {
        unsafe {
            (*self.ptr).value
        }
    }
}

pub fn get_port_attribute<'a>(c        : &'a base::Connection,
                              port     : Port,
                              attribute: xproto::Atom)
        -> GetPortAttributeCookie<'a> {
    unsafe {
        let cookie = xcb_xv_get_port_attribute(c.get_raw_conn(),
                                               port as xcb_xv_port_t,  // 0
                                               attribute as xcb_atom_t);  // 1
        GetPortAttributeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_port_attribute_unchecked<'a>(c        : &'a base::Connection,
                                        port     : Port,
                                        attribute: xproto::Atom)
        -> GetPortAttributeCookie<'a> {
    unsafe {
        let cookie = xcb_xv_get_port_attribute_unchecked(c.get_raw_conn(),
                                                         port as xcb_xv_port_t,  // 0
                                                         attribute as xcb_atom_t);  // 1
        GetPortAttributeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_PORT_ATTRIBUTES: u8 = 15;

pub type QueryPortAttributesCookie<'a> = base::Cookie<'a, xcb_xv_query_port_attributes_cookie_t>;

impl<'a> QueryPortAttributesCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryPortAttributesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryPortAttributesReply {
                    ptr: xcb_xv_query_port_attributes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryPortAttributesReply {
                    ptr: xcb_xv_query_port_attributes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryPortAttributesReply = base::Reply<xcb_xv_query_port_attributes_reply_t>;

impl QueryPortAttributesReply {
    pub fn num_attributes(&self) -> u32 {
        unsafe {
            (*self.ptr).num_attributes
        }
    }
    pub fn text_size(&self) -> u32 {
        unsafe {
            (*self.ptr).text_size
        }
    }
    pub fn attributes(&self) -> AttributeInfoIterator {
        unsafe {
            xcb_xv_query_port_attributes_attributes_iterator(self.ptr)
        }
    }
}

pub fn query_port_attributes<'a>(c   : &'a base::Connection,
                                 port: Port)
        -> QueryPortAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_port_attributes(c.get_raw_conn(),
                                                  port as xcb_xv_port_t);  // 0
        QueryPortAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_port_attributes_unchecked<'a>(c   : &'a base::Connection,
                                           port: Port)
        -> QueryPortAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_port_attributes_unchecked(c.get_raw_conn(),
                                                            port as xcb_xv_port_t);  // 0
        QueryPortAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_IMAGE_FORMATS: u8 = 16;

pub type ListImageFormatsCookie<'a> = base::Cookie<'a, xcb_xv_list_image_formats_cookie_t>;

impl<'a> ListImageFormatsCookie<'a> {
    pub fn get_reply(&self) -> Result<ListImageFormatsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListImageFormatsReply {
                    ptr: xcb_xv_list_image_formats_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListImageFormatsReply {
                    ptr: xcb_xv_list_image_formats_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListImageFormatsReply = base::Reply<xcb_xv_list_image_formats_reply_t>;

impl ListImageFormatsReply {
    pub fn num_formats(&self) -> u32 {
        unsafe {
            (*self.ptr).num_formats
        }
    }
    pub fn format(&self) -> ImageFormatInfoIterator {
        unsafe {
            xcb_xv_list_image_formats_format_iterator(self.ptr)
        }
    }
}

pub fn list_image_formats<'a>(c   : &'a base::Connection,
                              port: Port)
        -> ListImageFormatsCookie<'a> {
    unsafe {
        let cookie = xcb_xv_list_image_formats(c.get_raw_conn(),
                                               port as xcb_xv_port_t);  // 0
        ListImageFormatsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_image_formats_unchecked<'a>(c   : &'a base::Connection,
                                        port: Port)
        -> ListImageFormatsCookie<'a> {
    unsafe {
        let cookie = xcb_xv_list_image_formats_unchecked(c.get_raw_conn(),
                                                         port as xcb_xv_port_t);  // 0
        ListImageFormatsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const QUERY_IMAGE_ATTRIBUTES: u8 = 17;

pub type QueryImageAttributesCookie<'a> = base::Cookie<'a, xcb_xv_query_image_attributes_cookie_t>;

impl<'a> QueryImageAttributesCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryImageAttributesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryImageAttributesReply {
                    ptr: xcb_xv_query_image_attributes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryImageAttributesReply {
                    ptr: xcb_xv_query_image_attributes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryImageAttributesReply = base::Reply<xcb_xv_query_image_attributes_reply_t>;

impl QueryImageAttributesReply {
    pub fn num_planes(&self) -> u32 {
        unsafe {
            (*self.ptr).num_planes
        }
    }
    pub fn data_size(&self) -> u32 {
        unsafe {
            (*self.ptr).data_size
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
    pub fn pitches(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xv_query_image_attributes_pitches_length(field) as usize;
            let data = xcb_xv_query_image_attributes_pitches(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn offsets(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_xv_query_image_attributes_offsets_length(field) as usize;
            let data = xcb_xv_query_image_attributes_offsets(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn query_image_attributes<'a>(c     : &'a base::Connection,
                                  port  : Port,
                                  id    : u32,
                                  width : u16,
                                  height: u16)
        -> QueryImageAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_image_attributes(c.get_raw_conn(),
                                                   port as xcb_xv_port_t,  // 0
                                                   id as u32,  // 1
                                                   width as u16,  // 2
                                                   height as u16);  // 3
        QueryImageAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_image_attributes_unchecked<'a>(c     : &'a base::Connection,
                                            port  : Port,
                                            id    : u32,
                                            width : u16,
                                            height: u16)
        -> QueryImageAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_xv_query_image_attributes_unchecked(c.get_raw_conn(),
                                                             port as xcb_xv_port_t,  // 0
                                                             id as u32,  // 1
                                                             width as u16,  // 2
                                                             height as u16);  // 3
        QueryImageAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PUT_IMAGE: u8 = 18;

pub fn put_image<'a>(c       : &'a base::Connection,
                     port    : Port,
                     drawable: xproto::Drawable,
                     gc      : xproto::Gcontext,
                     id      : u32,
                     src_x   : i16,
                     src_y   : i16,
                     src_w   : u16,
                     src_h   : u16,
                     drw_x   : i16,
                     drw_y   : i16,
                     drw_w   : u16,
                     drw_h   : u16,
                     width   : u16,
                     height  : u16,
                     data    : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_xv_put_image(c.get_raw_conn(),
                                      port as xcb_xv_port_t,  // 0
                                      drawable as xcb_drawable_t,  // 1
                                      gc as xcb_gcontext_t,  // 2
                                      id as u32,  // 3
                                      src_x as i16,  // 4
                                      src_y as i16,  // 5
                                      src_w as u16,  // 6
                                      src_h as u16,  // 7
                                      drw_x as i16,  // 8
                                      drw_y as i16,  // 9
                                      drw_w as u16,  // 10
                                      drw_h as u16,  // 11
                                      width as u16,  // 12
                                      height as u16,  // 13
                                      data_len as u32,  // 14
                                      data_ptr as *const u8);  // 15
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn put_image_checked<'a>(c       : &'a base::Connection,
                             port    : Port,
                             drawable: xproto::Drawable,
                             gc      : xproto::Gcontext,
                             id      : u32,
                             src_x   : i16,
                             src_y   : i16,
                             src_w   : u16,
                             src_h   : u16,
                             drw_x   : i16,
                             drw_y   : i16,
                             drw_w   : u16,
                             drw_h   : u16,
                             width   : u16,
                             height  : u16,
                             data    : &[u8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let cookie = xcb_xv_put_image_checked(c.get_raw_conn(),
                                              port as xcb_xv_port_t,  // 0
                                              drawable as xcb_drawable_t,  // 1
                                              gc as xcb_gcontext_t,  // 2
                                              id as u32,  // 3
                                              src_x as i16,  // 4
                                              src_y as i16,  // 5
                                              src_w as u16,  // 6
                                              src_h as u16,  // 7
                                              drw_x as i16,  // 8
                                              drw_y as i16,  // 9
                                              drw_w as u16,  // 10
                                              drw_h as u16,  // 11
                                              width as u16,  // 12
                                              height as u16,  // 13
                                              data_len as u32,  // 14
                                              data_ptr as *const u8);  // 15
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SHM_PUT_IMAGE: u8 = 19;

pub fn shm_put_image<'a>(c         : &'a base::Connection,
                         port      : Port,
                         drawable  : xproto::Drawable,
                         gc        : xproto::Gcontext,
                         shmseg    : shm::Seg,
                         id        : u32,
                         offset    : u32,
                         src_x     : i16,
                         src_y     : i16,
                         src_w     : u16,
                         src_h     : u16,
                         drw_x     : i16,
                         drw_y     : i16,
                         drw_w     : u16,
                         drw_h     : u16,
                         width     : u16,
                         height    : u16,
                         send_event: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_shm_put_image(c.get_raw_conn(),
                                          port as xcb_xv_port_t,  // 0
                                          drawable as xcb_drawable_t,  // 1
                                          gc as xcb_gcontext_t,  // 2
                                          shmseg as xcb_shm_seg_t,  // 3
                                          id as u32,  // 4
                                          offset as u32,  // 5
                                          src_x as i16,  // 6
                                          src_y as i16,  // 7
                                          src_w as u16,  // 8
                                          src_h as u16,  // 9
                                          drw_x as i16,  // 10
                                          drw_y as i16,  // 11
                                          drw_w as u16,  // 12
                                          drw_h as u16,  // 13
                                          width as u16,  // 14
                                          height as u16,  // 15
                                          send_event as u8);  // 16
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn shm_put_image_checked<'a>(c         : &'a base::Connection,
                                 port      : Port,
                                 drawable  : xproto::Drawable,
                                 gc        : xproto::Gcontext,
                                 shmseg    : shm::Seg,
                                 id        : u32,
                                 offset    : u32,
                                 src_x     : i16,
                                 src_y     : i16,
                                 src_w     : u16,
                                 src_h     : u16,
                                 drw_x     : i16,
                                 drw_y     : i16,
                                 drw_w     : u16,
                                 drw_h     : u16,
                                 width     : u16,
                                 height    : u16,
                                 send_event: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_xv_shm_put_image_checked(c.get_raw_conn(),
                                                  port as xcb_xv_port_t,  // 0
                                                  drawable as xcb_drawable_t,  // 1
                                                  gc as xcb_gcontext_t,  // 2
                                                  shmseg as xcb_shm_seg_t,  // 3
                                                  id as u32,  // 4
                                                  offset as u32,  // 5
                                                  src_x as i16,  // 6
                                                  src_y as i16,  // 7
                                                  src_w as u16,  // 8
                                                  src_h as u16,  // 9
                                                  drw_x as i16,  // 10
                                                  drw_y as i16,  // 11
                                                  drw_w as u16,  // 12
                                                  drw_h as u16,  // 13
                                                  width as u16,  // 14
                                                  height as u16,  // 15
                                                  send_event as u8);  // 16
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}
