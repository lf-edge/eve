// Generated automatically from xprint.xml by rs_client.py version 0.8.2.
// Do not edit!


#![allow(improper_ctypes)]

use ffi::base::*;
use ffi::xproto::*;

use libc::{c_char, c_int, c_uint, c_void};
use std;


pub const XCB_X_PRINT_MAJOR_VERSION: u32 = 1;
pub const XCB_X_PRINT_MINOR_VERSION: u32 = 0;

pub type xcb_x_print_string8_t = c_char;

#[repr(C)]
pub struct xcb_x_print_string8_iterator_t {
    pub data:  *mut xcb_x_print_string8_t,
    pub rem:   c_int,
    pub index: c_int,
}

#[repr(C)]
pub struct xcb_x_print_printer_t {
    pub nameLen:     u32,
    pub descLen:     u32,
}

#[repr(C)]
pub struct xcb_x_print_printer_iterator_t<'a> {
    pub data:  *mut xcb_x_print_printer_t,
    pub rem:   c_int,
    pub index: c_int,
    _phantom:  std::marker::PhantomData<&'a xcb_x_print_printer_t>,
}

pub type xcb_x_print_pcontext_t = u32;

#[repr(C)]
pub struct xcb_x_print_pcontext_iterator_t {
    pub data:  *mut xcb_x_print_pcontext_t,
    pub rem:   c_int,
    pub index: c_int,
}

pub type xcb_x_print_get_doc_t = u32;
pub const XCB_X_PRINT_GET_DOC_FINISHED       : xcb_x_print_get_doc_t = 0x00;
pub const XCB_X_PRINT_GET_DOC_SECOND_CONSUMER: xcb_x_print_get_doc_t = 0x01;

pub type xcb_x_print_ev_mask_t = u32;
pub const XCB_X_PRINT_EV_MASK_NO_EVENT_MASK : xcb_x_print_ev_mask_t = 0x00;
pub const XCB_X_PRINT_EV_MASK_PRINT_MASK    : xcb_x_print_ev_mask_t = 0x01;
pub const XCB_X_PRINT_EV_MASK_ATTRIBUTE_MASK: xcb_x_print_ev_mask_t = 0x02;

pub type xcb_x_print_detail_t = u32;
pub const XCB_X_PRINT_DETAIL_START_JOB_NOTIFY : xcb_x_print_detail_t = 0x01;
pub const XCB_X_PRINT_DETAIL_END_JOB_NOTIFY   : xcb_x_print_detail_t = 0x02;
pub const XCB_X_PRINT_DETAIL_START_DOC_NOTIFY : xcb_x_print_detail_t = 0x03;
pub const XCB_X_PRINT_DETAIL_END_DOC_NOTIFY   : xcb_x_print_detail_t = 0x04;
pub const XCB_X_PRINT_DETAIL_START_PAGE_NOTIFY: xcb_x_print_detail_t = 0x05;
pub const XCB_X_PRINT_DETAIL_END_PAGE_NOTIFY  : xcb_x_print_detail_t = 0x06;

pub type xcb_x_print_attr_t = u32;
pub const XCB_X_PRINT_ATTR_JOB_ATTR    : xcb_x_print_attr_t = 0x01;
pub const XCB_X_PRINT_ATTR_DOC_ATTR    : xcb_x_print_attr_t = 0x02;
pub const XCB_X_PRINT_ATTR_PAGE_ATTR   : xcb_x_print_attr_t = 0x03;
pub const XCB_X_PRINT_ATTR_PRINTER_ATTR: xcb_x_print_attr_t = 0x04;
pub const XCB_X_PRINT_ATTR_SERVER_ATTR : xcb_x_print_attr_t = 0x05;
pub const XCB_X_PRINT_ATTR_MEDIUM_ATTR : xcb_x_print_attr_t = 0x06;
pub const XCB_X_PRINT_ATTR_SPOOLER_ATTR: xcb_x_print_attr_t = 0x07;

pub const XCB_X_PRINT_PRINT_QUERY_VERSION: u8 = 0;

#[repr(C)]
pub struct xcb_x_print_print_query_version_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_x_print_print_query_version_request_t {}
impl Clone for xcb_x_print_print_query_version_request_t {
    fn clone(&self) -> xcb_x_print_print_query_version_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_query_version_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_query_version_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub major_version: u16,
    pub minor_version: u16,
}

impl Copy for xcb_x_print_print_query_version_reply_t {}
impl Clone for xcb_x_print_print_query_version_reply_t {
    fn clone(&self) -> xcb_x_print_print_query_version_reply_t { *self }
}

pub const XCB_X_PRINT_PRINT_GET_PRINTER_LIST: u8 = 1;

#[repr(C)]
pub struct xcb_x_print_print_get_printer_list_request_t {
    pub major_opcode:   u8,
    pub minor_opcode:   u8,
    pub length:         u16,
    pub printerNameLen: u32,
    pub localeLen:      u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_get_printer_list_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_get_printer_list_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub listCount:     u32,
    pub pad1:          [u8; 20],
}

pub const XCB_X_PRINT_PRINT_REHASH_PRINTER_LIST: u8 = 20;

#[repr(C)]
pub struct xcb_x_print_print_rehash_printer_list_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_x_print_print_rehash_printer_list_request_t {}
impl Clone for xcb_x_print_print_rehash_printer_list_request_t {
    fn clone(&self) -> xcb_x_print_print_rehash_printer_list_request_t { *self }
}

pub const XCB_X_PRINT_CREATE_CONTEXT: u8 = 2;

#[repr(C)]
pub struct xcb_x_print_create_context_request_t {
    pub major_opcode:   u8,
    pub minor_opcode:   u8,
    pub length:         u16,
    pub context_id:     u32,
    pub printerNameLen: u32,
    pub localeLen:      u32,
}

pub const XCB_X_PRINT_PRINT_SET_CONTEXT: u8 = 3;

#[repr(C)]
pub struct xcb_x_print_print_set_context_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      u32,
}

impl Copy for xcb_x_print_print_set_context_request_t {}
impl Clone for xcb_x_print_print_set_context_request_t {
    fn clone(&self) -> xcb_x_print_print_set_context_request_t { *self }
}

pub const XCB_X_PRINT_PRINT_GET_CONTEXT: u8 = 4;

#[repr(C)]
pub struct xcb_x_print_print_get_context_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_x_print_print_get_context_request_t {}
impl Clone for xcb_x_print_print_get_context_request_t {
    fn clone(&self) -> xcb_x_print_print_get_context_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_get_context_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_get_context_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub context:       u32,
}

impl Copy for xcb_x_print_print_get_context_reply_t {}
impl Clone for xcb_x_print_print_get_context_reply_t {
    fn clone(&self) -> xcb_x_print_print_get_context_reply_t { *self }
}

pub const XCB_X_PRINT_PRINT_DESTROY_CONTEXT: u8 = 5;

#[repr(C)]
pub struct xcb_x_print_print_destroy_context_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      u32,
}

impl Copy for xcb_x_print_print_destroy_context_request_t {}
impl Clone for xcb_x_print_print_destroy_context_request_t {
    fn clone(&self) -> xcb_x_print_print_destroy_context_request_t { *self }
}

pub const XCB_X_PRINT_PRINT_GET_SCREEN_OF_CONTEXT: u8 = 6;

#[repr(C)]
pub struct xcb_x_print_print_get_screen_of_context_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_x_print_print_get_screen_of_context_request_t {}
impl Clone for xcb_x_print_print_get_screen_of_context_request_t {
    fn clone(&self) -> xcb_x_print_print_get_screen_of_context_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_get_screen_of_context_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_get_screen_of_context_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub root:          xcb_window_t,
}

impl Copy for xcb_x_print_print_get_screen_of_context_reply_t {}
impl Clone for xcb_x_print_print_get_screen_of_context_reply_t {
    fn clone(&self) -> xcb_x_print_print_get_screen_of_context_reply_t { *self }
}

pub const XCB_X_PRINT_PRINT_START_JOB: u8 = 7;

#[repr(C)]
pub struct xcb_x_print_print_start_job_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub output_mode:  u8,
}

impl Copy for xcb_x_print_print_start_job_request_t {}
impl Clone for xcb_x_print_print_start_job_request_t {
    fn clone(&self) -> xcb_x_print_print_start_job_request_t { *self }
}

pub const XCB_X_PRINT_PRINT_END_JOB: u8 = 8;

#[repr(C)]
pub struct xcb_x_print_print_end_job_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub cancel:       u8,
}

impl Copy for xcb_x_print_print_end_job_request_t {}
impl Clone for xcb_x_print_print_end_job_request_t {
    fn clone(&self) -> xcb_x_print_print_end_job_request_t { *self }
}

pub const XCB_X_PRINT_PRINT_START_DOC: u8 = 9;

#[repr(C)]
pub struct xcb_x_print_print_start_doc_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub driver_mode:  u8,
}

impl Copy for xcb_x_print_print_start_doc_request_t {}
impl Clone for xcb_x_print_print_start_doc_request_t {
    fn clone(&self) -> xcb_x_print_print_start_doc_request_t { *self }
}

pub const XCB_X_PRINT_PRINT_END_DOC: u8 = 10;

#[repr(C)]
pub struct xcb_x_print_print_end_doc_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub cancel:       u8,
}

impl Copy for xcb_x_print_print_end_doc_request_t {}
impl Clone for xcb_x_print_print_end_doc_request_t {
    fn clone(&self) -> xcb_x_print_print_end_doc_request_t { *self }
}

pub const XCB_X_PRINT_PRINT_PUT_DOCUMENT_DATA: u8 = 11;

#[repr(C)]
pub struct xcb_x_print_print_put_document_data_request_t {
    pub major_opcode:   u8,
    pub minor_opcode:   u8,
    pub length:         u16,
    pub drawable:       xcb_drawable_t,
    pub len_data:       u32,
    pub len_fmt:        u16,
    pub len_options:    u16,
}

pub const XCB_X_PRINT_PRINT_GET_DOCUMENT_DATA: u8 = 12;

#[repr(C)]
pub struct xcb_x_print_print_get_document_data_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      xcb_x_print_pcontext_t,
    pub max_bytes:    u32,
}

impl Copy for xcb_x_print_print_get_document_data_request_t {}
impl Clone for xcb_x_print_print_get_document_data_request_t {
    fn clone(&self) -> xcb_x_print_print_get_document_data_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_get_document_data_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_get_document_data_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub status_code:   u32,
    pub finished_flag: u32,
    pub dataLen:       u32,
    pub pad1:          [u8; 12],
}

pub const XCB_X_PRINT_PRINT_START_PAGE: u8 = 13;

#[repr(C)]
pub struct xcb_x_print_print_start_page_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub window:       xcb_window_t,
}

impl Copy for xcb_x_print_print_start_page_request_t {}
impl Clone for xcb_x_print_print_start_page_request_t {
    fn clone(&self) -> xcb_x_print_print_start_page_request_t { *self }
}

pub const XCB_X_PRINT_PRINT_END_PAGE: u8 = 14;

#[repr(C)]
pub struct xcb_x_print_print_end_page_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub cancel:       u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_x_print_print_end_page_request_t {}
impl Clone for xcb_x_print_print_end_page_request_t {
    fn clone(&self) -> xcb_x_print_print_end_page_request_t { *self }
}

pub const XCB_X_PRINT_PRINT_SELECT_INPUT: u8 = 15;

#[repr(C)]
pub struct xcb_x_print_print_select_input_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      xcb_x_print_pcontext_t,
    pub event_mask:   u32,
}

pub const XCB_X_PRINT_PRINT_INPUT_SELECTED: u8 = 16;

#[repr(C)]
pub struct xcb_x_print_print_input_selected_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      xcb_x_print_pcontext_t,
}

impl Copy for xcb_x_print_print_input_selected_request_t {}
impl Clone for xcb_x_print_print_input_selected_request_t {
    fn clone(&self) -> xcb_x_print_print_input_selected_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_input_selected_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_input_selected_reply_t {
    pub response_type:   u8,
    pub pad0:            u8,
    pub sequence:        u16,
    pub length:          u32,
    pub event_mask:      u32,
    pub all_events_mask: u32,
}

pub const XCB_X_PRINT_PRINT_GET_ATTRIBUTES: u8 = 17;

#[repr(C)]
pub struct xcb_x_print_print_get_attributes_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      xcb_x_print_pcontext_t,
    pub pool:         u8,
    pub pad0:         [u8; 3],
}

impl Copy for xcb_x_print_print_get_attributes_request_t {}
impl Clone for xcb_x_print_print_get_attributes_request_t {
    fn clone(&self) -> xcb_x_print_print_get_attributes_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_get_attributes_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_get_attributes_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub stringLen:     u32,
    pub pad1:          [u8; 20],
}

pub const XCB_X_PRINT_PRINT_GET_ONE_ATTRIBUTES: u8 = 19;

#[repr(C)]
pub struct xcb_x_print_print_get_one_attributes_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      xcb_x_print_pcontext_t,
    pub nameLen:      u32,
    pub pool:         u8,
    pub pad0:         [u8; 3],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_get_one_attributes_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_get_one_attributes_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub valueLen:      u32,
    pub pad1:          [u8; 20],
}

pub const XCB_X_PRINT_PRINT_SET_ATTRIBUTES: u8 = 18;

#[repr(C)]
pub struct xcb_x_print_print_set_attributes_request_t {
    pub major_opcode:   u8,
    pub minor_opcode:   u8,
    pub length:         u16,
    pub context:        xcb_x_print_pcontext_t,
    pub stringLen:      u32,
    pub pool:           u8,
    pub rule:           u8,
    pub pad0:           [u8; 2],
}

pub const XCB_X_PRINT_PRINT_GET_PAGE_DIMENSIONS: u8 = 21;

#[repr(C)]
pub struct xcb_x_print_print_get_page_dimensions_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      xcb_x_print_pcontext_t,
}

impl Copy for xcb_x_print_print_get_page_dimensions_request_t {}
impl Clone for xcb_x_print_print_get_page_dimensions_request_t {
    fn clone(&self) -> xcb_x_print_print_get_page_dimensions_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_get_page_dimensions_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_get_page_dimensions_reply_t {
    pub response_type:       u8,
    pub pad0:                u8,
    pub sequence:            u16,
    pub length:              u32,
    pub width:               u16,
    pub height:              u16,
    pub offset_x:            u16,
    pub offset_y:            u16,
    pub reproducible_width:  u16,
    pub reproducible_height: u16,
}

impl Copy for xcb_x_print_print_get_page_dimensions_reply_t {}
impl Clone for xcb_x_print_print_get_page_dimensions_reply_t {
    fn clone(&self) -> xcb_x_print_print_get_page_dimensions_reply_t { *self }
}

pub const XCB_X_PRINT_PRINT_QUERY_SCREENS: u8 = 22;

#[repr(C)]
pub struct xcb_x_print_print_query_screens_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
}

impl Copy for xcb_x_print_print_query_screens_request_t {}
impl Clone for xcb_x_print_print_query_screens_request_t {
    fn clone(&self) -> xcb_x_print_print_query_screens_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_query_screens_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_query_screens_reply_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub length:        u32,
    pub listCount:     u32,
    pub pad1:          [u8; 20],
}

pub const XCB_X_PRINT_PRINT_SET_IMAGE_RESOLUTION: u8 = 23;

#[repr(C)]
pub struct xcb_x_print_print_set_image_resolution_request_t {
    pub major_opcode:     u8,
    pub minor_opcode:     u8,
    pub length:           u16,
    pub context:          xcb_x_print_pcontext_t,
    pub image_resolution: u16,
}

impl Copy for xcb_x_print_print_set_image_resolution_request_t {}
impl Clone for xcb_x_print_print_set_image_resolution_request_t {
    fn clone(&self) -> xcb_x_print_print_set_image_resolution_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_set_image_resolution_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_set_image_resolution_reply_t {
    pub response_type:        u8,
    pub status:               u8,
    pub sequence:             u16,
    pub length:               u32,
    pub previous_resolutions: u16,
}

impl Copy for xcb_x_print_print_set_image_resolution_reply_t {}
impl Clone for xcb_x_print_print_set_image_resolution_reply_t {
    fn clone(&self) -> xcb_x_print_print_set_image_resolution_reply_t { *self }
}

pub const XCB_X_PRINT_PRINT_GET_IMAGE_RESOLUTION: u8 = 24;

#[repr(C)]
pub struct xcb_x_print_print_get_image_resolution_request_t {
    pub major_opcode: u8,
    pub minor_opcode: u8,
    pub length:       u16,
    pub context:      xcb_x_print_pcontext_t,
}

impl Copy for xcb_x_print_print_get_image_resolution_request_t {}
impl Clone for xcb_x_print_print_get_image_resolution_request_t {
    fn clone(&self) -> xcb_x_print_print_get_image_resolution_request_t { *self }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_x_print_print_get_image_resolution_cookie_t {
    sequence: c_uint
}

#[repr(C)]
pub struct xcb_x_print_print_get_image_resolution_reply_t {
    pub response_type:    u8,
    pub pad0:             u8,
    pub sequence:         u16,
    pub length:           u32,
    pub image_resolution: u16,
}

impl Copy for xcb_x_print_print_get_image_resolution_reply_t {}
impl Clone for xcb_x_print_print_get_image_resolution_reply_t {
    fn clone(&self) -> xcb_x_print_print_get_image_resolution_reply_t { *self }
}

pub const XCB_X_PRINT_NOTIFY: u8 = 0;

#[repr(C)]
pub struct xcb_x_print_notify_event_t {
    pub response_type: u8,
    pub detail:        u8,
    pub sequence:      u16,
    pub context:       xcb_x_print_pcontext_t,
    pub cancel:        u8,
}

impl Copy for xcb_x_print_notify_event_t {}
impl Clone for xcb_x_print_notify_event_t {
    fn clone(&self) -> xcb_x_print_notify_event_t { *self }
}

pub const XCB_X_PRINT_ATTRIBUT_NOTIFY: u8 = 1;

#[repr(C)]
pub struct xcb_x_print_attribut_notify_event_t {
    pub response_type: u8,
    pub detail:        u8,
    pub sequence:      u16,
    pub context:       xcb_x_print_pcontext_t,
}

impl Copy for xcb_x_print_attribut_notify_event_t {}
impl Clone for xcb_x_print_attribut_notify_event_t {
    fn clone(&self) -> xcb_x_print_attribut_notify_event_t { *self }
}

pub const XCB_X_PRINT_BAD_CONTEXT: u8 = 0;

#[repr(C)]
pub struct xcb_x_print_bad_context_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_x_print_bad_context_error_t {}
impl Clone for xcb_x_print_bad_context_error_t {
    fn clone(&self) -> xcb_x_print_bad_context_error_t { *self }
}

pub const XCB_X_PRINT_BAD_SEQUENCE: u8 = 1;

#[repr(C)]
pub struct xcb_x_print_bad_sequence_error_t {
    pub response_type: u8,
    pub error_code:    u8,
    pub sequence:      u16,
}

impl Copy for xcb_x_print_bad_sequence_error_t {}
impl Clone for xcb_x_print_bad_sequence_error_t {
    fn clone(&self) -> xcb_x_print_bad_sequence_error_t { *self }
}


#[link(name="xcb-xprint")]
extern {

    pub static mut xcb_x_print_id: xcb_extension_t;

    pub fn xcb_x_print_string8_next (i: *mut xcb_x_print_string8_iterator_t);

    pub fn xcb_x_print_string8_end (i: *mut xcb_x_print_string8_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_x_print_printer_name (R: *const xcb_x_print_printer_t)
            -> *mut xcb_x_print_string8_t;

    pub fn xcb_x_print_printer_name_length (R: *const xcb_x_print_printer_t)
            -> c_int;

    pub fn xcb_x_print_printer_name_end (R: *const xcb_x_print_printer_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_x_print_printer_description (R: *const xcb_x_print_printer_t)
            -> *mut xcb_x_print_string8_t;

    pub fn xcb_x_print_printer_description_length (R: *const xcb_x_print_printer_t)
            -> c_int;

    pub fn xcb_x_print_printer_description_end (R: *const xcb_x_print_printer_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_x_print_printer_next (i: *mut xcb_x_print_printer_iterator_t);

    pub fn xcb_x_print_printer_end (i: *mut xcb_x_print_printer_iterator_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_x_print_pcontext_next (i: *mut xcb_x_print_pcontext_iterator_t);

    pub fn xcb_x_print_pcontext_end (i: *mut xcb_x_print_pcontext_iterator_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_query_version_reply (c:      *mut xcb_connection_t,
                                                  cookie: xcb_x_print_print_query_version_cookie_t,
                                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_query_version_reply_t;

    pub fn xcb_x_print_print_query_version (c: *mut xcb_connection_t)
            -> xcb_x_print_print_query_version_cookie_t;

    pub fn xcb_x_print_print_query_version_unchecked (c: *mut xcb_connection_t)
            -> xcb_x_print_print_query_version_cookie_t;

    pub fn xcb_x_print_print_get_printer_list_printers_length (R: *const xcb_x_print_print_get_printer_list_reply_t)
            -> c_int;

    pub fn xcb_x_print_print_get_printer_list_printers_iterator<'a> (R: *const xcb_x_print_print_get_printer_list_reply_t)
            -> xcb_x_print_printer_iterator_t<'a>;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_get_printer_list_reply (c:      *mut xcb_connection_t,
                                                     cookie: xcb_x_print_print_get_printer_list_cookie_t,
                                                     error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_get_printer_list_reply_t;

    pub fn xcb_x_print_print_get_printer_list (c:              *mut xcb_connection_t,
                                               printerNameLen: u32,
                                               localeLen:      u32,
                                               printer_name:   *const xcb_x_print_string8_t,
                                               locale:         *const xcb_x_print_string8_t)
            -> xcb_x_print_print_get_printer_list_cookie_t;

    pub fn xcb_x_print_print_get_printer_list_unchecked (c:              *mut xcb_connection_t,
                                                         printerNameLen: u32,
                                                         localeLen:      u32,
                                                         printer_name:   *const xcb_x_print_string8_t,
                                                         locale:         *const xcb_x_print_string8_t)
            -> xcb_x_print_print_get_printer_list_cookie_t;

    pub fn xcb_x_print_print_rehash_printer_list (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_rehash_printer_list_checked (c: *mut xcb_connection_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_create_context (c:              *mut xcb_connection_t,
                                       context_id:     u32,
                                       printerNameLen: u32,
                                       localeLen:      u32,
                                       printerName:    *const xcb_x_print_string8_t,
                                       locale:         *const xcb_x_print_string8_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_create_context_checked (c:              *mut xcb_connection_t,
                                               context_id:     u32,
                                               printerNameLen: u32,
                                               localeLen:      u32,
                                               printerName:    *const xcb_x_print_string8_t,
                                               locale:         *const xcb_x_print_string8_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_set_context (c:       *mut xcb_connection_t,
                                          context: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_set_context_checked (c:       *mut xcb_connection_t,
                                                  context: u32)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_get_context_reply (c:      *mut xcb_connection_t,
                                                cookie: xcb_x_print_print_get_context_cookie_t,
                                                error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_get_context_reply_t;

    pub fn xcb_x_print_print_get_context (c: *mut xcb_connection_t)
            -> xcb_x_print_print_get_context_cookie_t;

    pub fn xcb_x_print_print_get_context_unchecked (c: *mut xcb_connection_t)
            -> xcb_x_print_print_get_context_cookie_t;

    pub fn xcb_x_print_print_destroy_context (c:       *mut xcb_connection_t,
                                              context: u32)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_destroy_context_checked (c:       *mut xcb_connection_t,
                                                      context: u32)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_get_screen_of_context_reply (c:      *mut xcb_connection_t,
                                                          cookie: xcb_x_print_print_get_screen_of_context_cookie_t,
                                                          error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_get_screen_of_context_reply_t;

    pub fn xcb_x_print_print_get_screen_of_context (c: *mut xcb_connection_t)
            -> xcb_x_print_print_get_screen_of_context_cookie_t;

    pub fn xcb_x_print_print_get_screen_of_context_unchecked (c: *mut xcb_connection_t)
            -> xcb_x_print_print_get_screen_of_context_cookie_t;

    pub fn xcb_x_print_print_start_job (c:           *mut xcb_connection_t,
                                        output_mode: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_start_job_checked (c:           *mut xcb_connection_t,
                                                output_mode: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_end_job (c:      *mut xcb_connection_t,
                                      cancel: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_end_job_checked (c:      *mut xcb_connection_t,
                                              cancel: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_start_doc (c:           *mut xcb_connection_t,
                                        driver_mode: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_start_doc_checked (c:           *mut xcb_connection_t,
                                                driver_mode: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_end_doc (c:      *mut xcb_connection_t,
                                      cancel: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_end_doc_checked (c:      *mut xcb_connection_t,
                                              cancel: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_put_document_data (c:              *mut xcb_connection_t,
                                                drawable:       xcb_drawable_t,
                                                len_data:       u32,
                                                len_fmt:        u16,
                                                len_options:    u16,
                                                data:           *const u8,
                                                doc_format_len: u32,
                                                doc_format:     *const xcb_x_print_string8_t,
                                                options_len:    u32,
                                                options:        *const xcb_x_print_string8_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_put_document_data_checked (c:              *mut xcb_connection_t,
                                                        drawable:       xcb_drawable_t,
                                                        len_data:       u32,
                                                        len_fmt:        u16,
                                                        len_options:    u16,
                                                        data:           *const u8,
                                                        doc_format_len: u32,
                                                        doc_format:     *const xcb_x_print_string8_t,
                                                        options_len:    u32,
                                                        options:        *const xcb_x_print_string8_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_get_document_data_data (R: *const xcb_x_print_print_get_document_data_reply_t)
            -> *mut u8;

    pub fn xcb_x_print_print_get_document_data_data_length (R: *const xcb_x_print_print_get_document_data_reply_t)
            -> c_int;

    pub fn xcb_x_print_print_get_document_data_data_end (R: *const xcb_x_print_print_get_document_data_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_get_document_data_reply (c:      *mut xcb_connection_t,
                                                      cookie: xcb_x_print_print_get_document_data_cookie_t,
                                                      error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_get_document_data_reply_t;

    pub fn xcb_x_print_print_get_document_data (c:         *mut xcb_connection_t,
                                                context:   xcb_x_print_pcontext_t,
                                                max_bytes: u32)
            -> xcb_x_print_print_get_document_data_cookie_t;

    pub fn xcb_x_print_print_get_document_data_unchecked (c:         *mut xcb_connection_t,
                                                          context:   xcb_x_print_pcontext_t,
                                                          max_bytes: u32)
            -> xcb_x_print_print_get_document_data_cookie_t;

    pub fn xcb_x_print_print_start_page (c:      *mut xcb_connection_t,
                                         window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_start_page_checked (c:      *mut xcb_connection_t,
                                                 window: xcb_window_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_end_page (c:      *mut xcb_connection_t,
                                       cancel: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_end_page_checked (c:      *mut xcb_connection_t,
                                               cancel: u8)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_select_input (c:          *mut xcb_connection_t,
                                           context:    xcb_x_print_pcontext_t,
                                           event_mask: u32,
                                           event_list: *const u32)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_select_input_checked (c:          *mut xcb_connection_t,
                                                   context:    xcb_x_print_pcontext_t,
                                                   event_mask: u32,
                                                   event_list: *const u32)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_input_selected_event_list (R: *const xcb_x_print_print_input_selected_reply_t)
            -> *mut u32;

    pub fn xcb_x_print_print_input_selected_event_list_length (R: *const xcb_x_print_print_input_selected_reply_t)
            -> c_int;

    pub fn xcb_x_print_print_input_selected_event_list_end (R: *const xcb_x_print_print_input_selected_reply_t)
            -> xcb_generic_iterator_t;

    pub fn xcb_x_print_print_input_selected_all_events_list (R: *const xcb_x_print_print_input_selected_reply_t)
            -> *mut u32;

    pub fn xcb_x_print_print_input_selected_all_events_list_length (R: *const xcb_x_print_print_input_selected_reply_t)
            -> c_int;

    pub fn xcb_x_print_print_input_selected_all_events_list_end (R: *const xcb_x_print_print_input_selected_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_input_selected_reply (c:      *mut xcb_connection_t,
                                                   cookie: xcb_x_print_print_input_selected_cookie_t,
                                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_input_selected_reply_t;

    pub fn xcb_x_print_print_input_selected (c:       *mut xcb_connection_t,
                                             context: xcb_x_print_pcontext_t)
            -> xcb_x_print_print_input_selected_cookie_t;

    pub fn xcb_x_print_print_input_selected_unchecked (c:       *mut xcb_connection_t,
                                                       context: xcb_x_print_pcontext_t)
            -> xcb_x_print_print_input_selected_cookie_t;

    pub fn xcb_x_print_print_get_attributes_attributes (R: *const xcb_x_print_print_get_attributes_reply_t)
            -> *mut xcb_x_print_string8_t;

    pub fn xcb_x_print_print_get_attributes_attributes_length (R: *const xcb_x_print_print_get_attributes_reply_t)
            -> c_int;

    pub fn xcb_x_print_print_get_attributes_attributes_end (R: *const xcb_x_print_print_get_attributes_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_get_attributes_reply (c:      *mut xcb_connection_t,
                                                   cookie: xcb_x_print_print_get_attributes_cookie_t,
                                                   error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_get_attributes_reply_t;

    pub fn xcb_x_print_print_get_attributes (c:       *mut xcb_connection_t,
                                             context: xcb_x_print_pcontext_t,
                                             pool:    u8)
            -> xcb_x_print_print_get_attributes_cookie_t;

    pub fn xcb_x_print_print_get_attributes_unchecked (c:       *mut xcb_connection_t,
                                                       context: xcb_x_print_pcontext_t,
                                                       pool:    u8)
            -> xcb_x_print_print_get_attributes_cookie_t;

    pub fn xcb_x_print_print_get_one_attributes_value (R: *const xcb_x_print_print_get_one_attributes_reply_t)
            -> *mut xcb_x_print_string8_t;

    pub fn xcb_x_print_print_get_one_attributes_value_length (R: *const xcb_x_print_print_get_one_attributes_reply_t)
            -> c_int;

    pub fn xcb_x_print_print_get_one_attributes_value_end (R: *const xcb_x_print_print_get_one_attributes_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_get_one_attributes_reply (c:      *mut xcb_connection_t,
                                                       cookie: xcb_x_print_print_get_one_attributes_cookie_t,
                                                       error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_get_one_attributes_reply_t;

    pub fn xcb_x_print_print_get_one_attributes (c:       *mut xcb_connection_t,
                                                 context: xcb_x_print_pcontext_t,
                                                 nameLen: u32,
                                                 pool:    u8,
                                                 name:    *const xcb_x_print_string8_t)
            -> xcb_x_print_print_get_one_attributes_cookie_t;

    pub fn xcb_x_print_print_get_one_attributes_unchecked (c:       *mut xcb_connection_t,
                                                           context: xcb_x_print_pcontext_t,
                                                           nameLen: u32,
                                                           pool:    u8,
                                                           name:    *const xcb_x_print_string8_t)
            -> xcb_x_print_print_get_one_attributes_cookie_t;

    pub fn xcb_x_print_print_set_attributes (c:              *mut xcb_connection_t,
                                             context:        xcb_x_print_pcontext_t,
                                             stringLen:      u32,
                                             pool:           u8,
                                             rule:           u8,
                                             attributes_len: u32,
                                             attributes:     *const xcb_x_print_string8_t)
            -> xcb_void_cookie_t;

    pub fn xcb_x_print_print_set_attributes_checked (c:              *mut xcb_connection_t,
                                                     context:        xcb_x_print_pcontext_t,
                                                     stringLen:      u32,
                                                     pool:           u8,
                                                     rule:           u8,
                                                     attributes_len: u32,
                                                     attributes:     *const xcb_x_print_string8_t)
            -> xcb_void_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_get_page_dimensions_reply (c:      *mut xcb_connection_t,
                                                        cookie: xcb_x_print_print_get_page_dimensions_cookie_t,
                                                        error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_get_page_dimensions_reply_t;

    pub fn xcb_x_print_print_get_page_dimensions (c:       *mut xcb_connection_t,
                                                  context: xcb_x_print_pcontext_t)
            -> xcb_x_print_print_get_page_dimensions_cookie_t;

    pub fn xcb_x_print_print_get_page_dimensions_unchecked (c:       *mut xcb_connection_t,
                                                            context: xcb_x_print_pcontext_t)
            -> xcb_x_print_print_get_page_dimensions_cookie_t;

    pub fn xcb_x_print_print_query_screens_roots (R: *const xcb_x_print_print_query_screens_reply_t)
            -> *mut xcb_window_t;

    pub fn xcb_x_print_print_query_screens_roots_length (R: *const xcb_x_print_print_query_screens_reply_t)
            -> c_int;

    pub fn xcb_x_print_print_query_screens_roots_end (R: *const xcb_x_print_print_query_screens_reply_t)
            -> xcb_generic_iterator_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_query_screens_reply (c:      *mut xcb_connection_t,
                                                  cookie: xcb_x_print_print_query_screens_cookie_t,
                                                  error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_query_screens_reply_t;

    pub fn xcb_x_print_print_query_screens (c: *mut xcb_connection_t)
            -> xcb_x_print_print_query_screens_cookie_t;

    pub fn xcb_x_print_print_query_screens_unchecked (c: *mut xcb_connection_t)
            -> xcb_x_print_print_query_screens_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_set_image_resolution_reply (c:      *mut xcb_connection_t,
                                                         cookie: xcb_x_print_print_set_image_resolution_cookie_t,
                                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_set_image_resolution_reply_t;

    pub fn xcb_x_print_print_set_image_resolution (c:                *mut xcb_connection_t,
                                                   context:          xcb_x_print_pcontext_t,
                                                   image_resolution: u16)
            -> xcb_x_print_print_set_image_resolution_cookie_t;

    pub fn xcb_x_print_print_set_image_resolution_unchecked (c:                *mut xcb_connection_t,
                                                             context:          xcb_x_print_pcontext_t,
                                                             image_resolution: u16)
            -> xcb_x_print_print_set_image_resolution_cookie_t;

    /// the returned value must be freed by the caller using libc::free().
    pub fn xcb_x_print_print_get_image_resolution_reply (c:      *mut xcb_connection_t,
                                                         cookie: xcb_x_print_print_get_image_resolution_cookie_t,
                                                         error:  *mut *mut xcb_generic_error_t)
            -> *mut xcb_x_print_print_get_image_resolution_reply_t;

    pub fn xcb_x_print_print_get_image_resolution (c:       *mut xcb_connection_t,
                                                   context: xcb_x_print_pcontext_t)
            -> xcb_x_print_print_get_image_resolution_cookie_t;

    pub fn xcb_x_print_print_get_image_resolution_unchecked (c:       *mut xcb_connection_t,
                                                             context: xcb_x_print_pcontext_t)
            -> xcb_x_print_print_get_image_resolution_cookie_t;

} // extern
