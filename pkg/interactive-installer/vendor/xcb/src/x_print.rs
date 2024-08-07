// Generated automatically from xprint.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::x_print::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_x_print_id
    }
}

pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 0;

pub type String8 = xcb_x_print_string8_t;

pub type Pcontext = xcb_x_print_pcontext_t;

pub type GetDoc = u32;
pub const GET_DOC_FINISHED       : GetDoc = 0x00;
pub const GET_DOC_SECOND_CONSUMER: GetDoc = 0x01;

pub type EvMask = u32;
pub const EV_MASK_NO_EVENT_MASK : EvMask = 0x00;
pub const EV_MASK_PRINT_MASK    : EvMask = 0x01;
pub const EV_MASK_ATTRIBUTE_MASK: EvMask = 0x02;

pub type Detail = u32;
pub const DETAIL_START_JOB_NOTIFY : Detail = 0x01;
pub const DETAIL_END_JOB_NOTIFY   : Detail = 0x02;
pub const DETAIL_START_DOC_NOTIFY : Detail = 0x03;
pub const DETAIL_END_DOC_NOTIFY   : Detail = 0x04;
pub const DETAIL_START_PAGE_NOTIFY: Detail = 0x05;
pub const DETAIL_END_PAGE_NOTIFY  : Detail = 0x06;

pub type Attr = u32;
pub const ATTR_JOB_ATTR    : Attr = 0x01;
pub const ATTR_DOC_ATTR    : Attr = 0x02;
pub const ATTR_PAGE_ATTR   : Attr = 0x03;
pub const ATTR_PRINTER_ATTR: Attr = 0x04;
pub const ATTR_SERVER_ATTR : Attr = 0x05;
pub const ATTR_MEDIUM_ATTR : Attr = 0x06;
pub const ATTR_SPOOLER_ATTR: Attr = 0x07;

pub struct BadContextError {
    pub base: base::Error<xcb_x_print_bad_context_error_t>
}

pub struct BadSequenceError {
    pub base: base::Error<xcb_x_print_bad_sequence_error_t>
}



pub type Printer<'a> = base::StructPtr<'a, xcb_x_print_printer_t>;

impl<'a> Printer<'a> {
    pub fn name_len(&self) -> u32 {
        unsafe {
            (*self.ptr).nameLen
        }
    }
    pub fn name(&self) -> &[String8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_x_print_printer_name_length(field) as usize;
            let data = xcb_x_print_printer_name(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn desc_len(&self) -> u32 {
        unsafe {
            (*self.ptr).descLen
        }
    }
    pub fn description(&self) -> &[String8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_x_print_printer_description_length(field) as usize;
            let data = xcb_x_print_printer_description(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub type PrinterIterator<'a> = xcb_x_print_printer_iterator_t<'a>;

impl<'a> Iterator for PrinterIterator<'a> {
    type Item = Printer<'a>;
    fn next(&mut self) -> std::option::Option<Printer<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_x_print_printer_iterator_t;
                let data = (*iter).data;
                xcb_x_print_printer_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

pub const PRINT_QUERY_VERSION: u8 = 0;

pub type PrintQueryVersionCookie<'a> = base::Cookie<'a, xcb_x_print_print_query_version_cookie_t>;

impl<'a> PrintQueryVersionCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintQueryVersionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintQueryVersionReply {
                    ptr: xcb_x_print_print_query_version_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintQueryVersionReply {
                    ptr: xcb_x_print_print_query_version_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintQueryVersionReply = base::Reply<xcb_x_print_print_query_version_reply_t>;

impl PrintQueryVersionReply {
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

pub fn print_query_version<'a>(c: &'a base::Connection)
        -> PrintQueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_query_version(c.get_raw_conn());
        PrintQueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_query_version_unchecked<'a>(c: &'a base::Connection)
        -> PrintQueryVersionCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_query_version_unchecked(c.get_raw_conn());
        PrintQueryVersionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_GET_PRINTER_LIST: u8 = 1;

pub type PrintGetPrinterListCookie<'a> = base::Cookie<'a, xcb_x_print_print_get_printer_list_cookie_t>;

impl<'a> PrintGetPrinterListCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintGetPrinterListReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintGetPrinterListReply {
                    ptr: xcb_x_print_print_get_printer_list_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintGetPrinterListReply {
                    ptr: xcb_x_print_print_get_printer_list_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintGetPrinterListReply = base::Reply<xcb_x_print_print_get_printer_list_reply_t>;

impl PrintGetPrinterListReply {
    pub fn list_count(&self) -> u32 {
        unsafe {
            (*self.ptr).listCount
        }
    }
    pub fn printers(&self) -> PrinterIterator {
        unsafe {
            xcb_x_print_print_get_printer_list_printers_iterator(self.ptr)
        }
    }
}

pub fn print_get_printer_list<'a>(c           : &'a base::Connection,
                                  printer_name: &[String8],
                                  locale      : &[String8])
        -> PrintGetPrinterListCookie<'a> {
    unsafe {
        let printer_name_len = printer_name.len();
        let printer_name_ptr = printer_name.as_ptr();
        let locale_len = locale.len();
        let locale_ptr = locale.as_ptr();
        let cookie = xcb_x_print_print_get_printer_list(c.get_raw_conn(),
                                                        printer_name_len as u32,  // 0
                                                        locale_len as u32,  // 1
                                                        printer_name_ptr as *const xcb_x_print_string8_t,  // 2
                                                        locale_ptr as *const xcb_x_print_string8_t);  // 3
        PrintGetPrinterListCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_get_printer_list_unchecked<'a>(c           : &'a base::Connection,
                                            printer_name: &[String8],
                                            locale      : &[String8])
        -> PrintGetPrinterListCookie<'a> {
    unsafe {
        let printer_name_len = printer_name.len();
        let printer_name_ptr = printer_name.as_ptr();
        let locale_len = locale.len();
        let locale_ptr = locale.as_ptr();
        let cookie = xcb_x_print_print_get_printer_list_unchecked(c.get_raw_conn(),
                                                                  printer_name_len as u32,  // 0
                                                                  locale_len as u32,  // 1
                                                                  printer_name_ptr as *const xcb_x_print_string8_t,  // 2
                                                                  locale_ptr as *const xcb_x_print_string8_t);  // 3
        PrintGetPrinterListCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_REHASH_PRINTER_LIST: u8 = 20;

pub fn print_rehash_printer_list<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_rehash_printer_list(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_rehash_printer_list_checked<'a>(c: &'a base::Connection)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_rehash_printer_list_checked(c.get_raw_conn());
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CREATE_CONTEXT: u8 = 2;

pub fn create_context<'a>(c           : &'a base::Connection,
                          context_id  : u32,
                          printer_name: &[String8],
                          locale      : &[String8])
        -> base::VoidCookie<'a> {
    unsafe {
        let printer_name_len = printer_name.len();
        let printer_name_ptr = printer_name.as_ptr();
        let locale_len = locale.len();
        let locale_ptr = locale.as_ptr();
        let cookie = xcb_x_print_create_context(c.get_raw_conn(),
                                                context_id as u32,  // 0
                                                printer_name_len as u32,  // 1
                                                locale_len as u32,  // 2
                                                printer_name_ptr as *const xcb_x_print_string8_t,  // 3
                                                locale_ptr as *const xcb_x_print_string8_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_context_checked<'a>(c           : &'a base::Connection,
                                  context_id  : u32,
                                  printer_name: &[String8],
                                  locale      : &[String8])
        -> base::VoidCookie<'a> {
    unsafe {
        let printer_name_len = printer_name.len();
        let printer_name_ptr = printer_name.as_ptr();
        let locale_len = locale.len();
        let locale_ptr = locale.as_ptr();
        let cookie = xcb_x_print_create_context_checked(c.get_raw_conn(),
                                                        context_id as u32,  // 0
                                                        printer_name_len as u32,  // 1
                                                        locale_len as u32,  // 2
                                                        printer_name_ptr as *const xcb_x_print_string8_t,  // 3
                                                        locale_ptr as *const xcb_x_print_string8_t);  // 4
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_SET_CONTEXT: u8 = 3;

pub fn print_set_context<'a>(c      : &'a base::Connection,
                             context: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_set_context(c.get_raw_conn(),
                                                   context as u32);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_set_context_checked<'a>(c      : &'a base::Connection,
                                     context: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_set_context_checked(c.get_raw_conn(),
                                                           context as u32);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_GET_CONTEXT: u8 = 4;

pub type PrintGetContextCookie<'a> = base::Cookie<'a, xcb_x_print_print_get_context_cookie_t>;

impl<'a> PrintGetContextCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintGetContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintGetContextReply {
                    ptr: xcb_x_print_print_get_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintGetContextReply {
                    ptr: xcb_x_print_print_get_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintGetContextReply = base::Reply<xcb_x_print_print_get_context_reply_t>;

impl PrintGetContextReply {
    pub fn context(&self) -> u32 {
        unsafe {
            (*self.ptr).context
        }
    }
}

pub fn print_get_context<'a>(c: &'a base::Connection)
        -> PrintGetContextCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_context(c.get_raw_conn());
        PrintGetContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_get_context_unchecked<'a>(c: &'a base::Connection)
        -> PrintGetContextCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_context_unchecked(c.get_raw_conn());
        PrintGetContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_DESTROY_CONTEXT: u8 = 5;

pub fn print_destroy_context<'a>(c      : &'a base::Connection,
                                 context: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_destroy_context(c.get_raw_conn(),
                                                       context as u32);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_destroy_context_checked<'a>(c      : &'a base::Connection,
                                         context: u32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_destroy_context_checked(c.get_raw_conn(),
                                                               context as u32);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_GET_SCREEN_OF_CONTEXT: u8 = 6;

pub type PrintGetScreenOfContextCookie<'a> = base::Cookie<'a, xcb_x_print_print_get_screen_of_context_cookie_t>;

impl<'a> PrintGetScreenOfContextCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintGetScreenOfContextReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintGetScreenOfContextReply {
                    ptr: xcb_x_print_print_get_screen_of_context_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintGetScreenOfContextReply {
                    ptr: xcb_x_print_print_get_screen_of_context_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintGetScreenOfContextReply = base::Reply<xcb_x_print_print_get_screen_of_context_reply_t>;

impl PrintGetScreenOfContextReply {
    pub fn root(&self) -> xproto::Window {
        unsafe {
            (*self.ptr).root
        }
    }
}

pub fn print_get_screen_of_context<'a>(c: &'a base::Connection)
        -> PrintGetScreenOfContextCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_screen_of_context(c.get_raw_conn());
        PrintGetScreenOfContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_get_screen_of_context_unchecked<'a>(c: &'a base::Connection)
        -> PrintGetScreenOfContextCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_screen_of_context_unchecked(c.get_raw_conn());
        PrintGetScreenOfContextCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_START_JOB: u8 = 7;

pub fn print_start_job<'a>(c          : &'a base::Connection,
                           output_mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_start_job(c.get_raw_conn(),
                                                 output_mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_start_job_checked<'a>(c          : &'a base::Connection,
                                   output_mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_start_job_checked(c.get_raw_conn(),
                                                         output_mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_END_JOB: u8 = 8;

pub fn print_end_job<'a>(c     : &'a base::Connection,
                         cancel: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_end_job(c.get_raw_conn(),
                                               cancel as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_end_job_checked<'a>(c     : &'a base::Connection,
                                 cancel: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_end_job_checked(c.get_raw_conn(),
                                                       cancel as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_START_DOC: u8 = 9;

pub fn print_start_doc<'a>(c          : &'a base::Connection,
                           driver_mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_start_doc(c.get_raw_conn(),
                                                 driver_mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_start_doc_checked<'a>(c          : &'a base::Connection,
                                   driver_mode: u8)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_start_doc_checked(c.get_raw_conn(),
                                                         driver_mode as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_END_DOC: u8 = 10;

pub fn print_end_doc<'a>(c     : &'a base::Connection,
                         cancel: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_end_doc(c.get_raw_conn(),
                                               cancel as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_end_doc_checked<'a>(c     : &'a base::Connection,
                                 cancel: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_end_doc_checked(c.get_raw_conn(),
                                                       cancel as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_PUT_DOCUMENT_DATA: u8 = 11;

pub fn print_put_document_data<'a>(c          : &'a base::Connection,
                                   drawable   : xproto::Drawable,
                                   len_fmt    : u16,
                                   len_options: u16,
                                   data       : &[u8],
                                   doc_format : &[String8],
                                   options    : &[String8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let doc_format_len = doc_format.len();
        let doc_format_ptr = doc_format.as_ptr();
        let options_len = options.len();
        let options_ptr = options.as_ptr();
        let cookie = xcb_x_print_print_put_document_data(c.get_raw_conn(),
                                                         drawable as xcb_drawable_t,  // 0
                                                         data_len as u32,  // 1
                                                         len_fmt as u16,  // 2
                                                         len_options as u16,  // 3
                                                         data_ptr as *const u8,  // 4
                                                         doc_format_len as u32,  // 5
                                                         doc_format_ptr as *const xcb_x_print_string8_t,  // 6
                                                         options_len as u32,  // 7
                                                         options_ptr as *const xcb_x_print_string8_t);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_put_document_data_checked<'a>(c          : &'a base::Connection,
                                           drawable   : xproto::Drawable,
                                           len_fmt    : u16,
                                           len_options: u16,
                                           data       : &[u8],
                                           doc_format : &[String8],
                                           options    : &[String8])
        -> base::VoidCookie<'a> {
    unsafe {
        let data_len = data.len();
        let data_ptr = data.as_ptr();
        let doc_format_len = doc_format.len();
        let doc_format_ptr = doc_format.as_ptr();
        let options_len = options.len();
        let options_ptr = options.as_ptr();
        let cookie = xcb_x_print_print_put_document_data_checked(c.get_raw_conn(),
                                                                 drawable as xcb_drawable_t,  // 0
                                                                 data_len as u32,  // 1
                                                                 len_fmt as u16,  // 2
                                                                 len_options as u16,  // 3
                                                                 data_ptr as *const u8,  // 4
                                                                 doc_format_len as u32,  // 5
                                                                 doc_format_ptr as *const xcb_x_print_string8_t,  // 6
                                                                 options_len as u32,  // 7
                                                                 options_ptr as *const xcb_x_print_string8_t);  // 8
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_GET_DOCUMENT_DATA: u8 = 12;

pub type PrintGetDocumentDataCookie<'a> = base::Cookie<'a, xcb_x_print_print_get_document_data_cookie_t>;

impl<'a> PrintGetDocumentDataCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintGetDocumentDataReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintGetDocumentDataReply {
                    ptr: xcb_x_print_print_get_document_data_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintGetDocumentDataReply {
                    ptr: xcb_x_print_print_get_document_data_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintGetDocumentDataReply = base::Reply<xcb_x_print_print_get_document_data_reply_t>;

impl PrintGetDocumentDataReply {
    pub fn status_code(&self) -> u32 {
        unsafe {
            (*self.ptr).status_code
        }
    }
    pub fn finished_flag(&self) -> u32 {
        unsafe {
            (*self.ptr).finished_flag
        }
    }
    pub fn data_len(&self) -> u32 {
        unsafe {
            (*self.ptr).dataLen
        }
    }
    pub fn data(&self) -> &[u8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_x_print_print_get_document_data_data_length(field) as usize;
            let data = xcb_x_print_print_get_document_data_data(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn print_get_document_data<'a>(c        : &'a base::Connection,
                                   context  : Pcontext,
                                   max_bytes: u32)
        -> PrintGetDocumentDataCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_document_data(c.get_raw_conn(),
                                                         context as xcb_x_print_pcontext_t,  // 0
                                                         max_bytes as u32);  // 1
        PrintGetDocumentDataCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_get_document_data_unchecked<'a>(c        : &'a base::Connection,
                                             context  : Pcontext,
                                             max_bytes: u32)
        -> PrintGetDocumentDataCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_document_data_unchecked(c.get_raw_conn(),
                                                                   context as xcb_x_print_pcontext_t,  // 0
                                                                   max_bytes as u32);  // 1
        PrintGetDocumentDataCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_START_PAGE: u8 = 13;

pub fn print_start_page<'a>(c     : &'a base::Connection,
                            window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_start_page(c.get_raw_conn(),
                                                  window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_start_page_checked<'a>(c     : &'a base::Connection,
                                    window: xproto::Window)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_start_page_checked(c.get_raw_conn(),
                                                          window as xcb_window_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_END_PAGE: u8 = 14;

pub fn print_end_page<'a>(c     : &'a base::Connection,
                          cancel: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_end_page(c.get_raw_conn(),
                                                cancel as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_end_page_checked<'a>(c     : &'a base::Connection,
                                  cancel: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_end_page_checked(c.get_raw_conn(),
                                                        cancel as u8);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_SELECT_INPUT: u8 = 15;

pub fn print_select_input<'a>(c         : &'a base::Connection,
                              context   : Pcontext,
                              event_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut event_list_copy = event_list.to_vec();
        let (event_list_mask, event_list_vec) = base::pack_bitfield(&mut event_list_copy);
        let event_list_ptr = event_list_vec.as_ptr();
        let cookie = xcb_x_print_print_select_input(c.get_raw_conn(),
                                                    context as xcb_x_print_pcontext_t,  // 0
                                                    event_list_mask as u32,  // 1
                                                    event_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_select_input_checked<'a>(c         : &'a base::Connection,
                                      context   : Pcontext,
                                      event_list: &[(u32, u32)])
        -> base::VoidCookie<'a> {
    unsafe {
        let mut event_list_copy = event_list.to_vec();
        let (event_list_mask, event_list_vec) = base::pack_bitfield(&mut event_list_copy);
        let event_list_ptr = event_list_vec.as_ptr();
        let cookie = xcb_x_print_print_select_input_checked(c.get_raw_conn(),
                                                            context as xcb_x_print_pcontext_t,  // 0
                                                            event_list_mask as u32,  // 1
                                                            event_list_ptr as *const u32);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_INPUT_SELECTED: u8 = 16;

pub type PrintInputSelectedCookie<'a> = base::Cookie<'a, xcb_x_print_print_input_selected_cookie_t>;

impl<'a> PrintInputSelectedCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintInputSelectedReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintInputSelectedReply {
                    ptr: xcb_x_print_print_input_selected_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintInputSelectedReply {
                    ptr: xcb_x_print_print_input_selected_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintInputSelectedReply = base::Reply<xcb_x_print_print_input_selected_reply_t>;

impl PrintInputSelectedReply {
    pub fn event_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).event_mask
        }
    }
    pub fn event_list(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_x_print_print_input_selected_event_list_length(field) as usize;
            let data = xcb_x_print_print_input_selected_event_list(field);
            std::slice::from_raw_parts(data, len)
        }
    }
    pub fn all_events_mask(&self) -> u32 {
        unsafe {
            (*self.ptr).all_events_mask
        }
    }
    pub fn all_events_list(&self) -> &[u32] {
        unsafe {
            let field = self.ptr;
            let len = xcb_x_print_print_input_selected_all_events_list_length(field) as usize;
            let data = xcb_x_print_print_input_selected_all_events_list(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn print_input_selected<'a>(c      : &'a base::Connection,
                                context: Pcontext)
        -> PrintInputSelectedCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_input_selected(c.get_raw_conn(),
                                                      context as xcb_x_print_pcontext_t);  // 0
        PrintInputSelectedCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_input_selected_unchecked<'a>(c      : &'a base::Connection,
                                          context: Pcontext)
        -> PrintInputSelectedCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_input_selected_unchecked(c.get_raw_conn(),
                                                                context as xcb_x_print_pcontext_t);  // 0
        PrintInputSelectedCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_GET_ATTRIBUTES: u8 = 17;

pub type PrintGetAttributesCookie<'a> = base::Cookie<'a, xcb_x_print_print_get_attributes_cookie_t>;

impl<'a> PrintGetAttributesCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintGetAttributesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintGetAttributesReply {
                    ptr: xcb_x_print_print_get_attributes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintGetAttributesReply {
                    ptr: xcb_x_print_print_get_attributes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintGetAttributesReply = base::Reply<xcb_x_print_print_get_attributes_reply_t>;

impl PrintGetAttributesReply {
    pub fn string_len(&self) -> u32 {
        unsafe {
            (*self.ptr).stringLen
        }
    }
    pub fn attributes(&self) -> &[String8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_x_print_print_get_attributes_attributes_length(field) as usize;
            let data = xcb_x_print_print_get_attributes_attributes(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn print_get_attributes<'a>(c      : &'a base::Connection,
                                context: Pcontext,
                                pool   : u8)
        -> PrintGetAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_attributes(c.get_raw_conn(),
                                                      context as xcb_x_print_pcontext_t,  // 0
                                                      pool as u8);  // 1
        PrintGetAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_get_attributes_unchecked<'a>(c      : &'a base::Connection,
                                          context: Pcontext,
                                          pool   : u8)
        -> PrintGetAttributesCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_attributes_unchecked(c.get_raw_conn(),
                                                                context as xcb_x_print_pcontext_t,  // 0
                                                                pool as u8);  // 1
        PrintGetAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_GET_ONE_ATTRIBUTES: u8 = 19;

pub type PrintGetOneAttributesCookie<'a> = base::Cookie<'a, xcb_x_print_print_get_one_attributes_cookie_t>;

impl<'a> PrintGetOneAttributesCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintGetOneAttributesReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintGetOneAttributesReply {
                    ptr: xcb_x_print_print_get_one_attributes_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintGetOneAttributesReply {
                    ptr: xcb_x_print_print_get_one_attributes_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintGetOneAttributesReply = base::Reply<xcb_x_print_print_get_one_attributes_reply_t>;

impl PrintGetOneAttributesReply {
    pub fn value_len(&self) -> u32 {
        unsafe {
            (*self.ptr).valueLen
        }
    }
    pub fn value(&self) -> &[String8] {
        unsafe {
            let field = self.ptr;
            let len = xcb_x_print_print_get_one_attributes_value_length(field) as usize;
            let data = xcb_x_print_print_get_one_attributes_value(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn print_get_one_attributes<'a>(c      : &'a base::Connection,
                                    context: Pcontext,
                                    pool   : u8,
                                    name   : &[String8])
        -> PrintGetOneAttributesCookie<'a> {
    unsafe {
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_x_print_print_get_one_attributes(c.get_raw_conn(),
                                                          context as xcb_x_print_pcontext_t,  // 0
                                                          name_len as u32,  // 1
                                                          pool as u8,  // 2
                                                          name_ptr as *const xcb_x_print_string8_t);  // 3
        PrintGetOneAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_get_one_attributes_unchecked<'a>(c      : &'a base::Connection,
                                              context: Pcontext,
                                              pool   : u8,
                                              name   : &[String8])
        -> PrintGetOneAttributesCookie<'a> {
    unsafe {
        let name_len = name.len();
        let name_ptr = name.as_ptr();
        let cookie = xcb_x_print_print_get_one_attributes_unchecked(c.get_raw_conn(),
                                                                    context as xcb_x_print_pcontext_t,  // 0
                                                                    name_len as u32,  // 1
                                                                    pool as u8,  // 2
                                                                    name_ptr as *const xcb_x_print_string8_t);  // 3
        PrintGetOneAttributesCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_SET_ATTRIBUTES: u8 = 18;

pub fn print_set_attributes<'a>(c         : &'a base::Connection,
                                context   : Pcontext,
                                string_len: u32,
                                pool      : u8,
                                rule      : u8,
                                attributes: &[String8])
        -> base::VoidCookie<'a> {
    unsafe {
        let attributes_len = attributes.len();
        let attributes_ptr = attributes.as_ptr();
        let cookie = xcb_x_print_print_set_attributes(c.get_raw_conn(),
                                                      context as xcb_x_print_pcontext_t,  // 0
                                                      string_len as u32,  // 1
                                                      pool as u8,  // 2
                                                      rule as u8,  // 3
                                                      attributes_len as u32,  // 4
                                                      attributes_ptr as *const xcb_x_print_string8_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn print_set_attributes_checked<'a>(c         : &'a base::Connection,
                                        context   : Pcontext,
                                        string_len: u32,
                                        pool      : u8,
                                        rule      : u8,
                                        attributes: &[String8])
        -> base::VoidCookie<'a> {
    unsafe {
        let attributes_len = attributes.len();
        let attributes_ptr = attributes.as_ptr();
        let cookie = xcb_x_print_print_set_attributes_checked(c.get_raw_conn(),
                                                              context as xcb_x_print_pcontext_t,  // 0
                                                              string_len as u32,  // 1
                                                              pool as u8,  // 2
                                                              rule as u8,  // 3
                                                              attributes_len as u32,  // 4
                                                              attributes_ptr as *const xcb_x_print_string8_t);  // 5
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const PRINT_GET_PAGE_DIMENSIONS: u8 = 21;

pub type PrintGetPageDimensionsCookie<'a> = base::Cookie<'a, xcb_x_print_print_get_page_dimensions_cookie_t>;

impl<'a> PrintGetPageDimensionsCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintGetPageDimensionsReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintGetPageDimensionsReply {
                    ptr: xcb_x_print_print_get_page_dimensions_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintGetPageDimensionsReply {
                    ptr: xcb_x_print_print_get_page_dimensions_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintGetPageDimensionsReply = base::Reply<xcb_x_print_print_get_page_dimensions_reply_t>;

impl PrintGetPageDimensionsReply {
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
    pub fn offset_x(&self) -> u16 {
        unsafe {
            (*self.ptr).offset_x
        }
    }
    pub fn offset_y(&self) -> u16 {
        unsafe {
            (*self.ptr).offset_y
        }
    }
    pub fn reproducible_width(&self) -> u16 {
        unsafe {
            (*self.ptr).reproducible_width
        }
    }
    pub fn reproducible_height(&self) -> u16 {
        unsafe {
            (*self.ptr).reproducible_height
        }
    }
}

pub fn print_get_page_dimensions<'a>(c      : &'a base::Connection,
                                     context: Pcontext)
        -> PrintGetPageDimensionsCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_page_dimensions(c.get_raw_conn(),
                                                           context as xcb_x_print_pcontext_t);  // 0
        PrintGetPageDimensionsCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_get_page_dimensions_unchecked<'a>(c      : &'a base::Connection,
                                               context: Pcontext)
        -> PrintGetPageDimensionsCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_page_dimensions_unchecked(c.get_raw_conn(),
                                                                     context as xcb_x_print_pcontext_t);  // 0
        PrintGetPageDimensionsCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_QUERY_SCREENS: u8 = 22;

pub type PrintQueryScreensCookie<'a> = base::Cookie<'a, xcb_x_print_print_query_screens_cookie_t>;

impl<'a> PrintQueryScreensCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintQueryScreensReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintQueryScreensReply {
                    ptr: xcb_x_print_print_query_screens_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintQueryScreensReply {
                    ptr: xcb_x_print_print_query_screens_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintQueryScreensReply = base::Reply<xcb_x_print_print_query_screens_reply_t>;

impl PrintQueryScreensReply {
    pub fn list_count(&self) -> u32 {
        unsafe {
            (*self.ptr).listCount
        }
    }
    pub fn roots(&self) -> &[xproto::Window] {
        unsafe {
            let field = self.ptr;
            let len = xcb_x_print_print_query_screens_roots_length(field) as usize;
            let data = xcb_x_print_print_query_screens_roots(field);
            std::slice::from_raw_parts(data, len)
        }
    }
}

pub fn print_query_screens<'a>(c: &'a base::Connection)
        -> PrintQueryScreensCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_query_screens(c.get_raw_conn());
        PrintQueryScreensCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_query_screens_unchecked<'a>(c: &'a base::Connection)
        -> PrintQueryScreensCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_query_screens_unchecked(c.get_raw_conn());
        PrintQueryScreensCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_SET_IMAGE_RESOLUTION: u8 = 23;

pub type PrintSetImageResolutionCookie<'a> = base::Cookie<'a, xcb_x_print_print_set_image_resolution_cookie_t>;

impl<'a> PrintSetImageResolutionCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintSetImageResolutionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintSetImageResolutionReply {
                    ptr: xcb_x_print_print_set_image_resolution_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintSetImageResolutionReply {
                    ptr: xcb_x_print_print_set_image_resolution_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintSetImageResolutionReply = base::Reply<xcb_x_print_print_set_image_resolution_reply_t>;

impl PrintSetImageResolutionReply {
    pub fn status(&self) -> bool {
        unsafe {
            (*self.ptr).status != 0
        }
    }
    pub fn previous_resolutions(&self) -> u16 {
        unsafe {
            (*self.ptr).previous_resolutions
        }
    }
}

pub fn print_set_image_resolution<'a>(c               : &'a base::Connection,
                                      context         : Pcontext,
                                      image_resolution: u16)
        -> PrintSetImageResolutionCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_set_image_resolution(c.get_raw_conn(),
                                                            context as xcb_x_print_pcontext_t,  // 0
                                                            image_resolution as u16);  // 1
        PrintSetImageResolutionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_set_image_resolution_unchecked<'a>(c               : &'a base::Connection,
                                                context         : Pcontext,
                                                image_resolution: u16)
        -> PrintSetImageResolutionCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_set_image_resolution_unchecked(c.get_raw_conn(),
                                                                      context as xcb_x_print_pcontext_t,  // 0
                                                                      image_resolution as u16);  // 1
        PrintSetImageResolutionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const PRINT_GET_IMAGE_RESOLUTION: u8 = 24;

pub type PrintGetImageResolutionCookie<'a> = base::Cookie<'a, xcb_x_print_print_get_image_resolution_cookie_t>;

impl<'a> PrintGetImageResolutionCookie<'a> {
    pub fn get_reply(&self) -> Result<PrintGetImageResolutionReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = PrintGetImageResolutionReply {
                    ptr: xcb_x_print_print_get_image_resolution_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( PrintGetImageResolutionReply {
                    ptr: xcb_x_print_print_get_image_resolution_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type PrintGetImageResolutionReply = base::Reply<xcb_x_print_print_get_image_resolution_reply_t>;

impl PrintGetImageResolutionReply {
    pub fn image_resolution(&self) -> u16 {
        unsafe {
            (*self.ptr).image_resolution
        }
    }
}

pub fn print_get_image_resolution<'a>(c      : &'a base::Connection,
                                      context: Pcontext)
        -> PrintGetImageResolutionCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_image_resolution(c.get_raw_conn(),
                                                            context as xcb_x_print_pcontext_t);  // 0
        PrintGetImageResolutionCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn print_get_image_resolution_unchecked<'a>(c      : &'a base::Connection,
                                                context: Pcontext)
        -> PrintGetImageResolutionCookie<'a> {
    unsafe {
        let cookie = xcb_x_print_print_get_image_resolution_unchecked(c.get_raw_conn(),
                                                                      context as xcb_x_print_pcontext_t);  // 0
        PrintGetImageResolutionCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const NOTIFY: u8 = 0;

pub type NotifyEvent = base::Event<xcb_x_print_notify_event_t>;

impl NotifyEvent {
    pub fn detail(&self) -> u8 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn context(&self) -> Pcontext {
        unsafe {
            (*self.ptr).context
        }
    }
    pub fn cancel(&self) -> bool {
        unsafe {
            (*self.ptr).cancel != 0
        }
    }
    /// Constructs a new NotifyEvent
    /// `response_type` will be set automatically to NOTIFY
    pub fn new(detail: u8,
               context: Pcontext,
               cancel: bool)
            -> NotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_x_print_notify_event_t;
            (*raw).response_type = NOTIFY;
            (*raw).detail = detail;
            (*raw).context = context;
            (*raw).cancel = if cancel { 1 } else { 0 };
            NotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const ATTRIBUT_NOTIFY: u8 = 1;

pub type AttributNotifyEvent = base::Event<xcb_x_print_attribut_notify_event_t>;

impl AttributNotifyEvent {
    pub fn detail(&self) -> u8 {
        unsafe {
            (*self.ptr).detail
        }
    }
    pub fn context(&self) -> Pcontext {
        unsafe {
            (*self.ptr).context
        }
    }
    /// Constructs a new AttributNotifyEvent
    /// `response_type` will be set automatically to ATTRIBUT_NOTIFY
    pub fn new(detail: u8,
               context: Pcontext)
            -> AttributNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_x_print_attribut_notify_event_t;
            (*raw).response_type = ATTRIBUT_NOTIFY;
            (*raw).detail = detail;
            (*raw).context = context;
            AttributNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const BAD_CONTEXT: u8 = 0;

pub const BAD_SEQUENCE: u8 = 1;
