/*
 * Copyright (C) 2013 James Miller <james@aatch.net>
 * Copyright (c) 2016
 *         Remi Thebault <remi.thebault@gmail.com>
 *         Thomas Bracht Laumann Jespersen <laumann.thomas@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without
 * limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
 * ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */


use libc::{c_int, c_uint, c_void};
use ffi::base::*;
use ffi::xproto;



#[repr(C)]
pub struct xcb_extension_t {
    name:      *const c_char,
    global_id: c_int
}

#[repr(C)]
pub struct xcb_protocol_request_t {
    count:  usize,
    ext:    *mut xcb_extension_t,
    opcode: u8,
    isvoid: u8
}


#[repr(C)]
pub enum xcb_send_request_flags_t {
    XCB_REQUEST_CHECKED       = 0x01,
    XCB_REQUEST_RAW           = 0x02,
    XCB_REQUEST_DISCARD_REPLY = 0x04,
    XCB_REQUEST_REPLY_FDS     = 0x08
}

#[link(name="xcb")]
extern {

    pub fn xcb_send_request(c: *mut xcb_connection_t,
                            flags: c_int,
                            vector: *mut iovec,
                            request: *const xcb_protocol_request_t)
            -> c_uint;

    pub fn xcb_send_request64(c: *mut xcb_connection_t,
                              flags: c_int,
                              vector: *mut iovec,
                              request: *const xcb_protocol_request_t)
            -> u64;

    pub fn xcb_send_fd(c: *mut xcb_connection_t,
                       fd: c_int);

    pub fn xcb_take_socket(c: *mut xcb_connection_t,
                           return_socket: extern fn(closure: *mut c_void),
                           closure: *mut c_void,
                           flags: c_int,
                           sent: *mut u64)
            -> c_int;

    pub fn xcb_writev(c: *mut xcb_connection_t,
                      vector: *mut iovec,
                      count: c_int,
                      requests: u64)
            -> c_int;

    pub fn xcb_wait_for_reply(c: *mut xcb_connection_t,
                              request: c_uint,
                              e: *mut *mut xcb_generic_error_t)
            -> *mut c_void;

    pub fn xcb_wait_for_reply64(c: *mut xcb_connection_t,
                                request: u64,
                                e: *mut *mut xcb_generic_error_t)
            -> *mut c_void;

    pub fn xcb_poll_for_reply(c: *mut xcb_connection_t,
                              request: c_uint,
                              reply: *mut *mut c_void,
                              error: *mut *mut xcb_generic_error_t)
            -> c_int;

    pub fn xcb_poll_for_reply64(c: *mut xcb_connection_t,
                                request: u64,
                                reply: *mut *mut c_void,
                                error: *mut *mut xcb_generic_error_t)
            -> c_int;

    pub fn xcb_get_reply_fds(c: *mut xcb_connection_t,
                             reply: *mut c_void,
                             replylen: usize)
            -> *mut c_int;

    pub fn xcb_popcount(mask: u32) -> c_int;

    pub fn xcb_sumof(list: *mut u8, len: c_int) -> c_int;

}

