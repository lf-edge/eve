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

use ffi::xproto::{xcb_setup_t, xcb_query_extension_reply_t};

use libc::{c_int, c_uint, c_void, c_char};


// Pre-defined constants

/// xcb connection errors because of socket, pipe and other stream errors.
pub const XCB_CONN_ERROR: c_int = 1;
/// xcb connection shutdown because of extension not supported
pub const XCB_CONN_CLOSED_EXT_NOTSUPPORTED: c_int = 2;
/// malloc(), calloc() and realloc() error upon failure, for eg ENOMEM
pub const XCB_CONN_CLOSED_MEM_INSUFFICIENT: c_int = 3;
/// Connection closed, exceeding request length that server accepts.
pub const XCB_CONN_CLOSED_REQ_LEN_EXCEED: c_int = 4;
/// Connection closed, error during parsing display string.
pub const XCB_CONN_CLOSED_PARSE_ERR: c_int = 5;
/// Connection closed because the server does not have a screen
/// matching the display.
pub const XCB_CONN_CLOSED_INVALID_SCREEN: c_int = 6;
/// Connection closed because some FD passing operation failed
pub const XCB_CONN_CLOSED_FDPASSING_FAILED: c_int = 7;


/// XCB connection structure
/// An opaque structure that contain all data that XCB needs to communicate
/// with an X server.
pub enum xcb_connection_t {}

/// Opaque structure used as key for xcb_get_extension_data_t
pub enum xcb_extension_t {}

pub enum xcb_special_event_t {}



/// Generic iterator
#[repr(C)]
pub struct xcb_generic_iterator_t {
    pub data:  *mut c_void,
    pub rem:   c_int,
    pub index: c_int
}

/// Generic reply
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_generic_reply_t {
    pub response_type: u8,
    pad0:              u8,
    pub sequence:      u16,
    pub length:        u32
}

/// Generic event
#[derive(Copy)]
#[repr(C)]
pub struct xcb_generic_event_t {
    pub response_type: u8,
    pub pad0:          u8,
    pub sequence:      u16,
    pub pad:           [u32; 7],
    pub full_sequence: u32
}
impl Clone for xcb_generic_event_t {
    fn clone(&self) -> xcb_generic_event_t { *self }
}

/// GE event
///
/// An event as sent by the XGE extension. The length field specifies the
/// number of 4-byte blocks trailing the struct.
///
/// Deprecated Since some fields in this struct have unfortunate names, it is
/// recommended to use xcb_ge_generic_event_t instead.
//#[deprecated]
#[derive(Copy)]
#[repr(C)]
pub struct xcb_ge_event_t {
    pub response_type: u8,
    pad0:              u8,
    pub sequence:      u16,
    pub length:        u32,
    pub event_type:    u16,
    pad1:              u16,
    pad:               [u32; 5],
    pub full_sequence: u32
}
impl Clone for xcb_ge_event_t {
    fn clone(&self) -> xcb_ge_event_t { *self }
}

/// Generic error
#[derive(Copy, Debug)]
#[repr(C)]
pub struct xcb_generic_error_t {
    pub response_type:  u8,
    pub error_code:     u8,
    pub sequence:       u16,
    pub resource_id:    u32,
    pub minor_code:     u16,
    pub major_code:     u8,
    pad0:               u8,
    pad:                [u32; 5],
    pub full_sequence:  u32
}
impl Clone for xcb_generic_error_t {
    fn clone(&self) -> xcb_generic_error_t { *self }
}

/// Generic cookie
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xcb_void_cookie_t {
    /// sequence number
    pub sequence: c_int
}


/// XCB_NONE is the universal null resource or null atom parameter value for many core X requests
pub const XCB_NONE: u32 = 0;
/// XCB_COPY_FROM_PARENT can be used for many xcb_create_window parameters
pub const XCB_COPY_FROM_PARENT: u32 = 0;
/// XCB_CURRENT_TIME can be used in most requests that take an xcb_timestamp_t
pub const XCB_CURRENT_TIME: u32 = 0;
/// XCB_NO_SYMBOL fills in unused entries in xcb_keysym_t tables
pub const XCB_NO_SYMBOL: u32 = 0;



/// Container for authorization information.
/// A container for authorization information to be sent to the X server
#[repr(C)]
pub struct xcb_auth_info_t {
    /// length of the string name (as returned by strlen)
    pub namelen:    c_int,
    /// String containing the authentication protocol name,
    /// such as "MIT-MAGIC-COOKIE-1" or "XDM-AUTHORIZATION-1".
    pub name:       *mut c_char,
    /// length of the data member
    pub datalen:    c_int,
    /// data interpreted in a protocol specific manner
    pub data:       *mut c_char
}

#[link(name="xcb")]
extern {

    /// Forces any buffered output to be written to the server. Blocks
    /// until the write is complete.
    ///
    /// Return > 0 on success, <= 0 otherwise.
    pub fn xcb_flush(c: *mut xcb_connection_t)
            -> c_int;

    /// Returns the maximum request length that this server accepts.
    ///
    /// In the absence of the BIG-REQUESTS extension, returns the
    /// maximum request length field from the connection setup data, which
    /// may be as much as 65535. If the server supports BIG-REQUESTS, then
    /// the maximum request length field from the reply to the
    /// BigRequestsEnable request will be returned instead.
    ///
    /// Note that this length is measured in four-byte units, making the
    /// theoretical maximum lengths roughly 256kB without BIG-REQUESTS and
    /// 16GB with.
    ///
    /// Returns The maximum request length field.
    pub fn xcb_get_maximum_request_length(c: *mut xcb_connection_t)
            -> u32;

    /// Prefetch the maximum request length without blocking.
    ///
    /// Without blocking, does as much work as possible toward computing
    /// the maximum request length accepted by the X server.
    ///
    /// Invoking this function may cause a call to xcb_big_requests_enable,
    /// but will not block waiting for the reply.
    /// xcb_get_maximum_request_length will return the prefetched data
    /// after possibly blocking while the reply is retrieved.
    ///
    /// Note that in order for this function to be fully non-blocking, the
    /// application must previously have called
    /// xcb_prefetch_extension_data(c, &xcb_big_requests_id) and the reply
    /// must have already arrived.
    pub fn xcb_prefetch_maximum_request_length(c: *mut xcb_connection_t);

    /// Returns the next event or error from the server.
    ///
    /// Returns the next event or error from the server, or returns null in
    /// the event of an I/O error. Blocks until either an event or error
    /// arrive, or an I/O error occurs.
    pub fn xcb_wait_for_event(c: *mut xcb_connection_t)
            -> *mut xcb_generic_event_t;

    /// Returns the next event or error from the server.
    ///
    /// Returns the next event or error from the server, if one is
    /// available, or returns @c NULL otherwise. If no event is available, that
    /// might be because an I/O error like connection close occurred while
    /// attempting to read the next event, in which case the connection is
    /// shut down when this function returns.
    pub fn xcb_poll_for_event(c: *mut xcb_connection_t)
            -> *mut xcb_generic_event_t;

    /// Returns the next event without reading from the connection.
    ///
    /// This is a version of xcb_poll_for_event that only examines the
    /// event queue for new events. The function doesn't try to read new
    /// events from the connection if no queued events are found.
    ///
    /// This function is useful for callers that know in advance that all
    /// interesting events have already been read from the connection. For
    /// example, callers might use xcb_wait_for_reply and be interested
    /// only of events that preceded a specific reply.
    pub fn xcb_poll_for_queued_event(c: *mut xcb_connection_t)
            -> *mut xcb_generic_event_t;

    /// Returns the next event from a special queue
    pub fn xcb_poll_for_special_event(c: *mut xcb_connection_t,
                                      se: *mut xcb_special_event_t)
            -> *mut xcb_generic_event_t;

    /// Returns the next event from a special queue, blocking until one arrives
    pub fn xcb_wait_for_special_event(c: *mut xcb_connection_t,
                                      se: *mut xcb_special_event_t)
            -> *mut xcb_generic_event_t;

    /// Listen for a special event
    pub fn xcb_register_for_special_xge(c: *mut xcb_connection_t,
                                        ext: *mut xcb_extension_t,
                                        eid: u32,
                                        stamp: *mut u32)
            -> *mut xcb_special_event_t;

    /// Stop listening for a special event
    pub fn xcb_unregister_for_special_event(c: *mut xcb_connection_t,
                                            se: *mut xcb_special_event_t);

    /// Return the error for a request, or NULL if none can ever arrive.
    ///
    /// The xcb_void_cookie_t cookie supplied to this function must have resulted
    /// from a call to xcb_[request_name]_checked().  This function will block
    /// until one of two conditions happens.  If an error is received, it will be
    /// returned.  If a reply to a subsequent request has already arrived, no error
    /// can arrive for this request, so this function will return NULL.
    ///
    /// Note that this function will perform a sync if needed to ensure that the
    /// sequence number will advance beyond that provided in cookie; this is a
    /// convenience to avoid races in determining whether the sync is needed.
    pub fn xcb_request_check(c: *mut xcb_connection_t,
                             cookie: xcb_void_cookie_t)
            -> *mut xcb_generic_error_t;

    /// Discards the reply for a request.
    ///
    /// sequence is the request sequence number from a cookie.
    ///
    /// Discards the reply for a request. Additionally, any error generated
    /// by the request is also discarded (unless it was an _unchecked request
    /// and the error has already arrived).
    ///
    /// This function will not block even if the reply is not yet available.
    ///
    /// Note that the sequence really does have to come from an xcb cookie;
    /// this function is not designed to operate on socket-handoff replies.
    pub fn xcb_discard_reply(c: *mut xcb_connection_t,
                             sequence: c_uint);

    /// Discards the reply for a request, given by a 64bit sequence number
    ///
    /// sequence is the 64-bit sequence number as returned by xcb_send_request64().
    ///
    /// Discards the reply for a request. Additionally, any error generated
    /// by the request is also discarded (unless it was an _unchecked request
    /// and the error has already arrived).
    ///
    /// This function will not block even if the reply is not yet available.
    ///
    /// Note that the sequence really does have to come from xcb_send_request64();
    /// the cookie sequence number is defined as "unsigned" int and therefore
    /// not 64-bit on all platforms.
    /// This function is not designed to operate on socket-handoff replies.
    ///
    /// Unlike its xcb_discard_reply() counterpart, the given sequence number is not
    /// automatically "widened" to 64-bit.
    ///
    pub fn xcb_discard_reply64(c: *mut xcb_connection_t,
                               sequence: u64);

    /// Caches reply information from QueryExtension requests.
    ///
    /// This function is the primary interface to the "extension cache",
    /// which caches reply information from QueryExtension
    /// requests. Invoking this function may cause a call to
    /// xcb_query_extension to retrieve extension information from the
    /// server, and may block until extension data is received from the
    /// server.
    ///
    /// The result must not be freed. This storage is managed by the cache
    /// itself.
    ///
    /// Returns A pointer to the xcb_query_extension_reply_t for the extension.
    pub fn xcb_get_extension_data(c: *mut xcb_connection_t,
                                  ext: *mut xcb_extension_t)
            -> *const xcb_query_extension_reply_t;

    /// Prefetch of extension data into the extension cache
    ///
    /// This function allows a "prefetch" of extension data into the
    /// extension cache. Invoking the function may cause a call to
    /// xcb_query_extension, but will not block waiting for the
    /// reply. xcb_get_extension_data will return the prefetched data after
    /// possibly blocking while it is retrieved.
    pub fn xcb_prefetch_extension_data(c: *mut xcb_connection_t,
                                       ext: *mut xcb_extension_t);

    /// Access the data returned by the server.
    ///
    /// Accessor for the data returned by the server when the xcb_connection_t
    /// was initialized. This data includes
    /// - the server's required format for images,
    /// - a list of available visuals,
    /// - a list of available screens,
    /// - the server's maximum request length (in the absence of the
    /// BIG-REQUESTS extension),
    /// - and other assorted information.
    ///
    /// See the X protocol specification for more details.
    ///
    /// Returns A pointer to an xcb_setup_t structure.
    /// The result must not be freed.
    pub fn xcb_get_setup(c: *mut xcb_connection_t)
            -> *const xcb_setup_t;

    /// Access the file descriptor of the connection.
    ///
    /// Accessor for the file descriptor that was passed to the
    /// xcb_connect_to_fd call that returned @p c.
    ///
    /// Returns The file descriptor.
    pub fn xcb_get_file_descriptor(c: *mut xcb_connection_t)
            -> c_int;

    /// Test whether the connection has shut down due to a fatal error.
    ///
    /// Some errors that occur in the context of an xcb_connection_t
    /// are unrecoverable. When such an error occurs, the
    /// connection is shut down and further operations on the
    /// xcb_connection_t have no effect, but memory will not be freed until
    /// xcb_disconnect() is called on the xcb_connection_t.
    ///
    /// Returns XCB_CONN_ERROR, because of socket errors, pipe errors or other stream errors.
    /// Returns XCB_CONN_CLOSED_EXT_NOTSUPPORTED, when extension not supported.
    /// Returns XCB_CONN_CLOSED_MEM_INSUFFICIENT, when memory not available.
    /// Returns XCB_CONN_CLOSED_REQ_LEN_EXCEED, exceeding request length that server accepts.
    /// Returns XCB_CONN_CLOSED_PARSE_ERR, error during parsing display string.
    /// Returns XCB_CONN_CLOSED_INVALID_SCREEN, because the server does not have a screen matching the display.
    ///
    /// Returns > 0 if the connection is in an error state; 0 otherwise.
    pub fn xcb_connection_has_error(c: *mut xcb_connection_t)
            -> c_int;

    /// Connects to the X server.
    ///
    /// Connects to an X server, given the open socket @p fd and the
    /// xcb_auth_info_t @p auth_info. The file descriptor @p fd is
    /// bidirectionally connected to an X server. If the connection
    /// should be unauthenticated, @p auth_info must be @c
    /// NULL.
    ///
    /// Always returns a non-NULL pointer to a xcb_connection_t, even on failure.
    /// Callers need to use xcb_connection_has_error() to check for failure.
    /// When finished, use xcb_disconnect() to close the connection and free
    /// the structure.
    pub fn xcb_connect_to_fd(fd: c_int,
                             auth_info: *mut xcb_auth_info_t)
            -> *mut xcb_connection_t;

    /// Closes the connection.
    ///
    /// Closes the file descriptor and frees all memory associated with the
    /// connection @c c. If @p c is @c NULL, nothing is done.
    pub fn xcb_disconnect(c: *mut xcb_connection_t);

    /// Parses a display string name in the form documented by X(7x).
    /// name: The name of the display.
    /// host: A pointer to a malloc'd copy of the hostname.
    /// display: A pointer to the display number.
    /// screen: A pointer to the screen number.
    ///
    /// Parses the display string name display_name in the form
    /// documented by X(7x). Has no side effects on failure. If
    /// displayname is NULL or empty, it uses the environment
    /// variable DISPLAY. hostp is a pointer to a newly allocated string
    /// that contain the host name. displayp is set to the display
    /// number and screenp to the preferred screen number. screenp
    /// can be NULL. If displayname does not contain a screen number,
    /// it is set to 0.
    ///
    /// Returns 0 on failure, non 0 otherwise.
    pub fn xcb_parse_display(name: *const c_char,
                             host: *mut *mut c_char,
                             display: *mut c_int,
                             screen: *mut c_int)
            -> c_int;

    /// Connects to the X server.
    /// displayname: The name of the display.
    /// screenp: A pointer to a preferred screen number.
    /// Returns A newly allocated xcb_connection_t structure.
    ///
    /// Connects to the X server specified by displayname. If
    /// displayname is NULL, uses the value of the DISPLAY environment
    /// variable. If a particular screen on that server is preferred, the
    /// int pointed to by screenp (if not NULL) will be set to that
    /// screen; otherwise the screen will be set to 0.
    ///
    /// Always returns a non-NULL pointer to a xcb_connection_t, even on failure.
    /// Callers need to use xcb_connection_has_error() to check for failure.
    /// When finished, use xcb_disconnect() to close the connection and free
    /// the structure.
    pub fn xcb_connect(displayname: *const c_char,
                       screenp: *mut c_int)
            -> *mut xcb_connection_t;

    /// Connects to the X server, using an authorization information.
    /// display: The name of the display.
    /// auth: The authorization information.
    /// screen: A pointer to a preferred screen number.
    /// Returns A newly allocated xcb_connection_t structure.
    ///
    /// Connects to the X server specified by displayname, using the
    /// authorization auth. If a particular screen on that server is
    /// preferred, the int pointed to by screenp (if not NULL) will
    /// be set to that screen; otherwise screenp will be set to 0.
    ///
    /// Always returns a non-NULL pointer to a xcb_connection_t, even on failure.
    /// Callers need to use xcb_connection_has_error() to check for failure.
    /// When finished, use xcb_disconnect() to close the connection and free
    /// the structure.
    pub fn xcb_connect_to_display_with_auth_info(display: *const c_char,
                                                 auth: *mut xcb_auth_info_t,
                                                 screen: *mut c_int)
            -> *mut xcb_connection_t;

    /// Allocates an XID for a new object.
    /// Returns A newly allocated XID.
    ///
    /// Allocates an XID for a new object. Typically used just prior to
    /// various object creation functions, such as xcb_create_window.
    pub fn xcb_generate_id(c: *mut xcb_connection_t)
            -> u32;

}

