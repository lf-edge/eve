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


use xproto::*;
use ffi::base::*;
use ffi::xproto::*;
#[cfg(feature="xlib_xcb")]
use ffi::xlib_xcb::*;

#[cfg(feature="xlib_xcb")]
use x11::xlib;

use libc::{self, c_int, c_char, c_void};
use std::option::Option;

use std::error;
use std::fmt;
use std::mem;
use std::ptr::{null, null_mut};
use std::marker::PhantomData;
// std::num::Zero is unstable in rustc 1.5 => remove the Zero defined
// hereunder as soon as Zero gets stabilized (or replaced by something else)
//use std::num::Zero;
use std::cmp::Ordering;
use std::ops::{BitAnd, BitOr};
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, RawFd};


/// Current protocol version
pub const X_PROTOCOL: u32 = 11;
/// Current minor version
pub const X_PROTOCOL_REVISION: u32 = 0;
/// X_TCP_PORT + display number = server port for TCP transport
pub const X_TCP_PORT: u32 = 6000;


/// Opaque type used as key for `Connection::get_extension_data`
pub type Extension = xcb_extension_t;


/// `xcb::NONE` is the universal null resource or null atom parameter value
/// for many core X requests
pub const NONE: u32 = 0;
/// `xcb::COPY_FROM_PARENT` can be used for many `xcb::create_window` parameters
pub const COPY_FROM_PARENT: u32 = 0;
/// `xcb::CURRENT_TIME` can be used in most requests that take an `xcb::Timestamp`
pub const CURRENT_TIME: u32 = 0;
/// `xcb::NO_SYMBOL` fills in unused entries in `xcb::Keysym` tables
pub const NO_SYMBOL: u32 = 0;




/// `StructPtr` is a wrapper for pointer to struct owned by XCB
/// that must not be freed
/// it is instead bound to the lifetime of its parent that it borrows immutably
pub struct StructPtr<'a, T: 'a> {
    pub ptr: *mut T,
    phantom: PhantomData<&'a T>
}


/// `Event` wraps a pointer to `xcb_*_event_t`
/// this pointer will be freed when the `Event` goes out of scope
pub struct Event<T> {
   pub ptr: *mut T
}

impl<T> Event<T> {
    pub fn response_type(&self) -> u8 {
        unsafe {
            let gev : *mut xcb_generic_event_t = mem::transmute(self.ptr);
            (*gev).response_type
        }
    }
}

impl<T> Drop for Event<T> {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.ptr as *mut c_void);
        }
    }
}

#[cfg(feature="thread")]
unsafe impl<T> Send for Event<T> {}
#[cfg(feature="thread")]
unsafe impl<T> Sync for Event<T> {}

/// Casts the generic event to the right event. Assumes that the given
/// event is really the correct type.
pub unsafe fn cast_event<'r, T>(event : &'r GenericEvent) -> &'r T {
    mem::transmute(event)
}




/// `Error` wraps a pointer to `xcb_*_error_t`
/// this pointer will be freed when the `Error` goes out of scope
#[derive(Debug)]
pub struct Error<T> {
    pub ptr: *mut T
}

impl<T> Error<T> {
    pub fn response_type(&self) -> u8 {
        unsafe {
            let ger : *mut xcb_generic_error_t = mem::transmute(self.ptr);
            (*ger).response_type
        }
    }
    pub fn error_code(&self) -> u8 {
        unsafe {
            let ger : *mut xcb_generic_error_t = mem::transmute(self.ptr);
            (*ger).error_code
        }
    }
}

impl<T> Drop for Error<T> {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.ptr as *mut c_void);
        }
    }
}

impl<T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "xcb::Error {{ response_type: {}, error_code: {} }}",
               self.response_type(),
               self.error_code())
    }
}
impl<T: fmt::Debug> error::Error for Error<T> {
    fn description(&self) -> &str {
        "xcb::Error"
    }
}

// Error are readonly and can be safely sent and shared with other threads
unsafe impl<T> Send for Error<T> {}
unsafe impl<T> Sync for Error<T> {}

/// Casts the generic error to the right error. Assumes that the given
/// error is really the correct type.
pub unsafe fn cast_error<'r, T>(error : &'r GenericError) -> &'r T {
    mem::transmute(error)
}




/// wraps a cookie as returned by a request function.
/// Instantiations of `Cookie` that are not `VoidCookie`
/// should provide a `get_reply` method to return a `Reply`
pub struct Cookie<'a, T: Copy> {
    pub cookie: T,
    pub conn: &'a Connection,
    pub checked: bool
}

pub type VoidCookie<'a> = Cookie<'a, xcb_void_cookie_t>;

impl<'a> VoidCookie<'a> {
    pub fn request_check(&self) -> Result<(), GenericError> {
        unsafe {
            let c : xcb_void_cookie_t = mem::transmute(self.cookie);
            let err = xcb_request_check(self.conn.get_raw_conn(), c);

            if err.is_null() {
                Ok(())
            } else {
                Err(GenericError{ ptr: err })
            }
        }
    }
}

#[cfg(feature="thread")]
unsafe impl<'a, T: Copy> Send for Cookie<'a, T> {}
#[cfg(feature="thread")]
unsafe impl<'a, T: Copy> Sync for Cookie<'a, T> {}



/// Wraps a pointer to a `xcb_*_reply_t`
/// the pointer is freed when the `Reply` goes out of scope
pub struct Reply<T> {
    pub ptr: *mut T
}

impl<T> Drop for Reply<T> {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.ptr as *mut c_void);
        }
    }
}

#[cfg(feature="thread")]
unsafe impl<T> Send for Reply<T> {}
#[cfg(feature="thread")]
unsafe impl<T> Sync for Reply<T> {}


pub type GenericEvent = Event<xcb_generic_event_t>;
pub type GenericError = Error<xcb_generic_error_t>;
pub type GenericReply = Reply<xcb_generic_reply_t>;




//TODO: Implement wrapper functions for constructing auth_info
pub type AuthInfo = xcb_auth_info_t;



#[cfg(feature="xlib_xcb")]
pub enum EventQueueOwner {
    Xcb,
    Xlib
}


/// Error type that is returned by `Connection::has_error`
#[derive(Debug)]
pub enum ConnError {
    /// xcb connection errors because of socket, pipe and other stream errors.
    Connection,
    /// xcb connection shutdown because of extension not supported
    ClosedExtNotSupported,
    /// malloc(), calloc() and realloc() error upon failure, for eg ENOMEM
    ClosedMemInsufficient,
    /// Connection closed, exceeding request length that server accepts.
    ClosedReqLenExceed,
    /// Connection closed, error during parsing display string.
    ClosedParseErr,
    /// Connection closed because the server does not have a screen
    /// matching the display.
    ClosedInvalidScreen,
    /// Connection closed because some FD passing operation failed
    ClosedFdPassingFailed,
}

impl ConnError {
    fn to_str(&self) -> &str {
        match *self {
            ConnError::Connection => "Connection error, possible I/O error",
            ConnError::ClosedExtNotSupported => "Connection closed, X extension not supported",
            ConnError::ClosedMemInsufficient => "Connection closed, insufficient memory",
            ConnError::ClosedReqLenExceed => "Connection closed, exceeded request length that server accepts.",
            ConnError::ClosedParseErr => "Connection closed, error during parsing display string",
            ConnError::ClosedInvalidScreen => "Connection closed, the server does not have a screen matching the display",
            ConnError::ClosedFdPassingFailed => "Connection closed, file-descriptor passing operation failed",
        }
    }
}

impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_str().fmt(f)
    }
}

impl error::Error for ConnError {
    fn description(&self) -> &str {
        self.to_str()
    }
}

pub type ConnResult<T> = Result<T, ConnError>;


/// xcb::Connection handles communication with the X server.
/// It wraps an `xcb_connection_t` object and
/// will call `xcb_disconnect` when the `Connection` goes out of scope
pub struct Connection {
    c:   *mut xcb_connection_t,
    #[cfg(feature="xlib_xcb")]
    dpy: *mut xlib::Display,
}

#[cfg(feature="thread")]
unsafe impl Send for Connection {}
#[cfg(feature="thread")]
unsafe impl Sync for Connection {}


impl Connection {

    /// Forces any buffered output to be written to the server. Blocks
    /// until the write is complete.
    ///
    /// Return `true` on success, `false` otherwise.
    pub fn flush(&self) -> bool {
        unsafe {
            xcb_flush(self.c) > 0
        }
    }

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
    pub fn get_maximum_request_length(&self) -> u32 {
        unsafe {
            xcb_get_maximum_request_length(self.c)
        }
    }

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
    /// `c.prefetch_extension_data(xcb::big_requests::id())` and the reply
    /// must have already arrived.
    pub fn prefetch_maximum_request_length(&self) {
        unsafe {
            xcb_prefetch_maximum_request_length(self.c);
        }
    }

    /// Returns the next event or error from the server.
    ///
    /// Returns the next event or error from the server, or returns `None` in
    /// the event of an I/O error. Blocks until either an event or error
    /// arrive, or an I/O error occurs.
    pub fn wait_for_event(&self) -> Option<GenericEvent> {
        unsafe {
            let event = xcb_wait_for_event(self.c);
            if event.is_null() {
                None
            } else {
                Some(GenericEvent { ptr: event })
            }
        }
    }

    /// Returns the next event or error from the server.
    ///
    /// Returns the next event or error from the server, if one is
    /// available, or returns `None` otherwise. If no event is available, that
    /// might be because an I/O error like connection close occurred while
    /// attempting to read the next event, in which case the connection is
    /// shut down when this function returns.
    pub fn poll_for_event(&self) -> Option<GenericEvent> {
        unsafe {
            let event = xcb_poll_for_event(self.c);
            if event.is_null() {
                None
            } else {
                Some(GenericEvent { ptr: event })
            }
        }
    }

    /// Returns the next event without reading from the connection.
    ///
    /// This is a version of `poll_for_event` that only examines the
    /// event queue for new events. The function doesn't try to read new
    /// events from the connection if no queued events are found.
    ///
    /// This function is useful for callers that know in advance that all
    /// interesting events have already been read from the connection. For
    /// example, callers might use `wait_for_reply` and be interested
    /// only of events that preceded a specific reply.
    pub fn poll_for_queued_event(&self) -> Option<GenericEvent> {
        unsafe {
            let event = xcb_poll_for_queued_event(self.c);
            if event.is_null() {
                None
            } else {
                Some(GenericEvent { ptr: event })
            }
        }
    }

    /// Access the data returned by the server.
    ///
    /// Accessor for the data returned by the server when the `Connection`
    /// was initialized. This data includes
    /// - the server's required format for images,
    /// - a list of available visuals,
    /// - a list of available screens,
    /// - the server's maximum request length (in the absence of the
    /// BIG-REQUESTS extension),
    /// - and other assorted information.
    ///
    /// See the X protocol specification for more details.
    pub fn get_setup(&self) -> Setup {
        unsafe {

            let setup = xcb_get_setup(self.c);
            if setup.is_null() {
                panic!("NULL setup on connection")
            }
            mem::transmute(setup)
        }
    }

    /// Test whether the connection has shut down due to a fatal error.
    ///
    /// Some errors that occur in the context of a `Connection`
    /// are unrecoverable. When such an error occurs, the
    /// connection is shut down and further operations on the
    /// `Connection` have no effect, but memory will not be freed until
    /// the `Connection` is dropped.
    pub fn has_error(&self) -> ConnResult<()> {
        unsafe {
            match xcb_connection_has_error(self.c) {
                0 => { Ok(()) },
                XCB_CONN_ERROR => { Err(ConnError::Connection) },
                XCB_CONN_CLOSED_EXT_NOTSUPPORTED =>
                        { Err(ConnError::ClosedExtNotSupported) },
                XCB_CONN_CLOSED_MEM_INSUFFICIENT =>
                        { Err(ConnError::ClosedMemInsufficient) },
                XCB_CONN_CLOSED_REQ_LEN_EXCEED =>
                        { Err(ConnError::ClosedReqLenExceed) },
                XCB_CONN_CLOSED_PARSE_ERR =>
                        { Err(ConnError::ClosedParseErr) },
                XCB_CONN_CLOSED_INVALID_SCREEN =>
                        { Err(ConnError::ClosedInvalidScreen) },
                XCB_CONN_CLOSED_FDPASSING_FAILED =>
                        { Err(ConnError::ClosedFdPassingFailed) },
                _ => {
                    warn!("XCB: unexpected error code from xcb_connection_has_error");
                    warn!("XCB: Default to ConnError::Connection");
                    Err(ConnError::Connection)
                },
            }
        }
    }

    /// Allocates an XID for a new object.
    ///
    /// Allocates an XID for a new object. Typically used just prior to
    /// various object creation functions, such as `xcb::create_window`.
    pub fn generate_id(&self) -> u32 {
        unsafe {
            xcb_generate_id(self.c)
        }
    }

    /// Returns the inner ffi `xcb_connection_t` pointer
    pub fn get_raw_conn(&self) -> *mut xcb_connection_t {
        self.c
    }

    /// Consumes this object, returning the inner ffi `xcb_connection_t` pointer
    pub fn into_raw_conn(self) -> *mut xcb_connection_t {
        let c = self.c;
        mem::forget(self);
        c
    }

    /// Returns the inner ffi `xlib::Display` pointer.
    #[cfg(feature="xlib_xcb")]
    pub fn get_raw_dpy(&self) -> *mut xlib::Display {
        self.dpy
    }

    /// Prefetch of extension data into the extension cache
    ///
    /// This function allows a "prefetch" of extension data into the
    /// extension cache. Invoking the function may cause a call to
    /// xcb_query_extension, but will not block waiting for the
    /// reply. xcb_get_extension_data will return the prefetched data after
    /// possibly blocking while it is retrieved.
    pub fn prefetch_extension_data(&self, ext: &mut Extension) {
        unsafe {
            xcb_prefetch_extension_data(self.c, ext);
        }
    }

    /// Caches reply information from QueryExtension requests.
    ///
    /// This function is the primary interface to the "extension cache",
    /// which caches reply information from QueryExtension
    /// requests. Invoking this function may cause a call to
    /// xcb_query_extension to retrieve extension information from the
    /// server, and may block until extension data is received from the
    /// server.
    pub fn get_extension_data<'a>(&'a self, ext: &mut Extension)
            -> Option<QueryExtensionData<'a>> {
        unsafe {
            let ptr = xcb_get_extension_data(self.c, ext);
            if !ptr.is_null() { Some(QueryExtensionData { ptr: ptr, _marker: PhantomData }) }
            else { None }
        }
    }

    /// Sets the owner of the event queue in the case if the connection is opened
    /// with the XLib interface. the default owner is XLib.
    #[cfg(feature="xlib_xcb")]
    pub fn set_event_queue_owner(&self, owner: EventQueueOwner) {
        debug_assert!(!self.dpy.is_null());
        unsafe {
            XSetEventQueueOwner(self.dpy, match owner {
                EventQueueOwner::Xcb => XCBOwnsEventQueue,
                EventQueueOwner::Xlib => XlibOwnsEventQueue
            });
        }
    }



    /// Connects to the X server.
    /// `displayname:` The name of the display.
    ///
    /// Connects to the X server specified by `displayname.` If
    /// `displayname` is `None,` uses the value of the DISPLAY environment
    /// variable.
    ///
    /// Returns Ok(connection object, preferred screen) in case of success, or
    /// Err(ConnError) in case of error. If no screen is preferred, the second
    /// member of the tuple is set to 0.
    pub fn connect(displayname: Option<&str>) -> ConnResult<(Connection, i32)> {
        unsafe {
            let display = displayname.map(|s| CString::new(s).unwrap());
            let mut screen_num : c_int = 0;
            let cconn = xcb_connect(
                display.map_or(null(), |s| s.as_ptr()),
                &mut screen_num
            );

            // xcb doc says that a valid object is always returned
            // so we simply assert without handling this in the return
            assert!(!cconn.is_null(), "had incorrect pointer");

            let conn = Self::from_raw_conn(cconn);

            conn.has_error().map(|_| {
                (conn, screen_num as i32)
            })
        }
    }

    /// Open a new connection with XLib.
    /// The event queue owner defaults to XLib
    /// One would need to open an XCB connection with Xlib in order to use
    /// OpenGL.
    #[cfg(feature="xlib_xcb")]
    pub fn connect_with_xlib_display() -> ConnResult<(Connection, i32)> {
        unsafe {
            let dpy = xlib::XOpenDisplay(null());
            let cconn = XGetXCBConnection(dpy);
            assert!(!dpy.is_null() && !cconn.is_null(),
                "XLib could not connect to the X server");

            let conn = Connection { c: cconn, dpy: dpy };

            conn.has_error().map(|_| {
                (conn, xlib::XDefaultScreen(dpy) as i32)
            })
        }
    }

    /// wraps a `xlib::Display` and get an XCB connection from an exisiting object
    /// `xlib::XCloseDisplay` will be called when the returned object is dropped
    #[cfg(feature="xlib_xcb")]
    pub unsafe fn new_from_xlib_display(dpy: *mut xlib::Display) -> Connection {
        assert!(!dpy.is_null(), "attempt connect with null display");
        Connection {
            c: XGetXCBConnection(dpy),
            dpy: dpy
        }
    }



    /// Connects to the X server, using an authorization information.
    /// display: The name of the display.
    /// auth_info: The authorization information.
    /// screen: A pointer to a preferred screen number.
    /// Returns A newly allocated `Connection` structure.
    ///
    /// Connects to the X server specified by displayname, using the
    /// authorization auth.
    /// The second member of the returned tuple is the preferred screen, or 0
    pub fn connect_with_auth_info(display: Option<&str>, auth_info: &AuthInfo)
    -> ConnResult<(Connection, i32)> {
        unsafe {
            let display = display.map(|s| CString::new(s).unwrap());
            let mut screen_num : c_int = 0;
            let cconn = xcb_connect_to_display_with_auth_info(
                display.map_or(null(), |s| s.as_ptr()),
                mem::transmute(auth_info),
                &mut screen_num
            );

            // xcb doc says that a valid object is always returned
            // so we simply assert without handling this in the return
            assert!(!cconn.is_null(), "had incorrect pointer");

            let conn = Self::from_raw_conn(cconn);

            conn.has_error().map(|_| {
                (conn, screen_num as i32)
            })
        }
    }

    /// builds a new Connection object from an available connection
    pub unsafe fn from_raw_conn(conn: *mut xcb_connection_t) -> Connection {
        assert!(!conn.is_null());

        #[cfg(not(feature="xlib_xcb"))]
        return Connection {
            c:  conn,
        };

        #[cfg(feature="xlib_xcb")]
        return Connection {
            c:  conn,
            dpy: null_mut(),
        };
    }
}

impl AsRawFd for Connection {
    fn as_raw_fd(&self) -> RawFd {
        unsafe {
            xcb_get_file_descriptor(self.c)
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        #[cfg(not(feature="xlib_xcb"))]
        unsafe {
            xcb_disconnect(self.c);
        }

        #[cfg(feature="xlib_xcb")]
        unsafe {
            if self.dpy.is_null() {
                xcb_disconnect(self.c);
            }
            else {
                xlib::XCloseDisplay(self.dpy);
            }
        }
    }
}


// Mimics xproto::QueryExtensionReply, but without the Drop trait.
// Used for Connection::get_extension_data whose returned value
// must not be freed.
// Named QueryExtensionData to avoid name collision
pub struct QueryExtensionData<'a> {
    ptr: *const xcb_query_extension_reply_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> QueryExtensionData<'a> {
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


pub trait Zero {
    fn zero() -> Self;
}

impl Zero for u8    { fn zero() -> u8    {0} }
impl Zero for u16   { fn zero() -> u16   {0} }
impl Zero for u32   { fn zero() -> u32   {0} }
impl Zero for u64   { fn zero() -> u64   {0} }
impl Zero for usize { fn zero() -> usize {0} }
impl Zero for i8    { fn zero() -> i8    {0} }
impl Zero for i16   { fn zero() -> i16   {0} }
impl Zero for i32   { fn zero() -> i32   {0} }
impl Zero for i64   { fn zero() -> i64   {0} }
impl Zero for isize { fn zero() -> isize {0} }
impl Zero for f32   { fn zero() -> f32   {0f32} }
impl Zero for f64   { fn zero() -> f64   {0f64} }

/// pack bitfields tuples into vector usable for FFI requests
/// ```
///     let values = [
///         (xcb::CW_EVENT_MASK, xcb::EVENT_MASK_EXPOSURE | xcb::EVENT_MASK_KEY_PRESS),
///         (xcb::CW_BACK_PIXEL, 0xffffffff),
///     ];
///     let ffi_values = (
///         xcb::CW_BACK_PIXEL | xcb::CW_EVENT_MASK,
///         [
///             Oxffffffff,
///             xcb::EVENT_MASK_EXPOSURE | xcb::EVENT_MASK_KEY_PRESS,
///             0
///         ]
///     );
///     assert_eq!(pack_bitfield(&mut values), ffi_values);
/// ```

pub fn pack_bitfield<T, L>(bf : &mut Vec<(T,L)>) -> (T, Vec<L>)
    where T: Ord + Zero + Copy + BitAnd<Output=T> + BitOr<Output=T>,
          L: Copy {
	bf.sort_by(|a,b| {
        let &(a, _) = a;
        let &(b, _) = b;
        if a < b {
            Ordering::Less
        }
        else if a > b {
            Ordering::Greater
        }
        else {
            Ordering::Equal
        }
    });

    let mut mask = T::zero();
    let mut list: Vec<L> = Vec::new();

    for el in bf.iter() {
        let &(f, v) = el;
        if mask & f > T::zero() {
            continue;
        } else {
            mask = mask|f;
            list.push(v);
        }
    }

    (mask, list)
}
