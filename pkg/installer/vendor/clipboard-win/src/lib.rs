#![cfg(windows)]
//! This crate provide simple means to operate with Windows clipboard.
//!
//!# Note keeping Clipboard around:
//!
//! In Windows [Clipboard](struct.Clipboard.html) opens globally and only one application can set data onto format at the time.
//!
//! Therefore as soon as operations are finished, user is advised to close [Clipboard](struct.Clipboard.html).
//!
//!# Clipboard
//!
//! All read and write access to Windows clipboard requires user to open it.
//!
//! For your convenience you can use [Clipboard](struct.Clipboard.html) struct that opens it at creation
//! and closes on its  drop.
//!
//! Alternatively you can access all functionality directly through [raw module](raw/index.html).
//!
//! Below you can find examples of usage.
//!
//!## Empty clipboard
//!
//! ```rust
//! extern crate clipboard_win;
//!
//! use clipboard_win::Clipboard;
//!
//! fn main() {
//!     Clipboard::new().unwrap().empty();
//! }
//! ```
//!## Set and get raw data
//! ```rust
//! extern crate clipboard_win;
//! use clipboard_win::formats;
//!
//! use clipboard_win::Clipboard;
//!
//! use std::str;
//!
//! fn main() {
//!     let text = "For my waifu!\0"; //For text we need to pass C-like string
//!     Clipboard::new().unwrap().set(formats::CF_TEXT, text.as_bytes());
//!
//!     let mut buffer = [0u8; 52];
//!     let result = Clipboard::new().unwrap().get(formats::CF_TEXT, &mut buffer).unwrap();
//!     assert_eq!(str::from_utf8(&buffer[..result]).unwrap(), text);
//! }
//! ```
//!
//!## Set and get String
//!
//! ```rust
//! extern crate clipboard_win;
//! use clipboard_win::Clipboard;
//!
//! use std::str;
//!
//! fn main() {
//!     let text = "For my waifu!";
//!     Clipboard::new().unwrap().set_string(text);
//!
//!     let result = Clipboard::new().unwrap().get_string().unwrap();
//!     assert_eq!(text, result);
//! }
//! ```
//!
//! # Feature list
//!
//! * `utf16error` - Uses non-lossy conversion from UTF-16 to UTF-8. On error returns `io::error`
//! with kind `InvalidData`
//!

#![warn(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

use std::io;
use std::slice;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

mod utils;
pub mod formats;
pub mod raw;
pub mod image;

pub use raw::{
    register_format
};

///Clipboard accessor.
///
///# Note:
///
///You can have only one such accessor across your program.
///
///# Warning:
///
///In Windows Clipboard opens globally and only one application can set data
///onto format at the time.
///
///Therefore as soon as operations are finished, user is advised to close Clipboard.
pub struct Clipboard {
    inner: ()
}

impl Clipboard {
    ///Initializes new clipboard accessor.
    ///
    ///Attempts to open clipboard.
    #[inline]
    pub fn new() -> io::Result<Clipboard> {
        raw::open().map(|_| Clipboard {inner: ()})
    }

    ///Empties clipboard.
    #[inline]
    pub fn empty(&self) -> io::Result<&Clipboard> {
        raw::empty().map(|_| self)
    }

    ///Retrieves size of clipboard content.
    #[inline]
    pub fn size(&self, format: u32) -> Option<usize> {
        raw::size(format)
    }

    ///Sets data onto clipboard with specified format.
    ///
    ///Wraps `raw::set()`
    #[inline]
    pub fn set(&self, format: u32, data: &[u8]) -> io::Result<()> {
        raw::set(format, data)
    }

    ///Sets `str` or `String` onto clipboard as Unicode format.
    ///
    ///Under hood it transforms Rust `UTF-8` String into `UTF-16`
    #[inline]
    pub fn set_string<T: ?Sized + AsRef<std::ffi::OsStr>>(&self, data: &T) -> io::Result<()> {
        let data = data.as_ref();
        let mut utf16_buff = data.encode_wide().collect::<Vec<u16>>();
        utf16_buff.push(0);

        let data = unsafe { slice::from_raw_parts(utf16_buff.as_ptr() as *const u8,
                                                  utf16_buff.len() * mem::size_of::<u16>()) };
        raw::set(formats::CF_UNICODETEXT, data)
    }

    ///Retrieves data of specified format from clipboard.
    ///
    ///Wraps `raw::get()`
    #[inline]
    pub fn get(&self, format: u32, data: &mut [u8]) -> io::Result<usize> {
        raw::get(format, data)
    }

    ///Retrieves `String` of `CF_UNICODETEXT` format from clipboard.
    ///
    ///Wraps `raw::get_string()`
    #[inline]
    pub fn get_string(&self) -> io::Result<String> {
        raw::get_string()
    }

    /// Retrieves a list of file paths from the `CF_HDROP` format from the clipboard.
    ///
    /// Wraps `raw::get_file_list()`
    #[inline]
    pub fn get_file_list(&self) -> io::Result<Vec<PathBuf>> {
        raw::get_file_list()
    }

    ///Retrieves `Bitmap` of `CF_BITMAP` format from clipboard.
    #[inline]
    pub fn get_bit_map(&self) -> io::Result<image::Bitmap> {
        raw::get_clipboard_data(formats::CF_BITMAP).and_then(|ptr| image::Bitmap::new(ptr.as_ptr()))
    }

    ///Enumerator over all formats on clipboard..
    #[inline]
    pub fn enum_formats(&self) -> raw::EnumFormats {
        raw::EnumFormats::new()
    }

    ///Returns Clipboard sequence number.
    #[inline]
    pub fn seq_num() -> Option<u32> {
        raw::seq_num()
    }

    ///Determines whenever provided clipboard format is available on clipboard or not.
    #[inline]
    pub fn is_format_avail(format: u32) -> bool {
        raw::is_format_avail(format)
    }

    ///Retrieves number of currently available formats on clipboard.
    #[inline]
    pub fn count_formats() -> io::Result<i32> {
        raw::count_formats()
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        let _ = raw::close();
        self.inner
    }
}

///Shortcut to retrieve string from clipboard.
///
///It opens clipboard and gets string, if possible.
#[inline]
pub fn get_clipboard_string() -> io::Result<String> {
    Clipboard::new()?.get_string()
}

///Shortcut to set string onto clipboard.
///
///It opens clipboard and attempts to set string.
#[inline]
pub fn set_clipboard_string<T: ?Sized + AsRef<std::ffi::OsStr>>(data: &T) -> io::Result<()> {
    Clipboard::new()?.set_string(data)
}
