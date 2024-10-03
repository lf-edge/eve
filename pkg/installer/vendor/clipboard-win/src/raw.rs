//!Raw bindings to Windows clipboard.
//!
//!## General information
//!
//!All pre & post conditions are stated in description of functions.
//!
//!### Open clipboard
//! To access any information inside clipboard it is necessary to open it by means of
//! [open()](fn.open.html).
//!
//! After that Clipboard cannot be opened any more until [close()](fn.close.html) is called.

extern crate winapi;

use std::cmp;
use std::ffi::OsString;
use std::os::windows::ffi::{
    OsStrExt,
    OsStringExt
};
use std::os::raw::{
    c_int,
    c_uint,
    c_void,
};
use std::path::PathBuf;
use std::ptr;
use std::io;

use crate::utils;
use crate::formats;

use winapi::shared::basetsd::{
    SIZE_T
};

use winapi::shared::ntdef::HANDLE;

use winapi::um::shellapi::{
    DragQueryFileW,
    HDROP
};

use winapi::um::winbase::{
    GlobalSize,
    GlobalLock,
    GlobalUnlock,
    GlobalAlloc,
    GlobalFree
};

use winapi::um::winuser::{
    OpenClipboard,
    CloseClipboard,
    EmptyClipboard,
    GetClipboardSequenceNumber,
    CountClipboardFormats,
    IsClipboardFormatAvailable,
    EnumClipboardFormats,
    RegisterClipboardFormatW,
    GetClipboardFormatNameW,
    GetClipboardData,
    SetClipboardData
};

#[inline]
///Opens clipboard.
///
///Wrapper around ```OpenClipboard```.
///
///# Pre-conditions:
///
///* Clipboard is not opened yet.
///
///# Post-conditions:
///
///* Clipboard can be accessed for read and write operations.
pub fn open() -> io::Result<()> {
    unsafe {
        if OpenClipboard(ptr::null_mut()) == 0 {
            return Err(utils::get_last_error());
        }
    }

    Ok(())
}

#[inline]
///Closes clipboard.
///
///Wrapper around ```CloseClipboard```.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
pub fn close() -> io::Result<()> {
    unsafe {
        if CloseClipboard() == 0 {
            return Err(utils::get_last_error());
        }
    }

    Ok(())
}

#[inline]
///Empties clipboard.
///
///Wrapper around ```EmptyClipboard```.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
pub fn empty() -> io::Result<()> {
    unsafe {
        if EmptyClipboard() == 0 {
            return Err(utils::get_last_error());
        }
    }

    Ok(())
}

#[inline]
///Retrieves clipboard sequence number.
///
///Wrapper around ```GetClipboardSequenceNumber```.
///
///# Returns:
///
///* ```Some``` Contains return value of ```GetClipboardSequenceNumber```.
///* ```None``` In case if you do not have access. It means that zero is returned by system.
pub fn seq_num() -> Option<u32> {
    let result: u32 = unsafe { GetClipboardSequenceNumber() };

    if result == 0 {
        return None;
    }

    Some(result)
}

#[inline]
///Retrieves size of clipboard data for specified format.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
///
///# Returns:
///
///Size in bytes if format presents on clipboard.
///
///# Unsafety:
///
///In some cases, clipboard content might be so invalid that it crashes on `GlobalSize` (e.g.
///Bitmap)
///
///Due to that function is marked as unsafe
pub unsafe fn size_unsafe(format: u32) -> Option<usize> {
    let clipboard_data = GetClipboardData(format);

    match clipboard_data.is_null() {
        false => Some(GlobalSize(clipboard_data) as usize),
        true => None,
    }
}

#[inline]
///Retrieves size of clipboard data for specified format.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
///
///# Returns:
///
///Size in bytes if format presents on clipboard.
pub fn size(format: u32) -> Option<usize> {
    let clipboard_data = unsafe {GetClipboardData(format)};

    if clipboard_data.is_null() {
        return None
    }

    unsafe {
        if GlobalLock(clipboard_data).is_null() {
            return None;
        }

        let result = Some(GlobalSize(clipboard_data) as usize);

        GlobalUnlock(clipboard_data);

        result
    }
}

///Retrieves raw pointer to clipboard data.
///
///Wrapper around ```GetClipboardData```.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
pub fn get_clipboard_data(format: c_uint) -> io::Result<ptr::NonNull<c_void>> {
    let clipboard_data = unsafe { GetClipboardData(format) };

    match ptr::NonNull::new(clipboard_data as *mut c_void) {
        Some(ptr) => Ok(ptr),
        None => Err(utils::get_last_error()),
    }
}

///Retrieves data of specified format from clipboard.
///
///Wrapper around ```GetClipboardData```.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
///
///# Note:
///
///Clipboard data is truncated by the size of provided storage.
///
///# Returns:
///
///Number of copied bytes.
pub fn get(format: u32, result: &mut [u8]) -> io::Result<usize> {
    let clipboard_data = unsafe { GetClipboardData(format as c_uint) };

    if clipboard_data.is_null() {
        Err(utils::get_last_error())
    }
    else {
        unsafe {
            let data_ptr = GlobalLock(clipboard_data) as *const u8;

            if data_ptr.is_null() {
                return Err(utils::get_last_error());
            }

            let data_size = cmp::min(GlobalSize(clipboard_data) as usize, result.len());

            ptr::copy_nonoverlapping(data_ptr, result.as_mut_ptr(), data_size);
            GlobalUnlock(clipboard_data);

            Ok(data_size)
        }
    }
}

///Retrieves String from `CF_UNICODETEXT` format
///
///Specialized version of [get](fn.get.html) to avoid unnecessary allocations.
///
///# Note:
///
///Usually WinAPI returns strings with null terminated character at the end.
///This character is trimmed.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
pub fn get_string() -> io::Result<String> {
    let clipboard_data = unsafe { GetClipboardData(formats::CF_UNICODETEXT) };

    if clipboard_data.is_null() {
        Err(utils::get_last_error())
    }
    else {
        unsafe {
            let data_ptr = GlobalLock(clipboard_data) as *const c_void as *const u16;

            if data_ptr.is_null() {
                return Err(utils::get_last_error());
            }

            let data_size = GlobalSize(clipboard_data) as usize / std::mem::size_of::<u16>();

            let str_slice = std::slice::from_raw_parts(data_ptr, data_size);
            #[cfg(not(feature = "utf16error"))]
            let mut result = String::from_utf16_lossy(str_slice);
            #[cfg(feature = "utf16error")]
            let mut result = match String::from_utf16(str_slice) {
                Ok(result) => result,
                Err(error) => {
                    GlobalUnlock(clipboard_data);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                }
            };

            //It seems WinAPI always supposed to have at the end null char.
            //But just to be safe let's check for it and only then remove.
            if let Some(null_idx) = result.find('\0') {
                result.drain(null_idx..);
            }

            GlobalUnlock(clipboard_data);

            Ok(result)
        }
    }
}

/// Retrieves a list of file paths from the `CF_HDROP` format.
///
/// # Pre-conditions:
///
/// * [open()](fn.open.html) has been called.
pub fn get_file_list() -> io::Result<Vec<PathBuf>> {
    unsafe {
        let clipboard_data = GetClipboardData(formats::CF_HDROP);
        if clipboard_data.is_null() {
            return Err(utils::get_last_error());
        }

        let _locked_data = {
            let locked_ptr = GlobalLock(clipboard_data);
            if locked_ptr.is_null() {
                return Err(utils::get_last_error());
            }
            LockedData(clipboard_data)
        };

        let num_files = DragQueryFileW(clipboard_data as HDROP, std::u32::MAX, ptr::null_mut(), 0);

        let mut file_names = Vec::with_capacity(num_files as usize);

        for file_index in 0..num_files {
            let required_size_no_null = DragQueryFileW(clipboard_data as HDROP, file_index, ptr::null_mut(), 0);
            if required_size_no_null == 0 {
                return Err(io::ErrorKind::Other.into());
            }
            let required_size = required_size_no_null + 1;
            let mut file_str_buf = Vec::with_capacity(required_size as usize);

            let write_retval = DragQueryFileW(
                clipboard_data as HDROP,
                file_index,
                file_str_buf.as_mut_ptr(),
                required_size,
            );
            if write_retval == 0 {
                return Err(io::ErrorKind::Other.into());
            }

            file_str_buf.set_len(required_size as usize);
            // Remove terminating zero
            let os_string = OsString::from_wide(&file_str_buf[..required_size_no_null as usize]);
            file_names.push(PathBuf::from(os_string));
        }

        Ok(file_names)
    }
}

///Sets data onto clipboard with specified format.
///
///Wrapper around ```SetClipboardData```.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
pub fn set(format: u32, data: &[u8]) -> io::Result<()> {
    const GHND: c_uint = 0x42;
    let size = data.len();

    let alloc_handle = unsafe { GlobalAlloc(GHND, size as SIZE_T) };

    if alloc_handle.is_null() {
        Err(utils::get_last_error())
    }
    else {
        unsafe {
            let lock = GlobalLock(alloc_handle) as *mut u8;

            ptr::copy_nonoverlapping(data.as_ptr(), lock, size);
            GlobalUnlock(alloc_handle);
            EmptyClipboard();

            if SetClipboardData(format, alloc_handle).is_null() {
                let result = utils::get_last_error();
                GlobalFree(alloc_handle);
                Err(result)
            }
            else {
                Ok(())
            }
        }
    }
}

#[inline(always)]
///Determines whenever provided clipboard format is available on clipboard or not.
pub fn is_format_avail(format: u32) -> bool {
    unsafe { IsClipboardFormatAvailable(format) != 0 }
}

#[inline]
///Retrieves number of currently available formats on clipboard.
pub fn count_formats() -> io::Result<i32> {
    let result = unsafe { CountClipboardFormats() };

    if result == 0 {
        let error = utils::get_last_error();

        if let Some(raw_error) = error.raw_os_error() {
            if raw_error != 0 {
                return Err(error)
            }
        }
    }

    Ok(result)
}

struct LockedData(HANDLE);

impl Drop for LockedData {
    fn drop(&mut self) {
        unsafe {
            GlobalUnlock(self.0);
        }
    }
}

///Enumerator over available clipboard formats.
///
///# Pre-conditions:
///
///* [open()](fn.open.html) has been called.
pub struct EnumFormats {
    idx: u32
}

impl EnumFormats {
    /// Constructs enumerator over all available formats.
    pub fn new() -> EnumFormats {
        EnumFormats { idx: 0 }
    }

    /// Constructs enumerator that starts from format.
    pub fn from(format: u32) -> EnumFormats {
        EnumFormats { idx: format }
    }

    /// Resets enumerator to list all available formats.
    pub fn reset(&mut self) -> &EnumFormats {
        self.idx = 0;
        self
    }
}

impl Iterator for EnumFormats {
    type Item = u32;

    /// Returns next format on clipboard.
    ///
    /// In case of failure (e.g. clipboard is closed) returns `None`.
    fn next(&mut self) -> Option<u32> {
        self.idx = unsafe { EnumClipboardFormats(self.idx) };

        if self.idx == 0 {
            None
        }
        else {
            Some(self.idx)
        }
    }

    /// Relies on `count_formats` so it is only reliable
    /// when hinting size for enumeration of all formats.
    ///
    /// Doesn't require opened clipboard.
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, count_formats().ok().map(|val| val as usize))
    }
}

macro_rules! match_format_name {
    ( $name:expr, $( $f:ident ),* ) => {
        match $name {
            $( formats::$f => Some(stringify!($f).to_string()),)*
            formats::CF_GDIOBJFIRST ... formats::CF_GDIOBJLAST => Some(format!("CF_GDIOBJ{}", $name - formats::CF_GDIOBJFIRST)),
            formats::CF_PRIVATEFIRST ... formats::CF_PRIVATELAST => Some(format!("CF_PRIVATE{}", $name - formats::CF_PRIVATEFIRST)),
            _ => {
                let format_buff = [0u16; 52];
                unsafe {
                    let buff_p = format_buff.as_ptr() as *mut u16;

                    if GetClipboardFormatNameW($name, buff_p, format_buff.len() as c_int) == 0 {
                        None
                    }
                    else {
                        Some(String::from_utf16_lossy(&format_buff))
                    }
                }
            }
        }
    }
}

///Returns format name based on it's code.
///
///# Parameters:
///
///* ```format``` clipboard format code.
///
///# Return result:
///
///* ```Some``` Name of valid format.
///* ```None``` Format is invalid or doesn't exist.
pub fn format_name(format: u32) -> Option<String> {
    match_format_name!(format,
                       CF_BITMAP,
                       CF_DIB,
                       CF_DIBV5,
                       CF_DIF,
                       CF_DSPBITMAP,
                       CF_DSPENHMETAFILE,
                       CF_DSPMETAFILEPICT,
                       CF_DSPTEXT,
                       CF_ENHMETAFILE,
                       CF_HDROP,
                       CF_LOCALE,
                       CF_METAFILEPICT,
                       CF_OEMTEXT,
                       CF_OWNERDISPLAY,
                       CF_PALETTE,
                       CF_PENDATA,
                       CF_RIFF,
                       CF_SYLK,
                       CF_TEXT,
                       CF_WAVE,
                       CF_TIFF,
                       CF_UNICODETEXT)
}

///Registers a new clipboard format with specified name.
///
///# Returns:
///
///Newly registered format identifier.
///
///# Note:
///
///Custom format identifier is in range `0xC000...0xFFFF`.
pub fn register_format<T: ?Sized + AsRef<std::ffi::OsStr>>(name: &T) -> io::Result<u32> {
    let mut utf16_buff: Vec<u16> = name.as_ref().encode_wide().collect();
    utf16_buff.push(0);

    let result = unsafe { RegisterClipboardFormatW(utf16_buff.as_ptr()) };

    if result == 0 {
        Err(utils::get_last_error())
    }
    else {
        Ok(result)
    }
}
