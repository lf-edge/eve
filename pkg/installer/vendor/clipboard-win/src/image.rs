//! Image module

use winapi::um::wingdi::{GetDIBits, GetObjectW};

use std::{ptr, slice, io, mem};
use std::os::raw::{c_void, c_int, c_long, c_ulong};

use crate::utils;

struct Dc(winapi::shared::windef::HDC);

impl Dc {
    fn new() -> Self {
        Self(unsafe { winapi::um::winuser::GetDC(ptr::null_mut()) })
    }
}

impl Drop for Dc {
    fn drop(&mut self) {
        unsafe { winapi::um::winuser::ReleaseDC(ptr::null_mut(), self.0) };
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BmpHeader {
    typ: u16,
    size: u32,
    reserved: u32,
    offset: u32,
    info: winapi::um::wingdi::BITMAPINFO,
}

impl BmpHeader {
    const fn len() -> usize {
        mem::size_of::<BmpHeader>() - mem::size_of::<winapi::um::wingdi::RGBQUAD>()
    }
}

impl Default for BmpHeader {
    fn default() -> Self {
        Self {
            typ: 0x4D42,
            size: 0,
            reserved: 0,
            offset: 54,
            info: unsafe { mem::zeroed() }
        }
    }
}

///Bitmap image from clipboard
pub struct Bitmap {
    inner: winapi::shared::windef::HBITMAP,
    ///Raw BITMAP data
    pub data: winapi::um::wingdi::BITMAP,
}

impl Bitmap {
    ///Creates instance from BITMAP handle
    pub fn new(ptr: *mut c_void) -> io::Result<Self> {
        use winapi::um::wingdi::BITMAP;

        let mut data: BITMAP = unsafe { mem::zeroed() };
        let data_ptr = &mut data as *mut BITMAP as *mut c_void;

        match unsafe { GetObjectW(ptr as *mut c_void, mem::size_of::<BITMAP>() as c_int, data_ptr) } {
            0 => Err(utils::get_last_error()),
            _ => Ok(Self {
                inner: ptr as winapi::shared::windef::HBITMAP,
                data
            }),
        }
    }

    #[inline]
    ///Calculates the size in bytes for pixel data
    pub fn size(&self) -> usize {
        let color_bits = (self.data.bmPlanes * self.data.bmBitsPixel) as c_long;
        let result = ((self.data.bmWidth * color_bits + 31) / color_bits) * 4 * self.data.bmHeight;
        result as usize
    }

    #[inline]
    ///Retrieves data of underlying Bitmap's data
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.data.bmBits as *const _, self.size()) }
    }

    #[inline]
    ///Returns raw handle.
    pub fn as_raw(&self) -> winapi::shared::windef::HBITMAP {
        self.inner
    }

    #[inline]
    ///Returns image dimensions as `(width, height)`
    pub fn dimensions(&self) -> (usize, usize) {
        (self.data.bmWidth as usize, self.data.bmHeight as usize)
    }

    #[doc(hidden)]
    ///Retrieves image as binary.
    ///
    ///TODO: make it work
    pub fn data(&self) -> io::Result<Vec<u8>> {
        use winapi::um::wingdi::{DIB_RGB_COLORS, BITMAPINFOHEADER, BITMAPINFO};

        let dc = Dc::new();

        let mut header = BmpHeader::default();

        header.info.bmiHeader.biSize = mem::size_of::<BITMAPINFOHEADER>() as c_ulong;
        let data_ptr = &mut header.info as *mut BITMAPINFO;

        match unsafe { GetDIBits(dc.0, self.inner, 0, 0, ptr::null_mut(), data_ptr, DIB_RGB_COLORS) } {
            0 => return Err(utils::get_last_error()),
            _ => (),
        }

        header.info.bmiHeader.biCompression = winapi::um::wingdi::BI_RGB;
        header.size = header.info.bmiHeader.biSizeImage as u32 + header.offset;

        let buffer_len = BmpHeader::len() + header.info.bmiHeader.biSizeImage as usize;
        let mut buffer = Vec::with_capacity(buffer_len);
        buffer.extend_from_slice(unsafe { slice::from_raw_parts(&header as *const _ as *const u8, BmpHeader::len()) });
        unsafe { buffer.set_len(buffer_len) };

        match unsafe { GetDIBits(dc.0, self.inner, 0, 0, buffer.get_unchecked_mut(mem::size_of::<BmpHeader>()) as *mut u8 as *mut _, data_ptr, DIB_RGB_COLORS) } {
            0 => Err(utils::get_last_error()),
            _ => Ok(buffer),
        }
    }
}
