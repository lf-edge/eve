use std::io;

#[inline(always)]
pub fn get_last_error() -> io::Error {
    io::Error::last_os_error()
}
