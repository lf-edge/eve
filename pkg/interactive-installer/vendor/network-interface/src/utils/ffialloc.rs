use std::ffi::c_void;

pub(crate) struct FFIAlloc<T> {
    ptr: *mut T,
}

impl<T> FFIAlloc<T> {
    pub fn alloc(buffer_size: usize) -> Option<Self> {
        let ptr = unsafe { libc::malloc(buffer_size) as *mut T };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    pub const fn as_ptr(&self) -> *const T {
        self.ptr
    }

    pub const fn as_mut_ptr(&self) -> *mut T {
        self.ptr
    }
}

impl<T> Drop for FFIAlloc<T> {
    fn drop(&mut self) {
        unsafe { libc::free(self.ptr as *mut c_void) }
    }
}
