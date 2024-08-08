use libc::ifaddrs;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
extern "C" {
    pub fn lladdr(ptr: *mut ifaddrs) -> *const u8;
}
