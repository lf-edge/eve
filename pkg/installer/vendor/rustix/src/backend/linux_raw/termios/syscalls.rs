//! linux_raw syscalls supporting `rustix::termios`.
//!
//! # Safety
//!
//! See the `rustix::backend` module documentation for details.
#![allow(unsafe_code, clippy::undocumented_unsafe_blocks)]

use crate::backend::c;
use crate::backend::conv::{by_ref, c_uint, ret};
use crate::fd::BorrowedFd;
use crate::io;
use crate::pid::Pid;
#[cfg(all(feature = "alloc", feature = "procfs"))]
use crate::procfs;
use crate::termios::{
    Action, ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, QueueSelector,
    SpecialCodeIndex, Termios, Winsize,
};
#[cfg(all(feature = "alloc", feature = "procfs"))]
use crate::{ffi::CStr, fs::FileType, path::DecInt};
use core::mem::MaybeUninit;
use linux_raw_sys::general::IBSHIFT;
use linux_raw_sys::ioctl::{
    TCFLSH, TCSBRK, TCXONC, TIOCGPGRP, TIOCGSID, TIOCGWINSZ, TIOCSPGRP, TIOCSWINSZ,
};

#[inline]
pub(crate) fn tcgetwinsize(fd: BorrowedFd<'_>) -> io::Result<Winsize> {
    unsafe {
        let mut result = MaybeUninit::<Winsize>::uninit();
        ret(syscall!(__NR_ioctl, fd, c_uint(TIOCGWINSZ), &mut result))?;
        Ok(result.assume_init())
    }
}

#[inline]
pub(crate) fn tcgetattr(fd: BorrowedFd<'_>) -> io::Result<Termios> {
    unsafe {
        let mut result = MaybeUninit::<Termios>::uninit();

        // QEMU's `TCGETS2` doesn't currently set `input_speed` or
        // `output_speed` on PowerPC, so zero out the fields ourselves.
        #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
        {
            result.write(core::mem::zeroed());
        }

        ret(syscall!(__NR_ioctl, fd, c_uint(c::TCGETS2), &mut result))?;

        let result = result.assume_init();

        // QEMU's `TCGETS2` doesn't currently set `input_speed` or
        // `output_speed` on PowerPC, so set them manually if we can.
        #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
        let result = {
            use crate::termios::speed;
            let mut result = result;
            if result.output_speed == 0 && (result.control_modes.bits() & c::CBAUD) != c::BOTHER {
                if let Some(output_speed) = speed::decode(result.control_modes.bits() & c::CBAUD) {
                    result.output_speed = output_speed;
                }
            }
            if result.input_speed == 0
                && ((result.control_modes.bits() & c::CIBAUD) >> c::IBSHIFT) != c::BOTHER
            {
                // For input speeds, `B0` is special-cased to mean the input
                // speed is the same as the output speed.
                if ((result.control_modes.bits() & c::CIBAUD) >> c::IBSHIFT) == c::B0 {
                    result.input_speed = result.output_speed;
                } else if let Some(input_speed) =
                    speed::decode((result.control_modes.bits() & c::CIBAUD) >> c::IBSHIFT)
                {
                    result.input_speed = input_speed;
                }
            }
            result
        };

        Ok(result)
    }
}

#[inline]
pub(crate) fn tcgetpgrp(fd: BorrowedFd<'_>) -> io::Result<Pid> {
    unsafe {
        let mut result = MaybeUninit::<c::pid_t>::uninit();
        ret(syscall!(__NR_ioctl, fd, c_uint(TIOCGPGRP), &mut result))?;
        let pid = result.assume_init();

        // This doesn't appear to be documented, but it appears `tcsetpgrp` can
        // succceed and set the pid to 0 if we pass it a pseudo-terminal device
        // fd. For now, fail with `OPNOTSUPP`.
        if pid == 0 {
            return Err(io::Errno::OPNOTSUPP);
        }

        Ok(Pid::from_raw_unchecked(pid))
    }
}

#[inline]
pub(crate) fn tcsetattr(
    fd: BorrowedFd<'_>,
    optional_actions: OptionalActions,
    termios: &Termios,
) -> io::Result<()> {
    // Translate from `optional_actions` into an ioctl request code. On MIPS,
    // `optional_actions` already has `TCGETS` added to it.
    let request = linux_raw_sys::ioctl::TCSETS2
        + if cfg!(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )) {
            optional_actions as u32 - linux_raw_sys::ioctl::TCSETS
        } else {
            optional_actions as u32
        };
    unsafe {
        ret(syscall_readonly!(
            __NR_ioctl,
            fd,
            c_uint(request),
            by_ref(termios)
        ))
    }
}

#[inline]
pub(crate) fn tcsendbreak(fd: BorrowedFd<'_>) -> io::Result<()> {
    unsafe { ret(syscall_readonly!(__NR_ioctl, fd, c_uint(TCSBRK), c_uint(0))) }
}

#[inline]
pub(crate) fn tcdrain(fd: BorrowedFd<'_>) -> io::Result<()> {
    unsafe { ret(syscall_readonly!(__NR_ioctl, fd, c_uint(TCSBRK), c_uint(1))) }
}

#[inline]
pub(crate) fn tcflush(fd: BorrowedFd<'_>, queue_selector: QueueSelector) -> io::Result<()> {
    unsafe {
        ret(syscall_readonly!(
            __NR_ioctl,
            fd,
            c_uint(TCFLSH),
            c_uint(queue_selector as u32)
        ))
    }
}

#[inline]
pub(crate) fn tcflow(fd: BorrowedFd<'_>, action: Action) -> io::Result<()> {
    unsafe {
        ret(syscall_readonly!(
            __NR_ioctl,
            fd,
            c_uint(TCXONC),
            c_uint(action as u32)
        ))
    }
}

#[inline]
pub(crate) fn tcgetsid(fd: BorrowedFd<'_>) -> io::Result<Pid> {
    unsafe {
        let mut result = MaybeUninit::<c::pid_t>::uninit();
        ret(syscall!(__NR_ioctl, fd, c_uint(TIOCGSID), &mut result))?;
        let pid = result.assume_init();
        Ok(Pid::from_raw_unchecked(pid))
    }
}

#[inline]
pub(crate) fn tcsetwinsize(fd: BorrowedFd<'_>, winsize: Winsize) -> io::Result<()> {
    unsafe {
        ret(syscall_readonly!(
            __NR_ioctl,
            fd,
            c_uint(TIOCSWINSZ),
            by_ref(&winsize)
        ))
    }
}

#[inline]
pub(crate) fn tcsetpgrp(fd: BorrowedFd<'_>, pid: Pid) -> io::Result<()> {
    let raw_pid: c::c_int = pid.as_raw_nonzero().get();
    unsafe {
        ret(syscall_readonly!(
            __NR_ioctl,
            fd,
            c_uint(TIOCSPGRP),
            by_ref(&raw_pid)
        ))
    }
}

/// A wrapper around a conceptual `cfsetspeed` which handles an arbitrary
/// integer speed value.
#[inline]
pub(crate) fn set_speed(termios: &mut Termios, arbitrary_speed: u32) -> io::Result<()> {
    let encoded_speed = crate::termios::speed::encode(arbitrary_speed).unwrap_or(c::BOTHER);

    debug_assert_eq!(encoded_speed & !c::CBAUD, 0);

    termios.control_modes -= ControlModes::from_bits_retain(c::CBAUD | c::CIBAUD);
    termios.control_modes |=
        ControlModes::from_bits_retain(encoded_speed | (encoded_speed << IBSHIFT));

    termios.input_speed = arbitrary_speed;
    termios.output_speed = arbitrary_speed;

    Ok(())
}

/// A wrapper around a conceptual `cfsetospeed` which handles an arbitrary
/// integer speed value.
#[inline]
pub(crate) fn set_output_speed(termios: &mut Termios, arbitrary_speed: u32) -> io::Result<()> {
    let encoded_speed = crate::termios::speed::encode(arbitrary_speed).unwrap_or(c::BOTHER);

    debug_assert_eq!(encoded_speed & !c::CBAUD, 0);

    termios.control_modes -= ControlModes::from_bits_retain(c::CBAUD);
    termios.control_modes |= ControlModes::from_bits_retain(encoded_speed);

    termios.output_speed = arbitrary_speed;

    Ok(())
}

/// A wrapper around a conceptual `cfsetispeed` which handles an arbitrary
/// integer speed value.
#[inline]
pub(crate) fn set_input_speed(termios: &mut Termios, arbitrary_speed: u32) -> io::Result<()> {
    let encoded_speed = crate::termios::speed::encode(arbitrary_speed).unwrap_or(c::BOTHER);

    debug_assert_eq!(encoded_speed & !c::CBAUD, 0);

    termios.control_modes -= ControlModes::from_bits_retain(c::CIBAUD);
    termios.control_modes |= ControlModes::from_bits_retain(encoded_speed << IBSHIFT);

    termios.input_speed = arbitrary_speed;

    Ok(())
}

#[inline]
pub(crate) fn cfmakeraw(termios: &mut Termios) {
    // From the Linux [`cfmakeraw` manual page]:
    //
    // [`cfmakeraw` manual page]: https://man7.org/linux/man-pages/man3/cfmakeraw.3.html
    termios.input_modes -= InputModes::IGNBRK
        | InputModes::BRKINT
        | InputModes::PARMRK
        | InputModes::ISTRIP
        | InputModes::INLCR
        | InputModes::IGNCR
        | InputModes::ICRNL
        | InputModes::IXON;
    termios.output_modes -= OutputModes::OPOST;
    termios.local_modes -= LocalModes::ECHO
        | LocalModes::ECHONL
        | LocalModes::ICANON
        | LocalModes::ISIG
        | LocalModes::IEXTEN;
    termios.control_modes -= ControlModes::CSIZE | ControlModes::PARENB;
    termios.control_modes |= ControlModes::CS8;

    // Musl and glibc also do these:
    termios.special_codes[SpecialCodeIndex::VMIN] = 1;
    termios.special_codes[SpecialCodeIndex::VTIME] = 0;
}

#[inline]
pub(crate) fn isatty(fd: BorrowedFd<'_>) -> bool {
    // On error, Linux will return either `EINVAL` (2.6.32) or `ENOTTY`
    // (otherwise), because we assume we're never passing an invalid
    // file descriptor (which would get `EBADF`). Either way, an error
    // means we don't have a tty.
    tcgetwinsize(fd).is_ok()
}

#[cfg(all(feature = "alloc", feature = "procfs"))]
pub(crate) fn ttyname(fd: BorrowedFd<'_>, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
    let fd_stat = crate::backend::fs::syscalls::fstat(fd)?;

    // Quick check: if `fd` isn't a character device, it's not a tty.
    if FileType::from_raw_mode(fd_stat.st_mode) != FileType::CharacterDevice {
        return Err(io::Errno::NOTTY);
    }

    // Check that `fd` is really a tty.
    tcgetwinsize(fd)?;

    // Get a fd to "/proc/self/fd".
    let proc_self_fd = procfs::proc_self_fd()?;

    // Gather the ttyname by reading the "fd" file inside `proc_self_fd`.
    let r = crate::backend::fs::syscalls::readlinkat(
        proc_self_fd,
        DecInt::from_fd(fd).as_c_str(),
        buf,
    )?;

    // If the number of bytes is equal to the buffer length, truncation may
    // have occurred. This check also ensures that we have enough space for
    // adding a NUL terminator.
    if r == buf.len() {
        return Err(io::Errno::RANGE);
    }

    // `readlinkat` returns the number of bytes placed in the buffer.
    // NUL-terminate the string at that offset.
    buf[r].write(b'\0');

    // Check that the path we read refers to the same file as `fd`.
    {
        // SAFETY: We just wrote the NUL byte above
        let path = unsafe { CStr::from_ptr(buf.as_ptr().cast()) };

        let path_stat = crate::backend::fs::syscalls::stat(path)?;
        if path_stat.st_dev != fd_stat.st_dev || path_stat.st_ino != fd_stat.st_ino {
            return Err(io::Errno::NODEV);
        }
    }

    Ok(r)
}
