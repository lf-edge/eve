bitflags::bitflags! {
    /// `FUTEX_*` flags for use with [`futex`].
    ///
    /// [`futex`]: crate::thread::futex
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct FutexFlags: u32 {
        /// `FUTEX_PRIVATE_FLAG`
        const PRIVATE = linux_raw_sys::general::FUTEX_PRIVATE_FLAG;
        /// `FUTEX_CLOCK_REALTIME`
        const CLOCK_REALTIME = linux_raw_sys::general::FUTEX_CLOCK_REALTIME;

        // This deliberately lacks a `const _ = !0`, so that users can use
        // `from_bits_truncate` to extract the `SocketFlags` from a flags
        // value that also includes a `SocketType`.
    }
}

/// `FUTEX_*` operations for use with [`futex`].
///
/// [`futex`]: crate::thread::futex
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum FutexOperation {
    /// `FUTEX_WAIT`
    Wait = linux_raw_sys::general::FUTEX_WAIT,
    /// `FUTEX_WAKE`
    Wake = linux_raw_sys::general::FUTEX_WAKE,
    /// `FUTEX_FD`
    Fd = linux_raw_sys::general::FUTEX_FD,
    /// `FUTEX_REQUEUE`
    Requeue = linux_raw_sys::general::FUTEX_REQUEUE,
    /// `FUTEX_CMP_REQUEUE`
    CmpRequeue = linux_raw_sys::general::FUTEX_CMP_REQUEUE,
    /// `FUTEX_WAKE_OP`
    WakeOp = linux_raw_sys::general::FUTEX_WAKE_OP,
    /// `FUTEX_LOCK_PI`
    LockPi = linux_raw_sys::general::FUTEX_LOCK_PI,
    /// `FUTEX_UNLOCK_PI`
    UnlockPi = linux_raw_sys::general::FUTEX_UNLOCK_PI,
    /// `FUTEX_TRYLOCK_PI`
    TrylockPi = linux_raw_sys::general::FUTEX_TRYLOCK_PI,
    /// `FUTEX_WAIT_BITSET`
    WaitBitset = linux_raw_sys::general::FUTEX_WAIT_BITSET,
}
