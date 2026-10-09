/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Low-level terminal I/O for driving several terminal devices at once (the real
//! screen on tty2 and one or more serial consoles). ratatui/crossterm's event
//! reader only knows about the process's controlling terminal, so we read raw
//! bytes from every device ourselves and decode the small set of keys the wizard
//! uses. Output is handled by ratatui (one `CrosstermBackend` per device); this
//! module owns raw-mode setup, window-size, and the merged input reader.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::JoinHandle;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Decode a chunk of raw terminal input bytes into the key events the wizard
/// understands: arrows (CSI / SS3), Enter, Backspace, printable chars (incl.
/// Space), and Esc. Ctrl-C is mapped to Esc so it cancels. Unknown escape
/// sequences degrade to a single Esc. Pure and total — the unit tests pin it.
pub fn decode(buf: &[u8]) -> Vec<KeyEvent> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let b = buf[i];
        match b {
            0x1b => {
                // CSI (ESC [) or SS3 (ESC O) cursor keys arrive as 3 bytes.
                let intro = buf.get(i + 1);
                if intro == Some(&b'[') || intro == Some(&b'O') {
                    match buf.get(i + 2) {
                        Some(b'A') => out.push(key(KeyCode::Up)),
                        Some(b'B') => out.push(key(KeyCode::Down)),
                        Some(b'C') => out.push(key(KeyCode::Right)),
                        Some(b'D') => out.push(key(KeyCode::Left)),
                        _ => out.push(key(KeyCode::Esc)),
                    }
                    i += 3;
                    continue;
                }
                // Lone ESC (or an unrecognized sequence start): treat as Esc.
                out.push(key(KeyCode::Esc));
                i += 1;
            }
            b'\r' | b'\n' => {
                out.push(key(KeyCode::Enter));
                i += 1;
            }
            0x7f | 0x08 => {
                out.push(key(KeyCode::Backspace));
                i += 1;
            }
            0x03 => {
                // Ctrl-C: cancel. Emit Esc, NOT Char('c') — that would confirm on
                // the Overview screen.
                out.push(key(KeyCode::Esc));
                i += 1;
            }
            0x20..=0x7e => {
                out.push(key(KeyCode::Char(b as char)));
                i += 1;
            }
            _ => i += 1, // ignore other control bytes
        }
    }
    out
}

/// Device path of the primary terminal (stdout), e.g. "/dev/tty2" under openvt
/// or "/dev/ttyS0" when driven directly on a serial line. Used to avoid opening
/// a serial console a second time when it is already the primary terminal.
pub fn primary_tty_path() -> Option<String> {
    unsafe {
        let p = libc::ttyname(libc::STDOUT_FILENO);
        if p.is_null() {
            return None;
        }
        std::ffi::CStr::from_ptr(p).to_str().ok().map(str::to_string)
    }
}

/// Saved termios for a device fd; restores the original settings on drop so the
/// terminal is left usable even on panic/unwind.
pub struct TermiosGuard {
    fd: RawFd,
    saved: libc::termios,
}

impl TermiosGuard {
    /// Put `fd` into raw mode, returning a guard that restores it on drop.
    ///
    /// # Safety
    /// `fd` must be a valid, open terminal file descriptor for the lifetime of
    /// the guard.
    pub unsafe fn make_raw(fd: RawFd) -> std::io::Result<TermiosGuard> {
        let mut saved: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut saved) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut raw = saved;
        libc::cfmakeraw(&mut raw);
        if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(TermiosGuard { fd, saved })
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

/// Return the terminal size (cols, rows) for `fd`. Serial lines frequently report
/// 0×0; in that case set a sane 80×24 so ratatui has something to render into.
///
/// # Safety
/// `fd` must be a valid, open terminal file descriptor.
pub unsafe fn ensure_winsize(fd: RawFd) -> (u16, u16) {
    let mut ws: libc::winsize = std::mem::zeroed();
    let ok = libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0;
    if !ok || ws.ws_col == 0 || ws.ws_row == 0 {
        ws.ws_col = 80;
        ws.ws_row = 24;
        ws.ws_xpixel = 0;
        ws.ws_ypixel = 0;
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
    (ws.ws_col, ws.ws_row)
}

/// A running input reader: a background thread polling every device fd and
/// pushing decoded keys onto a channel. Dropping (via `stop`) tells the thread
/// to exit; the caller joins it.
pub struct InputReader {
    pub rx: Receiver<KeyEvent>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl InputReader {
    /// Spawn a reader over the given fds. Keys from any device land on `rx`.
    pub fn spawn(fds: Vec<RawFd>) -> InputReader {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            let mut pollfds: Vec<libc::pollfd> = fds
                .iter()
                .map(|&fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
                .collect();
            let mut buf = [0u8; 64];
            while !stop_thread.load(Ordering::Relaxed) {
                for p in pollfds.iter_mut() {
                    p.revents = 0;
                }
                // 200ms timeout so the stop flag is checked promptly.
                let n = unsafe {
                    libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 200)
                };
                if n <= 0 {
                    continue; // timeout, EINTR, or error — re-check stop flag
                }
                for p in pollfds.iter() {
                    if p.revents & libc::POLLIN == 0 {
                        continue;
                    }
                    let got = unsafe {
                        libc::read(p.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                    };
                    if got > 0 {
                        for ev in decode(&buf[..got as usize]) {
                            if tx.send(ev).is_err() {
                                return; // receiver gone
                            }
                        }
                    }
                }
            }
        });
        InputReader { rx, stop, handle: Some(handle) }
    }
}

impl Drop for InputReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(buf: &[u8]) -> Vec<KeyCode> {
        decode(buf).into_iter().map(|k| k.code).collect()
    }

    #[test]
    fn arrows_csi_and_ss3() {
        assert_eq!(codes(b"\x1b[A"), vec![KeyCode::Up]);
        assert_eq!(codes(b"\x1b[B"), vec![KeyCode::Down]);
        assert_eq!(codes(b"\x1b[C"), vec![KeyCode::Right]);
        assert_eq!(codes(b"\x1b[D"), vec![KeyCode::Left]);
        assert_eq!(codes(b"\x1bOA"), vec![KeyCode::Up]); // application cursor mode
    }

    #[test]
    fn enter_space_and_chars() {
        assert_eq!(codes(b"\r"), vec![KeyCode::Enter]);
        assert_eq!(codes(b"\n"), vec![KeyCode::Enter]);
        assert_eq!(codes(b" "), vec![KeyCode::Char(' ')]);
        assert_eq!(codes(b"nbcq"), vec![
            KeyCode::Char('n'),
            KeyCode::Char('b'),
            KeyCode::Char('c'),
            KeyCode::Char('q'),
        ]);
    }

    #[test]
    fn lone_esc_and_ctrl_c_are_esc() {
        assert_eq!(codes(b"\x1b"), vec![KeyCode::Esc]);
        assert_eq!(codes(b"\x03"), vec![KeyCode::Esc]);
    }

    #[test]
    fn mixed_stream_decodes_in_order() {
        // Down arrow, then 'n', then Enter arriving in one read.
        assert_eq!(
            codes(b"\x1b[Bn\r"),
            vec![KeyCode::Down, KeyCode::Char('n'), KeyCode::Enter]
        );
    }

    #[test]
    fn unknown_escape_sequence_degrades_to_esc() {
        assert_eq!(codes(b"\x1b[Z"), vec![KeyCode::Esc]); // Shift-Tab etc.
    }
}
