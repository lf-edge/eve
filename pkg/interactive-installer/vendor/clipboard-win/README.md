clipboard-win
====================

[![Build status](https://ci.appveyor.com/api/projects/status/5mkbp9mh5vwpohtn?svg=true)](https://ci.appveyor.com/project/DoumanAsh/clipboard-win)
[![Crates.io](https://img.shields.io/crates/v/clipboard-win.svg)](https://crates.io/crates/clipboard-win)
[![Docs.rs](https://docs.rs/clipboard-win/badge.svg)](https://docs.rs/clipboard-win/*/x86_64-pc-windows-msvc/clipboard_win/)

Provides simple way to interact with Windows clipboard.

# Clipboard

All read and write access to Windows clipboard requires user to open it.

For your convenience you can use [Clipboard](https://docs.rs/clipboard-win/*/x86_64-pc-windows-msvc/clipboard_win/struct.Clipboard.html) struct that opens it at creation
and closes on its drop.

Alternatively you can access all functionality directly through [raw module](https://docs.rs/clipboard-win/*/x86_64-pc-windows-msvc/clipboard_win/raw/index.html).

Below you can find examples of usage.

## Empty clipboard

```rust
extern crate clipboard_win;

use clipboard_win::Clipboard;

fn main() {
    Clipboard::new().unwrap().empty();
}
```

## Set and get raw data

```rust
extern crate clipboard_win;
use clipboard_win::formats;

use clipboard_win::Clipboard;

use std::str;

fn main() {
    let text = "For my waifu!\0"; //For text we need to pass C-like string
    Clipboard::new().unwrap().set(formats::CF_TEXT, text.as_bytes());

    let mut buffer = [0u8; 52];
    let result = Clipboard::new().unwrap().get(formats::CF_TEXT, &mut buffer).unwrap();
    assert_eq!(str::from_utf8(&buffer[..result]).unwrap(), text);
}
```

## Set and get String

```rust
extern crate clipboard_win;
use clipboard_win::Clipboard;

use std::str;

fn main() {
    let text = "For my waifu!";
    Clipboard::new().unwrap().set_string(text);

    let result = Clipboard::new().unwrap().get_string().unwrap();
    assert_eq!(text, result);
}
```

# Feature list

* `utf16error` - Uses non-lossy conversion from UTF-16 to UTF-8. On error returns `io::error`
with kind `InvalidData`
