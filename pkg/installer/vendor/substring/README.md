# substring

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/Anders429/substring/Tests)](https://github.com/Anders429/substring/actions)
[![codecov.io](https://img.shields.io/codecov/c/gh/Anders429/substring)](https://codecov.io/gh/Anders429/substring)
[![crates.io](https://img.shields.io/crates/v/substring)](https://crates.io/crates/substring)
[![docs.rs](https://docs.rs/substring/badge.svg)](https://docs.rs/substring)
[![MSRV](https://img.shields.io/badge/rustc-1.0.0+-yellow.svg)](#minimum-supported-rust-version)
[![License](https://img.shields.io/crates/l/substring)](#license)

Substring method for string types.

This crate provides a `substring` method on Rust string types. The method takes a start and end
character index and returns a string slice containing the characters within that range.

The method is provided via the `Substring` trait which is implemented on the
[`str`](https://doc.rust-lang.org/std/primitive.str.html) primitive.

## Usage

To use this crate, simply bring the `Substring` trait into scope and call the `substring` method on
your string types.

```rust
use substring::Substring;

assert_eq!("hello, world!".substring(7, 12), "world");
```

Note that the indexing of substrings is based on
[*Unicode Scalar Value*](http://www.unicode.org/glossary/#unicode_scalar_value). As such,
substrings may not always match your intuition:

```rust
use substring::Substring;

assert_eq!("ã".substring(0, 1), "a");  // As opposed to "ã".
assert_eq!("ã".substring(1, 2), "\u{0303}")
```

The above example occurs because "ã" is technically made up of two UTF-8 scalar values: the letter
"a" and a combining tilde.


## Performance

As Rust strings are UTF-8 encoded, the algorithm for finding a character substring has temporal
complexity *O(n)*, where *n* is the byte length of the string. This is due to characters not being
of predictible byte lengths.

## Minimum Supported Rust Version
This crate is guaranteed to compile on stable `rustc 1.0.0` and up.

## License
This project is licensed under either of

* Apache License, Version 2.0
([LICENSE-APACHE](https://github.com/Anders429/substring/blob/HEAD/LICENSE-APACHE) or
http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
([LICENSE-MIT](https://github.com/Anders429/substring/blob/HEAD/LICENSE-MIT) or
http://opensource.org/licenses/MIT)

at your option.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
