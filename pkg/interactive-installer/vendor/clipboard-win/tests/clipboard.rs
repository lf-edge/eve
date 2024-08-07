extern crate clipboard_win;

use std::str;

use clipboard_win::Clipboard;
use clipboard_win::formats;
use clipboard_win::raw;
use clipboard_win::{
    get_clipboard_string,
    set_clipboard_string
};

#[test]
fn seq_num() {
    let result = raw::seq_num();

    assert!(result.is_some());
    assert!(result.unwrap() != 0);
}

#[test]
fn set_data() {
    let format = formats::CF_TEXT;
    let text = "For my waifu!\0"; //For text we need to pass C-like string
    let wide_text = "メヒーシャ";
    let data = text.as_bytes();
    let mut buff = [0u8; 52];
    let mut small_buff = [0u8; 4];

    let clipboard = Clipboard::new();
    assert!(clipboard.is_ok());
    let clipboard = clipboard.unwrap();

    let result = clipboard.empty();
    assert!(result.is_ok());
    let format_num = clipboard.enum_formats().count();
    assert_eq!(format_num, 0);
    let result = Clipboard::count_formats();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    //Check simple set of utf-8 bytes
    assert!(clipboard.size(format).is_none());
    let seq_num_before = Clipboard::seq_num();
    let result = clipboard.set(format, data);

    assert!(result.is_ok());

    let seq_num_after = Clipboard::seq_num();
    assert!(seq_num_before != seq_num_after);
    let size_after = clipboard.size(format).expect("Should have size after set");
    assert_eq!(size_after, data.len());

    //Check simple get of utf-8 bytes
    let result = clipboard.get(format, &mut buff);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result, data.len());
    let result = str::from_utf8(&buff[..result]).unwrap();
    assert_eq!(text, result);

    //Check truncated get of utf-8 bytes
    let result = clipboard.get(format, &mut small_buff);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result, small_buff.len());
    let result = str::from_utf8(&buff[..result]).unwrap();
    assert_eq!(&text[..small_buff.len()], result);

    //Check set of wide utf-8 bytes
    let seq_num_before = Clipboard::seq_num();
    let result = clipboard.set_string(wide_text);
    assert!(result.is_ok());
    assert!(Clipboard::is_format_avail(formats::CF_UNICODETEXT));
    let seq_num_after = Clipboard::seq_num();
    assert!(seq_num_before != seq_num_after);
    //Check get of wide utf-8 bytes
    let result = clipboard.get_string();
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), wide_text.len());
    assert_eq!(result, wide_text);

    //Try to copy & paste some url
    let url = "https://duckduckgo.com/html ";
    let seq_num_before = Clipboard::seq_num();
    let result = clipboard.set_string(url);
    assert!(Clipboard::is_format_avail(formats::CF_UNICODETEXT));
    assert!(result.is_ok());
    let seq_num_after = Clipboard::seq_num();
    assert!(seq_num_before != seq_num_after);

    let result = clipboard.get_string();
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), url.len());
    assert_eq!(result, url);

    //Shortcuts
    //Check set of wide utf-8 bytes
    let seq_num_before = Clipboard::seq_num();
    let result = set_clipboard_string(wide_text);
    assert!(result.is_ok());
    assert!(Clipboard::is_format_avail(formats::CF_UNICODETEXT));
    let seq_num_after = Clipboard::seq_num();
    assert!(seq_num_before != seq_num_after);

    //Check get of wide utf-8 bytes
    let result = get_clipboard_string();
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), wide_text.len());
    assert_eq!(result, wide_text);

    let expected_text = "For my waifu!";
    let text = "For my waifu!\0gg"; //Pass some garbage after \0
    //Check set of wide utf-8 bytes
    let seq_num_before = Clipboard::seq_num();
    let result = set_clipboard_string(text);
    assert!(result.is_ok());
    assert!(Clipboard::is_format_avail(formats::CF_UNICODETEXT));
    let seq_num_after = Clipboard::seq_num();
    assert!(seq_num_before != seq_num_after);

    //Check get of wide utf-8 bytes
    let result = get_clipboard_string();
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), expected_text.len());
    assert_eq!(result, expected_text);

}
