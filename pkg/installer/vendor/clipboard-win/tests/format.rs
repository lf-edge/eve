extern crate clipboard_win;

use clipboard_win::Clipboard;
use clipboard_win::formats;
use clipboard_win::raw;

#[test]
fn get_format_name() {
    let default_formats = [
        (formats::CF_TEXT, "CF_TEXT"),
        (formats::CF_OWNERDISPLAY, "CF_OWNERDISPLAY"),
        (formats::CF_BITMAP, "CF_BITMAP"),
        (formats::CF_DIB, "CF_DIB"),
        (formats::CF_DIBV5, "CF_DIBV5"),
        (formats::CF_DIF, "CF_DIF"),
        (formats::CF_DSPBITMAP, "CF_DSPBITMAP"),
        (formats::CF_DSPENHMETAFILE, "CF_DSPENHMETAFILE"),
        (formats::CF_DSPMETAFILEPICT, "CF_DSPMETAFILEPICT"),
        (formats::CF_DSPTEXT, "CF_DSPTEXT"),
        (formats::CF_ENHMETAFILE, "CF_ENHMETAFILE"),
        (formats::CF_HDROP, "CF_HDROP"),
        (formats::CF_LOCALE, "CF_LOCALE"),
        (formats::CF_METAFILEPICT, "CF_METAFILEPICT"),
        (formats::CF_OEMTEXT, "CF_OEMTEXT"),
        (formats::CF_OWNERDISPLAY, "CF_OWNERDISPLAY"),
        (formats::CF_PALETTE, "CF_PALETTE"),
        (formats::CF_PENDATA, "CF_PENDATA"),
        (formats::CF_RIFF, "CF_RIFF"),
        (formats::CF_SYLK, "CF_SYLK"),
        (formats::CF_WAVE, "CF_WAVE"),
        (formats::CF_TIFF, "CF_TIFF"),
        (formats::CF_UNICODETEXT, "CF_UNICODETEXT"),
        (formats::CF_GDIOBJFIRST, "CF_GDIOBJ0"),
        (formats::CF_GDIOBJFIRST + 55, "CF_GDIOBJ55"),
        (formats::CF_PRIVATEFIRST, "CF_PRIVATE0"),
        (formats::CF_PRIVATEFIRST + 63, "CF_PRIVATE63"),
    ];

    for format in default_formats.iter() {
        let result = raw::format_name(format.0);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), format.1);
    }
}

#[test]
fn count_formats() {
    let result = raw::count_formats();

    assert!(result.is_ok());

    let num_formats = result.unwrap() as usize;
    assert!(num_formats != 0);

    let enumerator = Clipboard::new().unwrap().enum_formats();
    assert_eq!((0, Some(num_formats)), enumerator.size_hint());

    let formats = Clipboard::new().unwrap().enum_formats().collect::<Vec<_>>();

    assert_eq!(formats.len(), num_formats);

    for format in formats {
        assert!(raw::is_format_avail(format));
    }
}
