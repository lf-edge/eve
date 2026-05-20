// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
)

// nulEscape is the literal 6-char text sequence that sanitizeGzipHeader
// writes for a NUL byte: backslash, lowercase u, four zeros. Written as a
// double-quoted Go string with an escaped backslash so this file contains
// no actual NUL bytes (which break editors and some tooling).
const nulEscape = "\\u0000"

// referenceSanitize is a second implementation of the sanitization rule that
// the production sanitizeGzipHeader must match. Keeping a parallel, simpler
// implementation here lets the table test assert the contract directly
// without hand-transcribed expected strings.
func referenceSanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == 0:
			b.WriteString(nulEscape)
		case r > 0xffff:
			fmt.Fprintf(&b, "\\U%08x", r)
		case r > 0xff:
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestSanitizeGzipHeader(t *testing.T) {
	inputs := []string{
		"",
		"my-app",
		"café-Ñandú",     // pure Latin-1 (é=0xE9, Ñ=0xD1, ú=0xFA)
		"中文",             // CJK -- both > 0xFF
		"“hi”",           // smart quotes U+201C / U+201D
		"Łódź",           // mixed: Ł=U+0141, ó=0x00F3, d ASCII, ź=U+017A
		"★",              // U+2605
		"\U0001F600",     // supplementary-plane emoji
		"a\x00b",         // NUL byte
		"app-中-é-\x00-Ł", // mix of all categories
	}
	for _, in := range inputs {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			got := sanitizeGzipHeader(in)
			want := referenceSanitize(in)
			if got != want {
				t.Fatalf("sanitizeGzipHeader(%q) = %q, want %q", in, got, want)
			}
			for _, r := range got {
				if r == 0 || r > 0xff {
					t.Fatalf("sanitizeGzipHeader(%q) = %q contains disallowed rune U+%04X",
						in, got, r)
				}
			}
		})
	}
}

// TestSanitizeGzipHeaderRoundTripsThroughGzip is the regression test for the
// "non-Latin-1 header string" crash in finalizeGzipToOutTempFile: a sanitized
// header must be accepted by gzip.Writer.Close() and survive a read-back.
func TestSanitizeGzipHeaderRoundTripsThroughGzip(t *testing.T) {
	inputs := []string{
		"ascii-name",
		"café-Ñandú",
		"中文-app",
		"app\x00with\x00nul",
		"\U0001F600-emoji",
		"mix-中-é-\x00-Ł",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			gw.Name = sanitizeGzipHeader(in)
			if _, err := gw.Write([]byte("payload\n")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := gw.Close(); err != nil {
				t.Fatalf("Close on sanitized header %q (original %q): %v", gw.Name, in, err)
			}
			gr, err := gzip.NewReader(&buf)
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			if gr.Name != sanitizeGzipHeader(in) {
				t.Fatalf("round-tripped Name = %q, want %q", gr.Name, sanitizeGzipHeader(in))
			}
		})
	}
}

// TestUnsanitizedHeaderCrashesGzip pins the precondition: assigning a raw
// non-Latin-1 string to gzip.Writer.Name causes Close() to fail. If Go ever
// loosens this, the sanitizer becomes unnecessary and this test surfaces it.
func TestUnsanitizedHeaderCrashesGzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Name = "中文"
	_, _ = gw.Write([]byte("payload\n"))
	if err := gw.Close(); err == nil {
		t.Fatalf("expected gzip Close to reject non-Latin-1 Name, got nil error")
	}
}
