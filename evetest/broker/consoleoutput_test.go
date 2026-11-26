// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTrimConsoleOutput(t *testing.T) {
	const maxBytes = 200
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "output that fits is kept whole",
			output: "line 1\nline 2\n",
			want:   "line 1\nline 2\n",
		},
		{
			// 136 bytes are left after the trimmed-lines line: the 120 of the
			// new lines and one old line of 9.
			name:   "whole lines are dropped from the start",
			output: strings.Repeat("old line\n", 30) + strings.Repeat("new\n", 30),
			want:   "[trimmed 29 log lines]\nold line\n" + strings.Repeat("new\n", 30),
		},
		{
			name:   "a line longer than the limit is cut on a rune boundary",
			output: "first\n" + strings.Repeat("é", 300),
			want:   "[trimmed 2 log lines]\n" + strings.Repeat("é", 68),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := trimConsoleOutput(tc.output, maxBytes)
			if got != tc.want {
				t.Errorf("trimConsoleOutput() = %q, want %q", got, tc.want)
			}
			if len(got) > maxBytes {
				t.Errorf("trimmed output has %d bytes, more than %d", len(got), maxBytes)
			}
			if !utf8.ValidString(got) {
				t.Error("trimmed output is not valid UTF-8")
			}
		})
	}
}
