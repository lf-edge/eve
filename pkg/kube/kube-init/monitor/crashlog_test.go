// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"strings"
	"testing"
)

// TestFindLastBannerLine covers the non-trivial behaviour of the
// banner scan used by gzipLastRestartPart: pick the LAST banner
// (not the first), default to line 1 when the banner is missing
// so the full file is included.
func TestFindLastBannerLine(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		search string
		want   int
	}{
		{
			name:   "single banner",
			body:   "noise\nStarting k3s v1.0.0\nmore noise\n",
			search: "Starting k3s v1.0.0",
			want:   2,
		},
		{
			name: "multiple banners — the LAST one wins",
			body: "Starting k3s v1.0.0\n" +
				"first restart logs\n" +
				"Starting k3s v1.0.0\n" +
				"second restart logs\n",
			search: "Starting k3s v1.0.0",
			want:   3,
		},
		{
			name:   "no banner → default to line 1 (full file)",
			body:   "no banner here\nmore lines\n",
			search: "Starting k3s v1.0.0",
			want:   1,
		},
		{
			name:   "banner is a substring on a line — still matches",
			body:   "log: prefix Starting k3s v1.0.0 suffix\n",
			search: "Starting k3s v1.0.0",
			want:   1,
		},
		{
			name:   "different version line does not match",
			body:   "Starting k3s v0.0.0\n",
			search: "Starting k3s v1.0.0",
			want:   1,
		},
		{
			name:   "empty file",
			body:   "",
			search: "Starting k3s v1.0.0",
			want:   1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := findLastBannerLine(strings.NewReader(c.body), c.search)
			if err != nil {
				t.Fatalf("findLastBannerLine: %v", err)
			}
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

// TestStreamLinesFrom covers the second-pass extractor that writes
// from startLine through EOF. Non-trivial: a startLine past EOF
// should produce zero output and no error (not a panic).
func TestStreamLinesFrom(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		startLine int
		want      string
	}{
		{
			name:      "start at 1 emits full file",
			body:      "a\nb\nc\n",
			startLine: 1,
			want:      "a\nb\nc\n",
		},
		{
			name:      "start mid-file skips earlier lines",
			body:      "a\nb\nc\nd\n",
			startLine: 3,
			want:      "c\nd\n",
		},
		{
			name:      "start beyond EOF emits nothing",
			body:      "a\nb\n",
			startLine: 99,
			want:      "",
		},
		{
			name:      "empty input emits nothing",
			body:      "",
			startLine: 1,
			want:      "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf strings.Builder
			if err := streamLinesFrom(strings.NewReader(c.body), &buf, c.startLine); err != nil {
				t.Fatalf("streamLinesFrom: %v", err)
			}
			if buf.String() != c.want {
				t.Errorf("got %q, want %q", buf.String(), c.want)
			}
		})
	}
}

