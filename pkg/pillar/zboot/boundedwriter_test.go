// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zboot

import (
	"bytes"
	"errors"
	"testing"
)

func TestBoundedWriter(t *testing.T) {
	var buf bytes.Buffer
	w := &boundedWriter{w: &buf, remaining: 8}

	if n, err := w.Write([]byte("12345")); n != 5 || err != nil {
		t.Fatalf("first write: n=%d err=%v", n, err)
	}
	if n, err := w.Write([]byte("678")); n != 3 || err != nil {
		t.Fatalf("write up to the limit: n=%d err=%v", n, err)
	}
	if n, err := w.Write([]byte("9")); n != 0 || !errors.Is(err, errRootfsTooLarge) {
		t.Fatalf("write past the limit: n=%d err=%v", n, err)
	}
	if got := buf.String(); got != "12345678" {
		t.Fatalf("underlying writer got %q", got)
	}
}
