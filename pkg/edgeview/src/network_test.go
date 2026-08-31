// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// The diagnostic must never expose any part of a PSK, including short keys.
func TestMaskPSK(t *testing.T) {
	if got := maskPSK("    ssid=\"home\""); got != "    ssid=\"home\"" {
		t.Errorf("non-PSK line changed: %q", got)
	}
	for _, value := range []string{"", "a", "abcdef", "0123456789abcdef"} {
		if got := maskPSK("    psk=" + value); got != "    psk=<redacted>" {
			t.Errorf("PSK value %q was not fully redacted: %q", value, got)
		}
	}
}
