// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"testing"

	"github.com/sirupsen/logrus"
)

// TestQMPEventLogLevel pins the classification: events a healthy guest emits
// continuously must not be warnings, unknown events must.
func TestQMPEventLogLevel(t *testing.T) {
	cases := map[string]logrus.Level{
		"RTC_CHANGE":            logrus.DebugLevel,
		"NIC_RX_FILTER_CHANGED": logrus.DebugLevel,
		"RESUME":                logrus.DebugLevel,
		"VNC_CONNECTED":         logrus.DebugLevel,
		"POWERDOWN":             logrus.InfoLevel,
		"RESET":                 logrus.InfoLevel,
		"DEVICE_DELETED":        logrus.InfoLevel,
		"BLOCK_IO_ERROR":        logrus.WarnLevel,
		"GUEST_PANICKED":        logrus.WarnLevel,
		"":                      logrus.WarnLevel,
	}
	for event, want := range cases {
		if got := qmpEventLogLevel(event); got != want {
			t.Errorf("qmpEventLogLevel(%q) = %v, want %v", event, got, want)
		}
	}
}
