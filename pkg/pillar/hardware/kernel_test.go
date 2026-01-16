// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"testing"
)

func TestGetFlavorFromKernelVersion(t *testing.T) {
	testCases := []struct {
		version     string
		expected    string
		description string
	}{
		{
			version:     "6.12.49-linuxkit-core-ef7ccc4d151c",
			expected:    "core",
			description: "Classic core version",
		},
		{
			version:     "6.1.155-linuxkit-hwe-abcdef",
			expected:    "hwe",
			description: "Hardware evaluation version",
		},
		{
			version:     "5.10.192-linuxkit-rt-123456",
			expected:    "rt",
			description: "Real-time version",
		},
		{
			version:     "5.10.0-rt",
			expected:    "rt",
			description: "Standard RT kernel version",
		},
		{
			version:     "6.12.49-linuxkit",
			expected:    "",
			description: "Linuxkit without following flavor",
		},
		{
			version:     "6.1.112-generic",
			expected:    "",
			description: "Generic kernel without linuxkit",
		},
		{
			version:     "",
			expected:    "",
			description: "Empty string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			actual := getFlavorFromKernelVersion(tc.version)
			if actual != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, actual)
			}
		})
	}
}
