// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ResolvConfToIfname — does not need a real filesystem

func TestResolvConfToIfname(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// Valid dhcp file in DhcpcdResolvConfDir
		{fmt.Sprintf("%s/eth0.dhcp", DhcpcdResolvConfDir), "eth0"},
		{fmt.Sprintf("%s/eth0.dhcp6", DhcpcdResolvConfDir), "eth0"},
		{fmt.Sprintf("%s/eth0.ra", DhcpcdResolvConfDir), "eth0"},
		// Valid file in WwanResolvConfDir
		{fmt.Sprintf("%s/wwan0.dhcp", WwanResolvConfDir), "wwan0"},
		// Unknown extension → empty
		{fmt.Sprintf("%s/eth0.conf", DhcpcdResolvConfDir), ""},
		// Not in any known dir → empty
		{"/tmp/eth0.dhcp", ""},
		// Empty string → empty
		{"", ""},
	}
	for _, tc := range cases {
		got := ResolvConfToIfname(tc.input)
		assert.Equal(t, tc.want, got, "input=%q", tc.input)
	}
}
