// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// zonetoString (unexported — tested within the package)

func TestZonetoString(t *testing.T) {
	cases := []struct {
		zone UsageZone
		want string
	}{
		{GreenZone, "GREEN"},
		{YellowZone, "YELLOW"},
		{OrangeZone, "ORANGE"},
		{RedZone, "RED"},
		{UsageZone(99), "UNKNOWN"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, zonetoString(tc.zone))
	}
}
