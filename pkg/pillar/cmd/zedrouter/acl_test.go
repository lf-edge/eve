// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"testing"
)

// Test hostIpsetBasename function.
func TestHostIpsetBasename(t *testing.T) {
	tests := []struct {
		testname         string
		hostname         string
		expIpsetBasename string
	}{
		{
			testname:         "short hostname",
			hostname:         "google.com",
			expIpsetBasename: "google.com",
		},
		{
			testname:         "short hostname ending with '.'",
			hostname:         "google.com.",
			expIpsetBasename: "google.com.",
		},
		{
			testname:         "short TLD",
			hostname:         "com",
			expIpsetBasename: "com",
		},
		{
			testname:         "short TLD ending with '.'",
			hostname:         "com.",
			expIpsetBasename: "com.",
		},
		{
			testname:         "hostname just at the length limit",
			hostname:         "this.host.fits.the.limit.x",
			expIpsetBasename: "this.host.fits.the.limit.x",
		},
		{
			testname:         "very long hostname",
			hostname:         "theofficialabsolutelongestdomainnameregisteredontheworldwideweb.international",
			expIpsetBasename: "unFy00boc2ME#international",
		},
		{
			testname:         "very long hostname ending with '.'",
			hostname:         "theofficialabsolutelongestdomainnameregisteredontheworldwideweb.international.",
			expIpsetBasename: "josqV3v361A#international.",
		},
		{
			testname:         "very long TLD",
			hostname:         "shop.verylongcompanynamewhichmakesnosense",
			expIpsetBasename: "jbfc_EF2sup6los19u4HLC4BN#",
		},
		{
			testname:         "very long TLD ending with '.'",
			hostname:         "shop.verylongcompanynamewhichmakesnosense.",
			expIpsetBasename: "3dNidrrnlGggYozJoicbPPi_y#",
		},
		{
			testname:         "hostname one character above the length limit",
			hostname:         "this.host.is.over.the.limit",
			expIpsetBasename: "rQRoWR0T#is.over.the.limit",
		},
		{
			testname:         "empty hostname",
			hostname:         "",
			expIpsetBasename: "",
		},
	}
	for _, test := range tests {
		t.Run(test.testname, func(t *testing.T) {
			if len(test.expIpsetBasename)+len("ipvX.") > ipsetNameLenLimit {
				t.Errorf("expected ipset basename '%s' is unexpectedly long"+
					" - mistake in the test?", test.expIpsetBasename)
			}
			ipsetBasename := hostIpsetBasename(test.hostname)
			if ipsetBasename != test.expIpsetBasename {
				t.Errorf("failed for: hostname=%s\n"+
					"expected ipset basename:\n\t%q\ngot ipset basename:\n\t%q",
					test.hostname, test.expIpsetBasename, ipsetBasename)
			}
		})
	}
}
