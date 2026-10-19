// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import "testing"

// TestCellularConnectivity and TestWifiConnectivity are intentionally left
// unimplemented for now: wireless connectivity tests require device
// passthrough support in the evetest framework (modems and Wi-Fi NICs are
// passed through to the EVE VM, not emulated). Implementing them is out of
// scope for the current effort; revisit once the passthrough infrastructure
// (PCI/USB passthrough through the broker) is in place.

func TestCellularConnectivity(test *testing.T) {
	test.Skip("not yet implemented")
	// TODO -- device passthrough not yet supported in evetest
}

func TestWifiConnectivity(test *testing.T) {
	test.Skip("not yet implemented")
	// TODO -- device passthrough not yet supported in evetest
}
