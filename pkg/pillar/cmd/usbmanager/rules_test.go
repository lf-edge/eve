// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"testing"
)

func TestUsbNetworkAdapterForbidPassthroughRule(t *testing.T) {
	usbNetworkAdapterForbidPassthroughRule := usbNetworkAdapterForbidPassthroughRule{}

	usbNetworkAdapterForbidPassthroughRule.netDevPaths = func() []string {
		return []string{"/sys/devices/pci0000:00/0000:00:14.0/usb4/4-2/4-2.1/4-2.1:1.0"}
	}

	ud := usbdevice{}

	ud.ueventFilePath = "/sys/devices/pci0000:00/0000:00:14.0/usb4/4-2/4-2.1/"

	if usbNetworkAdapterForbidPassthroughRule.evaluate(ud) != passthroughForbid {
		t.Fatalf("passthrough should be forbidden, but isn't")
	}
}

func TestUsbNetworkAdapterAllowPassthroughRule(t *testing.T) {
	usbNetworkAdapterForbidPassthroughRule := usbNetworkAdapterForbidPassthroughRule{}

	usbNetworkAdapterForbidPassthroughRule.netDevPaths = func() []string {
		return []string{"/sys/devices/pci0000:00/0000:00:14.0/usb4/4-2/4-2.11/4-2.1:1.0"}
	}

	ud := usbdevice{}

	ud.ueventFilePath = "/sys/devices/pci0000:00/0000:00:14.0/usb4/4-2/4-2.1/"

	if usbNetworkAdapterForbidPassthroughRule.evaluate(ud) == passthroughForbid {
		t.Fatalf("passthrough should not be forbidden (port 1 versus port 11), but it is")
	}
}
