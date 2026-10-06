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

	action, _ := usbNetworkAdapterForbidPassthroughRule.evaluate(ud)
	if action != passthroughForbid {
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

	action, _ := usbNetworkAdapterForbidPassthroughRule.evaluate(ud)
	if action == passthroughForbid {
		t.Fatalf("passthrough should not be forbidden (port 1 versus port 11), but it is")
	}
}

// Two different port rules claiming the same device must differ in priority,
// otherwise the rule engine picks the winner by map iteration order.
func FuzzOverlappingUsbPortRulesPriority(f *testing.F) {
	f.Add("1:2.*", "1:2.3", "2.3")
	f.Add("1:*", "1:2.*", "2.1")
	f.Add("1:2.*", "1:2.3.*", "2.3.4")
	f.Add("1:2.3", "1:2.4", "2.3")
	f.Add("1:1.1.1.1.1.*", "1:1.1.1.1.1.1.*", "1.1.1.1.1.1.1")
	f.Add("1:1.1.1.1.1.1.1.1.*", "1:1.1.1.1.1.1.1.1.1.*", "1.1.1.1.1.1.1.1.1.1")
	f.Add("0:*", "00:*", "0")

	f.Fuzz(func(t *testing.T, usbAddr1, usbAddr2, devicePort string) {
		rule1, err1 := usbAddr2passthroughRule(usbAddr1)
		rule2, err2 := usbAddr2passthroughRule(usbAddr2)

		// different spellings like "0:*" and "00:*" yield the same rule, which
		// the rule engine stores only once, so only distinct rules can tie
		if err1 != nil || err2 != nil {
			return
		}
		if rule1.busnum == rule2.busnum && rule1.portnum == rule2.portnum {
			return
		}

		ud := usbdevice{busnum: rule1.busnum, portnum: devicePort}
		action1, priority1 := rule1.evaluate(ud)
		action2, priority2 := rule2.evaluate(ud)
		if action1 == passthroughDo && action2 == passthroughDo && priority1 == priority2 {
			t.Fatalf("%s and %s both match port %q with priority %v",
				rule1, rule2, devicePort, priority1)
		}
	})
}
