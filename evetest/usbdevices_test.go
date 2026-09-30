// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"reflect"
	"testing"
)

// parseUSBDeviceList reads the output of the sysfs listing script: one device
// per line as "<bus>-<port> <idVendor> <idProduct> [<serial>]".
func TestParseUSBDeviceList(t *testing.T) {
	// A device without a serial number ends its line with a space.
	const stdout = "1-1 0627 0001 \n" +
		"2-3 46f4 0001 evtest-flash\n" +
		"2-3.4 0409 005a\n"
	got, err := parseUSBDeviceList(stdout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := USBDeviceList{
		{Bus: 1, Port: "1", VendorID: 0x0627, ProductID: 0x0001},
		{Bus: 2, Port: "3", VendorID: 0x46f4, ProductID: 0x0001, Serial: "evtest-flash"},
		{Bus: 2, Port: "3.4", VendorID: 0x0409, ProductID: 0x005a},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseUSBDeviceListEmpty(t *testing.T) {
	got, err := parseUSBDeviceList("\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no devices, got %+v", got)
	}
}

func TestParseUSBDeviceListMalformed(t *testing.T) {
	for _, line := range []string{"garbage", "1-1 zz 0001", "x-1 0627 0001", "1-1 0627"} {
		if _, err := parseUSBDeviceList(line + "\n"); err == nil {
			t.Fatalf("line %q should be rejected", line)
		}
	}
}

func TestUSBDeviceListFind(t *testing.T) {
	list := USBDeviceList{
		{Bus: 2, Port: "3", VendorID: 0x46f4, ProductID: 0x0001, Serial: "evtest-flash"},
	}
	if dev := list.FindBySerial("evtest-flash"); dev == nil || dev.Port != "3" {
		t.Fatalf("FindBySerial did not return the device: %+v", dev)
	}
	if dev := list.FindBySerial("other"); dev != nil {
		t.Fatalf("FindBySerial returned %+v for an unknown serial", dev)
	}
}
