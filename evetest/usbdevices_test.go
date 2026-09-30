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

// The allocator hands out the lowest free xHCI port and gives a drive its
// previous port back when it is re-plugged, so that a device-model entry
// claiming the drive by bus and port keeps matching across re-plugs.
func TestUSBPortAllocator(t *testing.T) {
	var ports usbPortAllocator
	if got := ports.claim("a"); got != "1" {
		t.Fatalf("first claim got port %q, want 1", got)
	}
	if got := ports.claim("b"); got != "2" {
		t.Fatalf("second claim got port %q, want 2", got)
	}
	if got := ports.claim("a"); got != "1" {
		t.Fatalf("claiming a held id again got %q, want its port 1", got)
	}
	ports.release("a")
	if got := ports.claim("a"); got != "1" {
		t.Fatalf("re-plugging a got port %q, want the port it left, 1", got)
	}
	ports.release("a")
	if got := ports.claim("c"); got != "1" {
		t.Fatalf("a new drive got port %q, want the lowest free port 1", got)
	}
	if got := ports.claim("a"); got != "3" {
		t.Fatalf("a re-plugged while its port is taken got %q, want the next free port 3", got)
	}
	ports.release("unknown") // must not panic
}
