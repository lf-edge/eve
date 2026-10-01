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

// The allocator hands out the lowest free port of the controller, or of the
// hub a device goes below, and gives a device its previous port back when it
// is re-plugged into the same parent, so that a device-model entry claiming
// it by bus and port keeps matching across re-plugs.
func TestUSBPortAllocator(t *testing.T) {
	var ports usbPortAllocator
	expect := func(what, got, want string) {
		t.Helper()
		if got != want {
			t.Fatalf("%s: got port %q, want %q", what, got, want)
		}
	}
	expect("first claim", ports.claim("a", ""), "1")
	expect("second claim", ports.claim("b", ""), "2")
	expect("claiming a held id again", ports.claim("a", ""), "1")
	ports.release("a")
	expect("re-plugging a", ports.claim("a", ""), "1")
	ports.release("a")
	expect("a new device", ports.claim("c", ""), "1")
	expect("a re-plugged while its port is taken", ports.claim("a", ""), "3")
	ports.release("unknown") // must not panic

	// Below a hub, paths extend the hub's; the re-plug memory only counts
	// for the same parent.
	expect("a hub", ports.claim("hub", ""), "4")
	expect("first device below the hub", ports.claim("d", "4"), "4.1")
	expect("a nested hub", ports.claim("hub2", "4"), "4.2")
	expect("a device below the nested hub", ports.claim("e", "4.2"), "4.2.1")
	ports.release("d")
	expect("re-plugging d below the hub", ports.claim("d", "4"), "4.1")
	ports.release("d")
	expect("plugging d into the controller instead", ports.claim("d", ""), "5")

	if path, ok := ports.path("hub2"); !ok || path != "4.2" {
		t.Fatalf("path(hub2) = %q, %v; want 4.2, true", path, ok)
	}
	if _, ok := ports.path("unknown"); ok {
		t.Fatal("path(unknown) reported a port")
	}
	if got := ports.children("4"); !reflect.DeepEqual(got, []string{"hub2", "e"}) {
		t.Fatalf("children(4) = %v, want [hub2 e]", got)
	}
	if got := ports.children("4.2.1"); len(got) != 0 {
		t.Fatalf("children(4.2.1) = %v, want none", got)
	}
}
