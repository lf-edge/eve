// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"testing"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
)

// newTestDeviceConfig builds a device configuration bound to a minimal
// harness, enough for builder methods whose success path never fails the
// test.
func newTestDeviceConfig(t *testing.T) *EdgeDeviceConfig {
	th := &TestHarness{}
	th.t = &T{T: t, th: th}
	return &EdgeDeviceConfig{
		EdgeDevConfig: &eveconfig.EdgeDevConfig{DeviceName: "unit-test"},
		th:            th,
	}
}

// DeletePhysicalIO removes exactly the named entry added with AddPhysicalIO
// and leaves the others in place.
func TestDeletePhysicalIO(t *testing.T) {
	dc := newTestDeviceConfig(t)
	dc.AddPhysicalIO(PhysicalIOConfig{
		LogicalLabel:  "usb-flash",
		PhysicalLabel: "usb-flash",
		Type:          evecommon.PhyIoType_PhyIoUSBDevice,
		USBAddress:    "1:2",
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})
	dc.AddPhysicalIO(PhysicalIOConfig{
		LogicalLabel:  "com1",
		PhysicalLabel: "COM1",
		Type:          evecommon.PhyIoType_PhyIoCOM,
		Serial:        "/dev/ttyS0",
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})

	dc.DeletePhysicalIO("usb-flash")

	if len(dc.DeviceIoList) != 1 || dc.DeviceIoList[0].Logicallabel != "com1" {
		t.Fatalf("expected only com1 to remain, got %v", dc.DeviceIoList)
	}
	// The label is free again for a new entry.
	dc.AddPhysicalIO(PhysicalIOConfig{
		LogicalLabel:  "usb-flash",
		PhysicalLabel: "usb-flash",
		Type:          evecommon.PhyIoType_PhyIoUSBDevice,
		USBAddress:    "1:3",
	})
	if len(dc.DeviceIoList) != 2 {
		t.Fatalf("expected the label to be reusable after deletion, got %v", dc.DeviceIoList)
	}
}
