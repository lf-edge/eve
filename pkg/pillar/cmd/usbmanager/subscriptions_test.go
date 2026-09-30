// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// pubsub hands a modify handler the new object third and the previous one
// fourth. An adapter present only in the new list has been added to the model
// and must become known to the controller; one present only in the old list
// has been removed and must be forgotten; one present in both under the same
// label but with a changed address must have its rule replaced.
func TestAssignableAdaptersModifyAddsNewAndRemovesOld(t *testing.T) {
	// The USB controller the drive hangs off stays in the model throughout.
	xhci := types.IoBundle{Phylabel: "xhci", Type: types.IoUSBController,
		AssignmentGroup: "xhci", PciLong: "0000:00:02.0"}
	usb := types.IoBundle{Phylabel: "usb-flash", AssignmentGroup: "usb-flash", UsbAddr: "1:2"}

	usbCtx := newUsbmanagerContext()
	usbCtx.handleAssignableAdaptersCreate(nil, "global",
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci}})

	// The model gains usb-flash.
	usbCtx.handleAssignableAdaptersModify(nil, "global",
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci, usb}},
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci}})
	if usbCtx.controller.iobt.ioBundle("usb-flash") == nil {
		t.Fatal("an adapter added to the model is unknown to the controller")
	}

	// usb-flash keeps its label but now claims a different address: the old
	// rule must go and the new one must be in force.
	usbWildcard := usb
	usbWildcard.UsbAddr = "1:*"
	usbCtx.handleAssignableAdaptersModify(nil, "global",
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci, usbWildcard}},
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci, usb}})
	if got := usbCtx.controller.iobt.ioBundle("usb-flash"); got == nil || got.UsbAddr != "1:*" {
		t.Fatalf("a changed adapter was not replaced in the controller: %+v", got)
	}
	if _, stale := usbCtx.controller.ruleEngine.rules["USB Port Passthrough Rule 1/2"]; stale {
		t.Fatal("the rule of the adapter's old address is still in the rule engine")
	}
	if _, ok := usbCtx.controller.ruleEngine.rules["USB Port Passthrough Rule 1/*"]; !ok {
		t.Fatalf("the rule of the adapter's new address is missing: %s", usbCtx.controller.ruleEngine)
	}

	// The model loses usb-flash again.
	usbCtx.handleAssignableAdaptersModify(nil, "global",
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci}},
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci, usbWildcard}})
	if usbCtx.controller.iobt.ioBundle("usb-flash") != nil {
		t.Fatal("an adapter removed from the model is still known to the controller")
	}
}
