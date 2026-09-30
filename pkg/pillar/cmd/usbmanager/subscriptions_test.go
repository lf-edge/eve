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
// has been removed and must be forgotten.
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

	// The model loses usb-flash again.
	usbCtx.handleAssignableAdaptersModify(nil, "global",
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci}},
		types.AssignableAdapters{IoBundleList: []types.IoBundle{xhci, usb}})
	if usbCtx.controller.iobt.ioBundle("usb-flash") != nil {
		t.Fatal("an adapter removed from the model is still known to the controller")
	}
}
