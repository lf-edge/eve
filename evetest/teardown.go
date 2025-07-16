// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	uuid "github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
)

// Tear down any previously set up devices.
func (th *TestHarness) teardownDevices() {
	if len(th.devices) == 0 {
		return
	}

	// Remove SDN tunnel interface.
	if th.sdnTunCancel != nil {
		th.sdnTunCancel()
		th.sdnTunWG.Wait()
		th.sdnTunCancel = nil
	}
	th.sdnTunStream = nil
	if th.sdnTunIntf != nil {
		err := th.sdnTunIntf.Close()
		if err != nil {
			th.log.Warnf("Failed to close descriptor for SDN tunnel interface %q",
				th.sdnTunIntf.Name())
		}
		if link, err := netlink.LinkByName(th.sdnTunIntf.Name()); err == nil {
			err = netlink.LinkDel(link)
			if err != nil {
				th.log.Warnf("Failed to remove SDN tunnel interface %q",
					th.sdnTunIntf.Name())
			}
		}
		th.sdnTunIntf = nil
	}

	// Close SDN client.
	if th.sdnClient != nil {
		err := th.sdnConn.Close()
		if err != nil {
			th.log.Warnf("Failed to close SDN client connection: %v", err)
		}
		th.sdnClient = nil
		th.sdnConn = nil
	}

	// Forget previously applied network model.
	th.netModelM.Lock()
	th.netModel = nil
	th.netModelM.Unlock()

	th.devicesM.Lock()
	defer th.devicesM.Unlock()

	// Unsubscribe device state watchers before removing devices from the controller.
	th.unsubscribeDeviceWatchersLocked()

	// Remove EVE device from the controller.
	for _, dev := range th.devices {
		if dev.ID == uuid.Nil {
			continue
		}
		ctx, cancel := context.WithTimeout(th.ctx, deviceRemoveTimeout)
		err := th.adamClient.RemoveDevice(ctx, dev.ID)
		cancel()
		if err != nil {
			th.t.Fatalf(
				"Failed to remove device %q from the controller: %v",
				dev.name, err)
		}
	}

	// Tear-down all deployed EVE devices and the SDN VM.
	ctx, cancel := context.WithTimeout(context.Background(), brokerTeardownDevicesTimeout)
	_, err := th.brokerClient.TeardownDevices(ctx,
		&api.TeardownDevicesRequest{ClientId: th.brokerClientID})
	cancel()
	if err != nil {
		th.t.Fatalf("Failed to tear-down all devices: %v", err)
	}
	th.devices = make(map[string]*deviceState)
}

// unsubscribeDeviceWatchers unsubscribes info and config request watchers
// for all devices. The caller must hold devicesM.
func (th *TestHarness) unsubscribeDeviceWatchersLocked() {
	for _, dev := range th.devices {
		if dev.unsubscribeInfo != nil {
			dev.unsubscribeInfo()
			dev.unsubscribeInfo = nil
		}
		if dev.unsubscribeReq != nil {
			dev.unsubscribeReq()
			dev.unsubscribeReq = nil
		}
		if dev.unsubscribeMetrics != nil {
			dev.unsubscribeMetrics()
			dev.unsubscribeMetrics = nil
		}
	}
}
