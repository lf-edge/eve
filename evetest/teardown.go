// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"fmt"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
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

	// Report failures after releasing devicesM: with pause-on-failure, Fatalf
	// blocks until resumed, and holding the lock would hang the Status RPC.
	if err := th.removeAndTeardownDevices(); err != nil {
		th.t.Fatalf("%v", err)
	}
}

// removeAndTeardownDevices removes all devices from the controller and tears
// them down together with the SDN VM.
func (th *TestHarness) removeAndTeardownDevices() error {
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
			return fmt.Errorf(
				"failed to remove device %q from the controller: %w",
				dev.name, err)
		}
	}

	// Tear-down all deployed EVE devices and the SDN VM. Sized to let every
	// device (+1 for the SDN device) fully use its own
	// constants.BrokerTeardownDevicesTimeout slice.
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(len(th.devices)+1)*constants.BrokerTeardownDevicesTimeout)
	_, err := th.brokerClient.TeardownDevices(ctx,
		&api.TeardownDevicesRequest{ClientId: th.brokerClientID})
	cancel()
	if err != nil {
		return fmt.Errorf("failed to tear-down all devices: %w", err)
	}
	th.devices = make(map[string]*deviceState)
	return nil
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
