// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware_test

import (
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	// Logical name of the (single) edge device used by every test in this package.
	devName = "hardware-dev"

	// The single management port every test in this package configures.
	// portLogicalLabel is what the controller calls it; portIfName is the
	// underlying Linux interface.
	portLogicalLabel = "ethernet0"
	portIfName       = "eth0"
)

// setupHardwareTestDevice declares the prerequisites shared by every test in
// this package and returns a handle to the device. They are stated in one
// place because the framework compares device requirements field by field to
// decide whether the VM from the previous test can be reused. Every test here
// changes the device's hardware through the hypervisor, so the suite is
// skipped on a provider without QMP access.
func setupHardwareTestDevice(hypervisor evetest.Hypervisor) *evetest.EdgeDevice {
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
		evetest.RequireCapabilities{
			Capabilities: []api.Capability{api.Capability_CAPABILITY_QMP},
		},
	)
	return evetest.GetEdgeDevice(devName)
}

// singleMgmtPortConfig builds the device configuration shared by the tests in
// this package: one DHCP-configured management+apps port and nothing else. The
// tests look at the device's hardware, so the configuration exists only to
// keep the device reporting to the controller.
func singleMgmtPortConfig() *evetest.EdgeDeviceConfig {
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  portLogicalLabel,
		PhysicalLabel: portIfName,
		InterfaceName: portIfName,
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	return devConfig
}

// hasUSBDevice is a predicate over ListUSBDevices: a device with the given
// serial number, vendor id and product id is enumerated.
func hasUSBDevice(serial string, vendorID, productID uint16) func(evetest.USBDeviceList) bool {
	return func(list evetest.USBDeviceList) bool {
		dev := list.FindBySerial(serial)
		return dev != nil && dev.VendorID == vendorID && dev.ProductID == productID
	}
}

// lacksUSBDevice is a predicate over ListUSBDevices: no device with the given
// serial number is enumerated.
func lacksUSBDevice(serial string) func(evetest.USBDeviceList) bool {
	return func(list evetest.USBDeviceList) bool {
		return list.FindBySerial(serial) == nil
	}
}
