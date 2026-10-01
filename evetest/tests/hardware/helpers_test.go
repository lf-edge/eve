// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware_test

import (
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// Logical name of the (single) edge device used by every test in this package.
	devName = "hardware-dev"

	// The single management port every test in this package configures.
	// portLogicalLabel is what the controller calls it; portIfName is the
	// underlying Linux interface.
	portLogicalLabel = "ethernet0"
	portIfName       = "eth0"

	// Image of the general-purpose test container (ships sshd). Deployed as
	// HVM, EVE runs it inside a QEMU domain, which is what USB passthrough
	// attaches to.
	ubuntuCtrImage = "lfedge/evetest-ubuntu-ctr"
	ubuntuCtrTag   = "1.0"

	// Local network instance connecting the app, and the port on the edge
	// node forwarded to the app's sshd.
	niDisplayName = "local-ni"
	niSubnet      = "10.11.12.0/24"
	niGateway     = "10.11.12.1"
	appSSHFwdPort = 2222

	// usbFlashLabel names the flash drive in the device model when claimed by
	// its exact bus and port, usbFlashWildcardLabel when claimed by a bus-wide
	// wildcard. A label serves as logical label, physical label and assignment
	// group alike: domainmgr resolves an app adapter name by group, then
	// physical, then logical label, and usbmanager keys on the physical label.
	usbFlashLabel         = "usb-flash"
	usbFlashWildcardLabel = "usb-flash-wildcard"

	// devInfoTimeout covers ZInfoDevice reflecting a change to the assignable
	// adapters after a config apply.
	devInfoTimeout = 5 * time.Minute
	// appRunningTimeout excludes the image download.
	appRunningTimeout = 10 * time.Minute
)

// Credentials baked into the evetest-ubuntu-ctr image.
var appAuth = evetest.UsernamePasswordAuth{
	Username: "root",
	Password: "testpassword",
}

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

// singleMgmtPortConfig builds the device configuration the tests in this
// package start from: one DHCP-configured management+apps port and nothing
// else. Tests add the network instance, model entries and apps they need.
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

// addLocalNI adds the local network instance the app is connected to:
// niSubnet on the management port.
func addLocalNI(devConfig *evetest.EdgeDeviceConfig) uuid.UUID {
	return devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: niDisplayName,
		Port:        portLogicalLabel,
		Subnet:      evetest.IPSubnet(niSubnet),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress(niGateway),
		MTU:     1500,
	})
}

// singleVIFWithSSH describes the app network adapter used to run commands
// inside the application: a VIF on the local NI, the sshd port forwarded from
// the edge node, and an allow-all ACL.
func singleVIFWithSSH(niUUID uuid.UUID) []evetest.AppNetworkAdapter {
	return []evetest.AppNetworkAdapter{
		evetest.VirtualNetworkAdapter{
			LogicalLabel:        "vif0",
			NetworkInstanceUUID: niUUID,
			PortFwdRules: []evetest.PortFwdRule{
				{
					Protocol:     evetest.NetworkProtocolTCP,
					EdgeNodePort: appSSHFwdPort,
					AppPort:      22,
				},
			},
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
		},
	}
}

// usbFlashPhysicalIO models the flash drive as an assignable USB device.
func usbFlashPhysicalIO(name, usbAddr string) evetest.PhysicalIOConfig {
	return evetest.PhysicalIOConfig{
		LogicalLabel:    name,
		PhysicalLabel:   name,
		AssignmentGroup: name,
		Type:            evecommon.PhyIoType_PhyIoUSBDevice,
		USBAddress:      usbAddr,
		Usage:           evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	}
}

// usbFlashAppConfig is the application the drive is assigned to: the ubuntu
// test container as an HVM domain, reachable over SSH through the local NI.
func usbFlashAppConfig(ioAdapterName string, niUUID uuid.UUID) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName: "usb-flash-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters:    singleVIFWithSSH(niUUID),
		IOAdapters: []evetest.IOAdapterConfig{
			{
				LogicalLabel: ioAdapterName,
				Type:         evecommon.PhyIoType_PhyIoUSBDevice,
			},
		},
	}
}

// usbFlashApps deploys applications that have the flash drive assigned. It
// holds what all of them share: the device, its configuration and the local
// network instance they hang off, which the factory adds to the configuration
// (applied together with the first app).
type usbFlashApps struct {
	t         *WithT
	device    *evetest.EdgeDevice
	devConfig *evetest.EdgeDeviceConfig
	niUUID    uuid.UUID
}

func newUSBFlashApps(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig) *usbFlashApps {
	return &usbFlashApps{
		t:         t,
		device:    device,
		devConfig: devConfig,
		niUUID:    addLocalNI(devConfig),
	}
}

// start models the drive as the PhysicalIO label claiming usbAddr, deploys the
// ubuntu test container with that adapter and returns once the app is RUNNING
// and answers over SSH.
func (f *usbFlashApps) start(label, usbAddr string) *usbFlashApp {
	evetest.Logger().Infof("Deploying app with the flash drive claimed as %q by usbaddr %q",
		label, usbAddr)
	f.devConfig.AddPhysicalIO(usbFlashPhysicalIO(label, usbAddr))
	appUUID := f.devConfig.AddApplication(usbFlashAppConfig(label, f.niUUID))
	f.device.ApplyConfig(f.devConfig, true, false)
	f.device.WaitUntilAppIsRunning(appUUID, appRunningTimeout)
	waitForAppSSH(f.t, f.device, appUUID)
	return &usbFlashApp{apps: f, label: label, uuid: appUUID}
}

// usbFlashApp is one running application with the drive assigned.
type usbFlashApp struct {
	apps  *usbFlashApps
	label string
	uuid  uuid.UUID
}

// usbDevices lists the USB devices the app's kernel enumerates; a method value
// for Eventually.
func (a *usbFlashApp) usbDevices() (evetest.USBDeviceList, error) {
	return a.apps.device.ListUSBDevicesInsideApp(a.uuid, appAuth)
}

// stop deletes the app, waits until the device reports it gone, and only then
// removes its model entry and applies. A confirmed config apply says nothing
// about the domain teardown, which releases the adapter some thirty seconds
// after the app is halted, and removing the entry before that used to crash
// domainmgr.
func (a *usbFlashApp) stop() {
	deleteAppAndWait(a.apps.t, a.apps.device, a.apps.devConfig, a.uuid)
	a.apps.devConfig.DeletePhysicalIO(a.label)
	a.apps.device.ApplyConfig(a.apps.devConfig, true, false)
}

// lookupAssignableAdapter returns the reported assignable adapter (group)
// named label or having label among its members, or nil.
func lookupAssignableAdapter(dinfo *eveinfo.ZInfoDevice, label string) *eveinfo.ZioBundle {
	for _, bundle := range dinfo.GetAssignableAdapters() {
		if bundle.GetName() == label {
			return bundle
		}
		for _, member := range bundle.GetMembers() {
			if member == label {
				return bundle
			}
		}
	}
	return nil
}

// adapterUsedBy is a predicate over ZInfoDevice: the adapter is reported
// without error and as assigned to the given application.
func adapterUsedBy(label string, appUUID uuid.UUID) func(*eveinfo.ZInfoDevice) bool {
	return func(dinfo *eveinfo.ZInfoDevice) bool {
		bundle := lookupAssignableAdapter(dinfo, label)
		return bundle != nil && bundle.GetErr() == nil &&
			bundle.GetUsedByAppUUID() == appUUID.String()
	}
}

// hasUSBDevice is a predicate over a USB device list: a device with the given
// serial number, vendor id and product id is enumerated.
func hasUSBDevice(serial string, vendorID, productID uint16) func(evetest.USBDeviceList) bool {
	return func(list evetest.USBDeviceList) bool {
		dev := list.FindBySerial(serial)
		return dev != nil && dev.VendorID == vendorID && dev.ProductID == productID
	}
}

// lacksUSBDevice is a predicate over a USB device list: no device with the
// given serial number is enumerated.
func lacksUSBDevice(serial string) func(evetest.USBDeviceList) bool {
	return func(list evetest.USBDeviceList) bool {
		return list.FindBySerial(serial) == nil
	}
}

// waitForAppSSH blocks until commands can be executed inside the application
// over the port-forwarded sshd. Reaching RUNNING only means the domain was
// created; sshd inside the container needs more time to accept connections.
func waitForAppSSH(t *WithT, device *evetest.EdgeDevice, appUUID uuid.UUID) {
	const (
		sshTimeout = 20 * time.Second
		timeout    = 3 * time.Minute
		polling    = 5 * time.Second
	)
	evetest.Logger().Infof("Waiting for app %q SSH to become reachable...", appUUID)
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"echo hello", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("hello"))
	}, timeout, polling).Should(Succeed())
}

// deleteAppAndWait removes the application from the device configuration,
// applies it, and blocks until the device reports the instance as gone, so
// that teardown cannot race the device-config reset before the next test.
func deleteAppAndWait(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, appUUID uuid.UUID) {
	const timeout = 5 * time.Minute
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Application instance is deleted",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
}
