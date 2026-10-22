// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"encoding/base64"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// Alpine cloud images, pinned per architecture. See https://alpinelinux.org/cloud/.
var unresponsiveGuestImages = map[string]struct {
	relativePath string
	sha256       string
	sizeBytes    uint64
}{
	"amd64": {
		relativePath: "/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2",
		sha256:       "6e2e6fe0572b6632527f268d3659e8fccebda4e1ee470fafe2c4d7b85b6a4df6",
		sizeBytes:    183697408,
	},
	"arm64": {
		relativePath: "/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-aarch64-uefi-cloudinit-r0.qcow2",
		sha256:       "3059a6280977c2122982632e0317c5ddbd39069d46ca1e60480de283091f720f",
		sizeBytes:    239271936,
	},
}

// How long the guest is given to finish applying its user-data before the test
// stops it, so the guest ignores the poweroff request rather than racing
// cloud-init for it.
const unresponsiveGuestSettle = 90 * time.Second

// TestHaltUnresponsiveGuest verifies that a guest which never acts on the ACPI
// poweroff request is still stopped promptly.
//
// Nothing obliges a guest to service that request, and when it does not only
// terminating the domain ends the stop; until then the application stays
// reported as halting and holds its memory and any assigned PCI devices. The
// guest here ignores it by construction -- acpid services the power button on
// Alpine, and cloud-init stops it and removes it from the runlevel. The mode is
// HVM, which already gets the short first wait, so what is left under test is
// the escalation after it.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the guest only has to reach the image
//     datastore and then be stopped.
//
// Device configuration
// --------------------
//   - one mgmt+apps port, one local network instance
//   - one HVM VM application from the pinned Alpine cloud image, with acpid
//     disabled through user-data
//
// Phases
// ------
//  1. Deploy the application and wait until it is reported RUNNING.
//  2. Let cloud-init finish disabling acpid.
//  3. Deactivate the application.
//  4. Require it to be reported HALTED within haltBudget.
func TestHaltUnresponsiveGuest(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	image, known := unresponsiveGuestImages[device.GetArch()]
	if !known {
		test.Skipf("no pinned Alpine cloud image for %s", device.GetArch())
	}

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	niUUID := addLocalNI(devConfig)
	cloudConfig := `#cloud-config
runcmd:
  - rc-service acpid stop
  - rc-update del acpid default
`
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "unresponsive-app",
		Activate:    true,
		Image: evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_QCOW2,
			ImageSHA256:       image.sha256,
			MaxDownloadBytes:  image.sizeBytes,
			ImageRelativePath: image.relativePath,
			ServerAddress:     "dl-cdn.alpinelinux.org",
			UseHTTPS:          true,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		UserData:           base64.StdEncoding.EncodeToString([]byte(cloudConfig)),
		NetworkAdapters:    singleVIFWithSSH(niUUID),
	})

	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 10*time.Minute)
	evetest.Checkpoint("app-running")

	time.Sleep(unresponsiveGuestSettle)

	halt := watchHalt(appUpdates)
	device.DeactivateApplication(appUUID, false, 0)
	evetest.Checkpoint("app-deactivated")

	requireHaltedWithinBudget(t, halt)
}
