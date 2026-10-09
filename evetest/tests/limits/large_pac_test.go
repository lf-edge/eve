// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package limits_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// pacKiBParamKey selects the size of the proxy auto-config script
// TestLargePACFile puts on the management port.
const pacKiBParamKey = "PAC_KIB"

// defaultPACKiB is the script size at which the port configuration outgrows
// a pubsub message with margin; see the test's description.
const defaultPACKiB = 64

// TestLargePACFile verifies that a proxy auto-config (PAC) script of a size
// real corporate PAC files have is handled without crashing the device: the
// port configuration carrying it is reported by the device, as current or
// with an error, and the device stays up either way.
//
// A controller may send the PAC script of a port's proxy configuration
// inline, base64-encoded; EVE keeps it that way in the port configuration
// (DevicePortConfig, published by zedagent), in the port status and in the
// list of port configurations nim keeps on disk. Unlike the proxy's CA
// certificates, the script is not spilled to a file. Measured on the real
// types with one port: a 32 KB script puts the port configuration at 58 KB on
// the wire and a 48 KB one at 87 KB, so the default of 64 KB (116 KB) is
// where an unfixed zedagent exits with "Too large message" while publishing
// the port configuration -- and keeps doing so after every reboot, since the
// device configuration is checkpointed and re-read. Corporate PAC files of
// 50 to 300 KB are common.
//
// The script itself routes everything DIRECT, so the device's connectivity
// is the same with it as without, and a build that carries it (spilling the
// script to a file, or changing the transport) verifies the port
// configuration as usual; a build that refuses it reports the configuration
// with an error. The test accepts both.
//
// Network model: netmodels.SingleEthWithDHCP.
//
// Device config: one DHCP management port, a 5-second metrics interval; then
// the port's network gets the PAC script as its proxy configuration.
//
// Phases:
//  1. Apply the base configuration and wait until it is processed.
//  2. Put the PAC script on the port's network, apply, and wait until the
//     device reports a controller port configuration newer than the change,
//     with the device still reporting metrics afterwards. Stop at once if
//     the device crashes.
//
// Parameters: HYPERVISOR (shared with the suite), PAC_KIB (default 64).
//
// Suite placement: TestLimitsSuite.
func TestLargePACFile(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          pacKiBParamKey,
			DefaultValue: defaultPACKiB,
			Description: evetest.TestParameterDescription{
				Summary: "Size of the PAC script on the management port, in KiB",
				Default: fmt.Sprint(defaultPACKiB),
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	pacKiB := evetest.GetTestParameter[int](pacKiBParamKey)

	device := setupDevice(hypervisor, 0)
	evetest.Checkpoint("setup-done")
	log := evetest.Logger()
	devConfig, dhcpNet := applyBaseConfig(device, hypervisor)
	evetest.Checkpoint("base-config-applied")
	crash := device.WatchForCrash()
	defer crash.Stop()

	// Phase 2: the PAC script on the port's network.
	script := pacScript(pacKiB * 1024)
	log.Infof("Putting a %d-byte PAC script on the management port", len(script))
	devConfig.UpdateNetwork(dhcpNet, evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		ProxyConfig: evetest.PACFileProxyConfig{PACScript: script},
	})
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	applyStart := time.Now().Add(-time.Minute) // tolerate clock skew
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("pac-config-applied")

	var latest *eveinfo.ZInfoDevice
	awaitWhileAlive(t, device, crash,
		"the device reports the port configuration carrying the PAC script",
		10*time.Minute, func() bool {
			for drained := false; !drained; {
				select {
				case info, ok := <-devUpdates:
					drained = !ok
					if ok {
						latest = info
					}
				default:
					drained = true
				}
			}
			return controllerDPCSince(latest, applyStart) != nil
		})
	dpc := controllerDPCSince(latest, applyStart)
	pacBytes := 0
	for _, port := range dpc.GetPorts() {
		pacBytes += len(port.GetProxy().GetPacfile())
	}
	log.Infof("The port configuration with the PAC script is reported: current=%v, "+
		"PAC carried in the port status: %d bytes, error: %q",
		latest.GetSystemAdapter().GetStatus()[latest.GetSystemAdapter().GetCurrentIndex()] == dpc,
		pacBytes, dpc.GetLastError())
	evetest.Checkpoint("pac-config-reported")
}

// pacScript returns a PAC script of about size bytes that routes every URL
// DIRECT: a FindProxyForURL of as many host checks as it takes.
func pacScript(size int) string {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")
	for i := 0; b.Len() < size-40; i++ {
		fmt.Fprintf(&b, "  if (shExpMatch(host, \"host-%06d.example.test\")) "+
			"{ return \"DIRECT\"; }\n", i)
	}
	b.WriteString("  return \"DIRECT\";\n}\n")
	return b.String()
}

// controllerDPCSince returns the controller's port configuration in the
// device info if it is newer than since, else nil.
func controllerDPCSince(dinfo *eveinfo.ZInfoDevice, since time.Time) *eveinfo.DevicePortStatus {
	for _, dpc := range dinfo.GetSystemAdapter().GetStatus() {
		if dpc.GetKey() == "zedagent" && dpc.GetTimePriority().AsTime().After(since) {
			return dpc
		}
	}
	return nil
}
