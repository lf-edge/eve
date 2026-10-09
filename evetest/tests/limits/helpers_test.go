// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package limits_test

import (
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

const (
	// devName is the logical name of the single device every test uses.
	devName = "edge-dev"

	// mgmtPort is the logical label of the device's only port.
	mgmtPort = "ethernet0"

	// heartbeatInterval is how often the device reports metrics during a test
	// (timer.metric.interval): the proof that pillar is still alive.
	heartbeatInterval = 5 * time.Second

	// Image of the general-purpose test container, for the tests whose
	// oversized object hangs off an application.
	ubuntuCtrImage = "lfedge/evetest-ubuntu-ctr"
	ubuntuCtrTag   = "1.0"
)

// setupDevice declares the device every test in this package uses: one
// device on netmodels.SingleEthWithDHCP, reused across the suite with its
// configuration reset in between, and returns it. minRAMInMiB is the
// device's memory, 0 for the framework's default.
func setupDevice(hypervisor evetest.Hypervisor, minRAMInMiB uint32) *evetest.EdgeDevice {
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			MinRAMInMiB:       minRAMInMiB,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	return evetest.GetEdgeDevice(devName)
}

// applyBaseConfig applies the configuration every test starts from, one DHCP
// management port and a metrics report every heartbeatInterval, and waits
// until the device has processed it. It returns the configuration, for the
// test to add its oversized object to, and the UUID of the port's network,
// for the test that changes it.
func applyBaseConfig(device *evetest.EdgeDevice, hypervisor evetest.Hypervisor) (
	*evetest.EdgeDeviceConfig, uuid.UUID) {
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	props := types.NewConfigItemValueMap()
	props.SetGlobalValueInt(types.MetricInterval, uint32(heartbeatInterval.Seconds()))
	devConfig.SetConfigProperties(props)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  mgmtPort,
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	return devConfig, dhcpNet
}

// containerApp returns the configuration of a small container application
// named displayName, without network adapters.
func containerApp(displayName string) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName: displayName,
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
	}
}

// awaitWhileAlive waits until ready holds, then until the device has reported
// metrics twice more, at least heartbeatInterval later, which proves pillar
// outlived whatever ready observed. It fails at once when the device is known
// to have crashed, naming the cause. what describes the awaited condition in
// the failure messages.
func awaitWhileAlive(t *WithT, device *evetest.EdgeDevice, crash *evetest.CrashWatch,
	what string, timeout time.Duration, ready func() bool) {
	metricUpdates, stopMetrics := device.WatchDeviceMetrics()
	defer stopMetrics()
	var readyAt time.Time
	heartbeats := 0
	t.Eventually(func(g Gomega) {
		for drained := false; !drained; {
			select {
			case _, ok := <-metricUpdates:
				drained = !ok
				if ok && !readyAt.IsZero() && time.Since(readyAt) > heartbeatInterval {
					heartbeats++
				}
			default:
				drained = true
			}
		}
		if reason := crash.Reason(); reason != "" {
			StopTrying("pillar did not survive: " + reason).Now()
		}
		g.Expect(ready()).To(BeTrue(), "%s has not happened yet", what)
		if readyAt.IsZero() {
			readyAt = time.Now()
		}
		g.Expect(heartbeats).To(BeNumerically(">=", 2),
			"the device has reported metrics %d time(s) since %s, two are required",
			heartbeats, what)
	}, timeout, 5*time.Second).Should(Succeed())
}

// deleteAppsAndWait removes the applications from the configuration, applies
// it and waits until the device reports every one of them gone.
func deleteAppsAndWait(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, appUUIDs []uuid.UUID) {
	watches := make([]<-chan *eveinfo.ZInfoApp, 0, len(appUUIDs))
	for _, appUUID := range appUUIDs {
		updates, stop := device.WatchAppInfo(appUUID)
		defer stop()
		watches = append(watches, updates)
		devConfig.DeleteApplication(appUUID)
	}
	device.ApplyConfig(devConfig, false, false)
	for i, updates := range watches {
		t.Eventually(updates, 10*time.Minute).Should(Receive(matchers.SatisfyPredicate(
			"application "+appUUIDs[i].String()+" is gone",
			func(info *eveinfo.ZInfoApp) bool {
				return info.State == eveinfo.ZSwState_INVALID
			})))
	}
}
