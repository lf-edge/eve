// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Application life-cycle operations tested against the EVE API:
// controller-requested restart of an application instance.

package apps_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestLotsOfApps(test *testing.T) {
	const countApps = 25

	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    hypervisor,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
		MinRAMInMiB:       24576,
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build the device configuration: one mgmt+apps port, one Local NI and
	// one container app connected to it.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})

	appUpdatess := make([]<-chan *eveinfo.ZInfoApp, 0)
	appUUIDs := make([]uuid.UUID, 0)
	for i := range countApps {
		appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
			DisplayName: fmt.Sprintf("restarted-app-%d", i),
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen, shim VM fails to start
			CPUs:               1,
			MemoryBytes:        500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        fmt.Sprintf("vif%d", i),
					NetworkInstanceUUID: niUUID,
					PortFwdRules: []evetest.PortFwdRule{
						{
							Protocol:     evetest.NetworkProtocolTCP,
							EdgeNodePort: 2222 + uint16(i),
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
			},
		})

		appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
		appUpdatess = append(appUpdatess, appUpdates)
		defer stopAppWatch()
		appUUIDs = append(appUUIDs, appUUID)

	}
	device.ApplyConfig(devConfig, true, true)

	// give it a bit more time for slow laptops
	timeoutExcludingDownload := 15 * time.Minute
	for _, appUUID := range appUUIDs {
		device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	}

	evetest.Checkpoint("app-deployed")

	// An app reaching RUNNING does not mean it has fully booted -- wait
	// until its SSH daemon is reachable through the 2222->22 port-forwarding
	// rule before considering the deployment complete.
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	timeout := 3 * time.Minute
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()
	verifyAppOverSSH := func() {
		for _, appUUID := range appUUIDs {
			t.Eventually(func(t Gomega) {
				log.Infof("Waiting for app SSH daemon to start and become reachable...")
				output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
					"hostname", sshTimeout, 0)
				t.Expect(err).ToNot(HaveOccurred())
				t.Expect(output).To(ContainSubstring(appUUID.String()))
			}, timeout, polling).Should(Succeed())
		}
	}
	verifyAppOverSSH()

	for _, appUpdates := range appUpdatess {
		t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
			"App is RUNNING and reports its boot time",
			func(info *eveinfo.ZInfoApp) bool {
				return info.State == eveinfo.ZSwState_RUNNING &&
					info.GetBootTime() != nil
			}).StopIf(appHasError)))
	}

	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable...")
		stdout, stderr, err := device.RunShellScript("pgrep -c qemu-system",
			time.Minute, 0)
		t.Expect(err).ToNot(HaveOccurred())
		log.Printf("stdout: \n%s\n", stdout)
		log.Printf("stderr: \n%s\n", stderr)
		result, err := strconv.Atoi(strings.TrimSpace(stdout))
		t.Expect(err).ToNot(HaveOccurred())
		if err == nil && result >= countApps {
			return
		}
		t.Expect(result).Should(BeNumerically("==", countApps))
	}, 10*time.Minute, 20*time.Second).Should(Succeed())
}
