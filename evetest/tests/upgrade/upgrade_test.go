// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	initialEVEVersionParamKey = "INITIAL_EVE_VERSION"
	initialHypervisorParamKey = "INITIAL_HYPERVISOR"
	expectRevertParamKey      = "EXPECT_REVERT"

	appSSHUser     = "root"
	appSSHPassword = "testpassword"
	appSSHFwdPort  = 2222
)

// TestEVEUpgrade performs an end-to-end upgrade from an initial EVE version to a
// target version. It deploys a container application before the upgrade, runs
// the upgrade (which causes one reboot), and then verifies that the application
// is still healthy under the new EVE version.
//
// The device boots on the initial version (EVETEST_INITIAL_EVE_VERSION +
// EVETEST_INITIAL_HYPERVISOR) and is upgraded to the target version
// (EVETEST_EVE_VERSION + EVETEST_HYPERVISOR). This way the standard EVETEST_EVE_VERSION
// variable always refers to the version being tested, which is the upgrade target.
//
// Parameters:
//   - EVE_VERSION: target EVE version to upgrade to (default is the current HEAD
//     of the checked-out EVE repo)
//   - HYPERVISOR: target hypervisor for the upgraded EVE (default: kvm)
//   - INITIAL_EVE_VERSION: initial EVE version the device starts on (required,
//     e.g. "16.0.0-lts")
//   - INITIAL_HYPERVISOR: initial hypervisor for the starting device (default: kvm)
//   - DISK_SIZE_MB: device disk size in MiB (0 = framework default 65536 MiB)
//   - EXPECT_REVERT: if true, the upgrade is expected to fail and EVE to revert
//     to the previous version (default: false)
//
// A container app (evetest-ubuntu-ctr) is deployed before the upgrade and verified
// to be healthy both before and after the upgrade (or revert).
func TestEVEUpgrade(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
		evetest.DiskSizeMiBParameter(),
		evetest.TestParameterDefinition{
			Key:          initialEVEVersionParamKey,
			DefaultValue: "16.0.0-lts",
			Description: evetest.TestParameterDescription{
				Summary: "EVE version to upgrade from (the pre-upgrade initial version)",
				Default: "16.0.0-lts",
			},
		},
		evetest.TestParameterDefinition{
			Key:          initialHypervisorParamKey,
			DefaultValue: evetest.HypervisorKVM,
			Description: evetest.TestParameterDescription{
				Summary:       "Hypervisor used by the initial (pre-upgrade) EVE version",
				Default:       "kvm",
				AllowedValues: "kvm|xen|kubevirt",
			},
		},
		evetest.TestParameterDefinition{
			Key:          expectRevertParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "Expect the upgrade to fail and EVE to revert to the previous version",
				Default: "false",
			},
		},
	)

	// Get parameter values set for this test execution.
	withTPM := evetest.GetTPMParameterValue()
	diskSizeMiB := evetest.GetDiskSizeMiBParameterValue()
	initialVersion := evetest.GetTestParameter[string](initialEVEVersionParamKey)
	if initialVersion == "" {
		evetestT.Fatalf("%s%s is required for TestEVEUpgrade",
			constants.EnvPrefix, initialEVEVersionParamKey)
	}
	initialHypervisor := evetest.GetTestParameter[evetest.Hypervisor](initialHypervisorParamKey)
	targetVersion := evetest.GetEVEVersionParameterValue()
	targetHypervisor := evetest.GetHypervisorParameterValue()
	expectRevert := evetest.GetTestParameter[bool](expectRevertParamKey)

	const devName = "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithEVEVersion:    initialVersion,
			WithHypervisor:    initialHypervisor,
			WithTPM:           withTPM,
			MinDiskSizeInMiB:  diskSizeMiB,
			DeviceReusePolicy: evetest.CreateFromScratchWithInstaller,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)

	// Apply initial device config: management adapter only.
	// For kubevirt, the NI and app are added only after the cluster is ready.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	networkUUID := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "eth0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   networkUUID,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})

	const nodeReadyCond = eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY
	isK3sReady := func(info *eveinfo.ZInfoKubeCluster) bool {
		if info == nil || len(info.Nodes) != 1 {
			return false
		}
		if info.Storage.Health != eveinfo.ServiceStatus_SERVICE_STATUS_HEALTHY {
			return false
		}
		for _, cond := range info.Nodes[0].GetConditions() {
			if cond.GetType() == nodeReadyCond {
				return cond.GetSet()
			}
		}
		return false
	}

	if initialHypervisor == evetest.HypervisorKubevirt {
		clusterUpdates, stopClusterWatch := device.WatchClusterInfo()
		defer stopClusterWatch()
		device.ApplyConfig(devConfig, true, true)

		t.Eventually(clusterUpdates, 20*time.Minute).Should(Receive(
			matchers.SatisfyPredicate("K3s node is ready", isK3sReady)))
		evetest.Checkpoint("k3s-ready")
	}

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "eth0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "upgrade-test-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
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
		},
	})
	device.ApplyConfig(devConfig, false, false)

	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)

	// Verify the app is reachable before the upgrade.
	appAuth := evetest.UsernamePasswordAuth{Username: appSSHUser, Password: appSSHPassword}
	sshTimeout := 20 * time.Second
	log := evetest.Logger()
	log.Infof("Verifying app is reachable before upgrade")
	t.Eventually(func(t Gomega) {
		out, _, err := device.RunShellScriptInsideApp(
			appUUID, appAuth, "hostname", sshTimeout, 0)
		t.Expect(err).NotTo(HaveOccurred())
		t.Expect(strings.TrimSpace(out)).To(Equal(appUUID.String()))
	}, 3*time.Minute, 5*time.Second).Should(Succeed())

	evetest.Checkpoint("pre-upgrade")

	device.UpgradeEVE(targetVersion, targetHypervisor, true, expectRevert)

	if expectRevert {
		evetest.Checkpoint("upgrade-reverted")
	} else {
		evetest.Checkpoint("upgrade-complete")
	}

	// If the EVE version now running uses Kubevirt, wait for K3s to be ready
	// before checking the app. Check the last published cluster info first --
	// the cluster may have already become ready during UpgradeEVE.
	activeHypervisor := targetHypervisor
	if expectRevert {
		activeHypervisor = initialHypervisor
	}
	if activeHypervisor == evetest.HypervisorKubevirt {
		if !isK3sReady(device.GetClusterInfo()) {
			clusterUpdates, stopClusterWatch := device.WatchClusterInfo()
			defer stopClusterWatch()
			t.Eventually(clusterUpdates, 20*time.Minute).Should(Receive(
				matchers.SatisfyPredicate("K3s node is ready", isK3sReady)))
		}
		evetest.Checkpoint("k3s-ready-post-upgrade")
	}

	// Verify the app comes back up and is still reachable (under the new EVE
	// version on success, or back under the original version after a revert).
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	log.Infof("Verifying app is reachable after upgrade")
	t.Eventually(func(t Gomega) {
		out, _, err := device.RunShellScriptInsideApp(
			appUUID, appAuth, "hostname", sshTimeout, 0)
		t.Expect(err).NotTo(HaveOccurred())
		t.Expect(strings.TrimSpace(out)).To(Equal(appUUID.String()))
	}, 3*time.Minute, 5*time.Second).Should(Succeed())

	if expectRevert {
		evetest.Checkpoint("post-revert-verified")
	} else {
		evetest.Checkpoint("post-upgrade-verified")
	}
}
