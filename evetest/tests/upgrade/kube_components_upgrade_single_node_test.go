// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestKubeComponentsUpgradeSingleNode installs a single EVE-k node on the
// most recent EVE release, runs an app with a data volume, and upgrades EVE
// to the build under test. Afterwards every kube component the upgrade pass
// covers (Multus, KubeVirt, CDI, Longhorn) must run the version the new
// build targets, every Longhorn volume must run the target engine image,
// and the data written before the upgrade must still be there. The app's
// volumes stay attached throughout, so a Longhorn upgrade upgrades their
// engines live.
//
// kube-init runs the component upgrade pass only when its build carries a
// higher kube version than the node has applied. The test logs the applied
// kube version before and after, so a run shows whether the two builds were
// separated by a kube version bump and the pass ran, or the target changed
// no component and the upgrade only had to leave them intact. A target that
// changes a component version without raising its kube version fails the
// test, because the component is never upgraded.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP: one management port is all a single node
//     needs.
//
// Device configuration
// --------------------
//   - eth0 as the management and app port.
//   - A local network instance with a port forward 2222->22 to the app.
//   - The evetest-ubuntu-ctr container app with a blank, clear-text data
//     volume, which the marker is written to as a raw disk. Clear-text
//     keeps vault readiness out of a test about the kube components.
//
// Test parameters
// ---------------
//   - INITIAL_EVE_VERSION: EVE-k version the node is installed with (default
//     initialEVEVersionForKubeUpgrade).
//   - INITIAL_EVE_REPO: repository INITIAL_EVE_VERSION is pulled from
//     (default lfedge/eve).
//   - EVE_VERSION: version to upgrade to, via evetest.EVEVersionParameter()
//     (default: the HEAD of the checked-out EVE repo).
//   - TPM (bool) via evetest.TPMParameter().
//
// Phases
// ------
//  1. k3s-ready: the node forms its single-node cluster on the initial
//     version and records its applied kube version.
//  2. app-deployed: the app runs and a marker is written to its data volume.
//  3. upgrade-complete: UpgradeEVE waits up to kubeUpgradeTimeout for the
//     new partition to be marked active.
//  4. kube-components-converged: every component runs its target version
//     and every Longhorn volume the target engine image, with no failed
//     component update and the applied kube version not lowered.
//  5. post-upgrade-verified: the app answers and the marker is intact.
//
// Suite placement
// ---------------
//   - TestUpgradeSuite.
func TestKubeComponentsUpgradeSingleNode(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.TPMParameter(),
		evetest.TestParameterDefinition{
			Key:          initialEVEVersionParamKey,
			DefaultValue: initialEVEVersionForKubeUpgrade,
			Description: evetest.TestParameterDescription{
				Summary: "EVE-k version the node is installed with before the upgrade",
				Default: initialEVEVersionForKubeUpgrade,
			},
		},
		evetest.TestParameterDefinition{
			// Hardcoded, not constants.DefaultEVERepo: list-tests can't
			// resolve cross-package constants.
			Key:          initialEVERepoParamKey,
			DefaultValue: "lfedge/eve",
			Description: evetest.TestParameterDescription{
				Summary: "Container image repository for the initial EVE version",
				Default: "lfedge/eve",
			},
		},
	)
	withTPM := evetest.GetTPMParameterValue()
	initialVersion := evetest.GetTestParameter[string](initialEVEVersionParamKey)
	if initialVersion == "" {
		evetestT.Fatalf("%s%s is required for TestKubeComponentsUpgradeSingleNode",
			constants.EnvPrefix, initialEVEVersionParamKey)
	}
	initialRepo := evetest.GetTestParameter[string](initialEVERepoParamKey)
	targetVersion := evetest.GetEVEVersionParameterValue()

	log := evetest.Logger()
	log.Infof("Installing %s:%s and upgrading it to %q",
		initialRepo, initialVersion, targetVersion)

	const devName = "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithEVEVersion:    initialVersion,
			WithEVERepo:       initialRepo,
			WithHypervisor:    evetest.HypervisorKubevirt,
			WithTPM:           withTPM,
			DeviceReusePolicy: evetest.CreateFromScratchWithInstaller,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)

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
	device.ApplyConfig(devConfig, true, true)
	device.WaitForClusterNodeIsReady(20 * time.Minute)
	appliedBefore := expectAppliedKubeVersion(t, device, 10*time.Minute)
	log.Infof("Applied kube version on %s: %d", initialVersion, appliedBefore)
	evetest.Checkpoint("k3s-ready")

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
	dataVolUUID := devConfig.AddBlankVolume("kube-upgrade-data",
		dataVolumeSize, true)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "kube-upgrade-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		Mounts: []evetest.MountConfig{
			{VolumeUUID: dataVolUUID, MountDir: dataMountDir},
		},
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
	device.WaitUntilAppIsRunning(appUUID, 10*time.Minute)

	appAuth := evetest.UsernamePasswordAuth{Username: appSSHUser, Password: appSSHPassword}
	writeDataMarker(t, device, appUUID, appAuth)
	evetest.Checkpoint("app-deployed")

	device.UpgradeEVE(targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, false, kubeUpgradeTimeout)
	evetest.Checkpoint("upgrade-complete")

	expectKubeComponentsConverged(t, device, appliedBefore, kubeConvergeTimeout)
	evetest.Checkpoint("kube-components-converged")

	// Budget above pillar's 600 s timer.boot.retry, which a VMIRS create
	// refused while kubevirt's webhook is still starting has to wait out.
	device.WaitUntilAppIsRunning(appUUID, 15*time.Minute)
	expectDataMarker(t, device, appUUID, appAuth, 15*time.Minute)
	evetest.Checkpoint("post-upgrade-verified")
}
