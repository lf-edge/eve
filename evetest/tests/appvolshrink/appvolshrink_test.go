// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package appvolshrink_test

import (
	"fmt"
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
	seedParamKey              = "VOLVERIFY_SEED"
	opsParamKey               = "VOLVERIFY_OPS"
	volSizeMiBParamKey        = "DATA_VOLUME_MB"
	volverifyImageParamKey    = "VOLVERIFY_IMAGE"

	// defaultVolverifyImage is the canonical published testapp image; override
	// VOLVERIFY_IMAGE to run against a personal registry copy.
	defaultVolverifyImage = "lfedge/evetest-volverify"

	appSSHUser     = "root"
	appSSHPassword = "testpassword"
	appSSHFwdPort  = 2222
	dataMountDir   = "/mnt/data"
	blockSize      = 4096
)

// TestAppVolumeShrinkCorruption checks whether a watchdog-interrupted EVE-kvm→EVE-k
// offline filesystem shrink corrupts an application data volume, and if so whether
// the corruption is detectable.
//
// It deploys the volverify app (github.com/lf-edge/eve/evetest/testapps/volverify)
// with a large BLANK data volume, fills it with a deterministic self-verifying
// pattern before the upgrade, drives the kvm→kubevirt upgrade (which repartitions
// and shrinks /persist, relocating the volume's blocks), and then re-verifies the
// pattern. The watchdog fault is baked into the target EVE image (the fork#7 no-pet
// stress build fires the HW watchdog inside the offline resizer), so this test just
// upgrades TO that build; the soak loops the test externally (design §5, §7).
//
// The target build must also relax the shrink+volumes gate (§3.1) — the shippable
// EVE refuses a cross-flavor shrink while a volume is present.
//
// Parameters:
//   - EVE_VERSION / HYPERVISOR: target build + hypervisor (default hypervisor kubevirt here).
//   - INITIAL_EVE_VERSION (required, e.g. "16.6.0") / INITIAL_HYPERVISOR (default kvm).
//   - DISK_SIZE_MB: device disk size (default 131072 = 128 GiB).
//   - DATA_VOLUME_MB: blank data-volume size (default 40960 = 40 GiB).
//   - VOLVERIFY_SEED / VOLVERIFY_OPS: pattern seed and op count.
func TestAppVolumeShrinkCorruption(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
		evetest.DiskSizeMiBParameter(),
		evetest.TestParameterDefinition{
			Key:          initialEVEVersionParamKey,
			DefaultValue: "16.6.0",
			Description: evetest.TestParameterDescription{
				Summary: "EVE-kvm version to start on (before the kvm→k conversion)",
				Default: "16.6.0",
			},
		},
		evetest.TestParameterDefinition{
			Key:          initialHypervisorParamKey,
			DefaultValue: evetest.HypervisorKVM,
			Description: evetest.TestParameterDescription{
				Summary:       "Hypervisor of the initial (pre-upgrade) EVE version",
				Default:       "kvm",
				AllowedValues: "kvm|kubevirt",
			},
		},
		evetest.TestParameterDefinition{
			Key:          volSizeMiBParamKey,
			DefaultValue: uint32(40960),
			Description: evetest.TestParameterDescription{
				Summary: "Blank data-volume size in MiB (should exceed the shrink evacuation zone)",
				Default: "40960",
			},
		},
		evetest.TestParameterDefinition{
			Key:          seedParamKey,
			DefaultValue: uint64(20260723),
			Description: evetest.TestParameterDescription{
				Summary: "volverify master seed for the fill/delete pattern",
				Default: "20260723",
			},
		},
		evetest.TestParameterDefinition{
			Key:          opsParamKey,
			DefaultValue: uint64(200000),
			Description: evetest.TestParameterDescription{
				Summary: "volverify op count (creates/deletes) to fill the volume",
				Default: "200000",
			},
		},
		evetest.TestParameterDefinition{
			Key:          volverifyImageParamKey,
			DefaultValue: defaultVolverifyImage,
			Description: evetest.TestParameterDescription{
				Summary: "Docker Hub repo of the volverify test app (override for a personal registry copy)",
				Default: defaultVolverifyImage,
			},
		},
	)

	withTPM := evetest.GetTPMParameterValue()
	diskSizeMiB := evetest.GetDiskSizeMiBParameterValue()
	if diskSizeMiB == 0 {
		diskSizeMiB = 131072 // 128 GiB — enough headroom for a real shrink
	}
	initialVersion := evetest.GetTestParameter[string](initialEVEVersionParamKey)
	if initialVersion == "" {
		evetestT.Fatalf("%s%s is required", constants.EnvPrefix, initialEVEVersionParamKey)
	}
	initialHypervisor := evetest.GetTestParameter[evetest.Hypervisor](initialHypervisorParamKey)
	targetVersion := evetest.GetEVEVersionParameterValue()
	targetHypervisor := evetest.GetHypervisorParameterValue()
	volSizeMiB := evetest.GetTestParameter[uint32](volSizeMiBParamKey)
	seed := evetest.GetTestParameter[uint64](seedParamKey)
	ops := evetest.GetTestParameter[uint64](opsParamKey)
	volverifyImage := evetest.GetTestParameter[string](volverifyImageParamKey)

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
	log := evetest.Logger()

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
		DisplayName: "volverify-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: volverifyImage,
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		DataVolumes: []evetest.DataVolumeConfig{
			{SizeBytes: uint64(volSizeMiB) * evetest.MiB, MountDir: dataMountDir},
		},
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: appSSHFwdPort, AppPort: 22},
				},
				ACLAllowRules: []evetest.ACLAllowRule{
					{Protocol: evetest.NetworkProtocolAny, RemoteSubnet: evetest.IPSubnet("0.0.0.0/0")},
				},
			},
		},
	})
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)

	appAuth := evetest.UsernamePasswordAuth{Username: appSSHUser, Password: appSSHPassword}

	// Fill the volume with the deterministic pattern before the shrink. The write
	// of a multi-GiB volume can take a while, so allow a generous timeout. It stops
	// at Ops or when the volume fills (whichever first) and reports the committed
	// high-water mark, which the post-shrink verify must expect.
	writeCmd := fmt.Sprintf("volverify write --dir %s --seed %d --ops %d --block-size %d",
		dataMountDir, seed, ops, blockSize)
	log.Infof("Filling data volume: %s", writeCmd)
	writtenCommitted := -1
	t.Eventually(func(t Gomega) {
		stdout, stderr, err := device.RunShellScriptInsideApp(appUUID, appAuth, writeCmd, 60*time.Minute, 0)
		t.Expect(err).NotTo(HaveOccurred(), "write stderr: %s", stderr)
		writtenCommitted = reportField(stdout, "committed")
		t.Expect(writtenCommitted).To(BeNumerically(">=", 0),
			"write did not report a committed index:\n%s", stdout)
	}, 65*time.Minute, 10*time.Second).Should(Succeed())
	log.Infof("volume filled through committed op %d", writtenCommitted)
	evetest.Checkpoint("volume-filled")

	// Drive the watchdog-interrupted kvm→k conversion (shrink relocates the volume).
	device.UpgradeEVE(targetVersion, targetHypervisor, true, false)
	evetest.Checkpoint("upgrade-complete")

	if targetHypervisor == evetest.HypervisorKubevirt {
		if !isK3sReady(device.GetClusterInfo()) {
			clusterUpdates, stopClusterWatch := device.WatchClusterInfo()
			defer stopClusterWatch()
			t.Eventually(clusterUpdates, 20*time.Minute).Should(Receive(
				matchers.SatisfyPredicate("K3s node is ready", isK3sReady)))
		}
		evetest.Checkpoint("k3s-ready-post-upgrade")
	}
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)

	// Re-verify against the write's high-water mark. The on-volume commit lives on
	// the shrunk filesystem and may be cleared by fsck along with data, so pass the
	// committed index the pre-shrink write reported as an off-volume floor (§4.2).
	verifyCmd := fmt.Sprintf("volverify verify --dir %s --seed %d --ops %d --block-size %d --expect-committed %d",
		dataMountDir, seed, ops, blockSize, writtenCommitted)
	log.Infof("Verifying data volume: %s", verifyCmd)
	var report string
	t.Eventually(func(t Gomega) {
		stdout, _, _ := device.RunShellScriptInsideApp(appUUID, appAuth, verifyCmd, 30*time.Minute, 0)
		t.Expect(stdout).NotTo(BeEmpty())
		report = strings.TrimSpace(stdout)
	}, 32*time.Minute, 10*time.Second).Should(Succeed())
	log.Infof("volverify report:\n%s", report)

	// present-corrupt is the dangerous silent case (§2.4): a torn-but-present
	// volume EVE would serve to the app as-is. orphaned/lost are the recoverable
	// modes (recreate path). Fail on present-corrupt; surface the rest for the
	// soak to tally. Phase 3's detect→recreate should drive present-corrupt to 0.
	presentCorrupt := reportField(report, "present-corrupt")
	t.Expect(presentCorrupt).To(BeNumerically(">=", 0),
		"could not parse present-corrupt count from report:\n%s", report)
	t.Expect(presentCorrupt).To(Equal(0),
		"data volume served corrupt-but-present after the interrupted shrink:\n%s", report)
	evetest.Checkpoint("volume-verified")
}

// reportField extracts an integer "key=N" field from a volverify summary line.
func reportField(report, key string) int {
	for _, tok := range strings.Fields(report) {
		if strings.HasPrefix(tok, key+"=") {
			var n int
			_, err := fmt.Sscanf(strings.TrimPrefix(tok, key+"="), "%d", &n)
			if err != nil {
				return -1
			}
			return n
		}
	}
	return -1
}
