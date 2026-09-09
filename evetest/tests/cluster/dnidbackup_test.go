// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"strconv"
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

const (
	// clusterTimeout bounds cluster formation and any wait that includes a
	// normal app boot -- deploy, or deactivate. Not DNID-specific: the same
	// budget any cluster test gives these operations.
	clusterTimeout = 30 * time.Minute

	// dnidOutageThresholdRequested is the outage threshold this test asks
	// for via dnidOutageThresholdKey, well under the ten-minute default, so
	// a backup node stands in a minute into the outage instead of ten.
	dnidOutageThresholdRequested = 1 * time.Minute

	// dnidOutageThresholdDefault is the threshold the device applies when it
	// does not accept the override above.
	dnidOutageThresholdDefault = 10 * time.Minute

	// backupOpBootBudget is the margin added on top of whichever threshold
	// is actually in effect, covering the pod scheduling and VM boot that
	// follow it. See backupOpTimeout.
	backupOpBootBudget = 5 * time.Minute

	// failbackTimeout bounds the failback step. Failback is existing
	// behavior and is gated by the descheduler's boot time enable feature
	failbackTimeout = 30 * time.Minute
)

// clusterVMImage describes the arch-specific pinned Alpine Linux
// cloud-init qcow2 image used to boot all VMs here. Mirrors
// tests/apps/vnc_test.go's alpineCloudImage/alpineCloudImages: same
// release, same pin-by-version rationale (the SHA256 stays valid
// indefinitely because it names a fixed release, not a rolling "latest").
// See https://alpinelinux.org/cloud/ for the full image list.
type clusterVMImage struct {
	relativePath string
	sha256       string
	sizeBytes    uint64
}

var clusterVMImages = map[string]clusterVMImage{
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

// dnidOutageThresholdKey is types.DnidOutageThresholdForUsage's
// GlobalSettingKey, "cluster.dnid.backupnode.threshold", referenced by its
// literal string because pillar does not define a Go constant for it.
// Setting an unregistered GlobalSettingKey is harmless -- zedagent's
// ConfigItemSpecMap.ParseItem records a per-item parse error and moves on
// (pkg/pillar/cmd/zedagent/parseconfig.go:3145-3154), it does not fail
// config application.
const dnidOutageThresholdKey = types.GlobalSettingKey("cluster.dnid.backupnode.threshold")

// backupOpTimeout bounds the waits that can only complete once the outage
// crosses DnidOutageThresholdForUsage: whichever threshold the device
// actually holds, plus backupOpBootBudget for the scheduling and VM boot
// that follow it. It does not assume this test's override was accepted --
// an override that did not land leaves the device on
// dnidOutageThresholdDefault, which needs the larger budget.
func backupOpTimeout(dev *evetest.EdgeDevice) (
	timeout time.Duration, overrideAccepted bool) {
	threshold := dnidOutageThresholdDefault
	overrideAccepted = configItemAccepted(dev, dnidOutageThresholdKey,
		strconv.Itoa(int(dnidOutageThresholdRequested.Seconds())))
	if overrideAccepted {
		threshold = dnidOutageThresholdRequested
	}
	return threshold + backupOpBootBudget, overrideAccepted
}

// configItemAccepted reports whether dev parsed key and holds exactly
// wantValue for it. Pillar reports every config item it parsed in
// ZInfoDevice.ConfigItemStatus.ConfigItems, with a per-item Error when
// parsing failed, and every key it did not recognize at all in
// .UnknownConfigItems -- the same status tests/telemetry/vector_test.go
// reads to check its own property.
func configItemAccepted(dev *evetest.EdgeDevice, key types.GlobalSettingKey,
	wantValue string) bool {
	status := dev.GetDeviceInfo().GetConfigItemStatus()
	if _, unknown := status.GetUnknownConfigItems()[string(key)]; unknown {
		return false
	}
	item, parsed := status.GetConfigItems()[string(key)]
	if !parsed || item.GetError() != "" {
		return false
	}
	return item.GetValue() == wantValue
}

// TestDNIDandBackupDNID exercises DNID backup takeover for a cluster app,
// across all four app operations backup DNID covers: activate, deactivate,
// purge, and delete. edge-dev3 is isolated with a hard power-off, and every
// operation below is expected to complete through a backup node while it
// stays down; any operation that instead blocks or times out means no node
// stands in for a downed DNID.
//
// DnidOutageThresholdForUsage is overridden down to one minute, well under
// the ten-minute default, so the test does not have to burn real minutes
// waiting for the outage to cross the threshold. Whether the device
// actually accepted that override is read back from its reported config
// item status rather than assumed, and the waits that depend on the
// threshold are sized off whichever value is really in effect -- see
// backupOpTimeout.
//
// Steps:
//  1. Deploy vm1 (DNID edge-dev1), vm2 (DNID edge-dev3, Preferred
//     affinity), and vm3 (DNID edge-dev3, Required affinity).
//  2. Deactivate vm2, before the outage. The app is already down when
//     its DNID node disappears, so step 4 exercises activation
//     specifically, not an in-flight domain staying up. vm3 is left
//     running: its own step (8) is about a hard failure taking apps down
//     mid-flight, not a clean prior deactivation.
//  3. Power off edge-dev3 hard. Not PrepareShutdown -- edge-dev3 gets no
//     chance to hand anything off cleanly. vm3 goes down with it.
//  4. Activate vm2 on a backup node, wait running, verify placement
//     moved off edge-dev3.  Proves backup DNID handled the command.
//  5. Deactivate vm2 again, still while edge-dev3 is down. Backup DNID
//     covers deactivate as well as activate -- both go through the same
//     gate (`getKubeAppActivateStatus`, called with `effectiveActivate`
//     either way) -- so this exercises that symmetry rather than
//     assuming it. Driven from edge-dev1, not edge-dev3 (down) or
//     edge-dev2 (the tie-breaker; cluster app workloads are not run
//     there).
//  6. Re-activate vm2 on the backup, same as step 4, so the purge below
//     has something running to purge.
//  7. Purge vm2, wait running, while still on the backup. A purge
//     recreates the app's own volume, so this exercises the volumemgr
//     side of backup DNID, not just the activation gate.
//  8. Delete vm3 entirely while edge-dev3 is still down, and confirm both
//     its app info and its volume info actually reach INVALID. This is
//     the one checkpoint that does not exclude Required affinity the way
//     the other two do: deleting a volume puts nothing on any node, so
//     there is no wrong-node hazard to guard against, and a
//     Required-affinity app -- one that, by definition, has nowhere to
//     fail over to -- is exactly the case most exposed to the volume
//     leak this step exists to catch (DestroyVolume's replicated-PVC
//     skip otherwise leaks vm3's volume for as long as edge-dev3 stays
//     down).
//  9. Power edge-dev3 back on, wait for vm2 to fail back to it. The test
//     ends here with vm2 left RUNNING: deactivating it again would only
//     exercise deactivate against a healthy, recovered DNID -- ordinary
//     non-backup behavior already covered by step 2.
//
// vm1, vm2, and vm3 are VM apps (a pinned Alpine Linux cloud-init
// qcow2, VirtualizationMode=HVM). WaitUntilAppIsRunning's timeout excludes
// download time, so the image fetch does not eat into the backup-activation
// budget in steps 4 and 6.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- the same model
//     TestSingleNodeCluster and TestTieBreakerCluster use.
//   - RequireInternetConnectivity -- the qcow2 image is fetched from
//     dl-cdn.alpinelinux.org, a real external host.
//
// Device configuration
// --------------------
//   - clusterDeviceRequirements (top of cluster_test.go) for all three
//     devices. edge-dev1 is the bootstrap node and vm1's DNID; edge-dev2
//     is the tie-breaker and hosts neither vm2 nor vm3, though it
//     receives the same AppInstanceConfig as every other device;
//     edge-dev3 is the DNID for both vm2 and vm3, and the node this test
//     takes down.
//
// Test params
// -----------
//   - TPM (bool), FILESYSTEM.
func TestDNIDandBackupDNID(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	var requiredDevices [3]evetest.Requirement
	var devName [3]string
	for i := 0; i < 3; i++ {
		devName[i] = fmt.Sprintf("edge-dev%d", i+1)
		requiredDevices[i] = clusterDeviceRequirements(devName[i], withTPM, filesystem, false)
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort,
	}
	var requirements []evetest.Requirement
	requirements = append(requirements, requiredDevices[:]...)
	requirements = append(requirements, requiredNetModel)
	requirements = append(requirements, evetest.RequireInternetConnectivity{})
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	const tieBreakerIdx = 1
	var nodes [3]evetest.ClusterNode
	for i := 0; i < 3; i++ {
		clusterIP := evetest.IPAddressWithPrefix(fmt.Sprintf("10.244.244.%d/24", i+2))
		nodes[i] = evetest.ClusterNode{
			DevName:          devName[i],
			ClusterIP:        clusterIP,
			ClusterInterface: "ethernet1",
			BootstrapNode:    i == 0,
			TieBreaker:       i == tieBreakerIdx,
		}
	}
	clusterConfig := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE,
		nodes[:]...,
	)

	dhcpNet := clusterConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	noIPNet := clusterConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	clusterConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel: "ethernet0", PhysicalLabel: "eth0", InterfaceName: "eth0",
		NetworkUUID: dhcpNet, Usage: evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	clusterConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel: "ethernet1", PhysicalLabel: "eth1", InterfaceName: "eth1",
		NetworkUUID: noIPNet, Usage: evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	configProps := types.NewConfigItemValueMap()
	configProps.SetGlobalValueInt(dnidOutageThresholdKey,
		uint32(dnidOutageThresholdRequested.Seconds()))
	// Step 9's failback depends on the descheduler evicting vm2 from the
	// backup node once edge-dev3 is up again, and event-driven descheduling
	// is off by default (KubernetesVmiDescheduleEvents defaults to ""). Set
	// it here, in the initial config, not later: the on-boot trigger is
	// armed once per boot, right after zedkube's WaitForKubernetes, and
	// enabling it after that window does not fire for that boot
	// (cmd/zedkube/zedkube.go's own note on the launch site).
	configProps.SetGlobalValueString(types.KubernetesVmiDescheduleEvents,
		types.VmiDescheduleEventBoot)
	clusterConfig.SetConfigProperties(configProps)

	cluster := evetest.NewEdgeCluster("test-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(clusterTimeout)
	evetest.Checkpoint("nodes-are-ready")

	log := evetest.Logger()
	dev1 := evetest.GetEdgeDevice(devName[0])
	dev3 := evetest.GetEdgeDevice(devName[2])

	// Fail here rather than at step 9 if the descheduler never got enabled:
	// without it, failback simply never happens, and the only symptom is
	// that step's wait running out.
	for _, dev := range []*evetest.EdgeDevice{dev1, dev3} {
		name := dev.GetConfig().GetDeviceName()
		t.Eventually(func() bool {
			return configItemAccepted(dev, types.KubernetesVmiDescheduleEvents,
				types.VmiDescheduleEventBoot)
		}, 5*time.Minute, 10*time.Second).Should(BeTrue(),
			"%s did not accept %s=%s", name,
			types.KubernetesVmiDescheduleEvents, types.VmiDescheduleEventBoot)
	}
	evetest.Checkpoint("descheduler-on-boot-enabled")

	arch := dev1.GetArch()
	vmImage, ok := clusterVMImages[arch]
	t.Expect(ok).To(BeTrue(), "no pinned Alpine cloud image for arch %q", arch)

	niUUID := clusterConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress("10.11.12.1"),
		EnableFlowlog: true,
		MTU:           1500,
		ForwardLLDP:   false,
	})

	newClusterVMApp := func(displayName, designatedNode string,
		affinity eveconfig.AffinityType) evetest.ClusterApplicationInstanceConfig {
		return evetest.ClusterApplicationInstanceConfig{
			ApplicationInstanceConfig: evetest.ApplicationInstanceConfig{
				DisplayName: displayName,
				Activate:    true,
				Image: evetest.HTTPStorage{
					ImageFormat:       eveconfig.Format_QCOW2,
					ImageSHA256:       vmImage.sha256,
					MaxDownloadBytes:  vmImage.sizeBytes,
					ImageRelativePath: vmImage.relativePath,
					ServerAddress:     "dl-cdn.alpinelinux.org",
					UseHTTPS:          true,
				},
				// Left unset, the target PVC is sized to exactly the
				// image's own virtual size, leaving no room for CDI's
				// scratch-space qcow2->raw conversion.
				DiskBytes:          1 * evetest.GiB,
				VirtualizationMode: eveconfig.VmMode_HVM,
				CPUs:               1,
				MemoryBytes:        512 * evetest.MiB,
				NetworkAdapters: []evetest.AppNetworkAdapter{
					evetest.VirtualNetworkAdapter{
						LogicalLabel:        displayName + "-vif0",
						NetworkInstanceUUID: niUUID,
					},
				},
			},
			DesignatedNodeName: designatedNode,
			Affinity:           affinity,
		}
	}

	// Step 1. Deployed one at a time, not in one ApplyConfig, so a
	// failure names exactly which app failed.
	vm1UUID := clusterConfig.AddApplication(newClusterVMApp("vm1", devName[0],
		eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED))
	cluster.ApplyConfig(clusterConfig, true, true)
	log.Infof("Waiting for vm1 to reach RUNNING for the first time")
	dev1.WaitUntilAppIsRunning(vm1UUID, clusterTimeout)
	evetest.Checkpoint("vm1-initially-running")

	vm2UUID := clusterConfig.AddApplication(newClusterVMApp("vm2", devName[2],
		eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED))
	cluster.ApplyConfig(clusterConfig, true, true)
	log.Infof("Waiting for vm2 to reach RUNNING for the first time")
	dev3.WaitUntilAppIsRunning(vm2UUID, clusterTimeout)
	evetest.Checkpoint("vm2-initially-running")

	// vm3 is Required affinity, deliberately: it can never fail over, so
	// that the delete is caught in a more complex domainmgr state
	vm3UUID := clusterConfig.AddApplication(newClusterVMApp("vm3", devName[2],
		eveconfig.AffinityType_AFFINITY_TYPE_REQUIRED))
	cluster.ApplyConfig(clusterConfig, true, true)
	log.Infof("Waiting for vm3 to reach RUNNING for the first time")
	dev3.WaitUntilAppIsRunning(vm3UUID, clusterTimeout)
	evetest.Checkpoint("vms-initially-running")

	// Step 2. deactivate app
	dev3.DeactivateApplication(vm2UUID, true, clusterTimeout)
	evetest.Checkpoint("vm2-deactivated")

	// Step 3. power off DNID
	dev3.PowerOff()
	evetest.Checkpoint("edge-dev3-powered-off")

	// Read the threshold actually in effect from a device that is still up,
	// before any wait depends on it.
	backupOpWait, thresholdOverrideAccepted := backupOpTimeout(dev1)
	log.Infof("Bounding backup-DNID operations at %v (threshold override accepted: %v)",
		backupOpWait, thresholdOverrideAccepted)

	// activateOnBackupAndVerify activates vm2 on edge-dev1, waits for it to
	// reach RUNNING, and confirms placement actually moved off edge-dev3.
	// Shared by steps 4 and 6, the two windows this test activates vm2 on
	// the backup. cluster.ActivateApplication is not usable here: it looks
	// for the node already hosting the app first, and vm2 is halted with
	// no pod anywhere. Set the flag directly on edge-dev1 instead --
	// edge-dev2 is the tie-breaker (cluster app workloads are not run
	// there) and edge-dev3 is down. checkpointSuffix keeps the two calls'
	// checkpoints distinct.
	activateOnBackupAndVerify := func(checkpointSuffix string) {
		dev1.ActivateApplication(vm2UUID, false, 0)
		log.Infof("Waiting for vm2 to activate on a backup node while %s is down", devName[2])
		dev1.WaitUntilAppIsRunning(vm2UUID, backupOpWait)
		evetest.Checkpoint("vm2-activated-on-backup" + checkpointSuffix)

		backupHost := cluster.FindDeviceHostingApp(vm2UUID, 2*time.Minute)
		t.Expect(backupHost).NotTo(BeNil(), "no cluster device reports hosting vm2")
		t.Expect(backupHost.GetConfig().GetDeviceName()).NotTo(Equal(devName[2]),
			"vm2 is supposed to be down on its own designated node %s, not running there", devName[2])
		evetest.Checkpoint("vm2-backup-placement-verified" + checkpointSuffix)
	}

	// Step 4.
	activateOnBackupAndVerify("")

	// Step 5. Driven from edge-dev1, not edge-dev3 (down, and structurally
	// cannot answer -- DeactivateApplication's wait reads that device's
	// own published info, and a powered-off device publishes nothing) or
	// edge-dev2 (the tie-breaker; cluster app workloads are not run there).
	dev1.DeactivateApplication(vm2UUID, true, clusterTimeout)
	evetest.Checkpoint("vm2-deactivated-while-backup-dnid-down")

	// Step 6.
	activateOnBackupAndVerify("-again")

	// Step 7.
	dev1.PurgeApplication(vm2UUID, true, clusterTimeout)
	evetest.Checkpoint("vm2-purged-on-backup")

	// Step 8. edge-dev3 is still down. Watch from dev1, not dev3 (it's
	// off): every cluster node's own ZInfoApp/ZInfoVolume reports reflect
	// the cluster-wide state, not just what runs locally -- the same
	// reason step 4 already watches vm2 from dev1 rather than from
	// whichever node ends up hosting it. Capture vm3's root volume UUID
	// before deleting it: DeleteApplication cascades the volume delete
	// into the config itself, so there is nothing left to look up once it
	// has run.
	vm3DevConfig := clusterConfig.GetDeviceConfig(devName[2])
	var vm3RootVolUUID string
	for _, app := range vm3DevConfig.Apps {
		if app.Uuidandversion.Uuid == vm3UUID.String() {
			t.Expect(app.VolumeRefList).NotTo(BeEmpty(), "vm3 has no root volume")
			vm3RootVolUUID = app.VolumeRefList[0].Uuid
			break
		}
	}
	t.Expect(vm3RootVolUUID).NotTo(BeEmpty(), "vm3's root volume UUID was not found")

	appUpdates, stopAppWatch := dev1.WatchAppInfo(vm3UUID)
	defer stopAppWatch()
	volUpdates, stopVolWatch := dev1.WatchVolumeInfo(uuid.Must(uuid.FromString(vm3RootVolUUID)))
	defer stopVolWatch()

	clusterConfig.DeleteApplication(vm3UUID)
	cluster.ApplyConfig(clusterConfig, true, true)
	log.Infof("Waiting for vm3 to be deleted while %s is down", devName[2])
	t.Eventually(appUpdates, backupOpWait).Should(Receive(matchers.SatisfyPredicate(
		"vm3 app info is gone",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	t.Eventually(volUpdates, backupOpWait).Should(Receive(matchers.SatisfyPredicate(
		"vm3 volume info is gone",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(volumeHasError)))
	evetest.Checkpoint("vm3-deleted-while-backup-dnid-down")

	// Step 9. waitUntilOnline=false per PowerOn's own doc comment: a hard
	// power-off leaves ZInfoDevice.LastRebootTime unreliable, so recovery
	// is confirmed via the app instead.
	dev3.PowerOn(false)
	log.Infof("Waiting for vm2 to fail back to %s", devName[2])
	dev3.WaitUntilAppIsRunning(vm2UUID, failbackTimeout)
	evetest.Checkpoint("vm2-failed-back")

	failbackHost := cluster.FindDeviceHostingApp(vm2UUID, 2*time.Minute)
	t.Expect(failbackHost).NotTo(BeNil(), "no cluster device reports hosting vm2")
	t.Expect(failbackHost.GetConfig().GetDeviceName()).To(Equal(devName[2]),
		"vm2 did not fail back to its own designated node %s", devName[2])
	evetest.Checkpoint("vm2-failback-placement-verified")
}

// appHasError reports whether info is in the ERROR state, for use as a
// StopIf fast-fail condition on Eventually assertions waiting on app state.
func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	if info.State == eveinfo.ZSwState_ERROR {
		return "Application instance is in error state", true
	}
	return "", false
}

// volumeHasError reports whether info carries a VolumeErr, for use as a
// StopIf fast-fail condition on Eventually assertions waiting on volume state.
func volumeHasError(info *eveinfo.ZInfoVolume) (string, bool) {
	if desc := info.GetVolumeErr().GetDescription(); desc != "" {
		return "Volume reports an error: " + desc, true
	}
	return "", false
}
