// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// Timeouts for TestClusterPVCGCDeletesOnlyOrphans. An Eventually stops as soon
// as its condition holds, so a large bound only delays a true failure.
const (
	// pvcGCClusterTimeout bounds three nodes forming a cluster, and one node
	// rejoining it after a power cycle.
	pvcGCClusterTimeout = 30 * time.Minute

	// pvcGCAppReadyTimeout bounds the app reaching RUNNING, and a volume
	// reaching CREATED_VOLUME, excluding download.
	pvcGCAppReadyTimeout = 15 * time.Minute

	// pvcGCPurgeTimeout bounds the purge that supersedes the app volume.
	pvcGCPurgeTimeout = 10 * time.Minute

	// pvcGCReclaimTimeout bounds finding the eve-app-op lease holder.
	pvcGCReclaimTimeout = 5 * time.Minute

	// pvcGCLogTimeout bounds a device log line reaching the controller.
	pvcGCLogTimeout = 5 * time.Minute

	// pvcGCLogClockSkew widens each log window, in case the device clock runs
	// behind the test's.
	pvcGCLogClockSkew = 30 * time.Second

	// pvcGCPollInterval is coarse because each poll runs kubectl on a device.
	pvcGCPollInterval = 10 * time.Second

	// pvcGCSettleWindow holds the survival assertions over many GC passes.
	pvcGCSettleWindow = 90 * time.Second

	// pvcGCSettleInterval is how often a survival assertion re-checks.
	pvcGCSettleInterval = 15 * time.Second

	// pvcGCVdiskGCTime is timer.gc.vdisk's floor. The GC ticker is
	// vdiskGCTime/10, so a pass runs every six seconds.
	pvcGCVdiskGCTime = 60

	// pvcGCStandaloneSize is the size of each standalone blank volume.
	pvcGCStandaloneSize = 100 * evetest.MiB

	// pvcGCDeleteLogPrefix starts the line volumemgr's gcPVCs logs before it
	// deletes a PVC.
	pvcGCDeleteLogPrefix = "gcPVCs: deleting PVC "
)

// KubeLeaderElectInfo is the part of zedkube's publication of the same name
// that this test reads. The pillar module evetest builds against predates
// IsAppOpLeader, so the test declares the field itself. ReadAllPublications
// finds the topic by this type's name.
type KubeLeaderElectInfo struct {
	IsAppOpLeader bool
}

// clusterPVCNames returns every PVC name in the EVE app namespace, as one node
// sees it. A kubectl failure fails the assertion. An empty set would satisfy
// an absence check for the wrong reason.
func clusterPVCNames(g Gomega, dev *evetest.EdgeDevice) map[string]bool {
	list, err := dev.KubectlListNames("pvc")
	g.Expect(err).ToNot(HaveOccurred(), "listing PVCs from device %q", dev.Name())
	names := make(map[string]bool, len(list))
	for _, name := range list {
		names[name] = true
	}
	return names
}

// nodeVolumeConfigs returns the VolumeConfigs zedagent publishes on one node.
func nodeVolumeConfigs(g Gomega, dev *evetest.EdgeDevice) []pillartypes.VolumeConfig {
	configs, err := evetest.ReadAllPublications[pillartypes.VolumeConfig](
		dev, "zedagent", false)
	g.Expect(err).ToNot(HaveOccurred(),
		"reading zedagent's VolumeConfig publications from %q", dev.Name())
	return configs
}

// nodeVolumeStatuses returns the VolumeStatuses volumemgr publishes on one node.
func nodeVolumeStatuses(g Gomega, dev *evetest.EdgeDevice) []pillartypes.VolumeStatus {
	statuses, err := evetest.ReadAllPublications[pillartypes.VolumeStatus](
		dev, "volumemgr", false)
	g.Expect(err).ToNot(HaveOccurred(),
		"reading volumemgr's VolumeStatus publications from %q", dev.Name())
	return statuses
}

// createdVolumeStatus returns the node's CREATED_VOLUME status for volumeID,
// or fails the assertion.
func createdVolumeStatus(g Gomega, dev *evetest.EdgeDevice,
	volumeID uuid.UUID) pillartypes.VolumeStatus {
	for _, vs := range nodeVolumeStatuses(g, dev) {
		if vs.VolumeID == volumeID && vs.State == pillartypes.CREATED_VOLUME {
			return vs
		}
	}
	g.Expect(false).To(BeTrue(),
		"node %q has no created VolumeStatus for volume %s", dev.Name(), volumeID)
	return pillartypes.VolumeStatus{}
}

// isAppOpLeader reports whether the node holds the eve-app-op lease, which
// makes it the node that stands in for a designated node that is down.
func isAppOpLeader(g Gomega, dev *evetest.EdgeDevice) bool {
	infos, err := evetest.ReadAllPublications[KubeLeaderElectInfo](
		dev, "zedkube", false)
	g.Expect(err).ToNot(HaveOccurred(),
		"reading zedkube's KubeLeaderElectInfo from %q", dev.Name())
	for _, info := range infos {
		if info.IsAppOpLeader {
			return true
		}
	}
	return false
}

// pvcDeleteLogs returns the gcPVCs lines on dev that name pvcName, since
// notBefore.
func pvcDeleteLogs(dev *evetest.EdgeDevice, pvcName string,
	notBefore time.Time) []evetest.LogMsg {
	return dev.GetLogs(evetest.LogMsgMatch{
		MsgHasSubstring: pvcGCDeleteLogPrefix + pvcName + ",",
		NotBefore:       notBefore.Add(-pvcGCLogClockSkew),
	})
}

// orphanPVCSpec is the part of a live PVC's spec an orphan copies, so the
// orphan is provisioned the way the volume it stands for was.
type orphanPVCSpec struct {
	storageClass string
	volumeMode   string
	accessMode   string
	size         string
}

// readOrphanPVCSpec reads the spec fields an orphan copies from a live PVC.
func readOrphanPVCSpec(g Gomega, dev *evetest.EdgeDevice,
	livePVC string) orphanPVCSpec {
	field := func(path string) string {
		out, err := dev.RunKubectl(fmt.Sprintf(
			"-n %s get pvc %s -o jsonpath='{%s}'",
			evetest.EVEKubeAppNamespace, livePVC, path), 20*time.Second)
		g.Expect(err).ToNot(HaveOccurred(), "reading %s of PVC %s", path, livePVC)
		return out
	}
	spec := orphanPVCSpec{
		storageClass: field(".spec.storageClassName"),
		volumeMode:   field(".spec.volumeMode"),
		accessMode:   field(".spec.accessModes[0]"),
		size:         field(".spec.resources.requests.storage"),
	}
	g.Expect(spec.storageClass).ToNot(BeEmpty(), "PVC %s has no storage class", livePVC)
	g.Expect(spec.size).ToNot(BeEmpty(), "PVC %s requests no storage", livePVC)
	if spec.accessMode == "" {
		spec.accessMode = "ReadWriteOnce"
	}
	return spec
}

// createOrphanPVC creates PVC name in the EVE app namespace and returns the
// time it did so. Named for a superseded generation of a live volume, it is
// the orphan a purge leaves when the old generation's VolumeStatus is lost.
func createOrphanPVC(t *WithT, dev *evetest.EdgeDevice, name string,
	spec orphanPVCSpec) time.Time {
	volumeMode := ""
	if spec.volumeMode != "" {
		volumeMode = "\n  volumeMode: " + spec.volumeMode
	}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s
  namespace: %s
spec:
  storageClassName: %s%s
  accessModes: [%s]
  resources:
    requests:
      storage: %s`, name, evetest.EVEKubeAppNamespace, spec.storageClass,
		volumeMode, spec.accessMode, spec.size)
	created := time.Now()
	applyManifest(t, dev, manifest, time.Minute)
	evetest.Logger().Infof("Created orphan PVC %q through %q", name, dev.Name())
	return created
}

// assertPVCsPresent checks that the cluster lists every PVC in names. PVCs
// are cluster objects, so any node's kubectl gives the same answer.
func assertPVCsPresent(g Gomega, dev *evetest.EdgeDevice, names ...string) {
	present := clusterPVCNames(g, dev)
	for _, name := range names {
		g.Expect(present).To(HaveKey(name), "the cluster does not list PVC %q", name)
	}
}

// assertPVCsAbsent checks that the cluster lists no PVC in names.
func assertPVCsAbsent(g Gomega, dev *evetest.EdgeDevice, names ...string) {
	present := clusterPVCNames(g, dev)
	for _, name := range names {
		g.Expect(present).ToNot(HaveKey(name), "the cluster still lists PVC %q", name)
	}
}

// TestClusterPVCGCDeletesOnlyOrphans checks that volumemgr's PVC garbage
// collection deletes an orphaned PVC and nothing else, and that only the
// volume's designated node (DNID), or its backup DNID while the DNID is down,
// deletes it.
//
// The PVC list is cluster-wide, but a controller need not send every volume to
// every node. The persistent volume here is a standalone volume that no app
// refers to, sent to two nodes of three. The node without it still lists its
// PVC, and must leave it alone, as must the nodes that hold it.
//
// An orphan is the PVC of a superseded volume generation that no VolumeStatus
// names, which a purge leaves when it lands while the DNID is down. The test
// creates orphans with kubectl rather than staging that outage, because GC
// sees only the PVC name and the node's config:
//
//   - The DNID orphan is created under the UUID of a volume no node has yet,
//     so every node must keep it, and it stays put while the test pauses at
//     orphan-exists. The test then sends that volume at generation 1, which
//     makes the orphan its superseded generation 0.
//   - The backup orphan is the app volume's superseded generation, created
//     right after the DNID powers off. No node may delete it until the outage
//     passes the backup threshold, one minute here, so a pause at
//     backup-orphan-exists sees it disappear soon after.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort: eth0 on a management and app bridge with
//     DHCP, eth1 on a cluster-only bridge for K3s traffic.
//
// Device configuration
// --------------------
//   - Three clusterDeviceRequirements devices.
//   - ClusterConfig (REPLICATED_STORAGE) over three nodes, node 1 bootstrap.
//   - timer.gc.vdisk at its 60s floor, so a GC pass runs every six seconds.
//   - cluster.dnid.backupnode.threshold at one minute, as in
//     TestDNIDandBackupDNID.
//   - The persistent volume: a standalone clear-text blank volume, sent to
//     edge-dev2 and edge-dev3 only, with no designated node.
//   - The superseded volume: a standalone blank volume at generation 1,
//     designated to edge-dev3, sent once its orphan exists.
//   - One Local NI and one container app designated to edge-dev3, with
//     Preferred affinity.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Checkpoints
// -----------
// The test asserts the named state before each checkpoint, and logs the PVC
// names to inspect there.
//
//  1. persistent-volume-exists: the persistent volume is created on edge-dev2
//     and edge-dev3, edge-dev1 has no config for it, and its PVC exists.
//  2. orphan-exists: the DNID orphan exists, and every node has kept it
//     through many GC passes.
//  3. orphan-cleaned-up: once its volume is sent, edge-dev3 deletes the
//     orphan, and no other node logs a delete. The persistent PVC remains.
//  4. persistent-volume-not-cleaned-up: over many more GC passes, the
//     persistent PVC and the live PVCs remain.
//  5. backup-orphan-exists: edge-dev3 is off and the backup orphan exists.
//  6. backup-orphan-cleaned-up: the node holding the eve-app-op lease deletes
//     it, and the other surviving node does not.
//  7. persistent-volume-not-cleaned-up-after-outage: edge-dev3 rejoins, the
//     persistent PVC and the live PVCs remain, and no node ever logged
//     deleting one of them.
//
// Suite placement
// ---------------
//   - TestNodeClusterResilienceSuite, because it powers a node off.
func TestClusterPVCGCDeletesOnlyOrphans(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()
	testStart := time.Now()
	log := evetest.Logger()

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
		requiredDevices[i] = clusterDeviceRequirements(
			devName[i], withTPM, filesystem, false)
	}
	var requirements []evetest.Requirement
	requirements = append(requirements, requiredDevices[:]...)
	requirements = append(requirements, evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort(devName[:]...),
	})
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	var nodes [3]evetest.ClusterNode
	for i := 0; i < 3; i++ {
		nodes[i] = evetest.ClusterNode{
			DevName:          devName[i],
			ClusterIP:        evetest.IPAddressWithPrefix(fmt.Sprintf("10.244.244.%d/24", i+2)),
			ClusterInterface: "ethernet1",
			BootstrapNode:    i == 0,
		}
	}
	clusterConfig := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE, nodes[:]...)

	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.VdiskGCTime, pvcGCVdiskGCTime)
	cfgProps.SetGlobalValueInt(dnidOutageThresholdKey,
		uint32(dnidOutageThresholdRequested.Seconds()))
	clusterConfig.SetConfigProperties(cfgProps)

	dhcpNet := clusterConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	noIPNet := clusterConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	clusterConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	clusterConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   noIPNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	cluster := evetest.NewEdgeCluster("pvc-gc-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(pvcGCClusterTimeout)
	evetest.Checkpoint("nodes-are-ready")

	var dev [3]*evetest.EdgeDevice
	for i, name := range devName {
		dev[i] = evetest.GetEdgeDevice(name)
	}
	dnid := dev[2]
	// kubeDev runs the cluster-wide PVC queries. It stays up throughout.
	kubeDev := dev[0]

	persistentUUID := clusterConfig.AddBlankVolume(evetest.ClusterBlankVolumeConfig{
		DisplayName: "pvc-gc-persistent",
		SizeBytes:   pvcGCStandaloneSize,
		ClearText:   true,
		NodeNames:   []string{devName[1], devName[2]},
	})
	niUUID := clusterConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.15.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.15.2"),
			End:   evetest.IPAddress("10.11.15.254"),
		},
		Gateway: evetest.IPAddress("10.11.15.1"),
		MTU:     1500,
	})
	appUUID := clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
		ApplicationInstanceConfig: evetest.ApplicationInstanceConfig{
			DisplayName: "pvc-gc-app",
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			CPUs:        1,
			MemoryBytes: 500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: niUUID,
				},
			},
		},
		DesignatedNodeName: devName[2],
		Affinity:           eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
	})
	cluster.ApplyConfig(clusterConfig, true, true)
	log.Infof("Submitted persistent volume %s and app %s (DNID %q)",
		persistentUUID, appUUID, devName[2])
	evetest.Checkpoint("persistent-volume-and-app-submitted")

	cluster.WaitUntilAppIsRunning(appUUID, pvcGCAppReadyTimeout)

	// edge-dev1 must lack the persistent volume, or this test cannot show that
	// a node leaves alone a PVC it has no config for.
	persistentPVC := ""
	t.Eventually(func(g Gomega) {
		for _, vc := range nodeVolumeConfigs(g, dev[0]) {
			g.Expect(vc.VolumeID).ToNot(Equal(persistentUUID),
				"edge-dev1 must not receive the persistent volume")
		}
		for _, d := range dev[1:] {
			persistentPVC = createdVolumeStatus(g, d, persistentUUID).GetPVCName()
		}
		assertPVCsPresent(g, kubeDev, persistentPVC)
	}, pvcGCAppReadyTimeout, pvcGCPollInterval).Should(Succeed())
	log.Infof("Persistent volume %s has PVC %q", persistentUUID, persistentPVC)
	evetest.Checkpoint("persistent-volume-exists")

	// The DNID orphan copies the persistent PVC's spec: both are blank volumes.
	var orphanSpec orphanPVCSpec
	t.Eventually(func(g Gomega) {
		orphanSpec = readOrphanPVCSpec(g, dev[1], persistentPVC)
	}, pvcGCPollInterval*6, pvcGCPollInterval).Should(Succeed())

	supersededUUID := uuid.Must(uuid.NewV4())
	orphanPVC := fmt.Sprintf("%s-pvc-0", supersededUUID)
	livePVC := fmt.Sprintf("%s-pvc-1", supersededUUID)
	orphanAt := createOrphanPVC(t, kubeDev, orphanPVC, orphanSpec)
	t.Consistently(func(g Gomega) {
		assertPVCsPresent(g, kubeDev, orphanPVC, persistentPVC)
	}, pvcGCSettleWindow, pvcGCSettleInterval).Should(Succeed())
	log.Infof("Orphan PVC %q exists; volume %s is not sent yet", orphanPVC, supersededUUID)
	evetest.Checkpoint("orphan-exists")

	clusterConfig.AddBlankVolume(evetest.ClusterBlankVolumeConfig{
		DisplayName:        "pvc-gc-superseded",
		SizeBytes:          pvcGCStandaloneSize,
		ClearText:          true,
		DesignatedNodeName: devName[2],
		GenerationCount:    1,
		VolumeUUID:         supersededUUID,
	})
	log.Infof("Sending volume %s at generation 1, designated to %q, to every node",
		supersededUUID, devName[2])
	cluster.ApplyConfig(clusterConfig, true, true)
	t.Eventually(func(g Gomega) {
		createdVolumeStatus(g, dnid, supersededUUID)
		assertPVCsAbsent(g, kubeDev, orphanPVC)
		assertPVCsPresent(g, kubeDev, livePVC, persistentPVC)
	}, pvcGCAppReadyTimeout, pvcGCPollInterval).Should(Succeed())
	t.Eventually(func() []evetest.LogMsg {
		return pvcDeleteLogs(dnid, orphanPVC, orphanAt)
	}, pvcGCLogTimeout, pvcGCPollInterval).ShouldNot(BeEmpty(),
		"the DNID %q must log deleting the orphan", dnid.Name())
	for _, d := range dev[:2] {
		t.Expect(pvcDeleteLogs(d, orphanPVC, orphanAt)).To(BeEmpty(),
			"%q deleted the orphan while the DNID was up", d.Name())
	}
	log.Infof("Orphan PVC %q deleted by %q; live PVC %q and persistent PVC %q remain",
		orphanPVC, dnid.Name(), livePVC, persistentPVC)
	evetest.Checkpoint("orphan-cleaned-up")

	var appVolumeUUID uuid.UUID
	appPVC := ""
	t.Eventually(func(g Gomega) {
		var found []pillartypes.VolumeStatus
		for _, vs := range nodeVolumeStatuses(g, dnid) {
			if vs.VolumeID != persistentUUID && vs.VolumeID != supersededUUID &&
				vs.State == pillartypes.CREATED_VOLUME {
				found = append(found, vs)
			}
		}
		g.Expect(found).To(HaveLen(1), "expected one app volume on the DNID")
		g.Expect(found[0].IsReplicated).To(BeFalse(), "the DNID must own the app volume")
		appVolumeUUID = found[0].VolumeID
		appPVC = found[0].GetPVCName()
	}, pvcGCAppReadyTimeout, pvcGCPollInterval).Should(Succeed())

	t.Consistently(func(g Gomega) {
		assertPVCsPresent(g, kubeDev, persistentPVC, livePVC, appPVC)
	}, pvcGCSettleWindow, pvcGCSettleInterval).Should(Succeed())
	log.Infof("Persistent PVC %q survives; live PVCs %q and %q remain",
		persistentPVC, livePVC, appPVC)
	evetest.Checkpoint("persistent-volume-not-cleaned-up")

	// Backup DNID applies to app volumes only: zedagent takes a volume's
	// designated node from the apps that use it. Supersede the app volume
	// first, so its old generation can stand as the backup orphan.
	var appOrphanSpec orphanPVCSpec
	t.Eventually(func(g Gomega) {
		appOrphanSpec = readOrphanPVCSpec(g, dnid, appPVC)
	}, pvcGCPollInterval*6, pvcGCPollInterval).Should(Succeed())
	cluster.PurgeApplication(appUUID, evetest.BumpVolumeGeneration, true, pvcGCPurgeTimeout)
	cluster.WaitUntilAppIsRunning(appUUID, pvcGCAppReadyTimeout)
	appOrphanPVC := appPVC
	t.Eventually(func(g Gomega) {
		appPVC = createdVolumeStatus(g, dnid, appVolumeUUID).GetPVCName()
		g.Expect(appPVC).ToNot(Equal(appOrphanPVC),
			"the purge must move the app volume to a new generation")
		assertPVCsAbsent(g, kubeDev, appOrphanPVC)
		assertPVCsPresent(g, kubeDev, appPVC)
	}, pvcGCAppReadyTimeout, pvcGCPollInterval).Should(Succeed())
	log.Infof("App volume %s moved from PVC %q to %q", appVolumeUUID, appOrphanPVC, appPVC)
	evetest.Checkpoint("app-volume-superseded")

	dnid.SyncDisks()
	dnid.PowerOff()
	evetest.Checkpoint("dnid-powered-off")
	backupWait, overrideAccepted := backupOpTimeout(dev[0])
	log.Infof("Waiting up to %v for a backup DNID (threshold override accepted: %v)",
		backupWait, overrideAccepted)
	survivors := dev[:2]

	backupOrphanAt := createOrphanPVC(t, kubeDev, appOrphanPVC, appOrphanSpec)
	t.Expect(clusterPVCNames(t, kubeDev)).To(HaveKey(appOrphanPVC),
		"the backup orphan must exist before the outage passes the threshold")
	log.Infof("Backup orphan PVC %q exists while the DNID is down", appOrphanPVC)
	evetest.Checkpoint("backup-orphan-exists")

	t.Eventually(func(g Gomega) {
		assertPVCsAbsent(g, kubeDev, appOrphanPVC)
		assertPVCsPresent(g, kubeDev, persistentPVC, livePVC, appPVC)
	}, backupWait, pvcGCPollInterval).Should(Succeed())
	var backup, bystander *evetest.EdgeDevice
	t.Eventually(func(g Gomega) {
		backup, bystander = nil, nil
		for _, d := range survivors {
			if isAppOpLeader(g, d) {
				g.Expect(backup).To(BeNil(), "two nodes hold the eve-app-op lease")
				backup = d
			} else {
				bystander = d
			}
		}
		g.Expect(backup).ToNot(BeNil(), "no surviving node holds the eve-app-op lease")
	}, pvcGCReclaimTimeout, pvcGCPollInterval).Should(Succeed())
	t.Eventually(func() []evetest.LogMsg {
		return pvcDeleteLogs(backup, appOrphanPVC, backupOrphanAt)
	}, pvcGCLogTimeout, pvcGCPollInterval).ShouldNot(BeEmpty(),
		"the backup DNID %q must log deleting the orphan", backup.Name())
	t.Expect(pvcDeleteLogs(bystander, appOrphanPVC, backupOrphanAt)).To(BeEmpty(),
		"%q deleted the orphan without the eve-app-op lease", bystander.Name())
	log.Infof("Backup orphan PVC %q deleted by backup DNID %q", appOrphanPVC, backup.Name())
	evetest.Checkpoint("backup-orphan-cleaned-up")

	// waitUntilOnline=false per PowerOn's own doc comment. The outage has
	// outlasted the backup threshold, so Kubernetes has marked the DNID
	// NotReady, and only a report from after the reboot shows it Ready.
	dnid.PowerOn(false)
	cluster.WaitForFreshNodesReady(pvcGCClusterTimeout)
	// A created VolumeStatus shows the DNID's volumemgr is back and has its
	// config, so the window below covers its GC passes, not just its boot.
	t.Eventually(func(g Gomega) {
		createdVolumeStatus(g, dnid, persistentUUID)
	}, pvcGCAppReadyTimeout, pvcGCPollInterval).Should(Succeed())
	evetest.Checkpoint("dnid-rejoined")
	t.Consistently(func(g Gomega) {
		assertPVCsPresent(g, kubeDev, persistentPVC, livePVC, appPVC)
	}, pvcGCSettleWindow, pvcGCSettleInterval).Should(Succeed())
	for _, d := range dev {
		for _, pvc := range []string{persistentPVC, livePVC, appPVC} {
			t.Expect(pvcDeleteLogs(d, pvc, testStart)).To(BeEmpty(),
				"%q logged deleting live PVC %q", d.Name(), pvc)
		}
	}
	log.Infof("Persistent PVC %q survives the DNID outage", persistentPVC)
	evetest.Checkpoint("persistent-volume-not-cleaned-up-after-outage")
}
