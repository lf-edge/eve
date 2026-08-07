// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// The app's disk, in all three forms it takes: volumemgr's own VolumeStatus, the
// PVC on eve-k, and the file or snapshot directory under /persist on kvm/xen.
//
// Rule for this file: readers and invariants about STORAGE. The "no artifact
// exists that EVE no longer references" checks live here rather than with the
// purge assertions on purpose - they are true after a delete, a restart or a
// snapshot rollback too, so a future non-purge test must be able to use them
// unchanged.
//
// Two scope caveats apply to everything in this file, because types.VolumeStatus
// carries no app UUID (the join is AppInstanceStatus.VolumeRefStatusList):
//
//   - Device-scoped, not app-scoped. These helpers describe every volume on the
//     node. They are only valid while the suite deploys exactly one app; the
//     moment a second app appears they must filter through VolumeRefStatusList.
//   - Single-node only. assertNoOrphanedPVCs compares cluster-wide `kubectl get
//     pvc` output against ONE node's publications, which in a replicated-storage
//     cluster generates false failures - which is why
//     purge_during_failover_test.go documents skipping volume checks entirely.

package apps_test

import (
	"path"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// volumeDirs mirrors types.VolumeClearDirName and types.VolumeEncryptedDirName.
// Which one a given volume lands in depends on VolumeStatus.Encrypted, so both
// are listed and a missing directory is not an error.
var volumeDirs = []string{"/persist/clear/volumes", "/persist/vault/volumes"}

// soleVolumeStatus returns the node's one and only published VolumeStatus,
// failing the assertion if there is not exactly one. Named "sole" rather than
// "single" as a reminder that the scope is the whole device: see this file's
// header for when that stops being valid.
func soleVolumeStatus(g Gomega, dev *evetest.EdgeDevice) types.VolumeStatus {
	vols, err := evetest.ReadAllPublications[types.VolumeStatus](dev, "volumemgr", false)
	g.Expect(err).ToNot(HaveOccurred(), "reading volumemgr's VolumeStatus publications")
	g.Expect(vols).To(HaveLen(1),
		"expected exactly one volume, found %d - a second one would mean the old "+
			"generation's disk was never torn down", len(vols))
	if len(vols) == 0 {
		return types.VolumeStatus{}
	}
	return vols[0]
}

// listPVCNames returns the names of every PVC in the namespace EVE runs app
// workloads in, regardless of which app or generation it belongs to - see
// assertNoOrphanedPVCs, which is what attributes them.
func listPVCNames(dev *evetest.EdgeDevice) []string {
	list, ok := kubectlListItems(dev, "pvc")
	if !ok {
		return nil
	}
	var names []string
	for _, item := range list.Items {
		names = append(names, item.Metadata.Name)
	}
	return names
}

// assertNoOrphanedPVCs cross-checks every PVC actually present in the cluster
// against the PVC name volumemgr's own current VolumeStatus publications would
// produce (VolumeStatus.GetPVCName): "<volume-id>-pvc-<generation>". A PVC that
// exists in Kubernetes but that no published VolumeStatus would name is orphaned
// - Kubernetes still has the disk, but EVE no longer references it.
//
// This is strictly stronger than a volume count: the stale-generation sweep in
// hypervisor/kubevirt.go reconciles the VMIRS/ReplicaSet and its pods only, not
// PVCs, so a purge that otherwise completes cleanly can still leave a stale
// generation's disk behind indefinitely and nothing else here would catch it.
func assertNoOrphanedPVCs(g Gomega, dev *evetest.EdgeDevice) {
	vols, err := evetest.ReadAllPublications[types.VolumeStatus](dev, "volumemgr", false)
	g.Expect(err).ToNot(HaveOccurred(), "reading volumemgr's VolumeStatus publications")
	expected := make(map[string]bool, len(vols))
	for _, v := range vols {
		expected[v.GetPVCName()] = true
	}
	for _, name := range listPVCNames(dev) {
		g.Expect(expected).To(HaveKey(name),
			"PVC %q exists in the cluster but no currently published VolumeStatus "+
				"would produce it - orphaned disk left behind by a stale generation", name)
	}
}

// listVolumeArtifacts returns the full path of every entry in EVE's volume
// directories. Entries can be files (a qcow2 or raw disk) or directories (a
// container volume's snapshot mount), so this does not filter by type - see
// assertNoStaleVolumeArtifacts, which attributes them.
func listVolumeArtifacts(dev *evetest.EdgeDevice) []string {
	var paths []string
	for _, dir := range volumeDirs {
		for _, name := range listDirEntries(dev, dir) {
			paths = append(paths, path.Join(dir, name))
		}
	}
	return paths
}

// assertNoStaleVolumeArtifacts is assertNoOrphanedPVCs' counterpart for a local
// hypervisor: it cross-checks every artifact on disk against the path each
// published VolumeStatus would produce (VolumeStatus.PathName). An artifact that
// exists but that no live VolumeStatus names is a stale generation's disk - the
// storage is still consumed, but EVE no longer references it.
//
// This carries the most weight on the kvm path. The duplicate-workload defects
// are structurally impossible there (no cluster-side object outlives the node), so
// a purge that goes wrong on kvm shows up as a disk nobody owns rather than as a
// second running domain.
func assertNoStaleVolumeArtifacts(g Gomega, dev *evetest.EdgeDevice) {
	vols, err := evetest.ReadAllPublications[types.VolumeStatus](dev, "volumemgr", false)
	g.Expect(err).ToNot(HaveOccurred(), "reading volumemgr's VolumeStatus publications")
	expected := make(map[string]bool, len(vols))
	for _, v := range vols {
		expected[v.PathName()] = true
	}
	for _, p := range listVolumeArtifacts(dev) {
		g.Expect(expected).To(HaveKey(p),
			"volume artifact %q exists on disk but no currently published "+
				"VolumeStatus would produce it - stale generation's disk left behind", p)
	}
}

// assertVolumeArtifactGone asserts a specific volume path no longer exists.
// Unlike assertNoStaleVolumeArtifacts, which needs volumemgr's publications to be
// trustworthy, this names the exact artifact the purge was supposed to replace.
func assertVolumeArtifactGone(g Gomega, dev *evetest.EdgeDevice, target string) {
	exists, ok := pathExists(dev, target)
	g.Expect(ok).To(BeTrue(), "could not check whether %q still exists", target)
	g.Expect(exists).To(BeFalse(),
		"the pre-purge volume %q must be deleted once the purge completes", target)
}

// A note on why the assertions above are meaningful, because they depend on
// something outside this package:
//
// The volume's generation key changes across a purge ONLY because
// evetest.PurgeApplication bumps the generationCount of every volume the app
// references, on the VolumeRef entries and on the matching Volume entries, the
// way a real controller does. Per the API, a change to that field "indicates that
// the mutated volume needs to be purged and built from scratch. This is a
// generalization of the purge command for an application instance."
//
// Bumping only the app's purge counter would NOT recreate the volume: zedmanager
// matches volume refs on VolumeRefConfig.Key() =
// "<volume-uuid>#<generationCount+localGenerationCount>#<app-uuid>"
// (cmd/zedmanager/handlevolumemgr.go:218), so with an unchanged generation the
// existing reference still matches at cmd/zedmanager/updatestatus.go:406, nothing
// is removed or added, RecreateVolumes only clears VerifyOnly, and the app
// restarts on its old disk. If PurgeApplication ever regresses to bumping just
// the app counter, every assertion in this file about a changed generation or a
// vanished artifact becomes unsatisfiable rather than merely weaker - so they are
// also the tripwire for that regression.
