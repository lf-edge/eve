// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// End-state assertions for the purge topic.
//
// Rule for this file: assertions that are meaningless outside a purge - anything
// taking a purge counter, or asserting a generation transition. The litmus test
// is "would this still make sense in a test that never purges anything?" If yes,
// it belongs in the subject file for whatever it observes (appstate,
// appworkload, appvolumes), not here.

package apps_test

import (
	"fmt"
	"strconv"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// assertPurgeCompleted asserts everything a completed purge must satisfy on every
// hypervisor, so one test sequence can be driven against eve-k and kvm with only
// the closing detector differing (assertKubePurgeEndState or
// assertLocalDomainPurgeEndState).
//
// The purge-phase check is the one that catches a purge which never finishes, as
// opposed to one which finishes wrongly - see appPurgePhase for that failure mode.
//
// The volume-generation check holds because evetest.PurgeApplication bumps the
// referenced volumes' generationCount alongside the app's purge counter, the way
// a controller does - see the note in appvolumes_test.go, which also explains why
// bumping only the app counter would make this assertion unsatisfiable.
func assertPurgeCompleted(g Gomega, dev *evetest.EdgeDevice, appUUID uuid.UUID,
	wantCounter uint32, baselineVolGen string) {
	newCounter, found := purgeCounter(dev, appUUID)
	g.Expect(found).To(BeTrue(), "expected the purge counter file to exist")
	g.Expect(newCounter).To(Equal(wantCounter),
		"persisted purge counter must advance by exactly one")

	state, purge, found := appPurgePhase(dev, appUUID)
	g.Expect(found).To(BeTrue(), "expected a published AppInstanceStatus for the app")
	g.Expect(purge).To(Equal(types.NotInprogress),
		"the purge must be finished, not parked in %s", inprogressName(purge))
	// domainmgr's own diagnosis goes in the message: SwState alone cannot
	// distinguish "never started" from a guest that boots and then powers itself
	// off, which is what a climbing TriedCount with BootFailed set looks like.
	domDiag := ""
	if dom, ok := appDomainStatus(dev, appUUID); ok {
		domDiag = fmt.Sprintf(" (DomainStatus BootFailed=%v TriedCount=%d Error=%q)",
			dom.BootFailed, dom.TriedCount, dom.Error)
	}
	g.Expect(state).To(Equal(types.RUNNING),
		"expected the app to be RUNNING after the purge, got %v%s", state, domDiag)

	// Exactly one volume, so the old generation's disk was not left alongside
	// the new one - and it is the new generation, so the disk really was rebuilt.
	g.Expect(soleVolumeStatus(g, dev).Key()).NotTo(Equal(baselineVolGen),
		"the app's volume must be a new generation, not the pre-purge one")
}

// assertDomainReplaced asserts the workload the app runs in is a different one
// than before the purge, identified by DomainId: the qemu pid on kvm/xen, and on
// eve-k a value derived from the VMIRS's own metadata.uid. A purge must stop the
// old domain and start a new one, so an unchanged id means the purge advanced its
// counter without doing the work.
//
// Only useful where nothing ELSE restarted the domain in the meantime - a reboot
// changes the id by itself, so a test that power-cycles the device cannot draw any
// conclusion from this.
func assertDomainReplaced(g Gomega, dev *evetest.EdgeDevice, appUUID uuid.UUID,
	baselineDomainID int) {
	domStatus, found := appDomainStatus(dev, appUUID)
	g.Expect(found).To(BeTrue(), "expected a published DomainStatus for the app")
	g.Expect(domStatus.DomainId).NotTo(BeZero(),
		"DomainId must identify a live domain; zero means 'confirmed absent'")
	g.Expect(domStatus.DomainId).NotTo(Equal(baselineDomainID),
		"the domain must have been replaced by the purge, but DomainId is still %d "+
			"- the purge counter advanced without the domain being recreated",
		baselineDomainID)
}

// assertExactlyOneVMIRSAtGeneration is the primary end-state detector this suite
// is built around: after a purge to newCounter there must be exactly one VMIRS for
// the app, and it must be named for the NEW generation - not the old one (a
// stalled purge leaves the old generation's VMIRS alone) and not both (the old
// generation's VMIRS surviving alongside a newly created one).
func assertExactlyOneVMIRSAtGeneration(
	g Gomega, dev *evetest.EdgeDevice, appUUID uuid.UUID, appDisplayName string,
	newCounter uint32) {
	// base.GetAppKubeNameWithPurge would be the exact match for this (name + "-" +
	// purge counter), but it is newer than the pillar module version currently
	// pinned by evetest's go.mod, so the suffix is appended here instead - see
	// base.GetAppKubeNameWithPurge's own implementation for why this is exactly
	// equivalent.
	wantName := base.GetAppKubeName(appDisplayName, appUUID) + "-" +
		strconv.FormatUint(uint64(newCounter), 10)
	names, found := listAppVMIRS(dev, appUUID)
	g.Expect(found).To(BeTrue(),
		"could not list VMIRS objects; k3s may still be starting")
	g.Expect(names).To(HaveLen(1),
		"expected exactly one VMIRS for the app, found %v", names)
	if len(names) == 1 {
		g.Expect(names[0]).To(Equal(wantName),
			"the surviving VMIRS must be the NEW generation %q, not a stale one", wantName)
	}
}

// assertKubePurgeEndState is the eve-k end-state detector: the decisive "exactly
// one VMIRS, and it is the new generation" check.
//
// Reclaiming the old generation's PVC is NOT checked here, for the same reason
// the local path does not check its disk here - see assertOldVolumeReclaimed.
// Callers run assertNoOrphanedPVCs separately, on the slower clock.
func assertKubePurgeEndState(g Gomega, dev *evetest.EdgeDevice, appUUID uuid.UUID,
	appDisplayName string, newCounter uint32) {
	assertExactlyOneVMIRSAtGeneration(g, dev, appUUID, appDisplayName, newCounter)
}

// assertLocalDomainPurgeEndState is assertKubePurgeEndState's counterpart for a
// hypervisor whose workload is a local process rather than a cluster object.
//
// Two things differ from the kube case. The first is what CANNOT be asserted:
// there is no "exactly one generation" check, because a kvm domain name carries no
// purge counter (see listKVMDomainDirs) - which is also why the
// duplicate-generation defect cannot take this shape on kvm at all.
//
// The second is reclaiming the old disk, which does NOT belong here: volumemgr
// removes the previous generation's artifact on its own clock, observed at
// roughly five minutes after the purge completed, so a check for it inside the
// purge's own end-state window fails on timing rather than on substance. See
// assertOldVolumeReclaimed, which the caller runs separately with a timeout
// suited to that.
func assertLocalDomainPurgeEndState(g Gomega, dev *evetest.EdgeDevice,
	appUUID uuid.UUID, baselineVolGen string, hv evetest.Hypervisor) {
	domStatus, found := appDomainStatus(dev, appUUID)
	g.Expect(found).To(BeTrue(), "expected a published DomainStatus for the app")
	g.Expect(domStatus.DomainId).NotTo(BeZero(),
		"DomainId must be the live domain's pid; zero means 'confirmed absent'")

	// Which generation the running domain is attached to. DomainStatus.PurgeCounter
	// would say this directly, but it is newer than the pillar module version
	// evetest's go.mod pins; each disk's VolumeKey carries the same information
	// (it is VolumeStatus.Key) and is available in the pinned version.
	var domainVolKeys []string
	for _, disk := range domStatus.DiskStatusList {
		if disk.VolumeKey != "" {
			domainVolKeys = append(domainVolKeys, disk.VolumeKey)
		}
	}
	g.Expect(domainVolKeys).NotTo(ContainElement(baselineVolGen),
		"the running domain must not still be attached to the pre-purge volume")

	if hv != evetest.HypervisorKVM {
		// The remaining assertions read qemu's own per-domain state directory,
		// which only the kvm backend writes.
		return
	}
	domainDirs := listKVMDomainDirs(dev, appUUID)
	g.Expect(domainDirs).To(HaveLen(1),
		"expected exactly one qemu domain state directory for the app, found %v",
		domainDirs)
	if len(domainDirs) != 1 {
		return
	}
	g.Expect(domainDirs[0]).To(Equal(domStatus.DomainName),
		"the domain directory must be the one DomainStatus names")
	pid, ok := kvmDomainPid(dev, domainDirs[0])
	g.Expect(ok).To(BeTrue(), "expected a readable pidfile for %q", domainDirs[0])
	g.Expect(pid).To(Equal(domStatus.DomainId),
		"DomainStatus.DomainId must be the pid qemu wrote for the domain")
}

// assertOldVolumeReclaimed asserts the previous generation's disk is eventually
// removed. Deliberately separate from the purge's end state: the purge is
// complete once the app runs on the new generation, while reclaiming the old
// artifact happens minutes later on volumemgr's own schedule (well before the
// one-hour VdiskGCTime, but far outside the purge window). Give it its own,
// longer Eventually.
func assertOldVolumeReclaimed(
	g Gomega, dev *evetest.EdgeDevice, baselineVolPath string) {
	assertVolumeArtifactGone(g, dev, baselineVolPath)
	assertNoStaleVolumeArtifacts(g, dev)
}
