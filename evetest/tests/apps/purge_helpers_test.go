// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Helpers owned by the purge tests: first what they build before they run
// (timeouts, device requirements, app config), then the end-state assertions
// only a purge can be asked for.
//
// Rule for this file: everything here is purge-specific. An assertion belongs
// here if it takes a purge counter or asserts a generation transition; the
// litmus test is "would this still make sense in a test that never purges
// anything?" If yes, it belongs in the helper file for whatever state it
// observes (appstate, appworkload, appvolumes), not here.

package apps_test

import (
	"fmt"
	"strconv"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Timeouts for this suite, in one place so they can be reviewed together.
//
// Sizing principle: Eventually returns as soon as its condition holds, so a
// generous timeout costs nothing when the system behaves and only delays a
// genuine failure. Each of these is set from an observed duration with real
// headroom, never tuned to just-barely-pass. If one of them starts expiring,
// the answer is to find out what changed - not to raise the number.
const (
	// assertPollInterval is how often the end-state assertions re-check.
	assertPollInterval = 5 * time.Second

	// appReadyTimeout bounds WaitUntilAppIsRunning. Excludes image download,
	// which the framework accounts for separately.
	appReadyTimeout = 10 * time.Minute

	// purgeCompleteTimeout bounds PurgeApplication(waitUntilPurged=true).
	purgeCompleteTimeout = 5 * time.Minute

	// baselineTimeout bounds reading the pre-purge state. Everything it reads is
	// already published by the time the app reports RUNNING, so this only
	// absorbs publication lag.
	baselineTimeout = 2 * time.Minute

	// purgeEndStateTimeout bounds the assertions about the NEW generation:
	// counter advanced, purge phase finished, app running, one volume, one
	// workload. Observed to settle within about a minute of the app coming back.
	purgeEndStateTimeout = 5 * time.Minute

	// storageReclaimTimeout bounds removal of the OLD generation's disk, which
	// is a separate concern on a separate clock: the purge is complete once the
	// app runs on the new generation, and volumemgr reclaims the previous
	// artifact afterwards - observed at roughly five minutes, far short of the
	// one-hour VdiskGCTime but far longer than the purge itself.
	storageReclaimTimeout = 15 * time.Minute

	// storageReclaimPollInterval is deliberately coarse: each poll shells out to
	// the device, and nothing is expected to change for minutes.
	storageReclaimPollInterval = 15 * time.Second

	// deviceRebootTimeout bounds the wait for evidence that a reboot the
	// controller asked for has actually happened. It only has to cover the
	// shutdown plus the first post-boot info message, not the app coming back.
	deviceRebootTimeout = 5 * time.Minute

	// clusterReadyTimeout bounds a single eve-k node becoming Ready. k3s and
	// Longhorn take minutes to come up, and an app deployed before that sits in
	// INITIAL - burning the app-ready budget on something that is not the app.
	// Measured at about six minutes on a 4-vCPU node; every other test in this
	// package allows twenty.
	clusterReadyTimeout = 20 * time.Minute
)

// purgeDeviceRequirements returns the RequireEdgeDevice used by every test in
// this suite: a node on the requested hypervisor, always created fresh so a
// previous test's purge counters or workload generations can never leak into
// this one - the invariants asserted here are precisely about what generations
// exist, so a warm/reused device would make a false pass indistinguishable
// from a true one.
//
// No grub CPU options: kube-init widens the EVE cpuset for the duration of the
// deploy and restores it on RUNNING (prereqs.WidenEVECPUs), so cluster
// formation no longer depends on the test raising eve_max_vcpus itself.
func purgeDeviceRequirements(devName string, withTPM bool,
	filesystem evetest.Filesystem, hv evetest.Hypervisor) evetest.RequireEdgeDevice {
	return evetest.RequireEdgeDevice{
		Name:              devName,
		WithTPM:           withTPM,
		WithHypervisor:    hv,
		DeviceReusePolicy: evetest.CreateFromScratchWithLiveImage,
		WithFilesystem:    filesystem,
	}
}

// vmShimApplication returns the ApplicationInstanceConfig for the app used
// throughout this suite: the standard evetest-ubuntu-ctr container image run
// with VirtualizationMode=HVM. On eve-k, HVM (rather than the
// container-native NOHYPER default) makes domainmgr's kube path create a
// VMIRS (hypervisor/kubevirt.go CreateReplicaVMIConfig) instead of a plain
// pod, so this "shim VM" is the cheapest fixture that exercises the
// VMIRS-lifecycle code this suite is testing. On kvm/xen the same config
// yields an ordinary qemu domain, which is what makes the two comparable.
func vmShimApplication(
	displayName string, niUUID uuid.UUID) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName: displayName,
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters:    singleVIFWithSSH(niUUID),
	}
}

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
// a controller does - see the note in appvolumes_helpers_test.go, which also
// explains why bumping only the app counter would make this assertion
// unsatisfiable.
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
// purge counter (see listKVMDomainDirs) - which is also why a surviving
// generation cannot take this shape on kvm at all.
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
	domainDirs := listKVMDomainDirs(g, dev, appUUID)
	g.Expect(domainDirs).To(HaveLen(1),
		"expected exactly one qemu domain state directory for the app, found %v",
		domainDirs)
	if len(domainDirs) != 1 {
		return
	}
	g.Expect(domainDirs[0]).To(Equal(domStatus.DomainName),
		"the domain directory must be the one DomainStatus names")
	pid, err := kvmDomainPid(dev, domainDirs[0])
	g.Expect(err).ToNot(HaveOccurred(), "reading the pidfile of %q", domainDirs[0])
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
