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
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

const (
	appVirtModeParamKey      = "APP_VIRT_MODE"
	constrainPersistParamKey = "CONSTRAIN_PERSIST"
	verifyRollbackParamKey   = "VERIFY_ROLLBACK"

	// appVirtModeNoHyper runs the container app as a plain k8s pod, whose
	// image CRI resolves through the configured snapshotter.
	appVirtModeNoHyper = "nohyper"
	// appVirtModeHVM runs it as a VMIRS-backed VM off a PVC, which never
	// reaches the CRI snapshotter.
	appVirtModeHVM = "hvm"

	// commitWindow is how long EVE holds the upgraded partition under test
	// before committing it. Long enough that the post-upgrade snapshotter
	// reading is unambiguously inside the window, short enough not to
	// dominate the run.
	commitWindow = 5 * time.Minute

	// appStartBudget covers image download, the qcow2 conversion and the
	// CDI upload into a PVC, which every eve-k container app pays for --
	// pod-backed ones included.
	appStartBudget = 20 * time.Minute
)

// TestSnapshotterUpgrade verifies that upgrading an eve-k device from a
// release that unpacks app images with the *overlayfs* containerd snapshotter
// to one configured for *erofs* leaves the already-deployed apps working.
//
// Why this needs its own test rather than relying on TestEVEUpgrade: on eve-k
// a "container app" becomes one of two very different things, and only one of
// them goes near the snapshotter this change touches.
//
//   - VirtualizationMode=NOHYPER -> domainmgr's kube path creates a plain
//     ReplicaSet pod (hypervisor/kubevirt.go CreateReplicaPodConfig) and CRI
//     resolves the app image through the configured snapshotter. After an
//     overlayfs->erofs switch the image is unpacked for the wrong snapshotter,
//     and containerd's CRI plugin silently re-unpacks it from local content
//     inside CreateContainer (internal/cri/opts/container.go WithNewSnapshot).
//     This is the path at risk.
//   - VirtualizationMode=HVM -> a VMIRS is created instead and pillar converts
//     the container image to a qcow2 rolled into a PVC. The app image never
//     reaches the CRI snapshotter, and pillar's own unpack uses a hardcoded
//     overlayfs (containerd/containerd.go) that this change does not touch.
//     Kept as a variant so that claim is tested rather than assumed.
//
// The existing TestEVEUpgrade variants all use HVM, so none of them exercise
// the NOHYPER path.
//
// Network model
// -------------
// netmodels.SingleEthWithDHCP: the app only needs one uplink and a local NI;
// nothing here is network-specific.
//
// Device configuration
// --------------------
//   - Created from scratch with the installer at INITIAL_EVE_VERSION, pinned to
//     the Kubevirt hypervisor (the overlayfs-era release).
//   - SystemAdapter on eth0 (DHCP, mgmt+app).
//   - One Local NI "local-ni" and one container app in the mode under test.
//     Under CONSTRAIN_PERSIST a second, deactivated app is added as well.
//
// Test parameters
// ---------------
//   - INITIAL_EVE_VERSION: the build to upgrade from. Must still use the
//     overlayfs snapshotter; defaults to a pinned master snapshot (see
//     initialEVEVersionForSnapshotter in testsuite_test.go for why).
//   - APP_VIRT_MODE: "nohyper" (default) or "hvm" -- see above.
//   - CONSTRAIN_PERSIST: squeeze /persist before the conversion so it cannot
//     succeed, and assert the failure and recovery behaviour (default false).
//   - EVE_VERSION / HYPERVISOR: the upgrade target, as for TestEVEUpgrade.
//   - TPM, DISK_SIZE_MB: as for TestEVEUpgrade.
//
// Phases
// ------
//  1. k3s-ready: device onboards on the initial release and the cluster forms.
//  2. app-running-pre-upgrade: the app is deployed and emitting heartbeats, and
//     the overlayfs snapshotter store is non-empty -- the precondition the
//     whole test depends on.
//  3. pre-upgrade: snapshotter populations and free space recorded.
//  4. (CONSTRAIN_PERSIST only) persist-constrained: after the upgrade has been
//     applied, /persist is squeezed below kubelet's 5% eviction floor and the
//     second app is activated, forcing a conversion that cannot fit.
//  5. upgrade-complete / k3s-ready-post-upgrade.
//  6. post-upgrade-verified: the app is emitting fresh heartbeats again, the
//     overlayfs store still holds its snapshots (the revert the A/B scheme
//     depends on is still possible), and for NOHYPER the erofs store has
//     grown -- i.e. a conversion actually happened.
//  7. (CONSTRAIN_PERSIST only) recovery-verified: freeing the space lets the
//     second app start without further intervention.
func TestSnapshotterUpgrade(test *testing.T) {
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
			DefaultValue: "0.0.0-master-5786db09",
			Description: evetest.TestParameterDescription{
				Summary: "EVE version to upgrade from; must be a build that still " +
					"uses the overlayfs snapshotter",
				Default: "0.0.0-master-5786db09",
			},
		},
		evetest.TestParameterDefinition{
			Key:          appVirtModeParamKey,
			DefaultValue: appVirtModeNoHyper,
			Description: evetest.TestParameterDescription{
				Summary: "How the container app runs: \"nohyper\" (plain k8s pod, " +
					"image resolved by the CRI snapshotter) or \"hvm\" (VMIRS off a PVC)",
				Default:       appVirtModeNoHyper,
				AllowedValues: "nohyper|hvm",
			},
		},
		evetest.TestParameterDefinition{
			Key:          verifyRollbackParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "After the reclaim has run, force a rollback to the initial " +
					"version and verify the app still recovers there",
				Default: "false",
			},
		},
		evetest.TestParameterDefinition{
			Key:          constrainPersistParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "Squeeze /persist below kubelet's eviction floor before the " +
					"conversion, to test the out-of-space behaviour and recovery",
				Default: "false",
			},
		},
	)

	withTPM := evetest.GetTPMParameterValue()
	diskSizeMiB := evetest.GetDiskSizeMiBParameterValue()
	initialVersion := evetest.GetTestParameter[string](initialEVEVersionParamKey)
	targetVersion := evetest.GetEVEVersionParameterValue()
	targetHypervisor := evetest.GetHypervisorParameterValue()
	virtModeParam := evetest.GetTestParameter[string](appVirtModeParamKey)
	constrainPersist := evetest.GetTestParameter[bool](constrainPersistParamKey)
	verifyRollback := evetest.GetTestParameter[bool](verifyRollbackParamKey)
	log := evetest.Logger()

	if initialVersion == "" {
		evetestT.Fatalf("%s%s is required for TestSnapshotterUpgrade",
			constants.EnvPrefix, initialEVEVersionParamKey)
	}
	// The snapshotter only exists under eve-k; the test is meaningless on
	// kvm/xen, so fail loudly rather than silently passing.
	if targetHypervisor != evetest.HypervisorKubevirt {
		evetestT.Fatalf("TestSnapshotterUpgrade requires the Kubevirt hypervisor, got %q",
			targetHypervisor)
	}

	var virtMode eveconfig.VmMode
	switch virtModeParam {
	case appVirtModeNoHyper:
		virtMode = eveconfig.VmMode_NOHYPER
	case appVirtModeHVM:
		virtMode = eveconfig.VmMode_HVM
	default:
		evetestT.Fatalf("unsupported %s%s value %q (want %q or %q)",
			constants.EnvPrefix, appVirtModeParamKey, virtModeParam,
			appVirtModeNoHyper, appVirtModeHVM)
	}

	const devName = "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithEVEVersion:    initialVersion,
			WithHypervisor:    evetest.HypervisorKubevirt,
			WithTPM:           withTPM,
			MinDiskSizeInMiB:  diskSizeMiB,
			DeviceReusePolicy: evetest.CreateFromScratchWithInstaller,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)

	// Management adapter only to begin with; the NI and app are added once the
	// cluster is up, as TestEVEUpgrade does for kubevirt.
	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// Widen the post-upgrade test window. evetest shortens it to 60s by
	// default to make upgrades finish faster, but this test has to observe
	// the device *inside* that window: the whole point of the reclaim gate
	// is that the old snapshots survive while a revert is still possible,
	// and at 60s the commit lands before the assertion can be made (which
	// is exactly how this test first failed). The framework only applies
	// its default when a test has not set the key itself.
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.MintimeUpdateSuccess,
		uint32(commitWindow/time.Second))
	devConfig.SetConfigProperties(cfgProps)

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

	clusterUpdates, stopClusterWatch := device.WatchClusterInfo()
	device.ApplyConfig(devConfig, true, true)
	t.Eventually(clusterUpdates, 20*time.Minute).Should(Receive(
		matchers.SatisfyPredicate("K3s node is ready", k3sNodeIsReady)))
	stopClusterWatch()
	evetest.Checkpoint("k3s-ready")

	niUUID := devConfig.AddNetworkInstance(snapshotterTestNI())
	appUUID := devConfig.AddApplication(
		snapshotterTestApp("snapshotter-app", niUUID, virtMode))

	// Under CONSTRAIN_PERSIST a second app is deployed but left deactivated,
	// so that the test controls the moment its first container is created --
	// and can therefore squeeze the disk exactly then. Squeezing before the
	// upgrade instead would starve the rootfs download and fail the upgrade
	// for an unrelated reason.
	//
	// Whether this ends up exercising a *conversion* (image already unpacked
	// for overlayfs by the initial release) or a first unpack depends on
	// whether EVE materialises volumes for an inactive app; the assertions
	// below hold either way, since both need room on /persist.
	var secondAppUUID uuid.UUID
	if constrainPersist {
		secondApp := snapshotterTestApp("snapshotter-app-2", niUUID, virtMode)
		secondApp.Activate = false
		secondAppUUID = devConfig.AddApplication(secondApp)
	}
	device.ApplyConfig(devConfig, false, false)

	// Generous because an eve-k container app does not simply start: the
	// CSI volume handler converts the image to a qcow2 and CDI uploads it
	// into a PVC before the pod is created, and a 10 minute budget has
	// been seen to expire mid-upload on a busy broker.
	device.WaitUntilAppIsRunning(appUUID, appStartBudget)

	// Liveness is "the container is emitting heartbeats *now*", not "the app
	// object says RUNNING". That distinction matters here: a pod stuck in
	// CrashLoopBackOff is still reported RUNNING by EVE, so the app state
	// alone would not catch a container that starts and immediately dies.
	expectAppAlive := func(what string, uuidToCheck uuid.UUID) {
		before := countHeartbeats(device, uuidToCheck)
		log.Infof("Verifying app %s is alive (%s), heartbeats so far=%d",
			uuidToCheck, what, before)
		t.Eventually(func() int {
			return countHeartbeats(device, uuidToCheck)
		}, 5*time.Minute, 10*time.Second).Should(BeNumerically(">", before),
			"app %s must still be emitting heartbeats (%s)", uuidToCheck, what)
	}
	expectAppAlive("before upgrade", appUUID)
	evetest.Checkpoint("app-running-pre-upgrade")

	// The whole test rests on the initial release having populated the
	// overlayfs store. If it did not, the upgrade has nothing to convert and a
	// pass would be meaningless -- so assert it rather than discovering later.
	overlayBefore, overlayCountBefore, err := snapshotterUsage(device, overlayfsSnapshotter)
	t.Expect(err).NotTo(HaveOccurred())
	erofsBefore, _, err := snapshotterUsage(device, erofsSnapshotter)
	t.Expect(err).NotTo(HaveOccurred())
	freeBefore, totalPersist, err := persistSpace(device)
	t.Expect(err).NotTo(HaveOccurred())
	log.Infof("pre-upgrade: overlayfs=%d bytes in %d snapshots, erofs=%d bytes, "+
		"/persist free=%d of %d", overlayBefore, overlayCountBefore, erofsBefore,
		freeBefore, totalPersist)
	t.Expect(overlayCountBefore).To(BeNumerically(">", 0),
		"the initial release must have unpacked images with the overlayfs "+
			"snapshotter, otherwise this test proves nothing")

	evetest.Checkpoint("pre-upgrade")

	device.UpgradeEVE(targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, false)
	evetest.Checkpoint("upgrade-complete")

	// Read the overlayfs store here, before waiting for anything else. The
	// revert-safety property only holds while the partition is under test,
	// and commitWindow is measured from the moment EVE enters TESTING --
	// not from when the node finishes coming back. Waiting for k3s and for
	// the app first burns well over ten minutes, by which point the commit
	// has landed, the reclaim has run and the store is legitimately empty.
	// That is how this assertion raced on its first two runs.
	overlayAfter, overlayCountAfter, err := snapshotterUsage(device, overlayfsSnapshotter)
	t.Expect(err).NotTo(HaveOccurred())
	log.Infof("just after upgrade: overlayfs=%d bytes in %d snapshots",
		overlayAfter, overlayCountAfter)

	// The old snapshots must survive while a revert is still possible: the
	// old rootfs runs the overlayfs snapshotter and needs exactly this state
	// to start these same apps. Reclaiming early would leave a revert that
	// boots into apps which cannot start -- the failure the A/B partition
	// scheme exists to prevent.
	//
	// Asserted on bytes rather than snapshot count, because the count is
	// *expected* to fall a little: kube-init re-registers the shipped image
	// catalog on the first boot of a new release, which re-points the previous
	// records and lets containerd's GC reap what they referenced. Measured on
	// this path, that removed 13 of 214 snapshots but only 897 KB of 4.56 GB
	// (~69 KB each -- empty and metadata-only layers). What must not disappear
	// is the user app's data, which is what the byte figure tracks.
	t.Expect(overlayAfter).To(BeNumerically(">=", overlayBefore/100*95),
		"overlayfs must still hold the app data a revert would need: "+
			"had %d bytes in %d snapshots, now %d bytes in %d",
		overlayBefore, overlayCountBefore, overlayAfter, overlayCountAfter)

	if !k3sNodeIsReady(device.GetClusterInfo()) {
		postUpdates, stopPostWatch := device.WatchClusterInfo()
		defer stopPostWatch()
		t.Eventually(postUpdates, 20*time.Minute).Should(Receive(
			matchers.SatisfyPredicate("K3s node is ready", k3sNodeIsReady)))
	}
	evetest.Checkpoint("k3s-ready-post-upgrade")

	// The first app must come back on the new snapshotter. For NOHYPER this is
	// the CRI fallback converting its image; for HVM it should be untouched.
	device.WaitUntilAppIsRunning(appUUID, appStartBudget)
	expectAppAlive("after upgrade", appUUID)

	erofsAfter, _, err := snapshotterUsage(device, erofsSnapshotter)
	t.Expect(err).NotTo(HaveOccurred())
	log.Infof("app running post-upgrade: erofs=%d bytes", erofsAfter)

	if virtMode == eveconfig.VmMode_NOHYPER {
		// A pod-backed app resolves its image through CRI, so the switch must
		// have produced erofs snapshots that did not exist before.
		t.Expect(erofsAfter).To(BeNumerically(">", erofsBefore),
			"the erofs store must have grown: a NOHYPER app's image is resolved "+
				"by CRI and so must have been converted")
	}

	evetest.Checkpoint("post-upgrade-verified")

	// Now the other half, which only becomes true later: once the
	// partition is committed, kube-init must actually delete what it just
	// proved it was keeping. The two assertions are the same property
	// observed either side of the commit -- keep it while a revert is
	// possible, drop it once it is not -- and asserting only the first
	// would let a reclaim that never runs pass silently, which is exactly
	// the bug that leaves several GB stranded on every upgraded device.
	t.Eventually(func() uint64 {
		got, count, err := snapshotterUsage(device, overlayfsSnapshotter)
		if err != nil {
			return overlayBefore
		}
		log.Infof("awaiting reclaim: overlayfs=%d bytes in %d snapshots", got, count)
		return got
	}, 20*time.Minute, 30*time.Second).Should(BeNumerically("<", overlayBefore/10),
		"kube-init must reclaim the superseded overlayfs snapshots once the "+
			"partition is committed (had %d bytes)", overlayBefore)
	evetest.Checkpoint("stale-snapshots-reclaimed")

	if verifyRollback {
		forceRollbackAndVerify(t, device, devConfig, appUUID,
			initialVersion, expectAppAlive)
	}

	if !constrainPersist {
		return
	}

	// Squeeze /persist below kubelet's hard eviction threshold. k3s ships
	// evictionHard nodefs.available=5%, so leaving less than that guarantees
	// the node reports DiskPressure and refuses to place the second app,
	// whatever the conversion itself would have cost.
	leaveFree := totalPersist / 100 // 1%, comfortably under the 5% floor
	claimed, err := fillPersist(device, leaveFree)
	t.Expect(err).NotTo(HaveOccurred())
	defer func() {
		if rmErr := removeBallast(device); rmErr != nil {
			log.Errorf("failed to remove ballast: %v", rmErr)
		}
	}()
	log.Infof("claimed %d bytes of /persist, leaving ~%d free", claimed, leaveFree)

	t.Eventually(func() bool {
		return nodeHasDiskPressure(device)
	}, 10*time.Minute, 15*time.Second).Should(BeTrue(),
		"kubelet must mark the node under disk pressure once /persist is "+
			"below its eviction threshold")
	evetest.Checkpoint("persist-constrained")

	// Activating the second app now forces its conversion with no room for it.
	device.ActivateApplication(secondAppUUID, false, 0)
	t.Consistently(func() eveinfo.ZSwState {
		// GetState is nil-safe and yields INVALID before the first publication.
		return device.GetAppInfo(secondAppUUID).GetState()
	}, 3*time.Minute, 15*time.Second).ShouldNot(Equal(eveinfo.ZSwState_RUNNING),
		"the second app must not reach RUNNING while /persist is below the "+
			"eviction threshold")
	evetest.Checkpoint("conversion-blocked")

	// Freeing the space must be enough on its own: kubelet retries, the
	// conversion completes and the app starts, with no operator action beyond
	// returning the disk. Note kubelet holds the DiskPressure taint for
	// evictionPressureTransitionPeriod (5m by default) after the condition
	// clears, so the budget here has to exceed that.
	t.Expect(removeBallast(device)).To(Succeed())
	device.WaitUntilAppIsRunning(secondAppUUID, 15*time.Minute)
	expectAppAlive("after freeing space", secondAppUUID)
	evetest.Checkpoint("recovery-verified")
}

// forceRollbackAndVerify covers the one destructive interaction the
// reclaim leaves open: once kube-init has deleted the superseded
// overlayfs snapshots, can an operator still roll back?
//
// EVE will not fall back on its own here -- the reclaim is gated on the
// partition being committed, and a committed partition is not reverted
// automatically. Only force.fallback.counter can do it, i.e. a deliberate
// operator action. The risk is therefore not silent breakage but a nasty
// surprise for whoever pulls that lever, so it is worth proving the old
// release re-unpacks what it needs from the content store rather than
// booting into apps that cannot start.
//
// Assumes the caller has already waited for the reclaim to happen.
func forceRollbackAndVerify(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, appUUID uuid.UUID,
	initialVersion string, expectAppAlive func(string, uuid.UUID)) {
	log := evetest.Logger()

	// Forcing the fallback reboots the device, which the framework audits
	// against declared reboots.
	device.ExpectReboots(1)
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.ForceFallbackCounter, 1)
	devConfig.SetConfigProperties(cfgProps)
	device.ApplyConfig(devConfig, false, false)
	log.Infof("forced fallback; expecting a revert to %s", initialVersion)

	t.Eventually(func() string {
		return activatedVersion(device)
	}, 20*time.Minute, 15*time.Second).Should(ContainSubstring(initialVersion),
		"the device must come back on the initial version after a forced fallback")
	evetest.Checkpoint("rolled-back")

	// The point of the whole exercise: the old release runs the overlayfs
	// snapshotter and its snapshots are gone, so it has to re-unpack from
	// the content store. That costs time, which is why the budget inside
	// expectAppAlive is generous, but it must not cost the app.
	expectAppAlive("after forced rollback", appUUID)
	evetest.Checkpoint("rollback-verified")
}
