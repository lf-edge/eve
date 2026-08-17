// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package resize_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	seedParamKey           = "VOLVERIFY_SEED"
	opsParamKey            = "VOLVERIFY_OPS"
	volverifyImageParamKey = "VOLVERIFY_IMAGE"

	// defaultVolverifyImage is where the volverify testapp is currently published.
	// The canonical lfedge/evetest-volverify repository does not exist yet; point
	// VOLVERIFY_IMAGE at it once it does.
	defaultVolverifyImage = "eriknordmark/evetest-volverify"

	// volverifyBlockSize is the on-disk block size of the verification pattern; it
	// must be identical for the write and the verify, which replay the same stream.
	volverifyBlockSize = 4096

	// volverifyCommitDir is volverify's on-volume committed-index directory. Its
	// presence identifies the data volume among the guest's block devices after
	// the conversion, when the volume is no longer mounted at its MountDir.
	volverifyCommitDir = ".vv-commit"

	fillPeakPctParamKey = "FILL_PEAK_PCT"
	fillKeepGiBParamKey = "FILL_KEEP_GIB"
	devsideOnlyParamKey = "DEVSIDE_ONLY"

	// Fill /persist to this percentage before the app is deployed, then trim back
	// to this many GiB once its volume is written. The peak has to sit well above
	// the shrink boundary (~38 GiB of a 61.7 GiB /persist on a 64 GiB boot disk) so
	// that the volume, allocated last, lands above it; the keep figure has to stay
	// under the resizer's own limit (~34 GiB) and leave room for EVE-k's images
	// (~8 GiB measured), while still leaving enough high-residing data that the
	// shrink runs long enough for the watchdog to interrupt it.
	defaultFillPeakPct = 90
	// Filler left after the trim. Small on purpose: the data volume alone keeps the
	// shrink slow enough to cut (measured: 5 cuts an iteration with the filler fully
	// removed), while every GiB kept here is a GiB EVE-k does not have for Longhorn.
	defaultFillKeepGiB = 2

	// stageCDataVolMiB is the data-volume size this test defaults to. The app
	// redeploy on EVE-k wedges in a Longhorn CSI CreateVolume race above ~256 MiB
	// (sweep: 100/256 MiB pass, >=512 MiB wedge), which would mask the corruption
	// result behind an unrelated failure, so stay under that ceiling by default.
	stageCDataVolMiB = 256
)

// TestAppVolumeShrinkCorruption checks whether the EVE-kvm→EVE-k offline boot-disk
// shrink corrupts an application data volume when it is interrupted part-way, and
// whether the corruption is detectable.
//
// It follows the same conversion sequence as TestKvmToKResize — that ordering and
// those readiness gates are load-bearing, see the comments there — and swaps the
// plain container app for volverify with a blank data volume. The volume is filled
// with a deterministic self-verifying pattern on EVE-kvm, the conversion relocates
// its blocks, and the pattern is re-verified on EVE-k.
//
// The fault is baked into the target EVE image rather than driven from here: the
// fork#7 stress build runs the offline resizer under a no-pet hardware watchdog
// whose timeout escalates with the retry count, so early attempts are cut mid
// shrink/grow and a later one converges. Run this against a non-stress build to
// get the same measurement with no fault injected.
//
// Parameters: as TestKvmToKResize, plus
//   - DATAVOL_MB: blank data-volume size (default 256; see stageCDataVolMiB).
//   - VOLVERIFY_SEED / VOLVERIFY_OPS: pattern seed and op count. The writer stops
//     early when the volume fills and reports the committed high-water mark, which
//     the verify is then held to.
//   - VOLVERIFY_IMAGE: Docker repo of the volverify testapp.
//
// The device is provisioned from the LIVE image; see
// TestAppVolumeShrinkCorruptionFromInstaller for the installer-written variant.
func TestAppVolumeShrinkCorruption(test *testing.T) {
	runAppVolumeShrinkCorruption(test, evetest.CreateFromScratchWithLiveImage)
}

// TestAppVolumeShrinkCorruptionFromInstaller takes the same corruption
// measurement against a boot disk the EVE installer laid out, instead of a
// pre-built live image written to the disk whole. An installer-written ESP carries
// a zero-length boot/.boot_repository, which the offline grow's FAT32 copy can only
// read with diskfs/go-diskfs#419 ("invalid start cluster: 0" without it); a
// live-image ESP has no such file, so only this variant covers that path.
//
// Same parameters as TestAppVolumeShrinkCorruption. Expect a longer setup: the
// installer VM boots and writes the disk before the test's own device is up.
func TestAppVolumeShrinkCorruptionFromInstaller(test *testing.T) {
	runAppVolumeShrinkCorruption(test, evetest.CreateFromScratchWithInstaller)
}

// runAppVolumeShrinkCorruption is the body shared by both variants.
// provisionPolicy selects how the device's boot disk comes into existence;
// everything after Setup is identical.
func runAppVolumeShrinkCorruption(test *testing.T,
	provisionPolicy evetest.ExistingEdgeDeviceReusePolicy) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
		evetest.DiskSizeMiBParameter(),
		evetest.TestParameterDefinition{
			Key:          ramSizeMiBParamKey,
			DefaultValue: uint32(minDeviceRAMInMiB),
			Description: evetest.TestParameterDescription{
				Summary: "Device RAM in MiB (EVE-k + Longhorn need >= 16 GiB)",
				Default: "16384 (16 GiB)",
			},
		},
		evetest.TestParameterDefinition{
			Key:          cpusParamKey,
			DefaultValue: uint8(minDeviceCPUs),
			Description: evetest.TestParameterDescription{
				Summary: "Device vCPUs (EVE-k + Longhorn need >= 8)",
				Default: "8",
			},
		},
		evetest.TestParameterDefinition{
			Key:          dataVolMiBParamKey,
			DefaultValue: uint32(stageCDataVolMiB),
			Description: evetest.TestParameterDescription{
				Summary: "App data-volume size in MiB (stay <= 256 to avoid the EVE-k CSI create race)",
				Default: "256",
			},
		},
		evetest.TestParameterDefinition{
			Key:          fillPeakPctParamKey,
			DefaultValue: uint32(defaultFillPeakPct),
			Description: evetest.TestParameterDescription{
				Summary: "Fill /persist to this % before deploying the app, so its volume lands in the blocks the shrink evacuates (0 disables)",
				Default: "90",
			},
		},
		evetest.TestParameterDefinition{
			Key:          fillKeepGiBParamKey,
			DefaultValue: uint32(defaultFillKeepGiB),
			Description: evetest.TestParameterDescription{
				Summary: "Leave this many GiB of filler after the volume is written; the rest is deleted so EVE-k has room. Measures the filler alone, not total /persist usage",
				Default: "2",
			},
		},
		evetest.TestParameterDefinition{
			Key:          devsideOnlyParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "Stop once the volume verdict is taken, skipping the app-side checks",
				Default: "false",
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
				Summary: "volverify op count; the writer stops early once the volume fills",
				Default: "200000",
			},
		},
		evetest.TestParameterDefinition{
			Key:          volverifyImageParamKey,
			DefaultValue: defaultVolverifyImage,
			Description: evetest.TestParameterDescription{
				Summary: "Docker repo of the volverify test app",
				Default: defaultVolverifyImage,
			},
		},
		evetest.TestParameterDefinition{
			Key:          initialEVEVersionParamKey,
			DefaultValue: "16.6.0",
			Description: evetest.TestParameterDescription{
				Summary: "SMALL-geometry EVE-kvm base to start on (pre-large-geometry)",
				Default: "16.6.0",
			},
		},
		evetest.TestParameterDefinition{
			Key:          initialHypervisorParamKey,
			DefaultValue: evetest.HypervisorKVM,
			Description: evetest.TestParameterDescription{
				Summary:       "Hypervisor of the initial (small) base",
				Default:       "kvm",
				AllowedValues: "kvm",
			},
		},
	)

	withTPM := evetest.GetTPMParameterValue()
	diskSizeMiB := evetest.GetDiskSizeMiBParameterValue()
	initialVersion := evetest.GetTestParameter[string](initialEVEVersionParamKey)
	if initialVersion == "" {
		evetestT.Fatalf("%s%s is required", constants.EnvPrefix, initialEVEVersionParamKey)
	}
	initialHypervisor := evetest.GetTestParameter[evetest.Hypervisor](initialHypervisorParamKey)
	convVersion := evetest.GetEVEVersionParameterValue()
	targetHypervisor := evetest.GetHypervisorParameterValue()

	effectiveDiskMiB := diskSizeMiB
	if effectiveDiskMiB == 0 {
		effectiveDiskMiB = constants.DefaultEVEDeviceDiskSizeInMiB
	}
	if effectiveDiskMiB < constants.DefaultEVEDeviceDiskSizeInMiB {
		evetestT.Fatalf("boot disk %d MiB is too small for the kvm→k conversion; "+
			"need at least %d MiB (64 GiB) — set DISK_SIZE_MB accordingly",
			effectiveDiskMiB, constants.DefaultEVEDeviceDiskSizeInMiB)
	}
	effectiveRAMMiB := evetest.GetTestParameter[uint32](ramSizeMiBParamKey)
	if effectiveRAMMiB == 0 {
		effectiveRAMMiB = constants.DefaultEVEDeviceRAMInMiB
	}
	if effectiveRAMMiB < minDeviceRAMInMiB {
		evetestT.Fatalf("device RAM %d MiB is too small for the kvm→k conversion "+
			"(EVE-k + Longhorn); need at least %d MiB (16 GiB) — set RAM_SIZE_MB accordingly",
			effectiveRAMMiB, minDeviceRAMInMiB)
	}
	effectiveCPUs := evetest.GetTestParameter[uint8](cpusParamKey)
	if effectiveCPUs == 0 {
		effectiveCPUs = constants.DefaultEVEDeviceCPUs
	}
	if effectiveCPUs < minDeviceCPUs {
		evetestT.Fatalf("device vCPUs %d is too few for the kvm→k conversion "+
			"(EVE-k + Longhorn); need at least %d — set CPUS accordingly",
			effectiveCPUs, minDeviceCPUs)
	}
	dataVolMiB := evetest.GetTestParameter[uint32](dataVolMiBParamKey)
	dataVolBytes := uint64(dataVolMiB) * evetest.MiB
	seed := evetest.GetTestParameter[uint64](seedParamKey)
	ops := evetest.GetTestParameter[uint64](opsParamKey)
	volverifyImage := evetest.GetTestParameter[string](volverifyImageParamKey)
	fillPeakPct := evetest.GetTestParameter[uint32](fillPeakPctParamKey)
	fillKeepGiB := evetest.GetTestParameter[uint32](fillKeepGiBParamKey)
	// 0 is meaningful now that the budget counts only the filler: it means delete all
	// of it once the volume is placed, which is the most headroom EVE-k can get.

	// Cap a single file at a sixteenth of the volume. volverify's default large-file
	// bound is 256 MiB, which on a volume this size would let one op consume the
	// whole thing and leave the pattern with almost no files to place — and so
	// almost no coverage of the relocated block range.
	maxBlocks := uint64(dataVolMiB) * evetest.MiB / 16 / volverifyBlockSize
	if maxBlocks < 256 {
		maxBlocks = 256
	}
	volverifyArgs := fmt.Sprintf("--dir %s --seed %d --ops %d --block-size %d --max-blocks %d",
		dataMountDir, seed, ops, volverifyBlockSize, maxBlocks)

	const devName = "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithEVEVersion:    initialVersion,
			WithHypervisor:    initialHypervisor,
			WithTPM:           withTPM,
			MinDiskSizeInMiB:  diskSizeMiB,
			MinRAMInMiB:       effectiveRAMMiB,
			MinCPUs:           effectiveCPUs,
			DeviceReusePolicy: provisionPolicy,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	log.Infof("volverify app %s:1.0 on a %d MiB data volume (max file %d blocks)",
		volverifyImage, dataVolMiB, maxBlocks)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	if fillPeakPct > 0 {
		// The volume is deliberately created on a nearly-full /persist, which EVE
		// would otherwise refuse: volumemgr declines a volume whose size exceeds the
		// remaining space, counting a dom0 reservation of 20% on top. The fill is
		// transient and trimmed away before the conversion, so the check is what is
		// wrong here, not the request.
		devConfig.ConfigItems = append(devConfig.ConfigItems, &eveconfig.ConfigItem{
			Key:   string(pillartypes.IgnoreDiskCheckForApps),
			Value: "true",
		})
	}
	networkUUID := devConfig.AddNetwork(evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "eth0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   networkUUID,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, false, false)

	// The conversion is several reboots plus an EVE-k bring-up and runs close to
	// the framework's default upgrade budget, so give it room; without this a
	// conversion that is merely slow is reported as a failed one.
	device.SetUpgradeTimeout(45 * time.Minute)

	log.Infof("baseline: asserting SMALL boot-disk geometry")
	assertSmallGeometry(t, device)
	assertWatchdogDriverBound(t, device)
	evetest.Checkpoint("baseline-small")

	log.Infof("kvm→kvm hop: upgrading to the conversion-capable build %s (kvm)", convVersion)
	device.UpgradeEVE(convVersion, evetest.HypervisorKVM, evetest.BaseOSDatastoreHTTP, true, false)
	assertSmallGeometry(t, device)
	assertCheckDecision(t, device, "shrink")
	evetest.Checkpoint("kvm-hop-done")

	log.Infof("settling vault to a local TPM unlock")
	settleVaultLocal(t, device)
	evetest.Checkpoint("vault-settled")

	// Fill /persist before the app exists, so its data volume is allocated at the
	// top of the filesystem — inside the range the shrink has to evacuate. On an
	// almost-empty /persist the volume lands low, the shrink finishes in about a
	// second, and the watchdog only ever interrupts the grow.
	if fillPeakPct > 0 {
		log.Infof("filling /persist to %d%% so the app's volume lands in the shrink's evacuation zone", fillPeakPct)
		fillPersistToPct(t, device, int(fillPeakPct), dataVolMiB)
		evetest.Checkpoint("persist-filled")
	}

	// Switch (L2-bridged) NI: the carried app gets its own DHCP address on the eth0
	// segment and is reached directly. A local NI does not reconverge onto the
	// kubevirt VMI after the conversion (verified stuck, not slow).
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	// Encrypted, not clear text: this test drives a conversion across a vault
	// transition, so the data volume must exercise the vault-dependent path.
	dataVolUUID := devConfig.AddBlankVolume("appvolshrink-data0", dataVolBytes, false)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:        "volverify-app",
		Activate:           true,
		Image:              evetest.DockerContainer{ImageName: volverifyImage, Tag: "1.0"},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
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
		Mounts: []evetest.MountConfig{
			{VolumeUUID: dataVolUUID, MountDir: dataMountDir},
		},
	})
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	appAuth := evetest.UsernamePasswordAuth{Username: appSSHUser, Password: appSSHPassword}
	assertAppSSH(t, device, appUUID, appAuth)
	captureAppNet(device, "pre-conversion EVE-kvm (SSH OK)")
	captureLostFound(device, "pre-conversion")

	// Fill the volume on EVE-kvm, where the runx shim has formatted and mounted it
	// at MountDir. The writer stops at Ops or when the volume fills, whichever comes
	// first, and reports the committed high-water mark the verify is held to.
	log.Infof("pre-conversion: filling the data volume with the volverify pattern")
	writtenCommitted := writeVolverifyPattern(t, device, appUUID, appAuth, volverifyArgs)
	log.Infof("volume filled through committed op %d", writtenCommitted)

	// Free the low blocks now that the volume is placed. This is what lets the
	// shrink fit at all, and it leaves the relocation work — including the volume —
	// concentrated above the boundary.
	if fillPeakPct > 0 {
		log.Infof("trimming the filler back to %d GiB (lowest blocks first)", fillKeepGiB)
		trimPersistToGiB(t, device, int(fillKeepGiB))
		log.Infof("asserting the data volume actually lies above the shrink boundary")
		assertVolumeAboveShrinkBoundary(t, device)
		evetest.Checkpoint("volume-placed-high")
	}
	capturePersist(device, "pre-conversion EVE-kvm (volume filled)")
	evetest.Checkpoint("volume-filled")

	// EVE's post-resize check hashes each volume against a pre-resize manifest and
	// DELETES any that mismatches, so a torn volume is gone before this test can look
	// at it — which is why nine 8 GiB corruptions were recorded as "nothing to
	// measure". The marker makes baseosmgr quarantine it as <name>.corrupt instead,
	// leaving the damaged bytes for fsck and volverify to characterize.
	markerOut, _, markerErr := device.RunShellScript(
		`eve exec pillar touch /persist/volmanifest-keep-corrupt`, eveShellTimeout, 0)
	t.Expect(markerErr).NotTo(HaveOccurred(),
		"could not arm the corrupt-volume quarantine marker:\n%s", markerOut)
	log.Infof("armed /persist/volmanifest-keep-corrupt so a torn volume is kept, not deleted")

	log.Infof("kvm→k conversion: upgrading to %s (%s) — triggers the offline shrink+grow", convVersion, targetHypervisor)
	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	// Do not wait for EVE to commit the new partition. Committing is a trial
	// period that runs long after the device is already up on the target, and
	// nothing this test asserts depends on it: the geometry is grown by then and
	// what matters is whether the app and its volume come back. Waiting for it
	// only delays — and can fail — a conversion that is doing fine. The commit is
	// observed at the end instead, where it costs nothing.
	device.UpgradeEVE(convVersion, targetHypervisor, evetest.BaseOSDatastoreHTTP, false, false)
	waitDeviceOnTarget(t, device, targetHypervisor, 45*time.Minute)
	conversionOK = true
	device.ExpectAdditionalReboots(1)
	captureResizeEvidence(device)
	captureLostFound(device, "post-conversion")
	evetest.Checkpoint("conversion-complete")

	assertGrownShrink(t, device)
	evetest.Checkpoint("geometry-grown")

	stopPersistSampler := startPersistSampler(device, 45*time.Second)
	defer stopPersistSampler()

	// Take the verdict here, before Longhorn can ingest the volume and long before
	// the app is asked to boot. This is the only reading that survives the
	// post-conversion app wedge, which has cost every verdict it has hit.
	verifyRelocatedVolumeOnDevice(t, device, dataVolMiB, seed, ops, maxBlocks, writtenCommitted)

	// The volume verdict is complete here, about 32 minutes into a run whose
	// remaining 48 minutes are the app-side checks. At data-volume sizes where the
	// post-conversion app reliably wedges, those 48 minutes re-derive a known
	// failure, so a corruption soak can stop here and collect roughly two and a
	// half times as many volume verdicts per day.
	//
	// This forfeits the wedge diagnostics, which are produced by the app-failure
	// path and nowhere else: leave it off when the run is meant to investigate why
	// the app does not come back.
	if evetest.GetTestParameter[bool](devsideOnlyParamKey) {
		log.Infof("DEVSIDE_ONLY: volume verdict taken; skipping the app-side checks")
		evetest.Checkpoint("devside-only-complete")
		return
	}

	if targetHypervisor == evetest.HypervisorKubevirt {
		log.Infof("(a) waiting for k3s node ready")
		if !isK3sReady(device.GetClusterInfo()) {
			clusterUpdates, stop := device.WatchClusterInfo()
			defer stop()
			t.Eventually(clusterUpdates, 30*time.Minute).Should(Receive(
				matchers.SatisfyPredicate("K3s node is ready", isK3sReady)))
		}
		log.Infof("(b) waiting for volumemgr Initialized")
		waitVolumemgrReady(t, device)
		log.Infof("(c) waiting for longhorn StorageClass ready")
		waitLonghornSC(t, device)
	}
	// Registered above the wait, not below it: the app failing to reach RUNNING is the
	// most common way this test fails, and a defer set up after the wait never runs on
	// that path — which is exactly where the wedge evidence is needed.
	appRunning := false
	appSSHOK := false
	defer func() {
		if appSSHOK {
			return
		}
		stage := "never reached RUNNING"
		if appRunning {
			stage = "RUNNING but unreachable"
		}
		captureAppNet(device, "post-conversion EVE-k (app "+stage+")")
		captureAppNetFailure(device, appUUID)
	}()
	log.Infof("(d) waiting for the app to reach RUNNING on the target")
	// Five seconds, not thirty: a failing import keeps its upload pod for the whole
	// recovery budget, but a successful one finishes inside a minute and CDI deletes
	// the pod immediately, so a coarse interval catches the failures and misses
	// exactly the successes this exists to explain.
	stopCDISampler := startCDISampler(device, 5*time.Second)
	waitAppRunningWithPVCRecovery(t, device, appUUID, dataVolMiB)
	stopCDISampler()
	appRunning = true
	log.Infof("(e0) post-conversion: waiting up to 10m for the app to report a routable IPv4")
	waitAppHasRoutableIPv4(t, device, appUUID, 10*time.Minute)
	log.Infof("(e) post-conversion: app must be SSH-reachable")
	assertAppSSH(t, device, appUUID, appAuth)
	appSSHOK = true

	log.Infof("(f) post-conversion: re-verifying the data-volume pattern")
	captureVolManifest(device)

	// Check the filesystem before anything mounts it, so the structural verdict can
	// be set against the content verdict below. A mount would replay the journal and
	// could repair what is being measured.
	volDev := findDataVolumeDevice(t, device, appUUID, appAuth, dataVolMiB)
	fsckRC, fsckOut := fsckDataVolume(device, appUUID, appAuth, volDev)

	state := mountDataVolumeRO(t, device, appUUID, appAuth, dataMountDir)
	if state == volumeStateBlank {
		recordVolumeOutcome(dataVolMiB, state, fsckRC, "", fsckOut, -1, "")
		// The pattern is gone but the volume is intact and empty: either the
		// post-resize manifest check found the volume torn and removed it, so EVE
		// recreated it blank, or the shrink destroyed the filesystem outright. The
		// manifest capture above says which. Either way nothing corrupt is being
		// served to the app, so this is not the failure this test gates on.
		log.Errorf("data volume came back BLANK — the pattern did not survive; " +
			"check the volume-manifest capture for whether the detector removed it")
		evetest.Checkpoint("volume-recreated-blank")
		return
	}

	report := verifyVolverifyPattern(t, device, appUUID, appAuth, volverifyArgs, writtenCommitted)
	log.Infof("volverify report:\n%s", report)

	// Content is captured, so the filesystem can now be checked with the journal
	// replayed — the only reading that distinguishes real damage from the stale
	// accounting an unclean unmount leaves behind.
	log.Infof("re-checking the volume filesystem with the journal replayed")
	replayRC, replayOut := fsckDataVolumeAfterVerify(device, appUUID, appAuth, volDev, dataMountDir)
	recordVolumeOutcome(dataVolMiB, state, fsckRC, report, fsckOut, replayRC, replayOut)

	// present-corrupt is the silent case: a torn-but-present volume that EVE would
	// serve to the app as-is, invisible to fsck and to qemu-img. orphaned and lost
	// files are the recoverable modes — EVE recreates a missing volume file blank —
	// so surface them but do not fail on them.
	presentCorrupt := reportField(report, "present-corrupt")
	t.Expect(presentCorrupt).To(BeNumerically(">=", 0),
		"could not parse present-corrupt from the volverify report:\n%s", report)
	t.Expect(presentCorrupt).To(Equal(0),
		"data volume served corrupt-but-present after the interrupted shrink:\n%s", report)
	evetest.Checkpoint("volume-verified")

	// Whether EVE committed the new partition is recorded rather than asserted:
	// the volume result above does not depend on it, but a target still sitting at
	// "inprogress" here means the trial period had not finished, and one that
	// reverted would explain an otherwise puzzling later failure.
	logPartitionState(device)

	// The data volume is independent of the app and outlives it, so the app
	// must go first (DeleteVolume refuses while a VolumeRef still points at
	// it). Tests cloned from this one inherit the full lifecycle.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	devConfig.DeleteVolume(dataVolUUID)
	device.ApplyConfig(devConfig, false, false)
}

// devsideVerifyScript checks the carried-over volume on the device itself.
//
// upgradeconverter moves the pre-conversion app volumes out of
// /persist/vault/volumes — which Longhorn must own on EVE-k — into
// /persist/vault/volumes-kvm, and volumemgr rolls them into PVCs lazily once the
// cluster is up. In between, and for as long as that import keeps failing, the file
// sits there as a plain ext4 image holding the volume exactly as the shrink left it.
// The data-volume path in csihandler returns on a failed RolloutDiskToPVC without
// removing the source, so a wedged import preserves it rather than consuming it.
//
// volverify does not have to be shipped in: containerd has already unpacked the app
// image, so the same statically-linked binary the app would run is on disk. Args:
// seed, ops, max-blocks, expect-committed.
const devsideVerifyScript = `set -u
# Both artifacts appear on their own schedule after the conversion: containerd unpacks
# the app image, and the post-vault phase of upgradeconverter moves the volumes. The
# device reports itself on the target before either is guaranteed, so wait for both
# together — checking one first and exiting early skips the wait on the other.
# Encrypted volumes land in vault/volumes-kvm; clear ones stay in clear/volumes, which
# is where kvmMigratedSourcePath looks for them.
VV=""
F=""
i=0
while [ "$i" -lt 60 ]; do
  [ -n "$VV" ] || VV=$(find /persist/vault/containerd -path '*usr/local/bin/volverify' 2>/dev/null | head -1)
  # A *.raw.corrupt is EVE's post-resize hash check having caught the interrupted
  # shrink tearing this volume, quarantined instead of deleted (see the marker this
  # test drops before the conversion). That is the finding, not a missing volume:
  # verify it exactly like an intact one, so fsck and volverify can say whether the
  # damage is structurally visible or silent.
  # Quarantined copies are listed first: a *.raw.corrupt IS the finding, so picking
  # an intact sibling ahead of it would report a clean verdict for a conversion that
  # had already been caught tearing a volume.
  [ -n "$F" ] || F=$(ls /persist/vault/volumes-kvm/*.raw.corrupt /persist/clear/volumes/*.raw.corrupt \
      /persist/vault/volumes-kvm/*.raw /persist/clear/volumes/*.raw \
      2>/dev/null | head -1)
  [ -n "$VV" ] && [ -n "$F" ] && break
  i=$((i + 1)); sleep 10
done
echo "DEVSIDE-WAITED=${i}0s"
# Giving up is only actionable with the layout that defeated the search: an 8 GiB run
# put ~8 GiB somewhere under /persist/vault inside the wait window, yet matched nothing
# here, and du -d1 could not say where. List the candidates so the next occurrence
# reports the actual path instead of only that it is not the expected one.
if [ -z "$VV" ] || [ -z "$F" ]; then
  echo "DEVSIDE-LAYOUT:"
  for d in /persist/vault/volumes-kvm /persist/vault/volumes /persist/clear/volumes; do
    echo "  $d:"
    ls -l "$d" 2>&1
  done
  echo "  largest under /persist/vault:"
  du -x -B1 -d2 /persist/vault 2>/dev/null | sort -rn | head -12
fi
[ -n "$VV" ] || { echo "DEVSIDE=no-volverify"; exit 0; }
[ -n "$F" ] || { echo "DEVSIDE=no-relocated-volume"; exit 0; }
echo "DEVSIDE-FILE=$F size=$(stat -c %s "$F")"
# Whether the selection above had a choice at all: >1 means head -1 discarded a
# candidate and the verdict may describe the wrong volume.
echo "DEVSIDE-CANDIDATES=$(ls /persist/vault/volumes-kvm/*.raw.corrupt \
    /persist/clear/volumes/*.raw.corrupt /persist/vault/volumes-kvm/*.raw \
    /persist/clear/volumes/*.raw 2>/dev/null | wc -l)"
# Read the filesystem before anything mounts it: a mount replays the journal and can
# repair the very damage being measured.
e2fsck -fn "$F" > /tmp/dsfsck.out 2>&1
echo "DEVSIDE-FSCK-RC=$?"
sed -n '1,40p' /tmp/dsfsck.out
mkdir -p /tmp/dsmnt
L=$(losetup -r -f --show "$F" 2>&1) || { echo "DEVSIDE=losetup-failed:$L"; exit 0; }
if mount -o ro,noload "$L" /tmp/dsmnt 2>&1; then
  # Redirect rather than pipe, so the status is volverify's and not the pager's.
  "$VV" verify --dir /tmp/dsmnt --seed "$1" --ops "$2" \
      --block-size 4096 --max-blocks "$3" --expect-committed "$4" > /tmp/dsvv.out 2>&1
  echo "DEVSIDE-VERIFY-RC=$?"
  grep -aE 'committed=|verify:' /tmp/dsvv.out | tail -4
  umount /tmp/dsmnt || true
else
  echo "DEVSIDE=mount-failed"
fi
losetup -d "$L" || true
rm -rf /tmp/dsmnt /tmp/dsvv.out /tmp/dsfsck.out`

// verifyRelocatedVolumeOnDevice records the volume verdict without involving the app,
// Longhorn, CDI or a completed PVC import — see devsideVerifyScript.
//
// Not finding anything to check is non-fatal ONLY when the app-side verdict is still to
// come: on a clear-volume or ZFS layout the file may not be where this looks. Under
// DEVSIDE_ONLY there is no second verdict, so the same silence means the iteration
// measured nothing — and a run that measures nothing must not report PASS, or a soak
// banks clean-looking rows that never examined a volume.
// A volume it does read and find corrupt fails the test either way; that is the finding
// being hunted.
func verifyRelocatedVolumeOnDevice(t Gomega, device *evetest.EdgeDevice, dataVolMiB uint32,
	seed, ops uint64, maxBlocks uint64, expectCommitted int) {
	log := evetest.Logger()
	out, err := runOnEVEScript(device, devsideVerifyScript, 15*time.Minute,
		fmt.Sprintf("%d", seed), fmt.Sprintf("%d", ops),
		fmt.Sprintf("%d", maxBlocks), fmt.Sprintf("%d", expectCommitted))
	if err != nil {
		log.Errorf("device-side volume verify could not run:\n%s", out)
		return
	}
	log.Infof("device-side volume verify:\n%s", strings.TrimSpace(out))

	if i := strings.Index(out, "DEVSIDE="); i >= 0 {
		var reason string
		fmt.Sscanf(out[i:], "DEVSIDE=%s", &reason)
		log.Errorf("device-side volume verify skipped: %s", reason)
		// The volume was present and written before the conversion, so its absence
		// afterwards is upgradeconverter's account to give: stageKvmVolumes logs
		// "relocated N, skipped M" per run, plus a line for each entry it declined to
		// move and for the sentinel short-circuit. Without this the layout dump can
		// only say the volume is not there, not whether it was moved elsewhere,
		// skipped, or never seen.
		for _, p := range []struct{ what, pipeline string }{
			{"upgradeconverter volume relocation", "grep -a stageKvmVolumes | tail -20"},
			{"upgradeconverter kube entry", "grep -a relocateKvmVolumesForKube | tail -10"},
			// stageKvmVolumes reports relocating everything it finds, so the volume is
			// already gone when it runs. Grep for the file itself rather than any one
			// agent's wording: whoever removed it had to name it.
			{"every mention of a volume file", `grep -a "#0.raw" | tail -40`},
			{"volumemgr delete path", `grep -a volumemgr | grep -aiE "delete|destroy|purge|remov" | tail -30`},
		} {
			o, _, e := device.RunShellScript(newlogProbe(p.pipeline), 90*time.Second, 0)
			log.Errorf("[devside-miss] %s:\n%s(err=%v)", p.what, strings.TrimSpace(o), e)
		}
		t.Expect(evetest.GetTestParameter[bool](devsideOnlyParamKey)).To(BeFalse(),
			"DEVSIDE_ONLY run banked no volume verdict (%s): this iteration measured "+
				"nothing about shrink corruption:\n%s", reason, out)
		return
	}

	fsckRC, verifyRC := -1, -1
	if i := strings.Index(out, "DEVSIDE-FSCK-RC="); i >= 0 {
		fmt.Sscanf(out[i:], "DEVSIDE-FSCK-RC=%d", &fsckRC)
	}
	if i := strings.Index(out, "DEVSIDE-VERIFY-RC="); i >= 0 {
		fmt.Sscanf(out[i:], "DEVSIDE-VERIFY-RC=%d", &verifyRC)
	}
	// eve-detected records whether EVE's own post-resize hash check had already
	// condemned this volume: the file it hands us is then the quarantined copy. A
	// clean volverify on such a file would mean the two checks disagree, so the
	// distinction has to survive into the row rather than being inferred from a path.
	eveDetected := strings.Contains(out, ".raw"+".corrupt")
	evetest.Logger().Infof("[DEVICE-VOLUME-OUTCOME] datavolMiB=%d app-independent=true "+
		"eve-detected-corrupt=%t fsck-rc=%d structural-damage=%t verify-rc=%d verify=[%s]",
		dataVolMiB, eveDetected, fsckRC, fsckFoundStructuralDamage(out), verifyRC,
		volverifySummary(out))
	evetest.Checkpoint("devside-volume-verified")

	// volverify exits non-zero on ANY anomaly, so its status is the catch-all: a
	// verdict class not named individually below still fails the run.
	t.Expect(verifyRC).To(BeNumerically("==", 0),
		"volverify rejected the relocated volume (DEVSIDE-VERIFY-RC=%d):\n%s", verifyRC, out)

	presentCorrupt := reportField(out, "present-corrupt")
	// An absent field reads as -1, which would satisfy the bound below and bank a
	// clean-looking row for a run that measured nothing.
	t.Expect(presentCorrupt).To(BeNumerically(">=", 0),
		"volverify produced no present-corrupt count, so this iteration measured "+
			"nothing about shrink corruption:\n%s", out)
	t.Expect(presentCorrupt).To(BeNumerically("<=", 0),
		"the relocated pre-conversion volume is present but CORRUPT (present-corrupt=%d) — "+
			"the interrupted shrink tore data the filesystem check cannot see:\n%s",
		presentCorrupt, out)
	// Losing a committed file outright, or resurrecting a committed-deleted one, is
	// data loss just as much as torn content. Orphaned is excluded: recovery into
	// lost+found self-heals to a blank/content-tree recreate.
	for _, key := range []string{"lost", "resurrected"} {
		n := reportField(out, key)
		t.Expect(n).To(BeNumerically("<=", 0),
			"the relocated pre-conversion volume lost committed data (%s=%d):\n%s",
			key, n, out)
	}
}

// volverifySummary pulls volverify's one-line tally out of the device-side output so
// the outcome record carries the counts rather than the whole transcript.
func volverifySummary(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "committed=") && strings.Contains(line, "ok=") {
			return strings.TrimSpace(line)
		}
	}
	return "no-summary"
}

// writeVolverifyPattern fills the app's data volume with the deterministic pattern
// and returns the committed op index the writer reached. It requires the volume to
// be mounted at its MountDir, which the runx shim does on EVE-kvm.
func writeVolverifyPattern(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	auth evetest.AuthMethod, args string) int {
	script := fmt.Sprintf(
		"grep -q ' %s ' /proc/mounts || { echo NOT-MOUNTED; cat /proc/mounts; exit 1; }; "+
			"volverify write %s && sync", dataMountDir, args)
	committed := -1
	t.Eventually(func(t Gomega) {
		stdout, stderr, err := device.RunShellScriptInsideApp(appUUID, auth, script, 60*time.Minute, 0)
		t.Expect(err).NotTo(HaveOccurred(), "volverify write failed:\n%s%s", stdout, stderr)
		committed = reportField(stdout, "committed")
		t.Expect(committed).To(BeNumerically(">=", 0),
			"volverify write reported no committed index:\n%s", stdout)
	}, 65*time.Minute, 10*time.Second).Should(Succeed())
	return committed
}

// Outcomes of locating the app's data volume after the conversion.
const (
	volumeStatePattern = "PATTERN" // mounted and still carrying the volverify pattern
	volumeStateBlank   = "BLANK"   // the volume exists but the pattern is gone
)

// recordVolumeOutcome emits one line pairing what the filesystem check concluded
// with what the content verify found, which is the row a soak accumulates over
// many iterations. Read on its own, either verdict is ambiguous; together they say
// whether corruption occurred and whether a structural check would have noticed.
//
// The line is deliberately single and grep-friendly, since the point is to compare
// hundreds of these rather than to read one.
func recordVolumeOutcome(dataVolMiB uint32, state string, fsckRC int, report, fsckOut string,
	replayRC int, replayOut string) {
	// Before the journal is replayed, count mismatches are expected and mean
	// nothing; after it, anything found is real.
	dirty := fmt.Sprintf("rc=%d", fsckRC)
	switch fsckRC {
	case 0:
		dirty += "(clean)"
	case 4:
		dirty += "(errors-unreplayed)"
	}
	if strings.Contains(fsckOut, "skipping journal recovery") {
		dirty += "+journal-not-replayed"
	}
	replayed := "not-run"
	if replayRC >= 0 {
		replayed = fmt.Sprintf("rc=%d", replayRC)
		switch replayRC {
		case 0:
			replayed += "(clean)"
		case 1, 2:
			// A non-zero status is not by itself damage. A volume captured while it
			// was still being written to has stale superblock counters, an orphan
			// flag and extent trees e2fsck would rather rewrite, and it repairs all
			// of those on every run while saying nothing about the data. Only
			// findings that imply lost, crossed or unreachable blocks mean the
			// interrupted shrink actually hurt the volume.
			if fsckFoundStructuralDamage(replayOut) {
				replayed += "(STRUCTURAL-DAMAGE)"
			} else {
				replayed += "(accounting-only)"
			}
		case 4:
			replayed += "(errors-left)"
		}
		if strings.Contains(replayOut, "FILE SYSTEM WAS MODIFIED") {
			replayed += "+modified"
		}
	}
	if report == "" {
		report = "no-content-verify"
	}
	evetest.Logger().Errorf("[VOLUME-OUTCOME] datavolMiB=%d state=%s fsck-dirty=%s fsck-replayed=%s verify=[%s]",
		dataVolMiB, state, dirty, replayed, strings.ReplaceAll(report, "\n", " | "))
}

// fsckDataVolume runs a read-only filesystem check on the data volume's block
// device and returns e2fsck's exit status and output.
//
// This is the counterpart to the content verify, and the pair is the point: a
// structural check is blind to data blocks that were relocated wrongly but left
// self-consistent, so the interesting result is fsck reporting a clean filesystem
// while the content verify finds files quietly full of zeroes. Recording only one
// of the two would lose exactly the comparison this test exists to make.
//
// It must run before anything mounts the volume — a mount can replay the journal
// and repair the very damage being measured — and with -n so the check itself
// changes nothing. Exit status 0 means fsck saw a clean filesystem; 4 means it
// found errors it was not allowed to fix.
func fsckDataVolume(device *evetest.EdgeDevice, appUUID uuid.UUID,
	auth evetest.AuthMethod, dev string) (int, string) {
	script := fmt.Sprintf("e2fsck -fn %s 2>&1; echo FSCK_RC=$?", dev)
	out, _, _ := device.RunShellScriptInsideApp(appUUID, auth, script, 20*time.Minute, 0)
	rc := -1
	if i := strings.Index(out, "FSCK_RC="); i >= 0 {
		fmt.Sscanf(out[i:], "FSCK_RC=%d", &rc)
	}
	evetest.Logger().Errorf("[fsck] %s exit=%d\n%s", dev, rc, strings.TrimSpace(out))
	return rc, strings.TrimSpace(out)
}

// fsckFoundStructuralDamage reports whether an e2fsck transcript contains findings
// that mean blocks or inodes were actually lost, crossed or orphaned — as opposed
// to the accounting an unclean capture always produces.
//
// Repairing stale free-block and free-inode counters, clearing the orphan-file
// feature flag and narrowing extent trees all happen on a volume that was simply
// snapshotted mid-write; treating those as damage would mark every iteration of a
// soak as a hit and bury the real signal. The patterns below are the ones that
// imply data actually went missing.
func fsckFoundStructuralDamage(out string) bool {
	damage := []string{
		"Unattached inode",
		"Unattached zero-length inode",
		"multiply-claimed",
		"Multiply-claimed",
		"illegal block",
		"Illegal block",
		"illegal indirect block",
		"lost+found",
		"Inode bitmap differences",
		"Block bitmap differences",
		"Directory inode",
		"has an incorrect filesize",
		"Entry '",
		"deleted/unused inode",
		"root inode is not a directory",
		"Corrupt",
		"corrupted",
	}
	for _, d := range damage {
		if strings.Contains(out, d) {
			return true
		}
	}
	return false
}

// fsckDataVolumeAfterVerify unmounts the volume and checks it again, this time
// letting e2fsck replay the journal and repair what it finds.
//
// The read-only check taken before the mount cannot distinguish real damage from
// bookkeeping: the volume was never cleanly unmounted, so its journal is unreplayed
// and the superblock's free counts necessarily disagree with the disk. That check
// therefore reports errors on every run and says nothing on its own. Replaying
// first removes that noise, so whatever is still wrong here is genuine — at the
// cost of modifying the filesystem, which is why it runs only after the content
// verify has already been recorded.
//
// Exit 0 means clean once the journal was applied; 1 means e2fsck found and fixed
// real structural damage.
func fsckDataVolumeAfterVerify(device *evetest.EdgeDevice, appUUID uuid.UUID,
	auth evetest.AuthMethod, dev, mountDir string) (int, string) {
	script := fmt.Sprintf(
		"umount %s 2>/dev/null; e2fsck -fy %s 2>&1; echo FSCK_RC=$?", mountDir, dev)
	out, _, _ := device.RunShellScriptInsideApp(appUUID, auth, script, 20*time.Minute, 0)
	rc := -1
	if i := strings.Index(out, "FSCK_RC="); i >= 0 {
		fmt.Sscanf(out[i:], "FSCK_RC=%d", &rc)
	}
	evetest.Logger().Errorf("[fsck-replayed] %s exit=%d\n%s", dev, rc, strings.TrimSpace(out))
	return rc, strings.TrimSpace(out)
}

// findDataVolumeDevice returns the guest block device holding the app's data
// volume, identified by size rather than by mounting anything, so the caller can
// check the filesystem before it is touched. The app's own root disk differs in
// size by orders of magnitude, so a size match is unambiguous here.
func findDataVolumeDevice(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	auth evetest.AuthMethod, dataVolMiB uint32) string {
	script := fmt.Sprintf(`set -u
WANT=%d
for d in /dev/vd[b-z] /dev/sd[b-z]; do
  [ -b "$d" ] || continue
  sz=$(blockdev --getsize64 "$d" 2>/dev/null) || continue
  mib=$(( sz / 1048576 ))
  echo "CAND $d ${mib}MiB"
  diff=$(( mib - WANT )); [ "$diff" -lt 0 ] && diff=$(( -diff ))
  [ "$diff" -le 128 ] && { echo "DEV=$d"; break; }
done`, dataVolMiB)
	var dev string
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, auth, script, 2*time.Minute, 0)
		g.Expect(err).NotTo(HaveOccurred(), "listing guest block devices failed:\n%s", out)
		for _, tok := range strings.Fields(out) {
			if d, ok := strings.CutPrefix(tok, "DEV="); ok {
				dev = d
			}
		}
		g.Expect(dev).NotTo(BeEmpty(),
			"no guest block device close to %d MiB — the data volume is not attached:\n%s", dataVolMiB, out)
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
	evetest.Logger().Infof("data volume device: %s", dev)
	return dev
}

// mountDataVolumeRO finds the app's data volume among the guest's block devices
// and mounts it at mountDir, returning which of the states above it is in. EVE-k
// does not auto-mount a container app's data volume at its MountDir
// (lf-edge/eve#6145), so after the conversion the verify has to do it; volverify's
// committed-index directory is what identifies the volume.
//
// The mount is read-only and skips the ext4 journal: the verify only reads, and
// replaying the journal would heal exactly the torn state this test is measuring.
//
// A volume that holds no pattern is reported as BLANK rather than as a failure —
// that is what the caller sees when the post-resize manifest check removed a torn
// volume and EVE recreated it empty. Only finding no data volume at all is an
// error, so the block-device inventory is dumped either way.
func mountDataVolumeRO(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	auth evetest.AuthMethod, mountDir string) string {
	script := fmt.Sprintf(`set -u
mkdir -p %[1]s
[ -d %[1]s/%[2]s ] && { echo STATE=%[3]s already-mounted; exit 0; }
mountpoint -q %[1]s && umount %[1]s
found=
for d in /dev/vd[b-z] /dev/sd[b-z]; do
  [ -b "$d" ] || continue
  found="$found $d"
  mount -o ro,noload -t ext4 "$d" %[1]s 2>/dev/null || continue
  if [ -d %[1]s/%[2]s ]; then echo "STATE=%[3]s $d"; exit 0; fi
  umount %[1]s
done
echo "candidates:$found"
lsblk 2>/dev/null; blkid 2>/dev/null; cat /proc/mounts
[ -n "$found" ] && { echo STATE=%[4]s; exit 0; }
echo STATE=NO-DATA-DEVICE
exit 1`, mountDir, volverifyCommitDir, volumeStatePattern, volumeStateBlank)
	state := ""
	t.Eventually(func(t Gomega) {
		stdout, stderr, err := device.RunShellScriptInsideApp(appUUID, auth, script, 2*time.Minute, 0)
		t.Expect(err).NotTo(HaveOccurred(),
			"no data volume among the guest block devices after the conversion:\n%s%s", stdout, stderr)
		for _, tok := range strings.Fields(stdout) {
			if s, ok := strings.CutPrefix(tok, "STATE="); ok {
				state = s
			}
		}
		t.Expect(state).To(Or(Equal(volumeStatePattern), Equal(volumeStateBlank)),
			"could not classify the data volume:\n%s", stdout)
		evetest.Logger().Infof("data volume state %s:\n%s", state, strings.TrimSpace(stdout))
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
	return state
}

// runOnEVEScript runs a shell script on EVE inside the pillar container, passing
// it through base64 so nothing has to survive the ssh → `eve exec pillar sh -c`
// quoting layers (the same trick the eden scripts use). args are appended as $1…
func runOnEVEScript(device *evetest.EdgeDevice, script string,
	timeout time.Duration, args ...string) (string, error) {
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	cmd := fmt.Sprintf(
		`eve exec pillar sh -c 'echo %s | base64 -d > /tmp/evetest-frag.sh; sh /tmp/evetest-frag.sh %s; rm -f /tmp/evetest-frag.sh'`,
		b64, strings.Join(args, " "))
	out, errOut, err := device.RunShellScript(cmd, timeout, 0)
	if err != nil {
		return out + errOut, err
	}
	return out, nil
}

// fillPersistToPct fills /persist with incompressible files until it is pct% full,
// so that the app's data volume — created afterwards, while the filesystem is at
// its peak — is allocated in the high block groups that the shrink must evacuate.
//
// The bytes have to be incompressible. Zeroes would let the qcow2 backing file
// store the blocks sparsely, and the relocation would then read and write nothing,
// leaving the shrink as fast as it is on an empty filesystem — which is the whole
// problem this is here to fix.
// reserveMiB is the size of the data volume written next: the fill stops that much
// short of pct, so the peak INCLUDING the volume is the requested percentage. Filling
// all the way to pct and then writing the volume into what little is left collapses the
// allowance volumemgr grants apps — the filler counts as dom0 usage, which is subtracted
// from it — and at RemainingSpace 0 the device enters
// MAINTENANCE_MODE_REASON_LOW_DISK_SPACE and reboots. Observed 3/3 at 8 GiB (peak 95%,
// 3.0 GiB free) and 0/3 at 2 GiB, where the volume still fit in the slack.
func fillPersistToPct(t Gomega, device *evetest.EdgeDevice, pct int, reserveMiB uint32) {
	// The filler lives under /persist/log, NOT /persist/tmp: onboot.sh removes
	// /persist/tmp unconditionally on every boot (no threshold, no df), so a reboot
	// anywhere between the fill and the trim silently voids the placement this step
	// exists to create. /persist/log survives a boot and is still the first entry in
	// onboot.sh's PERSIST_CLEANUPS list, so a device that genuinely runs out of space
	// reclaims it instead of wedging.
	const script = `set -u
PCT=$1
RESERVE_KB=$(( $2 * 1024 ))
DIR=/persist/log/stressfill
rm -rf "$DIR"; mkdir -p "$DIR"
cap=$(df -k /persist | tail -1 | awk '{print $2}')
want=$(( cap * PCT / 100 - RESERVE_KB ))
[ "$want" -lt 0 ] && want=0
n=0
while [ "$(df -k /persist | tail -1 | awk '{print $3}')" -lt "$want" ]; do
  f=$(printf "%s/%06d" "$DIR" "$n")
  dd if=/dev/urandom of="$f" bs=1M count=256 2>/dev/null || break
  n=$((n + 1))
done
sync
echo "FILLED files=$n $(df -h /persist | tail -1)"`
	out, err := runOnEVEScript(device, script, 40*time.Minute,
		fmt.Sprintf("%d", pct), fmt.Sprintf("%d", reserveMiB))
	t.Expect(err).NotTo(HaveOccurred(), "filling /persist failed:\n%s", out)
	t.Expect(out).To(ContainSubstring("FILLED"), "fill did not report completion:\n%s", out)
	evetest.Logger().Infof("filled /persist to ~%d%%: %s", pct, strings.TrimSpace(out))
}

// trimPersistToGiB deletes the LOWEST-numbered fill files until the FILLER is down
// to keepGiB, which leaves the survivors — and the data volume created at peak —
// concentrated in the high blocks above the future shrink boundary.
//
// Trimming is what makes the shrink possible at all: the resizer refuses when the
// filesystem cannot fit in the target size, and EVE-k needs room afterwards for
// its own images. Deleting from the bottom is what keeps the relocation work high.
//
// keepGiB measures the filler directory alone, deliberately: a budget on total
// /persist usage also counts the data volume, so a large volume consumes it and the
// trim stops early. At 8 GiB the old total-usage form left 6.75 GiB of filler, EVE-k
// then booted onto a ~40%-full /persist, and Longhorn refused to place replicas
// below its 25%-of-total floor — a harness artifact that read as a product failure
// in 3 of 12 iterations and vanished once the filler was actually removed.
func trimPersistToGiB(t Gomega, device *evetest.EdgeDevice, keepGiB int) {
	const script = `set -u
KEEP_KB=$(( $1 * 1024 * 1024 ))
DIR=/persist/log/stressfill
# A missing filler means the volume was not placed in the evacuation zone, so the
# iteration cannot say anything about shrink safety. Fail rather than continue: the
# silent version of this produced three clean-looking rows that had measured nothing.
[ -d "$DIR" ] || { echo "TRIM-FAILED no-fill-dir"; exit 1; }
for f in $(ls -1 "$DIR" 2>/dev/null | sort); do
  [ "$(du -sk "$DIR" | awk '{print $1}')" -le "$KEEP_KB" ] && break
  rm -f "$DIR/$f"
done
sync
echo "TRIMMED remaining=$(ls -1 "$DIR" 2>/dev/null | wc -l) fillerKB=$(du -sk "$DIR" | awk '{print $1}') $(df -h /persist | tail -1)"`
	out, err := runOnEVEScript(device, script, 10*time.Minute, fmt.Sprintf("%d", keepGiB))
	t.Expect(err).NotTo(HaveOccurred(), "trimming /persist failed:\n%s", out)
	t.Expect(out).To(ContainSubstring("TRIMMED"), "trim did not report completion:\n%s", out)
	evetest.Logger().Infof("trimmed the filler to ~%d GiB: %s", keepGiB, strings.TrimSpace(out))
}

// assertVolumeAboveShrinkBoundary fails the run unless the app's data volume has
// blocks above the size the shrink will cut /persist down to — i.e. unless the
// shrink will actually have to relocate it.
//
// Without this the test can pass for the wrong reason: a volume that sits entirely
// below the boundary is untouched by the shrink, so a clean verify says nothing
// about whether an interrupted relocation corrupts data. The boundary comes from
// the resizer's own check (TargetBytes) rather than an assumption, and the block
// placement from filefrag, which reports physical extents relative to the
// filesystem the file lives on.
func assertVolumeAboveShrinkBoundary(t Gomega, device *evetest.EdgeDevice) {
	disk, err := bootDiskPath(device)
	t.Expect(err).NotTo(HaveOccurred())
	out, err := runEVE(device, "eve exec pillar /usr/bin/storage-resizer check --disk "+disk+" --json")
	t.Expect(err).NotTo(HaveOccurred())
	// targetBytes is the post-shrink filesystem size (ShrinkResult.TargetBytes).
	var target int64
	if i := strings.Index(out, `"targetBytes"`); i >= 0 {
		fmt.Sscanf(out[i:], `"targetBytes": %d`, &target)
	}
	t.Expect(target).To(BeNumerically(">", 0),
		"could not read targetBytes from the resizer check:\n%s", out)

	// The physical range is the third column once any space inside "start.. end"
	// is closed up, which keeps the parse independent of filefrag's alignment; the
	// second half of that range is the file's highest block. Verified against real
	// filefrag output for both spacings and for a file with no extents.
	const script = `set -u
sync
FF=/usr/sbin/filefrag
[ -x "$FF" ] || FF=$(command -v filefrag 2>/dev/null || echo filefrag)
max=0
for d in /persist/vault/volumes /persist/clear/volumes /persist/vault/volumes-kvm /persist/clear/volumes-kvm; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    e=$("$FF" -b4096 -v "$f" 2>/dev/null | awk '
      { line=$0; gsub(/\.\.[ \t]+/, "..", line); $0=line }
      $1 ~ /^[0-9]+:$/ { split($3, r, /\.\./); x=r[2]; sub(/:$/, "", x); if (x+0 > m) m=x+0 }
      END { print m+0 }')
    [ -n "$e" ] || continue
    echo "VOL $f top4k=$e"
    [ "$e" -gt "$max" ] && max=$e
  done
done
echo "MAXTOP4K $max"`
	fragOut, err := runOnEVEScript(device, script, 5*time.Minute)
	t.Expect(err).NotTo(HaveOccurred(), "reading volume block placement failed:\n%s", fragOut)
	var top4k int64
	if i := strings.Index(fragOut, "MAXTOP4K "); i >= 0 {
		fmt.Sscanf(fragOut[i:], "MAXTOP4K %d", &top4k)
	}
	topByte := top4k * 4096
	evetest.Logger().Infof("volume top block %d (%.1f GiB) vs shrink target %.1f GiB\n%s",
		top4k, float64(topByte)/(1<<30), float64(target)/(1<<30), strings.TrimSpace(fragOut))
	t.Expect(topByte).To(BeNumerically(">", target),
		"the data volume lies entirely below the shrink boundary (top %.1f GiB vs target %.1f GiB), "+
			"so the shrink would not relocate it and a clean verify would prove nothing",
		float64(topByte)/(1<<30), float64(target)/(1<<30))
}

// logPartitionState records what EVE currently reports for each base image, so a
// run that did not commit its target (or reverted) is visible after the fact.
// Best-effort; never fails the test.
func logPartitionState(device *evetest.EdgeDevice) {
	info := device.GetDeviceInfo()
	if info == nil {
		evetest.Logger().Errorf("[partition-state] no device info")
		return
	}
	for _, sw := range info.GetSwList() {
		evetest.Logger().Errorf("[partition-state] %s partition=%s status=%s %s",
			sw.GetShortVersion(), sw.GetPartitionState(), sw.GetUserStatus(), sw.GetSubStatusStr())
	}
}

// waitDeviceOnTarget waits until the device is RUNNING the target flavor, which
// is a weaker and much earlier condition than the framework's upgrade wait: that
// one blocks until EVE commits the partition (state "active"), whereas this
// returns as soon as the target is the booted partition ("inprogress" counts).
//
// It fails fast if EVE flags any base image FAILED, so a rejected conversion still
// surfaces immediately rather than burning the whole budget.
func waitDeviceOnTarget(t Gomega, device *evetest.EdgeDevice,
	hv evetest.Hypervisor, timeout time.Duration) {
	// The target's short version carries a flavor suffix; for the conversion the
	// only thing that distinguishes it from the kvm hop is that suffix.
	suffix := "-kvm-"
	if hv == evetest.HypervisorKubevirt {
		suffix = "-k-"
	}
	t.Eventually(func(g Gomega) {
		info := device.GetDeviceInfo()
		g.Expect(info).NotTo(BeNil())
		var seen []string
		for _, sw := range info.GetSwList() {
			ver, state := sw.GetShortVersion(), sw.GetPartitionState()
			seen = append(seen, fmt.Sprintf("%s[%s/%s]", ver, state, sw.GetUserStatus()))
			if !strings.Contains(ver, suffix) {
				continue
			}
			g.Expect(sw.GetUserStatus()).NotTo(Equal(eveinfo.BaseOsStatus_FAILED),
				"EVE flagged %s FAILED: %s", ver, sw.GetSubStatusStr())
			if state == "inprogress" || state == "active" {
				evetest.Logger().Infof("device is running %s (partition %s)", ver, state)
				return
			}
		}
		g.Expect(false).To(BeTrue(), "device not running a %s image yet: %v", suffix, seen)
	}, timeout, 15*time.Second).Should(Succeed())
}

// Rounds of "wait, then try the documented PVC recovery" allowed before the app
// is declared stuck, and how long each round waits.
const (
	pvcRecoveryRounds = 3
	pvcRecoveryWait   = 12 * time.Minute
)

// waitAppRunningWithPVCRecovery waits for the app to reach RUNNING on EVE-k,
// applying the documented recovery for the known app-PVC wedge between attempts.
//
// The wedge is a Longhorn CSI create/verify race that leaves a PVC Pending
// forever: it is "stuck, not slow", so simply waiting longer never rescues it.
// Deleting the PVC lets the provisioner re-drive it cleanly, which is what makes
// data volumes above ~256 MiB usable at all — below that the race is rare, above
// it the wedge is the norm.
func waitAppRunningWithPVCRecovery(t Gomega, device *evetest.EdgeDevice,
	appUUID uuid.UUID, dataVolMiB uint32) {
	log := evetest.Logger()
	for round := 1; round <= pvcRecoveryRounds; round++ {
		if waitAppRunningQuietly(device, appUUID, pvcRecoveryWait) {
			recordVolumeSizing(device, "app-running")
			log.Infof("app RUNNING; CDI size verdict: %q", cdiImportSizeVerdict(device))
			return
		}
		recordVolumeSizing(device, fmt.Sprintf("app-not-running-round-%d", round))
		// An import CDI has rejected on size cannot be recovered by re-driving the
		// PVCs, so stop rather than spend the remaining rounds re-confirming it.
		if verdict := cdiImportSizeVerdict(device); verdict != "" {
			t.Expect(false).To(BeTrue(),
				"CDI refuses the import and retrying cannot change it: %s", verdict)
		}
		log.Errorf("app not RUNNING after %s (round %d/%d) — trying the PVC-wedge recovery",
			pvcRecoveryWait, round, pvcRecoveryRounds)
		if !recoverWedgedAppPVCs(device, dataVolMiB) {
			log.Errorf("nothing safe to recover this round")
		}
	}
	t.Expect(appIsRunning(device, appUUID)).To(BeTrue(),
		"app never reached RUNNING after %d PVC-wedge recovery attempts (CDI size verdict: %q)",
		pvcRecoveryRounds, cdiImportSizeVerdict(device))
}

// cdiImportSizeVerdict returns CDI's own size comparison for the app's import, or
// "" when it has not made one.
//
// CDI refuses an import whose virtual image size exceeds the capacity of the PVC it
// was handed, and then retries on a ~70-90s loop indefinitely, so the app never
// reaches RUNNING. Deleting PVCs cannot help — the sizes are the same on the next
// attempt — which is why this is worth reading rather than waiting out.
//
// Called on the success path too, deliberately. The failing runs compare
// 8592031744 against 8589938688, but the SAME triple is present in runs that pass,
// so sampling only failures cannot distinguish the two outcomes and leaves the
// intermittency unexplained.
func cdiImportSizeVerdict(device *evetest.EdgeDevice) string {
	// Run at dom0 level, as the capture probes do, NOT through runOnEVEScript:
	// that wraps its script in `eve exec pillar sh -c`, and the pillar container has
	// no `eve` binary, so a nested `eve exec kube` dies with "eve: not found" and the
	// verdict comes back empty — indistinguishable from CDI having made no
	// comparison, which is the very thing this is here to tell apart.
	const script = `eve exec kube kubectl -n eve-kube-app logs ` +
		`-l cdi.kubevirt.io=cdi-upload-server --tail=400 2>/dev/null | ` +
		`grep -aoE "Virtual image size [0-9]+ is larger than the reported available storage [0-9]+" | ` +
		`tail -1`
	out, errOut, err := device.RunShellScript(script, 2*time.Minute, 0)
	if err != nil {
		evetest.Logger().Warnf("CDI size verdict unavailable: %v%s", err, errOut)
		return ""
	}
	return strings.TrimSpace(out)
}

// startCDISampler records the upload server's own view of the import while it is in
// flight, alongside the claim's requested and provisioned sizes read at the same
// moment. Returns a stop func (call once).
//
// Sampling has to happen during the wait rather than after it. CDI removes the
// upload pod as soon as an import completes, so a run that succeeds leaves nothing
// to read afterwards, and reading later cannot distinguish "no size comparison was
// made" from "the pod is already gone" — which is why runs that succeeded have
// never been explained.
//
// The pairing is the point: CDI rejects an import when the volume it is given is
// larger than the size it was told to expect, and a claim's provisioned size is
// only observable after Longhorn has settled it. Sampling both together shows what
// CDI saw at the moment it decided, rather than what the claim looked like minutes
// later.
func startCDISampler(device *evetest.EdgeDevice, interval time.Duration) (stop func()) {
	// UPLOAD_IMAGE_SIZE is what CDI was told to expect. The upload pod carries it,
	// the scratch claim is provisioned at exactly that figure while the Longhorn
	// destination is rounded past it, and the rejection quotes both numbers — so
	// capture all three together rather than inferring which the check compares.
	const probe = `eve exec kube kubectl -n eve-kube-app logs ` +
		`-l cdi.kubevirt.io=cdi-upload-server --tail=25 2>/dev/null | ` +
		`grep -aE "Target size|irtual image size|block volume size|New phase|Saving stream failed" ; ` +
		`eve exec kube kubectl -n eve-kube-app get pod -l cdi.kubevirt.io=cdi-upload-server ` +
		`-o yaml 2>/dev/null | grep -aA1 "name: UPLOAD_IMAGE_SIZE" | grep -a value ; ` +
		`eve exec kube kubectl -n eve-kube-app get pvc ` +
		`-o custom-columns=NAME:.metadata.name,REQ:.spec.resources.requests.storage,` +
		`PROV:.status.capacity.storage --no-headers 2>/dev/null`

	done := make(chan struct{})
	go func() {
		log := evetest.Logger()
		for n := 0; ; n++ {
			out, errOut, err := device.RunShellScript(probe, 90*time.Second, 0)
			log.Infof("[cdi:sample #%d]\n%s%s(err=%v)", n, strings.TrimSpace(out), errOut, err)
			select {
			case <-done:
				return
			case <-time.After(interval):
			}
		}
	}()
	return func() { close(done) }
}

// recordVolumeSizing logs the numbers that decide whether CDI will accept the
// import, on every run rather than only on failures.
//
// A verdict alone cannot explain an outcome here. CDI removes the upload pod once
// an import succeeds, so reading its log after the app is RUNNING returns nothing
// whether or not a size comparison ever happened, and a run that passes looks
// identical to one whose log query simply arrived too late. The sizes do explain
// it: Longhorn rounds a claim up to a 2 MiB multiple, so a PVC whose requested and
// provisioned sizes differ is one CDI will reject, and one where they agree is one
// it will accept. Recording both, next to the virtual and allocated size of the
// file the request was derived from, says which case a run was and why.
func recordVolumeSizing(device *evetest.EdgeDevice, label string) {
	log := evetest.Logger()

	pvc := `eve exec kube kubectl -n eve-kube-app get pvc ` +
		`-o custom-columns=NAME:.metadata.name,REQUESTED:.spec.resources.requests.storage,` +
		`PROVISIONED:.status.capacity.storage --no-headers 2>/dev/null || echo none`
	out, errOut, err := device.RunShellScript(pvc, 90*time.Second, 0)
	log.Infof("[sizing:%s] pvc requested vs provisioned:\n%s%s(err=%v)",
		label, strings.TrimSpace(out), errOut, err)

	// Virtual size is the volume's size; the allocated figure is what the file
	// occupies on /persist, which is what can push a request off a 2 MiB boundary.
	const files = `set -u
for f in /persist/vault/volumes-kvm/*.raw /persist/vault/volumes/*.raw; do
  [ -f "$f" ] || continue
  echo "$f virtual=$(stat -c %s "$f") allocated=$(( $(stat -c %b "$f") * 512 ))"
done`
	fout, ferr := runOnEVEScript(device, files, 2*time.Minute)
	if ferr != nil {
		log.Infof("[sizing:%s] volume files unavailable: %v", label, ferr)
		return
	}
	log.Infof("[sizing:%s] volume files:\n%s", label, strings.TrimSpace(fout))
}

// appIsRunning reports the app's current state without asserting.
func appIsRunning(device *evetest.EdgeDevice, appUUID uuid.UUID) bool {
	info := device.GetAppInfo(appUUID)
	return info != nil && info.GetState() == eveinfo.ZSwState_RUNNING
}

// waitAppRunningQuietly polls until the app is RUNNING or the timeout expires,
// returning whether it got there. Unlike the framework's waiter it does not fail
// the test on timeout, so the caller can intervene and keep waiting.
func waitAppRunningQuietly(device *evetest.EdgeDevice, appUUID uuid.UUID, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if appIsRunning(device, appUUID) {
			return true
		}
		time.Sleep(15 * time.Second)
	}
	return appIsRunning(device, appUUID)
}

// recoverWedgedAppPVCs deletes Pending PVCs in the app namespace so the
// provisioner re-drives them, and reports whether it deleted any.
//
// It must never delete the data volume's PVC or that volume's CDI scratch: the
// data volume holds the pattern this test verifies, and EVE recreates a deleted
// volume BLANK — the verify would then find an empty volume and the run would
// report a clean pass, a false negative wearing the clothes of a result. So the
// size check is deliberately biased towards protecting: anything within reach of
// the data volume's size is left alone, and if that is the wedged PVC then no
// recovery happens and the run is allowed to fail honestly.
//
// The discriminator is size because the harness does not know the volume UUIDs
// EVE assigns. That is sound while the data volume is comfortably larger than the
// app's image PVC (a few hundred MiB) — which is exactly the case where recovery
// is needed. At data-volume sizes near the image size the app's own PVC gets
// protected too and recovery no-ops; the classification is logged so that is
// visible rather than silent.
//
// Sizes arrive in whatever form kubectl prints, which for these PVCs is a plain
// byte count rather than the Gi/Mi suffixes one might expect, so every form is
// handled and anything unrecognised is protected rather than deleted. Getting this
// wrong is not a missed recovery but a destroyed volume followed by a run that
// passes because the volume came back empty.
func recoverWedgedAppPVCs(device *evetest.EdgeDevice, dataVolMiB uint32) bool {
	log := evetest.Logger()
	script := fmt.Sprintf(`set -u
DV=%d
LIST=$(eve exec kube kubectl -n eve-kube-app get pvc \
  -o custom-columns=N:.metadata.name,P:.status.phase,R:.spec.resources.requests.storage \
  --no-headers 2>/dev/null)
[ -z "$LIST" ] && { echo NO-PVCS; exit 0; }
echo "$LIST" | sed 's/^/PVC: /'
VICTIMS=$(echo "$LIST" | awk -v dv="$DV" '
  function mib(s) {
    if (s ~ /^[0-9]+$/)   { return s / 1048576 }
    if (s ~ /^[0-9]+Ki$/) { sub(/Ki$/, "", s); return s / 1024 }
    if (s ~ /^[0-9]+Mi$/) { sub(/Mi$/, "", s); return s + 0 }
    if (s ~ /^[0-9]+Gi$/) { sub(/Gi$/, "", s); return s * 1024 }
    if (s ~ /^[0-9]+Ti$/) { sub(/Ti$/, "", s); return s * 1048576 }
    return -1
  }
  $2 == "Pending" {
    v = mib($3)
    if (v < 0 || v >= dv - 32) { printf "PROTECTED %%s (%%s)\n", $1, $3; next }
    printf "VICTIM %%s (%%s)\n", $1, $3
  }')
echo "$VICTIMS"
NAMES=$(echo "$VICTIMS" | awk '$1=="VICTIM" {print $2}')
[ -z "$NAMES" ] && { echo NOTHING-TO-RECOVER; exit 0; }
for v in $NAMES; do
  echo "RECOVERING $v"
  eve exec kube kubectl -n eve-kube-app delete pvc "$v" --wait=false 2>&1 | sed 's/^/  /'
done`, dataVolMiB)
	out, errOut, err := device.RunShellScript(script, 3*time.Minute, 0)
	log.Errorf("[pvc-recovery]\n%s%s(err=%v)", strings.TrimSpace(out), errOut, err)
	return strings.Contains(out, "RECOVERING ")
}

// assertWatchdogDriverBound fails the run if no watchdog driver is bound in the
// guest. It checks sysfs rather than the device node: a /dev/watchdog character
// node can exist with nothing behind it, so its presence alone proves nothing,
// whereas an entry under /sys/class/watchdog means a driver registered. It does
// not try to open the node — once EVE's watchdog service is up it holds it, and
// EBUSY here would be a false alarm.
//
// This checks the QEMU setup, not EVE. The stress build's resizer arms
// /dev/watchdog and then deliberately stops feeding it, which is how this test
// interrupts the offline resize — but if the resizer cannot open the device it
// exits quietly and nothing is interrupted. The conversion then completes and the
// volume verifies perfectly, which reads exactly like evidence that an interrupted
// shrink preserves the data.
//
// Necessary but not sufficient: this runs with the system fully up, whereas the
// resizer runs from an onboot container much earlier. Only the resizer's own
// console output confirms it armed the watchdog on that path.
func assertWatchdogDriverBound(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device,
			`ls /sys/class/watchdog/ 2>/dev/null | grep -q watchdog && echo WATCHDOG-DRIVER-BOUND || echo WATCHDOG-DRIVER-MISSING; `+
				`ls /sys/class/watchdog/ 2>&1; cat /sys/class/watchdog/watchdog0/identity 2>/dev/null`)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring("WATCHDOG-DRIVER-BOUND"),
			"no watchdog driver bound in the guest, so the stress resizer cannot "+
				"interrupt the resize and a clean result here would mean nothing; check "+
				"that QEMU exposes a watchdog and the chipset may reset:\n%s", out)
		evetest.Logger().Infof("watchdog driver:\n%s", strings.TrimSpace(out))
	}, 2*time.Minute, 10*time.Second).Should(Succeed())
}

// captureResizeEvidence records whether the offline resize was actually
// interrupted, which is the whole premise of this test and is otherwise
// invisible: a clean conversion and a fault-injected one that happened to
// converge look identical from the harness side.
//
// Note the resize attempt counter on the CONFIG partition is NOT usable here:
// storage-resize.sh deletes it on the success path, so by the time the conversion
// has finished it always reads empty regardless of how many attempts it took. The
// durable evidence is what EVE recorded about why it rebooted — a watchdog reset
// is reported as its own boot reason — plus whatever the resizer left in the logs.
func captureResizeEvidence(device *evetest.EdgeDevice) {
	log := evetest.Logger()
	log.Errorf("=== offline-resize fault evidence ===")
	probes := []struct{ what, script string }{
		{"boot / reboot reasons", `for f in /persist/boot-reason /persist/reboot-reason /persist/status/boot-reason /persist/status/reboot-reason /persist/log/reboot-reason.log; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done 2>/dev/null || echo NONE`},
		{"watchdog boot reason in logs", newlogProbe(`grep -ahoE "BootReason[A-Za-z]+" | sort | uniq -c | sort -rn | head`)},
		{"resize-failed.json", `cat /config/resize-failed.json 2>/dev/null || echo NONE`},
		{"watchdog device", `[ -c /dev/watchdog ] && echo PRESENT || echo MISSING; wdctl /dev/watchdog 2>&1 | head -8`},
		{"resizer/watchdog log lines", newlogProbe(`grep -ahiE "run-watchdog|storage-resizer|resize did not converge|watchdog" | tail -30`)},
	}
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, 60*time.Second, 0)
		log.Errorf("[resize:%s]\n%s%s(err=%v)", p.what, strings.TrimSpace(out), errOut, err)
	}
}

const lostFoundScript = `set -u
# du before ls: on a repair that reconnected a large subtree the listing is long, and
# the total is the number worth having even if the listing is truncated.
echo "--- total"
du -sh /persist/lost+found 2>/dev/null || echo NONE
echo "--- per-entry (largest first)"
du -sh /persist/lost+found/* 2>/dev/null | sort -rh | head -20 || true
# -i because the console names what e2fsck reconnected only by inode number, and
# nothing on the device resolves those afterwards.
echo "--- ls -li"
ls -li /persist/lost+found 2>/dev/null | head -40 || true
`

// captureLostFound records what an e2fsck repair moved into /persist/lost+found —
// inode numbers, sizes, modes and the space held.
//
// Each interrupted shrink reboots the device and storage-init fscks /persist again, so
// a structural repair there is a candidate cause of damage to the volume under test.
// The serial console reports such a repair only as inode numbers, and by the time the
// console is read the device is gone, so this is the one reading that ties those
// numbers to a size and a mode. Nothing reclaims the space either, which is why the
// total is worth a line of its own. Taken before and after the conversion so residue
// can be attributed to it. Best-effort; never fails the test.
func captureLostFound(device *evetest.EdgeDevice, when string) {
	log := evetest.Logger()
	out, err := runOnEVEScript(device, lostFoundScript, 90*time.Second)
	if err != nil {
		log.Infof("[lost+found:%s] capture failed: %v\n%s", when, err, strings.TrimSpace(out))
		return
	}
	log.Infof("[lost+found:%s]\n%s", when, strings.TrimSpace(out))
}

// captureVolManifest reports whether the post-resize volume-manifest check ran and
// what it concluded — whether it found the pre-shrink hashes, judged any volume
// torn, and removed it. This is what separates "the shrink left the volume alone"
// from "the detector cleaned up after it". Best-effort; never fails the test.
func captureVolManifest(device *evetest.EdgeDevice) {
	log := evetest.Logger()
	log.Errorf("=== volume-manifest (post-resize detect+recreate) ===")
	probes := []struct{ what, script string }{
		{"manifest files on /persist", `eve exec pillar sh -c 'ls -l /persist/vault/volumes/.sha256 /persist/clear/volumes/.sha256 2>&1'`},
		{"volmanifest / recreate signatures (newlog)", newlogProbe(`grep -ahiE "volmanifest|recreateCorruptVolumes|verifyVolumes|torn by the resize" | tail -40`)},
		{"app volume files", `eve exec pillar sh -c 'ls -l /persist/vault/volumes /persist/clear/volumes 2>&1'`},
	}
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, 60*time.Second, 0)
		log.Errorf("[volmanifest:%s]\n%s%s(err=%v)", p.what, strings.TrimSpace(out), errOut, err)
	}
}

// verifyVolverifyPattern replays the pattern against the volume and returns the
// report. volverify exits non-zero on a dirty report, so the exit status is not an
// assertion failure here — the caller classifies the report instead.
func verifyVolverifyPattern(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	auth evetest.AuthMethod, args string, expectCommitted int) string {
	cmd := fmt.Sprintf("volverify verify %s --expect-committed %d", args, expectCommitted)
	var report string
	t.Eventually(func(t Gomega) {
		stdout, _, _ := device.RunShellScriptInsideApp(appUUID, auth, cmd, 30*time.Minute, 0)
		t.Expect(stdout).NotTo(BeEmpty(), "volverify verify produced no output")
		report = strings.TrimSpace(stdout)
	}, 32*time.Minute, 10*time.Second).Should(Succeed())
	return report
}

// reportField extracts an integer "key=N" field from a volverify summary line,
// returning -1 when the field is absent or unparsable.
func reportField(report, key string) int {
	for _, tok := range strings.Fields(report) {
		if !strings.HasPrefix(tok, key+"=") {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(strings.TrimPrefix(tok, key+"="), "%d", &n); err != nil {
			return -1
		}
		return n
	}
	return -1
}
