// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package resize_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
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
			Name:             devName,
			WithEVEVersion:   initialVersion,
			WithHypervisor:   initialHypervisor,
			WithTPM:          withTPM,
			MinDiskSizeInMiB: diskSizeMiB,
			MinRAMInMiB:      effectiveRAMMiB,
			MinCPUs:          effectiveCPUs,
			// Provision from the LIVE image, not the installer: the installer ESP
			// carries a 0-byte boot/.boot_repository that the offline grow's FAT32
			// copy rejects with "invalid start cluster: 0" (diskfs/go-diskfs#417).
			DeviceReusePolicy: evetest.CreateFromScratchWithLiveImage,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	log.Infof("volverify app %s:1.0 on a %d MiB data volume (max file %d blocks)",
		volverifyImage, dataVolMiB, maxBlocks)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
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
	device.UpgradeEVE(convVersion, evetest.HypervisorKVM, true, false)
	assertSmallGeometry(t, device)
	assertCheckDecision(t, device, "shrink")
	evetest.Checkpoint("kvm-hop-done")

	log.Infof("settling vault to a local TPM unlock")
	settleVaultLocal(t, device)
	evetest.Checkpoint("vault-settled")

	// Switch (L2-bridged) NI: the carried app gets its own DHCP address on the eth0
	// segment and is reached directly. A local NI does not reconverge onto the
	// kubevirt VMI after the conversion (verified stuck, not slow).
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
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
		DataVolumes: []evetest.DataVolumeConfig{
			{SizeBytes: dataVolBytes, MountDir: dataMountDir},
		},
	})
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	appAuth := evetest.UsernamePasswordAuth{Username: appSSHUser, Password: appSSHPassword}
	assertAppSSH(t, device, appUUID, appAuth)
	captureAppNet(device, "pre-conversion EVE-kvm (SSH OK)")

	// Fill the volume on EVE-kvm, where the runx shim has formatted and mounted it
	// at MountDir. The writer stops at Ops or when the volume fills, whichever comes
	// first, and reports the committed high-water mark the verify is held to.
	log.Infof("pre-conversion: filling the data volume with the volverify pattern")
	writtenCommitted := writeVolverifyPattern(t, device, appUUID, appAuth, volverifyArgs)
	log.Infof("volume filled through committed op %d", writtenCommitted)
	capturePersist(device, "pre-conversion EVE-kvm (volume filled)")
	evetest.Checkpoint("volume-filled")

	log.Infof("kvm→k conversion: upgrading to %s (%s) — triggers the offline shrink+grow", convVersion, targetHypervisor)
	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	device.UpgradeEVE(convVersion, targetHypervisor, true, false)
	conversionOK = true
	device.ExpectAdditionalReboots(1)
	captureResizeEvidence(device)
	evetest.Checkpoint("conversion-complete")

	assertGrownShrink(t, device)
	evetest.Checkpoint("geometry-grown")

	stopPersistSampler := startPersistSampler(device, 45*time.Second)
	defer stopPersistSampler()

	if targetHypervisor == evetest.HypervisorKubevirt {
		log.Infof("(a) waiting for k3s node ready")
		if !isK3sReady(device.GetClusterInfo()) {
			clusterUpdates, stop := device.WatchClusterInfo()
			defer stop()
			t.Eventually(clusterUpdates, 20*time.Minute).Should(Receive(
				matchers.SatisfyPredicate("K3s node is ready", isK3sReady)))
		}
		log.Infof("(b) waiting for volumemgr Initialized")
		waitVolumemgrReady(t, device)
		log.Infof("(c) waiting for longhorn StorageClass ready")
		waitLonghornSC(t, device)
	}
	log.Infof("(d) waiting for the app to reach RUNNING on the target")
	device.WaitUntilAppIsRunning(appUUID, 65*time.Minute)
	appSSHOK := false
	defer func() {
		if !appSSHOK {
			captureAppNet(device, "post-conversion EVE-k (app net FAILED)")
			captureAppNetFailure(device, appUUID)
		}
	}()
	log.Infof("(e0) post-conversion: waiting up to 10m for the app to report a routable IPv4")
	waitAppHasRoutableIPv4(t, device, appUUID, 10*time.Minute)
	log.Infof("(e) post-conversion: app must be SSH-reachable")
	assertAppSSH(t, device, appUUID, appAuth)
	appSSHOK = true

	log.Infof("(f) post-conversion: re-verifying the data-volume pattern")
	captureVolManifest(device)
	state := mountDataVolumeRO(t, device, appUUID, appAuth, dataMountDir)
	if state == volumeStateBlank {
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
		{"watchdog boot reason in logs", `eve exec pillar sh -c 'grep -ahoE "BootReason[A-Za-z]+" /persist/newlog/collect/*.log 2>/dev/null | sort | uniq -c | sort -rn | head' || echo none`},
		{"resize-failed.json", `cat /config/resize-failed.json 2>/dev/null || echo NONE`},
		{"watchdog device", `[ -c /dev/watchdog ] && echo PRESENT || echo MISSING; wdctl /dev/watchdog 2>&1 | head -8`},
		{"resizer/watchdog log lines", `eve exec pillar sh -c 'grep -ahiE "run-watchdog|storage-resizer|resize did not converge|watchdog" /persist/newlog/collect/*.log 2>/dev/null | tail -30' || echo none`},
	}
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, 60*time.Second, 0)
		log.Errorf("[resize:%s]\n%s%s(err=%v)", p.what, strings.TrimSpace(out), errOut, err)
	}
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
		{"volmanifest / recreate signatures (newlog)", `eve exec pillar sh -c 'grep -ahiE "volmanifest|recreateCorruptVolumes|verifyVolumes|torn by the resize" /persist/newlog/collect/*.log 2>/dev/null | tail -40' || echo none`},
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
