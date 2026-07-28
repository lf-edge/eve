// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package resize_test reproduces, in evetest, the eden EVE-kvm→EVE-k in-field
// boot-disk shrink+grow conversion — the proven sequence in eden's
// update_eve_image_kvm_to_k.txt (EXPECT_DECISION=shrink), one step at a time.
//
// This is the "basic resize" stage (no application volume, no fault injection):
// it proves evetest can drive the whole small→large conversion with the shrink
// and keep a container app alive across it. The ordering and the waits mirror the
// eden escript deliberately — they are load-bearing (vault must settle to a local
// TPM unlock before the app; the offline resize reboots several times; on EVE-k
// the volumemgr → longhorn → app → SSH readiness gates must be waited on in order).
//
// The one deliberate divergence from the eden escript: it DELETES the app before
// the k update (the old cross-flavor gate refused any volume). With the gate
// lifted (baseosmgr allow-shrink-with-volumes), this test KEEPS the app across the
// conversion.
package resize_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	initialEVEVersionParamKey = "INITIAL_EVE_VERSION"
	initialHypervisorParamKey = "INITIAL_HYPERVISOR"
	ramSizeMiBParamKey        = "RAM_SIZE_MB"
	cpusParamKey              = "CPUS"

	// minDeviceRAMInMiB and minDeviceCPUs are the resource floors for the kvm→k
	// conversion. EVE-k (kubevirt + Longhorn) needs well above the 8 GiB / 4 vCPU
	// framework defaults; the eden runs that pass 7/7 use 16 GiB and 8 vCPUs, so
	// require at least that here.
	minDeviceRAMInMiB = 16384
	minDeviceCPUs     = 8

	appSSHUser     = "root"
	appSSHPassword = "testpassword"
	appSSHFwdPort  = 2222
	sshTimeout     = 20 * time.Second

	// Stage B: a blank data volume attached to the app, with a marker written into
	// it on EVE-kvm that must survive the shrink conversion onto EVE-k.
	dataMountDir       = "/mnt/data"
	dataVolMiBParamKey = "DATAVOL_MB" // app data-volume size sweep: 2 GiB wedges the CSI create/verify race, 100 MiB passes
	volMarker          = "STAGE-B-VOL-MARKER-9f3a1c7e-survives-kvm-to-k"
)

// TestKvmToKResize drives 16.6.0-kvm (small) → current EVE-kvm (same geometry,
// lands the conversion code) → current EVE-k (cross-flavor ⇒ offline shrink+grow),
// keeping a container app across the conversion.
//
// Parameters:
//   - INITIAL_EVE_VERSION (required, e.g. "16.6.0") / INITIAL_HYPERVISOR (kvm) —
//     the SMALL-geometry base; it must lack the large EVE-k geometry or the
//     conversion is a no-op and proves nothing (asserted).
//   - EVE_VERSION / HYPERVISOR — the conversion-capable current build; the kvm
//     variant is the intermediate hop, the kubevirt variant is the k target.
//   - DISK_SIZE_MB — keep the boot disk full (no free tail) so the conversion
//     SHRINKS P3 rather than growing into free space (asserted: decision==shrink).
func TestKvmToKResize(test *testing.T) {
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
			DefaultValue: uint32(2048),
			Description: evetest.TestParameterDescription{
				Summary: "App data-volume size in MiB (size->CSI-race sweep)",
				Default: "2048 (2 GiB)",
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
	convVersion := evetest.GetEVEVersionParameterValue() // the conversion-capable build (kvm hop + k target share this version)
	targetHypervisor := evetest.GetHypervisorParameterValue()

	// The kvm→k conversion provisions Longhorn/kubevirt onto P3; a boot disk
	// smaller than the framework default (64 GiB) starves that geometry and the
	// conversion wedges instead of failing cleanly. Reject an undersized
	// DISK_SIZE_MB up front rather than burning a full run to discover it.
	effectiveDiskMiB := diskSizeMiB
	if effectiveDiskMiB == 0 {
		effectiveDiskMiB = constants.DefaultEVEDeviceDiskSizeInMiB
	}
	if effectiveDiskMiB < constants.DefaultEVEDeviceDiskSizeInMiB {
		evetestT.Fatalf("boot disk %d MiB is too small for the kvm→k conversion; "+
			"need at least %d MiB (64 GiB) — set DISK_SIZE_MB accordingly",
			effectiveDiskMiB, constants.DefaultEVEDeviceDiskSizeInMiB)
	}
	ramSizeMiB := evetest.GetTestParameter[uint32](ramSizeMiBParamKey)
	effectiveRAMMiB := ramSizeMiB
	if effectiveRAMMiB == 0 {
		effectiveRAMMiB = constants.DefaultEVEDeviceRAMInMiB
	}
	if effectiveRAMMiB < minDeviceRAMInMiB {
		evetestT.Fatalf("device RAM %d MiB is too small for the kvm→k conversion "+
			"(EVE-k + Longhorn); need at least %d MiB (16 GiB) — set RAM_SIZE_MB accordingly",
			effectiveRAMMiB, minDeviceRAMInMiB)
	}
	cpus := evetest.GetTestParameter[uint8](cpusParamKey)
	effectiveCPUs := cpus
	if effectiveCPUs == 0 {
		effectiveCPUs = constants.DefaultEVEDeviceCPUs
	}
	if effectiveCPUs < minDeviceCPUs {
		evetestT.Fatalf("device vCPUs %d is too few for the kvm→k conversion "+
			"(EVE-k + Longhorn); need at least %d — set CPUS accordingly",
			effectiveCPUs, minDeviceCPUs)
	}
	dataVolBytes := uint64(evetest.GetTestParameter[uint32](dataVolMiBParamKey)) * evetest.MiB

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
			// Provision from the LIVE image (as eden does), not the installer. The
			// installer ESP carries a 0-byte marker (boot/.boot_repository) that the
			// offline grow's FAT32 copy (go-diskfs) rejects with "invalid start
			// cluster: 0"; the live ESP has no such file. See the go-diskfs issue.
			DeviceReusePolicy: evetest.CreateFromScratchWithLiveImage,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	log.Infof("app data-volume size: %d MiB", dataVolBytes/evetest.MiB)

	// Management + app network.
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

	// Step 1: baseline — the boot disk must be SMALL, else the conversion is a no-op.
	log.Infof("baseline: asserting SMALL boot-disk geometry")
	assertSmallGeometry(t, device)
	evetest.Checkpoint("baseline-small")

	// Step 2: kvm→kvm hop — lands the conversion code, geometry unchanged.
	log.Infof("kvm→kvm hop: upgrading to the conversion-capable build %s (kvm)", convVersion)
	device.UpgradeEVE(convVersion, evetest.HypervisorKVM, true, false)
	log.Infof("post-kvm-hop: geometry must still be SMALL")
	assertSmallGeometry(t, device)
	log.Infof("post-kvm-hop: storage-resizer check must decide 'shrink'")
	assertCheckDecision(t, device, "shrink")
	evetest.Checkpoint("kvm-hop-done")

	// Step 3: settle the vault to a LOCAL TPM unlock (a new rootfs moves PCRs, so
	// the first boot unlocks via the controller key; reboot until it seals locally).
	log.Infof("settling vault to a local TPM unlock")
	settleVaultLocal(t, device)
	evetest.Checkpoint("vault-settled")

	// Step 4: deploy a container app + a blank DATA VOLUME on EVE-kvm; wait RUNNING
	// + SSH-reachable, then write a marker into the volume.
	// SWITCH (L2, bridged) NI: the app gets its own DHCP address on the eth0 segment
	// and is reached directly at app-IP:22 (the port-map is kept as a 2nd candidate
	// endpoint). Verified: the LOCAL NI does NOT reconverge onto the kubevirt VMI
	// after the conversion (no app IP even after a 10-min wait), whereas the switch
	// NI does (~3.5 min); the readiness gate (step 7) absorbs that delay.
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:        "resize-test-app",
		Activate:           true,
		Image:              evetest.DockerContainer{ImageName: "milan4zededa/evetest-ubuntu-ctr", Tag: "1.0"},
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
	log.Infof("pre-conversion: app must be SSH-reachable")
	assertAppSSH(t, device, appUUID, appAuth)
	// Baseline network snapshot on EVE-kvm where the port-map SSH works, to diff
	// against the post-conversion EVE-k snapshot if that SSH fails.
	captureAppNet(device, "pre-conversion EVE-kvm (SSH OK)")
	log.Infof("pre-conversion: writing a marker into the app data volume at %s", dataMountDir)
	writeVolumeMarker(t, device, appUUID, appAuth, dataMountDir, volMarker)
	capturePersist(device, "pre-conversion EVE-kvm (app running)")
	evetest.Checkpoint("pre-conversion-app-ready")

	// Step 5: kvm→k — the cross-flavor seam triggers the offline shrink+grow. The
	// app is KEPT (gate lifted). UpgradeEVE drives the multi-reboot conversion.
	log.Infof("kvm→k conversion: upgrading to %s (%s) — triggers the offline shrink+grow", convVersion, targetHypervisor)
	// On conversion failure the device returns online on the unconverted kvm
	// partition — still SSH-reachable — while EVE flags the -k baseos FAILED, and
	// UpgradeEVE fatals. Capture the on-device reason first (the deferred probe runs
	// before harness teardown; conversionOK stays false because the fatal skips it).
	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	device.UpgradeEVE(convVersion, targetHypervisor, true, false)
	conversionOK = true
	// The offline shrink+grow reboots once more than UpgradeEVE accounts for (its
	// intermediate initrd-resize boot is invisible to the controller, but the
	// post-resize kvm boot and the -k boot are two observed reboots vs the one
	// UpgradeEVE expects). Declare that extra reboot so the teardown check balances.
	device.ExpectAdditionalReboots(1)
	evetest.Checkpoint("conversion-complete")

	// Step 6: assert the boot disk grew to LARGE and P3 shrank.
	log.Infof("post-conversion: asserting boot disk grew (shrink path: ESP-B created, P3 shrank)")
	assertGrownShrink(t, device)
	evetest.Checkpoint("geometry-grown")

	// Sample /persist + Longhorn disk accounting through the EVE-k startup window
	// (k3s → volumemgr → Longhorn SC → app), to see the "no available disk for
	// replica" accounting as it evolves. Stopped once readiness resolves below.
	stopPersistSampler := startPersistSampler(device, 45*time.Second)
	defer stopPersistSampler()

	// Step 7: post-conversion readiness — in order, so a failure localizes.
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
	// If the app network doesn't come back on EVE-k, snapshot the app network state
	// for comparison against the pre-conversion EVE-kvm baseline (the deferred probe
	// runs before teardown; appSSHOK stays false on the fatal).
	appSSHOK := false
	defer func() {
		if !appSSHOK {
			captureAppNet(device, "post-conversion EVE-k (app net FAILED)")
			captureAppNetFailure(device, appUUID)
		}
	}()
	// Readiness gate: the carried app's network reconvergence on EVE-k is slow /
	// non-deterministic, so wait (generously) for it to report a routable IPv4
	// before asserting SSH. This separates "not ready yet" from "unreachable": a
	// slow reconvergence still passes; a genuinely stuck one fails here with the
	// network snapshot, distinguishing it from an SSH/routing problem.
	log.Infof("(e0) post-conversion: waiting up to 10m for the app to report a routable IPv4")
	waitAppHasRoutableIPv4(t, device, appUUID, 10*time.Minute)
	log.Infof("(e) post-conversion: app must be SSH-reachable")
	assertAppSSH(t, device, appUUID, appAuth)
	appSSHOK = true
	// (f) the data volume — and its marker — must have survived the shrink onto
	// EVE-k. EVE-k does not auto-mount the container data volume at MountDir
	// (lf-edge/eve#6145), so read it off the raw block device from inside the app.
	log.Infof("(f) post-conversion: the app data-volume marker must survive on EVE-k")
	assertVolumeMarker(t, device, appUUID, appAuth, volMarker)
	evetest.Checkpoint("post-conversion-app-ready")
}

// ---- helpers (mirror the eden escript's assert/wait scripts) ----

const eveShellTimeout = 30 * time.Second

// dumpConversionFailure captures why the kvm→k conversion was marked FAILED by
// EVE. At that point the device has returned online on the unconverted kvm
// partition and is SSH-reachable, so it can be queried directly. Best-effort: it
// logs whatever each probe returns and never fails the (already-failing) test.
func dumpConversionFailure(device *evetest.EdgeDevice) {
	log := evetest.Logger()
	log.Errorf("kvm→k conversion FAILED — capturing on-device diagnostics")
	probes := []struct{ what, script string }{
		{"resize-failed.json", "cat /config/resize-failed.json 2>/dev/null || echo NONE"},
		{"resize-flags", "echo repartition-inprogress=$(cat /config/repartition-inprogress 2>/dev/null); echo resize-reboots=$(cat /config/resize-reboots 2>/dev/null)"},
		{"zboot-status", "zboot status 2>&1 || true"},
		{"BaseOsStatus", "eve exec pillar sh -c 'cat /run/baseosmgr/BaseOsStatus/*.json 2>/dev/null' || echo NONE"},
	}
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, eveShellTimeout, 0)
		log.Errorf("[capture:%s]\n%s%s(err=%v)", p.what, out, errOut, err)
	}
}

// captureAppNet snapshots the EVE-side app networking behind the port-map SSH:
// the NAT DNAT rules (node:2222→app:22), the app's assigned IP + applied ACLs,
// and the node bridges/IPs. Taken on EVE-kvm (working) and again on EVE-k
// (failing) so the two can be diffed. Best-effort; never fails the test.
func captureAppNet(device *evetest.EdgeDevice, label string) {
	log := evetest.Logger()
	log.Errorf("=== app-network capture: %s ===", label)
	probes := []struct{ what, script string }{
		{"nat-portmap", "eve exec pillar iptables -t nat -S 2>/dev/null | grep -aiE '2222|DNAT|to-destination' || echo none"},
		{"AppNetworkStatus", "eve exec pillar sh -c 'cat /run/zedrouter/AppNetworkStatus/*.json 2>/dev/null' || echo none"},
		{"bridges+ips", "eve exec pillar ip -br addr 2>/dev/null || echo none"},
	}
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, eveShellTimeout, 0)
		log.Errorf("[net:%s] %s:\n%s%s(err=%v)", label, p.what, strings.TrimSpace(out), errOut, err)
	}
}

// captureAppNetFailure characterizes the known EVE-k app-pvc-not-ready / CDI
// upload-pod wedge that leaves the app stuck CREATING_VOLUME (no VMI → no net).
// It grabs the signals ~/notes/kvm-to-k-resize-soak-app-pvc-not-ready-stats.md
// prescribes for pinning the variant (V1–V5) and whether the image's recovery
// engaged: the scratch/data PVC state (Terminating? storageClass?), the cdi-upload
// pod phase/reason, Longhorn volume+attachment state, the CDI upload-controller
// reconcile errors, and the volumemgr / MOUNT-WEDGE-RECOVERY newlog signatures.
func captureAppNetFailure(device *evetest.EdgeDevice, appUUID uuid.UUID) {
	log := evetest.Logger()
	log.Errorf("=== EVE-k app-pvc-not-ready / CDI-wedge diagnostics (app %s) ===", appUUID)
	probes := []struct{ what, script string }{
		{"eve-kube-app pvc+pods -o wide", `eve exec kube kubectl -n eve-kube-app get pvc,pods -o wide 2>/dev/null || echo none`},
		{"describe pvc (scratch Terminating/SC/finalizers/events)", `eve exec kube kubectl -n eve-kube-app describe pvc 2>/dev/null || echo none`},
		{"describe pods (cdi-upload phase/reason/events)", `eve exec kube kubectl -n eve-kube-app describe pods 2>/dev/null || echo none`},
		{"longhorn volumes", `eve exec kube kubectl get volumes.longhorn.io -A -o wide 2>/dev/null || echo none`},
		{"volumeattachments", `eve exec kube kubectl get volumeattachments 2>/dev/null || echo none`},
		{"longhorn-csi-provisioner log (CreateVolume 404/500 origin)", `eve exec kube kubectl -n longhorn-system logs deployment/csi-provisioner -c csi-provisioner --tail=250 2>/dev/null || echo none`},
		{"longhorn-manager log (create/verify race)", `eve exec kube kubectl -n longhorn-system logs -l app=longhorn-manager -c longhorn-manager --tail=250 --prefix 2>/dev/null || echo none`},
		{"longhorn StorageClass (replicas/config)", `eve exec kube kubectl get sc longhorn -o yaml 2>/dev/null || echo none`},
		{"longhorn version (manager ds image)", `eve exec kube kubectl -n longhorn-system get ds longhorn-manager -o wide 2>/dev/null || echo none`},
		{"CDI upload-controller log", `eve exec kube kubectl -n cdi logs deployment/cdi-deployment --tail=60 2>/dev/null || echo none`},
		{"volumemgr RolloutDiskToPVC / V5 signature (newlog)", `eve exec pillar sh -c 'grep -aiE "RolloutDiskToPVC|retryFailedClusterVolumeCreate|terminating:true|local-path" /persist/newlog/collect/*.log 2>/dev/null | tail -30' || echo none`},
		{"MOUNT-WEDGE-RECOVERY (detector fired?)", `eve exec pillar sh -c 'grep -ai MOUNT-WEDGE-RECOVERY /persist/newlog/collect/*.log 2>/dev/null | tail -10' || echo none`},
		{"kubevirt vmi -A", `eve exec kube kubectl get vmi -A -o wide 2>/dev/null || echo none`},
	}
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, 90*time.Second, 0)
		log.Errorf("[wedge:%s]\n%s%s(err=%v)", p.what, strings.TrimSpace(out), errOut, err)
	}
}

// capturePersist snapshots everything about /persist sizing/usage plus Longhorn's
// own view of the node disk — storageMaximum/Available/Scheduled/Reserved and the
// scheduling settings — i.e. the accounting behind "no available disk for replica".
// The kube/longhorn probes no-op on EVE-kvm (pre-conversion) and light up on EVE-k.
// Best-effort; never fails the test.
func capturePersist(device *evetest.EdgeDevice, label string) {
	log := evetest.Logger()
	log.Errorf("=== /persist capture: %s ===", label)
	probes := []struct{ what, script string }{
		{"df persist+submounts", `eve exec pillar sh -c 'df -B1 | awk "NR==1 || /persist/"' 2>/dev/null || echo none`},
		{"lsblk sizes+mounts", `eve exec pillar lsblk -b -o NAME,PARTLABEL,SIZE,FSTYPE,MOUNTPOINT 2>/dev/null || echo none`},
		{"du -d1 /persist", `eve exec pillar sh -c 'du -x -B1 -d1 /persist 2>/dev/null | sort -rn' || echo none`},
		{"longhorn node disk accounting", `eve exec kube kubectl -n longhorn-system get nodes.longhorn.io -o yaml 2>/dev/null | grep -aE "name:|path:|storageMaximum|storageAvailable|storageScheduled|storageReserved|allowScheduling|diskUUID|type:|reason:|message:" || echo none`},
		{"longhorn node -o wide", `eve exec kube kubectl -n longhorn-system get nodes.longhorn.io -o wide 2>/dev/null || echo none`},
		{"longhorn storage settings", `eve exec kube kubectl -n longhorn-system get settings.longhorn.io -o custom-columns=NAME:.metadata.name,VALUE:.value 2>/dev/null | grep -aiE "NAME|reserved|over-provisioning|minimal-available|soft-anti-affinity" || echo none`},
		{"eve-kube-app pvc (requested sizes)", `eve exec kube kubectl -n eve-kube-app get pvc 2>/dev/null || echo none`},
	}
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, 60*time.Second, 0)
		log.Errorf("[persist:%s] %s:\n%s%s(err=%v)", label, p.what, strings.TrimSpace(out), errOut, err)
	}
}

// startPersistSampler runs capturePersist in the background every interval (bounded)
// so /persist + Longhorn disk accounting can be watched evolving while k3s/Longhorn/
// CDI start after the conversion. Returns a stop func (call once, e.g. via defer).
func startPersistSampler(device *evetest.EdgeDevice, interval time.Duration) (stop func()) {
	done := make(chan struct{})
	go func() {
		for n := 0; n < 13; n++ {
			capturePersist(device, fmt.Sprintf("post-conversion startup sample #%d", n))
			select {
			case <-done:
				return
			case <-time.After(interval):
			}
		}
	}()
	return func() { close(done) }
}

// partsLsblk enumerates partition sizes across ALL block devices (not a fixed
// /dev/sda — evetest's broker QEMU presents the boot disk as virtio /dev/vda).
// We identify partitions by PARTLABEL, so the parent disk name doesn't matter.
const partsLsblk = "eve exec pillar lsblk -b -P -o NAME,PARTLABEL,PARTUUID,SIZE"

// runEVE runs a command on EVE and returns cleaned stdout (dropping empty and
// level=… lines) plus any error, WITHOUT asserting — so callers can retry, since
// EVE SSH/pillar can be briefly unavailable right after a reboot or the conversion.
func runEVE(device *evetest.EdgeDevice, script string) (string, error) {
	stdout, _, err := device.RunShellScript(script, eveShellTimeout, 0)
	if err != nil {
		return "", err
	}
	var lines []string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(l) == "" || strings.Contains(l, "level=") {
			continue
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n"), nil
}

// assertSmallGeometry asserts ESP/IMGA/IMGB are small and no ESP-B exists yet
// (mirror capture-partitions.sh assert-small). Retried: it also runs right after
// the kvm→kvm reboot.
func assertSmallGeometry(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, partsLsblk)
		g.Expect(err).NotTo(HaveOccurred())
		// ESP-B carries the fresh-install GUID ...30056; it exists only after the grow.
		g.Expect(strings.ToLower(out)).NotTo(ContainSubstring("30056"),
			"SMALL geometry must not have an ESP-B yet:\n%s", out)
		imga := partSizeBytes(out, "IMGA")
		imgb := partSizeBytes(out, "IMGB")
		const oneGiB = int64(1) << 30
		g.Expect(imga).To(BeNumerically(">", 0), "could not read IMGA size:\n%s", out)
		g.Expect(imga).To(BeNumerically("<", oneGiB), "IMGA is not SMALL (%d bytes):\n%s", imga, out)
		g.Expect(imgb).To(BeNumerically("<", oneGiB), "IMGB is not SMALL (%d bytes):\n%s", imgb, out)
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
}

// assertGrownShrink asserts the LARGE layout after the conversion: the reserved
// ESP-B was created and IMGA/IMGB grew past 8 GiB (mirror capture-partitions.sh
// assert-grown). That the shrink path (not grow) was taken is confirmed earlier by
// assertCheckDecision(shrink). Retried: it runs right after the EVE-k boot.
func assertGrownShrink(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, partsLsblk)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.ToLower(out)).To(ContainSubstring("30056"),
			"grow must have created the reserved ESP-B (GUID ...30056):\n%s", out)
		const eightGiB = int64(8) << 30
		g.Expect(partSizeBytes(out, "IMGA")).To(BeNumerically(">=", eightGiB), "IMGA did not grow to LARGE:\n%s", out)
		g.Expect(partSizeBytes(out, "IMGB")).To(BeNumerically(">=", eightGiB), "IMGB did not grow to LARGE:\n%s", out)
	}, 5*time.Minute, 10*time.Second).Should(Succeed())
}

// partSizeBytes extracts the SIZE of the partition with PARTLABEL==label from a
// `lsblk -b -P` dump.
func partSizeBytes(lsblk, label string) int64 {
	for _, line := range strings.Split(lsblk, "\n") {
		if !strings.Contains(line, fmt.Sprintf("PARTLABEL=%q", label)) {
			continue
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "SIZE=") {
				var n int64
				fmt.Sscanf(strings.Trim(strings.TrimPrefix(field, "SIZE="), `"`), "%d", &n)
				return n
			}
		}
	}
	return 0
}

// bootDiskPath resolves the boot disk (the parent of the IMGA partition), e.g.
// /dev/vda under evetest's virtio QEMU.
func bootDiskPath(device *evetest.EdgeDevice) (string, error) {
	out, err := runEVE(device, `eve exec pillar sh -c 'lsblk -ndo pkname $(findfs PARTLABEL=IMGA)'`)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("could not resolve boot disk (IMGA parent)")
	}
	return "/dev/" + name, nil
}

// assertCheckDecision asserts storage-resizer's pre-flight check returns the
// expected decision on the live boot disk (mirror assert-check-decision.sh).
func assertCheckDecision(t Gomega, device *evetest.EdgeDevice, want string) {
	t.Eventually(func(g Gomega) {
		disk, err := bootDiskPath(device)
		g.Expect(err).NotTo(HaveOccurred())
		out, err := runEVE(device, "eve exec pillar /usr/bin/storage-resizer check --disk "+disk+" --json")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(fmt.Sprintf("%q", want)),
			"storage-resizer check did not decide %q:\n%s", want, out)
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
}

// settleVaultLocal reboots through the controller until the vault reports a local
// TPM unlock (UnlockMethod==1); a controller-key unlock (2) triggers a reboot,
// no-tpm (3) fails (mirror settle-vault-local.sh).
func settleVaultLocal(t Gomega, device *evetest.EdgeDevice) {
	log := evetest.Logger()
	readUnlock := func() string {
		out, _, err := device.RunShellScript(
			`eve exec pillar sh -c "cat /run/vaultmgr/VaultStatus/*.json 2>/dev/null"`, eveShellTimeout, 0)
		if err != nil {
			return ""
		}
		switch {
		case strings.Contains(out, `"UnlockMethod":1`):
			return "local"
		case strings.Contains(out, `"UnlockMethod":2`):
			return "controller"
		case strings.Contains(out, `"UnlockMethod":3`):
			return "no-tpm"
		}
		return ""
	}
	for attempt := 1; attempt <= 4; attempt++ {
		var decided string
		t.Eventually(func() string { decided = readUnlock(); return decided }, 12*time.Minute, 10*time.Second).
			ShouldNot(BeEmpty(), "vault never reported an unlock method")
		switch decided {
		case "local":
			log.Infof("vault settled: local TPM unlock")
			return
		case "no-tpm":
			t.Expect(decided).NotTo(Equal("no-tpm"), "vault is no-tpm; this test requires TPM")
			return
		default: // controller-key: reboot to re-seal
			log.Infof("vault unlock=controller-key (attempt %d); rebooting to re-seal", attempt)
			device.RequestReboot(true)
		}
	}
	t.Expect(false).To(BeTrue(), "vault did not settle to a local unlock after 4 reboots")
}

// waitVolumemgrReady waits for volumemgr Initialized:true (mirror
// wait-for-volumemgr-ready.sh). The budget must exceed volumemgr's own pre-publish
// block on a slow EVE-k bring-up: up to 20m in WaitForKubernetes (node + KubeVirt +
// Longhorn) plus up to 20m more in storageWait before any VolumeMgrStatus is
// published, so 45m could expire right as volumemgr is released (eden 29346e15).
func waitVolumemgrReady(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func() string {
		out, _, _ := device.RunShellScript(
			"eve exec pillar cat /run/volumemgr/VolumeMgrStatus/volumemgr.json 2>/dev/null", eveShellTimeout, 0)
		return out
	}, 60*time.Minute, 15*time.Second).Should(ContainSubstring(`"Initialized":true`),
		"volumemgr did not reach Initialized:true")
}

// waitLonghornSC waits for the longhorn StorageClass (mirror wait-for-longhorn-sc.sh).
func waitLonghornSC(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func() string {
		out, _, _ := device.RunShellScript("eve exec kube kubectl get sc 2>/dev/null", eveShellTimeout, 0)
		return out
	}, 50*time.Minute, 30*time.Second).Should(ContainSubstring("longhorn"),
		"longhorn StorageClass not ready")
}

// waitAppHasRoutableIPv4 blocks until the app reports at least one routable
// (non-link-local) IPv4 address in its ZInfoApp, or fatals after timeout. This is
// the app-network readiness signal: without a reported IPv4 the harness cannot
// build a direct app-IP SSH endpoint, so a still-converging app looks the same as
// an unreachable one. It logs the address it settles on.
func waitAppHasRoutableIPv4(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, timeout time.Duration) {
	t.Eventually(func(t Gomega) {
		info := device.GetAppInfo(appUUID)
		t.Expect(info).NotTo(BeNil())
		var found string
		for _, netInfo := range info.GetNetwork() {
			for _, ipStr := range netInfo.GetIPAddrs() {
				ip := net.ParseIP(ipStr)
				if ip != nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
					found = ipStr
				}
			}
		}
		t.Expect(found).NotTo(BeEmpty(), "app reports no routable IPv4 yet")
		evetest.Logger().Infof("app reports routable IPv4 %s", found)
	}, timeout, 5*time.Second).Should(Succeed())
}

// assertAppSSH asserts the app is reachable over SSH (returns non-empty hostname).
func assertAppSSH(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, auth evetest.AuthMethod) {
	t.Eventually(func(t Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, auth, "hostname", sshTimeout, 0)
		t.Expect(err).NotTo(HaveOccurred())
		t.Expect(strings.TrimSpace(out)).NotTo(BeEmpty())
	}, 3*time.Minute, 5*time.Second).Should(Succeed())
}

// writeVolumeMarker writes a unique marker into the app's mounted data volume and
// fsyncs it, failing if the volume isn't mounted at mountDir. Run on EVE-kvm,
// where the runx shim formats and mounts the blank volume at MountDir.
func writeVolumeMarker(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, auth evetest.AuthMethod, mountDir, marker string) {
	script := fmt.Sprintf(
		"grep -q ' %s ' /proc/mounts || { echo NOT-MOUNTED; cat /proc/mounts; exit 1; }; "+
			"echo %q > %s/marker && sync && echo WROTE-OK",
		mountDir, marker, mountDir)
	t.Eventually(func(t Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, auth, script, 60*time.Second, 0)
		t.Expect(err).NotTo(HaveOccurred())
		t.Expect(out).To(ContainSubstring("WROTE-OK"))
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// assertVolumeMarker verifies the marker survived the conversion by reading it off
// the data volume's RAW block device from inside the app — EVE-k does not
// auto-mount the container data volume at MountDir (lf-edge/eve#6145). The data
// volume is a virtio disk after the rootfs (/dev/vd[b-z]); grep it for the marker.
func assertVolumeMarker(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, auth evetest.AuthMethod, marker string) {
	script := fmt.Sprintf(
		"for d in /dev/vd[b-z] /dev/sd[b-z]; do [ -b \"$d\" ] || continue; "+
			"grep -aq %q \"$d\" 2>/dev/null && { echo FOUND-ON $d; exit 0; }; done; "+
			"echo NOT-FOUND; ls -l /dev/vd* /dev/sd* 2>/dev/null; lsblk 2>/dev/null; blkid 2>/dev/null; exit 1",
		marker)
	t.Eventually(func(t Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, auth, script, 90*time.Second, 0)
		t.Expect(err).NotTo(HaveOccurred())
		t.Expect(out).To(ContainSubstring("FOUND-ON"))
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
}

// isK3sReady reports whether the single k3s node is ready with healthy storage.
func isK3sReady(info *eveinfo.ZInfoKubeCluster) bool {
	if info == nil || len(info.Nodes) != 1 {
		return false
	}
	if info.Storage.Health != eveinfo.ServiceStatus_SERVICE_STATUS_HEALTHY {
		return false
	}
	for _, cond := range info.Nodes[0].GetConditions() {
		if cond.GetType() == eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY {
			return cond.GetSet()
		}
	}
	return false
}
