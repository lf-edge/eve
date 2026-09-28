// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Helpers observing the k3s node's containerd snapshotter stores and the
// free space they compete for. Used by TestSnapshotterUpgrade; kept out of
// the test file so that file carries only the test itself.

const (
	// containerdSnapshotRoot is containerd's root from
	// pkg/kube/config-k3s.toml. Snapshotter stores live directly under it,
	// one directory per snapshotter.
	containerdSnapshotRoot = "/persist/vault/containerd"

	overlayfsSnapshotter = "overlayfs"
	erofsSnapshotter     = "erofs"

	// ballastPath is the file used to consume free space on /persist. Kept
	// outside /persist/vault so it cannot be mistaken for containerd state
	// by anything walking the vault.
	ballastPath = "/persist/evetest-snapshotter-ballast"

	// shellTimeout bounds every inspection command. These are all cheap
	// reads except the du walks, which cross a few thousand directories.
	shellTimeout = 120 * time.Second

	// The app fixture: a container that stays alive in both a VM and a pod.
	loggerCtrImage = "lfedge/evetest-logger-ctr"
	loggerCtrTag   = "1.0"

	// Emitted every few seconds by loggerCtrImage's init.sh.
	loggerHeartbeatRE = `evetest-logger-ctr: heartbeat [0-9]+`
)

// snapshotterStoreDir returns the on-device path of one snapshotter's store.
func snapshotterStoreDir(snapshotter string) string {
	return fmt.Sprintf("%s/io.containerd.snapshotter.v1.%s",
		containerdSnapshotRoot, snapshotter)
}

// snapshotterUsage reports the allocated size in bytes and the number of
// snapshots held by one containerd snapshotter on the device. A snapshotter
// that has never been used reports (0, 0) rather than an error, so a caller
// can compare populations across an upgrade without special-casing.
//
// du is given -x deliberately: an erofs snapshot directory contains fs/, the
// mountpoint where that layer's image is mounted, so a du that crosses into
// it counts both the compressed image and its decompressed contents and
// roughly doubles the figure. -x keeps the walk on /persist.
//
// containerd runs in the kube container, and so does its state, so these run
// under "eve exec kube" rather than the host shell.
func snapshotterUsage(
	device *evetest.EdgeDevice, snapshotter string) (bytes uint64, count int, err error) {
	dir := snapshotterStoreDir(snapshotter)
	script := fmt.Sprintf(
		`eve exec kube sh -c '`+
			`if [ -d %[1]s ]; then du -sxk %[1]s | cut -f1; else echo 0; fi; `+
			`if [ -d %[1]s/snapshots ]; then ls %[1]s/snapshots | wc -l; else echo 0; fi'`,
		dir)
	stdout, _, err := device.RunShellScript(script, shellTimeout, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("reading %s usage: %w", snapshotter, err)
	}
	fields := strings.Fields(stdout)
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf(
			"unexpected output reading %s usage: %q", snapshotter, stdout)
	}
	kb, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing %s size %q: %w", snapshotter, fields[0], err)
	}
	count, err = strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, fmt.Errorf("parsing %s count %q: %w", snapshotter, fields[1], err)
	}
	return kb * 1024, count, nil
}

// persistSpace reports free and total bytes on /persist, which is where both
// snapshotter stores live and therefore the resource a conversion competes
// for.
func persistSpace(device *evetest.EdgeDevice) (free, total uint64, err error) {
	stdout, _, err := device.RunShellScript(
		`eve exec kube df -k /persist | tail -1 | awk '{print $2, $4}'`,
		shellTimeout, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("reading /persist space: %w", err)
	}
	fields := strings.Fields(stdout)
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("unexpected df output: %q", stdout)
	}
	totalKB, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing total %q: %w", fields[0], err)
	}
	freeKB, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing free %q: %w", fields[1], err)
	}
	return freeKB * 1024, totalKB * 1024, nil
}

// fillPersist consumes free space on /persist so that only leaveFree bytes
// remain, and reports how many bytes it claimed.
//
// fallocate rather than dd: it reserves the extent without writing it, so a
// multi-gigabyte squeeze is instant instead of disk-bound. The test only
// needs the space to be unavailable, not to contain anything.
func fillPersist(device *evetest.EdgeDevice, leaveFree uint64) (claimed uint64, err error) {
	free, _, err := persistSpace(device)
	if err != nil {
		return 0, err
	}
	if free <= leaveFree {
		return 0, fmt.Errorf(
			"/persist already has only %d bytes free, wanted to leave %d",
			free, leaveFree)
	}
	claimed = free - leaveFree
	_, _, err = device.RunShellScript(
		fmt.Sprintf("eve exec kube fallocate -l %d %s", claimed, ballastPath),
		shellTimeout, 0)
	if err != nil {
		return 0, fmt.Errorf("allocating %d-byte ballast: %w", claimed, err)
	}
	return claimed, nil
}

// removeBallast frees whatever fillPersist claimed. Safe to call when no
// ballast exists, so it can be deferred unconditionally.
func removeBallast(device *evetest.EdgeDevice) error {
	_, _, err := device.RunShellScript(
		fmt.Sprintf("eve exec kube rm -f %s", ballastPath), shellTimeout, 0)
	if err != nil {
		return fmt.Errorf("removing ballast: %w", err)
	}
	return nil
}

// nodeConditionSet reports whether the single node in the cluster info has
// the given condition set. It returns false for a nil or multi-node info so
// it can be used directly as an Eventually predicate.
func nodeConditionSet(
	info *eveinfo.ZInfoKubeCluster, want eveinfo.KubeNodeConditionType) bool {
	if info == nil || len(info.Nodes) != 1 {
		return false
	}
	for _, cond := range info.Nodes[0].GetConditions() {
		if cond.GetType() == want {
			return cond.GetSet()
		}
	}
	return false
}

// k3sNodeIsReady reports whether the single-node cluster is fully up:
// the node is Ready and storage is healthy. Shared by TestEVEUpgrade and
// TestSnapshotterUpgrade.
func k3sNodeIsReady(info *eveinfo.ZInfoKubeCluster) bool {
	if info == nil || len(info.Nodes) != 1 {
		return false
	}
	if info.Storage.Health != eveinfo.ServiceStatus_SERVICE_STATUS_HEALTHY {
		return false
	}
	return nodeConditionSet(info, eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY)
}

// snapshotterTestApp builds the app config used by TestSnapshotterUpgrade.
//
// virtMode is what the test is really parameterized on, because it selects
// which code path resolves the app image on eve-k:
//
//   - VmMode_NOHYPER makes domainmgr's kube path create a plain ReplicaSet
//     pod (hypervisor/kubevirt.go CreateReplicaPodConfig), whose image is
//     resolved by CRI and therefore by the configured snapshotter. This is
//     the path the overlayfs->erofs switch actually changes.
//   - VmMode_HVM makes it create a VMIRS instead, and pillar converts the
//     container image to a qcow2 rolled into a PVC. The app image never
//     reaches the CRI snapshotter, so this variant is the control.
//
// The image is evetest-logger-ctr rather than evetest-ubuntu-ctr because it
// has to survive in both shapes. ubuntu-ctr's init.sh ends in `exec /bin/bash`,
// which has a console in a VM but reads EOF and exits immediately in a pod
// with no stdin/tty -- the container then CrashLoopBackOffs. logger-ctr loops
// forever emitting heartbeats, so it stays up either way, and its liveness is
// observable through the EVE app-log pipeline instead of SSH (which would
// otherwise need a port forward into a pod).
//
// A VIF is mandatory, not cosmetic: CreateReplicaPodConfig refuses to build a
// pod with an empty VifList ("no network selections, exit").
func snapshotterTestApp(displayName string, niUUID uuid.UUID,
	virtMode eveconfig.VmMode) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName: displayName,
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: loggerCtrImage,
			Tag:       loggerCtrTag,
		},
		VirtualizationMode: virtMode,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	}
}

// countHeartbeats returns how many heartbeat lines the controller has received
// from the app. The counter restarts at 1 on every container (re)creation, so
// a rising count is proof the container is alive now -- not merely that it ran
// at some point before the upgrade.
func countHeartbeats(device *evetest.EdgeDevice, appUUID uuid.UUID) int {
	return len(device.GetAppLogs(appUUID, evetest.LogMsgMatch{
		MsgMatchesRegexp: *regexp.MustCompile(loggerHeartbeatRE),
	}))
}

// snapshotterTestNI builds the local network instance the test app attaches to.
func snapshotterTestNI() evetest.LocalNetworkInstanceConfig {
	return evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "eth0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	}
}

// activatedVersion returns the EVE version the device is actually
// running, from the SwList entry flagged Activated. Empty until device
// info has been published, so it works directly inside Eventually.
func activatedVersion(device *evetest.EdgeDevice) string {
	info := device.GetDeviceInfo()
	if info == nil {
		return ""
	}
	for _, sw := range info.GetSwList() {
		if sw.GetActivated() {
			return sw.GetShortVersion()
		}
	}
	return ""
}

// nodeHasDiskPressure reports whether kubelet has marked the node under
// disk pressure.
//
// Read with kubectl rather than from the EVE API, which cannot express
// it: types.zedkubetypes ZKubeNodeInfo only ever emits a READY
// condition, so DISK_PRESSURE is defined in the eve-api enum but never
// populated. Asserting on the API here would wait out the full timeout
// on a node that is, in fact, under pressure.
func nodeHasDiskPressure(device *evetest.EdgeDevice) bool {
	out, _, err := device.RunShellScript(
		`eve exec kube kubectl get nodes -o `+
			`jsonpath='{.items[*].status.conditions[?(@.type=="DiskPressure")].status}'`,
		shellTimeout, 0)
	if err != nil {
		return false
	}
	return strings.Contains(out, "True")
}
