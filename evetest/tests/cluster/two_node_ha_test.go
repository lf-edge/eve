// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

// failoverCycleCountParamKey is the key for the parameter controlling how
// many times TestTwoNodeHACluster repeats its failover/recovery cycle.
const failoverCycleCountParamKey = "CLUSTER_FAILOVER_CYCLE_COUNT"

// placementSettle is how long a node must have been ready to receive apps
// before it pulls the apps designated to it back
// (kubernetes.vmi.deschedule.periodic.settle). Shortened from the default 3
// minutes: the test waits for it at every move of the apps back to their
// designated node.
const placementSettle = 30 * time.Second

// placementSettleKey is kubernetes.vmi.deschedule.periodic.settle, referenced
// by its literal string until evetest depends on a pillar version that
// defines types.KubernetesVmiDeschedulePeriodicSettle.
const placementSettleKey = types.GlobalSettingKey("kubernetes.vmi.deschedule.periodic.settle")

var failoverCycleCountParam = evetest.TestParameterDefinition{
	Key:          failoverCycleCountParamKey,
	DefaultValue: uint32(1),
	Description: evetest.TestParameterDescription{
		Summary: "Number of times to repeat the non-seed/seed failover and quorum-recovery cycle",
		Default: "1",
	},
}

// haApp is one of the apps TestTwoNodeHACluster places on the non-seed and
// follows through every failover.
type haApp struct {
	displayName string
	config      evetest.ApplicationInstanceConfig
	uuid        uuid.UUID
	// hostname is a substring of what `hostname` prints inside the app.
	hostname string
	// diskMarkerPath is a file, or a raw block device, on a replicated
	// Longhorn volume of the app, so data written to it must follow the app
	// between nodes.
	diskMarkerPath string
	// diskMarker is the content diskMarkerPath must hold: written before the
	// first failover, and replaced by what survives the cluster link cut.
	diskMarker string
	// startTime is the baseline for the no-downtime checks.
	startTime int64
}

// appNodeName returns the k3s node name currently hosting the app (matched
// by display name, allowing for Kubernetes' hash suffix - mirrors
// edgecluster.go's unexported findAppNodeName), or "" if not yet reported.
func appNodeName(info *eveinfo.ZInfoKubeCluster, appDisplayName string) string {
	prefix := appDisplayName + "-"
	matches := func(name string) bool {
		return name == appDisplayName || strings.HasPrefix(name, prefix)
	}
	for _, app := range info.GetEveApps() {
		if matches(app.GetName()) && app.GetNodeName() != "" {
			return app.GetNodeName()
		}
	}
	for _, vm := range info.GetEveVmApps() {
		if matches(vm.GetName()) && vm.GetNodeName() != "" {
			return vm.GetNodeName()
		}
	}
	return ""
}

// witnessJoined returns a predicate checking that ZInfoKubeCluster.Witness
// reports the expected witness IP in JOINED state. The witness carries no
// separate recovery/convergence status of its own: unlike a node it never
// holds a partial share of the cluster's data, so JOINED already means
// caught up.
func witnessJoined(witnessIP string) func(*eveinfo.ZInfoKubeCluster) bool {
	return func(info *eveinfo.ZInfoKubeCluster) bool {
		w := info.GetWitness()
		if w == nil || w.GetWitnessIp() != witnessIP {
			return false
		}
		return w.GetState() == eveinfo.WitnessEtcdState_WITNESS_ETCD_STATE_JOINED
	}
}

// nodeRecoveryConverged returns a predicate checking that the named node's
// KubeNodeInfo.Recovery reports the expected applied generation, with no
// error and no convergence in progress.
func nodeRecoveryConverged(
	nodeName string, wantGeneration uint32) func(*eveinfo.ZInfoKubeCluster) bool {
	return func(info *eveinfo.ZInfoKubeCluster) bool {
		for _, node := range info.GetNodes() {
			if node.GetName() != nodeName {
				continue
			}
			rec := node.GetRecovery()
			return rec.GetAppliedGeneration() == wantGeneration &&
				!rec.GetConverging() && rec.GetError() == nil
		}
		return false
	}
}

// nodeIsReady reports whether the named node is listed with its Ready
// condition set.
func nodeIsReady(info *eveinfo.ZInfoKubeCluster, nodeName string) bool {
	for _, node := range info.GetNodes() {
		if node.GetName() != nodeName {
			continue
		}
		for _, cond := range node.GetConditions() {
			if cond.GetType() == eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY &&
				cond.GetSet() {
				return true
			}
		}
	}
	return false
}

// haState is the redundancy level of a 2-node HA cluster that can be read
// off a single cluster report.
type haState string

const (
	haHealthy   haState = "HEALTHY"
	haDegraded  haState = "DEGRADED"
	haRestoring haState = "RESTORING"
)

// haStateFromReport classifies a 2-node HA cluster from a ZInfoKubeCluster
// alone, the way a controller that only keeps the last report would:
//   - HEALTHY: two nodes listed, both Ready, witness JOINED at witnessIP.
//   - DEGRADED: exactly one node listed and it is Ready (the survivor of a
//     quorum recovery, with quorum from the co-located witness).
//   - RESTORING: anything else.
//
// A controller may also fold in state of its own, such as device
// connectivity, which a test cannot observe and which is not modelled.
func haStateFromReport(info *eveinfo.ZInfoKubeCluster, witnessIP string) haState {
	nodes := info.GetNodes()
	if len(nodes) == 1 {
		if nodeIsReady(info, nodes[0].GetName()) {
			return haDegraded
		}
		return haRestoring
	}
	if len(nodes) != 2 || !witnessJoined(witnessIP)(info) {
		return haRestoring
	}
	for _, node := range nodes {
		if !nodeIsReady(info, node.GetName()) {
			return haRestoring
		}
	}
	return haHealthy
}

// haStateIs returns a predicate checking that the report classifies as want.
func haStateIs(want haState, witnessIP string) func(*eveinfo.ZInfoKubeCluster) bool {
	return func(info *eveinfo.ZInfoKubeCluster) bool {
		return haStateFromReport(info, witnessIP) == want
	}
}

// waitForQuorumLostReport waits for a report on updates in which the node
// says it has lost the quorum of its cluster. It returns the last report
// received, and whether it says so; the last report is nil if none arrived.
// Reports sent before the watch started do not count, so one from before the
// loss cannot satisfy it.
func waitForQuorumLostReport(updates <-chan *eveinfo.ZInfoClusterNode,
	timeout time.Duration) (last *eveinfo.ZInfoClusterNode, lost bool) {
	deadline := time.After(timeout)
	for {
		select {
		case report, ok := <-updates:
			if !ok {
				return last, false
			}
			last = report
			if report.GetQuorum() == eveinfo.ZInfoClusterNodeQuorum_Z_INFO_CLUSTER_NODE_QUORUM_LOST {
				return last, true
			}
		case <-deadline:
			return last, false
		}
	}
}

// appStartTimeScript prints when the app's PID 1 started, as a Unix
// timestamp: the kernel's boot time plus the process start time, which
// /proc/1/stat gives in clock ticks since boot (field 22, the 20th after the
// parenthesised command name, which may contain spaces). In a VM, PID 1 is
// the guest's init, so this is the VM's boot time. A NOHYPER container shares
// the node's kernel, whose boot time says nothing about the app, but its PID
// 1 is the container's entrypoint. Either way the value changes exactly when
// the app restarts.
const appStartTimeScript = `btime=$(awk '/^btime/{print $2}' /proc/stat)
ticks=$(sed 's/.*) //' /proc/1/stat | awk '{print $20}')
echo $((btime + ticks / $(getconf CLK_TCK)))`

// getAppStartTime returns when the app last started (see
// appStartTimeScript). Use to detect whether the app was restarted.
//
// The SSH call is retried within a short Eventually: it runs right after
// powering a cluster node off/on, and a transient connection race at that
// moment (e.g. "unexpected packet in response to channel open") must not be
// mistaken for an app restart.
func getAppStartTime(t *WithT, cluster *evetest.EdgeCluster, appUUID uuid.UUID,
	auth evetest.AuthMethod, timeout time.Duration) int64 {
	var startTime int64
	t.Eventually(func(t Gomega) {
		output, _, err := cluster.RunShellScriptInsideApp(appUUID, auth,
			appStartTimeScript, timeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		parsed, parseErr := strconv.ParseInt(strings.TrimSpace(output), 10, 64)
		t.Expect(parseErr).ToNot(HaveOccurred())
		startTime = parsed
	}, time.Minute, 3*time.Second).Should(Succeed())
	return startTime
}

// outboundCheckScript fetches a page from the SDN HTTP server. The name is
// resolved by the network instance's DNS, served on its gateway, which is
// the app's default gateway: EVE-k gives a NOHYPER container fixed public
// DNS servers instead, which do not know the SDN's names.
const outboundCheckScript = `gw=$(ip route | awk '/^default/ {print $3; exit}')
addr=$(nslookup http-server.test "$gw" | awk '/^Address/ && $2 !~ /#/ {a=$2} END {print a}')
[ -n "$addr" ] || { echo "http-server.test not resolved by $gw" >&2; exit 1; }
curl -sS --resolve "http-server.test:80:$addr" http://http-server.test/helloworld`

// verifyAppReachable checks SSH (through the app's port forwarding to port
// 22) and outbound connectivity (curl to an SDN HTTP endpoint) for the app,
// wherever in the cluster it currently runs. hostname is a substring of the
// app's hostname, which confirms SSH reached the right app.
func verifyAppReachable(t *WithT, cluster *evetest.EdgeCluster, appUUID uuid.UUID,
	hostname string, auth evetest.AuthMethod, sshTimeout time.Duration) {
	log := evetest.Logger()
	log.Infof("Verifying app %q is reachable...", appUUID)
	t.Eventually(func(t Gomega) {
		output, _, err := cluster.RunShellScriptInsideApp(appUUID, auth,
			"hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(hostname))
	}, 3*time.Minute, 3*time.Second).Should(Succeed())

	output, _, err := cluster.RunShellScriptInsideApp(appUUID, auth,
		outboundCheckScript, sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello world!"))
}

// writeDiskMarker writes a one-line, caller-supplied marker to the file or
// block device at path inside the app and syncs it, then reads it back and
// returns the exact content written, for later comparison by
// verifyDiskMarker. marker should be unique per call (e.g. the name of the
// checkpoint it is establishing a baseline for) so a failed comparison
// names which write is missing.
//
// path must be on a Longhorn-backed volume. Checking its content after a
// failover proves the write made it onto the node the app lands on next -
// i.e. the surviving node already had a synced Longhorn replica - not merely
// that the running process state carried over.
//
// shell is the cluster, to reach the app wherever it runs, or a device, to
// reach the instance that device runs.
func writeDiskMarker(t *WithT, shell appShell, appUUID uuid.UUID,
	path string, auth evetest.AuthMethod, timeout time.Duration, marker string) string {
	content := fmt.Sprintf("ha-disk-marker:%s:%d", marker, time.Now().UTC().UnixNano())
	script := fmt.Sprintf("printf '%s\\n' > %s && sync && head -n1 %s",
		content, path, path)
	output, _, err := shell.RunShellScriptInsideApp(appUUID, auth, script, timeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSpace(output)).To(Equal(content))
	return content
}

// appShell runs a script inside an app: evetest.EdgeCluster wherever the app
// runs, evetest.EdgeDevice in the instance that device runs.
type appShell interface {
	RunShellScriptInsideApp(appUUID uuid.UUID, auth evetest.AuthMethod,
		script string, timeout time.Duration,
		stdoutWatchdogTimeout time.Duration) (stdout, stderr string, err error)
}

// readDiskMarker returns the first line of the file or block device at path
// inside the app, wherever in the cluster it runs.
func readDiskMarker(t *WithT, cluster *evetest.EdgeCluster, appUUID uuid.UUID,
	path string, auth evetest.AuthMethod, timeout time.Duration) string {
	output, _, err := cluster.RunShellScriptInsideApp(appUUID, auth,
		fmt.Sprintf("head -n1 %s", path), timeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	return strings.TrimSpace(output)
}

// verifyDiskMarker checks that the first line of the file or block device at
// path is still exactly wantContent, proving data written before a node
// failover is still present afterward: the surviving/rescheduled-onto node's
// Longhorn replica, not just the pod definition, carried the write across.
func verifyDiskMarker(t *WithT, cluster *evetest.EdgeCluster, appUUID uuid.UUID,
	path string, auth evetest.AuthMethod, timeout time.Duration, wantContent string) {
	t.Expect(readDiskMarker(t, cluster, appUUID, path, auth, timeout)).To(Equal(wantContent),
		"disk marker content changed or went missing after failover - "+
			"the write did not survive on the node the app is now running on")
}

// TestTwoNodeHACluster verifies EVE-k's 2-node HA (witness) feature: two K3s
// server nodes plus a lightweight etcd-only witness co-located with the
// seed/bootstrap node, tolerating the loss of either physical node - either
// automatically (non-seed dies, quorum survives) or via a controller-driven
// quorum recovery (seed dies, quorum lost).
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort(devName[:]...) -- a dedicated cluster
//     port per device (same shape as the 3-node cluster test, but built
//     for exactly the 2 devices requested here, so it's a distinct
//     network model instance from the 3-node test's - this rules out
//     device-VM reuse between the two tests for now).
//
// Device configuration
// --------------------
//   - Two RequireEdgeDevice entries via clusterDeviceRequirements (same as
//     the 3-node test: Kubevirt, fresh image, ext4 by default), but with
//     MinCPUs/MinRAMInMiB raised to 8/16384. The 3-node test's default 4/8
//     floor spreads etcd, kubevirt, Longhorn, multus and traefik across
//     three real voting members; a quorum recovery here collapses to a
//     single voting member, so the survivor alone carries all of that plus
//     whatever the dead node was running, on the same per-node floor. At
//     4/8 that was enough to make etcd too slow to serve its own
//     leader-election lease renewals in time, crashing k3s outright.
//   - ClusterConfig with two ClusterNode entries: edge-dev1 (seed,
//     BootstrapNode=true, 10.244.244.2/24) and edge-dev2 (non-seed,
//     10.244.244.3/24), ClusterInterface="ethernet1".
//   - Witness configured via SetWitness(10.244.244.5) - co-locates with
//     whichever device currently owns JoinServerIp (initially edge-dev1).
//   - shim-vm-app (lfedge/evetest-ubuntu-ctr:1.3): VirtualizationMode left
//     at its default, so the container runs in a shim VM backed by a
//     VMIRS/VMI, with its root filesystem on a replicated Longhorn volume.
//     SSH on port 2222.
//   - nohyper-app (the same image): VirtualizationMode NOHYPER, a
//     container run in a plain ReplicaSet/pod, not a VM. Its root
//     filesystem is the image on the node it runs on (the image is
//     downloaded to every node) and is not replicated, so its data lives
//     on a blank volume, which is. EVE-k cannot mount a volume into a
//     NOHYPER container (lf-edge/eve#6145), so the volume is attached as
//     the raw block device /dev/xvdb. SSH on port 2223.
//   - Both apps have PREFERRED affinity and DesignatedNodeName=edge-dev2
//     (the non-seed). There are two because EVE-k moves them through
//     different code paths at every failover. The apps are deliberately
//     kept away from the seed so that losing the seed (and the co-located
//     witness) never interrupts them, only the control plane; losing the
//     non-seed instead causes a short, fully automatic reschedule by K3s,
//     and a failback by the designated node, which in a 2-node HA cluster
//     pulls back its apps whenever they run elsewhere.
//     Unlike the seed role, which follows join_server_ip on its own, an
//     app's designated node does not move by itself: the controller
//     repoints it explicitly after the quorum recovery below, once the old
//     seed has rejoined as the new non-seed.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//     With zfs the devices are provisioned by the installer with
//     eve_install_k3s_witness, so the witness gets its own zvol.
//   - CLUSTER_FAILOVER_CYCLE_COUNT (uint32, defaults to 1): how many times
//     phases 8-23 repeat. Each cycle ends with the seed and non-seed roles
//     swapped between the two devices, so the next cycle exercises the
//     same steps with the physical devices reversed. The quorum recovery
//     generation keeps counting up across cycles (cycle N expects
//     generation N) rather than resetting. Checkpoint names from phases
//     8-23 get a "-cycle-N" suffix when this is set above 1.
//
// Phases
// ------
//  1. setup-done
//  2. initial-config-applied
//  3. nodes-are-ready
//  4. witness-is-ready: ZInfoKubeCluster.Witness reports JOINED at the
//     configured IP, with no recovery error/in-progress. The report must
//     then classify as a healthy cluster (two Ready nodes, witness JOINED),
//     a controller deriving its HA state from the last report would.
//  5. <app>-config-is-submitted / app-is-deployed: the apps are deployed
//     one at a time, each with the standard timeout, as the device builds
//     the root volumes of container images one at a time. Both apps land
//     on the non-seed node.
//  6. app-verified-on-non-seed: SSH (hostname) + outbound curl checks for
//     each app.
//  7. disk-marker-written: a unique line is written to a file on each
//     app's Longhorn-backed volume (shim-vm-app's root volume, nohyper-app's
//     raw data volume) and fsync'd. Every later app-move checkpoint re-reads
//     it and expects the exact same content (until step 13 replaces it),
//     proving the node
//     the app lands on next already had (or, for the rejoined old seed,
//     correctly rebuilt) a synced Longhorn replica - not just that the
//     running process state carried over.
//  8. non-seed-powered-off: the seed and witness must report the dead node
//     as not Ready (non-seed-reported-down).
//  9. app-failed-over-to-seed: quorum survives (seed+witness=2 of 3), K3s
//     reschedules both apps onto the seed automatically; SSH+curl and the
//     disk marker re-verified there. The apps restart here (expected - the
//     pods restarted elsewhere).
//  10. non-seed-powered-on
//  11. app-failed-back-to-non-seed: the non-seed pulls both apps back once
//     it has been healthy for a while;
//     SSH+curl and the disk marker re-verified. The apps restart again.
//  12. cluster-link-cut: the non-seed's cluster port (eth1) is taken down in
//     the SDN, while its management port stays up, so both devices keep
//     running and reaching the controller. The seed and the witness keep
//     quorum and must report the non-seed as not Ready
//     (cluster-link-cut-reported).
//  13. app-running-on-both-nodes: the seed cannot tell a cut link from a
//     dead node, so it fails both apps over to itself, while the isolated
//     non-seed, without quorum, keeps its own instances running. Each
//     device's forwarded SSH port reaches an instance of each app. Each
//     instance then writes a disk marker of its own
//     (split-disk-markers-written): the app's volume has split into two
//     copies that both change.
//  14. cluster-link-restored: the port is brought back up, and the report
//     must describe a healthy cluster again.
//  15. app-only-on-non-seed: each app must end up running on the non-seed
//     only, with no instance left on the seed, and with the disk marker
//     the seed's instance wrote during the cut: the seed and the witness
//     hold quorum, so Longhorn keeps the seed's copy of the volume and
//     rebuilds the non-seed's from it, discarding what the isolated
//     instance wrote. The apps restart here (last expected
//     restart; each app's start time, when its PID 1 started, is
//     re-baselined here for the no-downtime checks below).
//  16. seed-powered-off: witness dies with it (2 of 3 votes gone) - quorum
//     lost, but the apps were never on the seed. The cluster-wide report
//     stops, as its elected sender needs the Kubernetes API, so the
//     survivor must report on its own that it lost quorum
//     (seed-loss-reported).
//  17. no-downtime-confirmed: each app's start time is compared against the
//     step-15 baseline and must be unchanged - proves the control-plane
//     outage never touched the running apps.
//  18. k3s-unresponsive-confirmed: `eve exec kube kubectl get nodes` over
//     SSH to the surviving (non-seed) device's EVE host must fail/timeout
//     - the local apiserver can't serve requests without quorum.
//  19. quorum-recovery-triggered: TriggerQuorumRecovery(edge-dev2) promotes
//     the non-seed to be the new seed, and withdraws the dead seed's
//     cluster config in the same config change, so it is never told to
//     converge to the new generation at all.
//  20. cluster-reset-completed: the new seed's KubeNodeInfo.Recovery
//     reaches the new generation with no error, and the witness has
//     followed the new seed (JOINED again), and the report lists only that
//     node, Ready (a degraded, single-node cluster). Start times are
//     re-checked against the step-15/17 baseline - the reset itself must
//     not interrupt the apps either.
//  21. old-seed-powered-on: expects the power-on reboot plus one more -
//     with no cluster config to find, it converts back to single-node the
//     same way TestClusterToSingleConversion does.
//  22. old-seed-converted-to-single / old-seed-rejoined: once it reports
//     itself as a lone ready node, it is rejoined as a plain (non-
//     bootstrap) member through the ordinary join workflow, and the
//     controller repoints both apps' DesignatedNodeName at it in the same
//     config change - the apps are placed by node id alone, so nothing else
//     would move them here.
//  23. app-moved-to-new-non-seed: once edge-dev1 has rejoined and been
//     healthy for a while, it pulls both apps onto itself; final SSH+curl
//     checks, plus a final disk-marker check - the old seed's Longhorn
//     replica was wiped along with everything else in steps 20-22, so
//     finding the current marker here proves Longhorn rebuilt it correctly
//     from the surviving node's copy before the app started.
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite. Like the other cluster tests this runs only on eve-k
func TestTwoNodeHACluster(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
		failoverCycleCountParam,
	)

	// Get parameter values set for this test execution.
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()
	failoverCycles := evetest.GetTestParameter[uint32](failoverCycleCountParamKey)

	// Set up the test harness and specify the test prerequisites.
	const numNodes = 2
	var requiredDevices [numNodes]evetest.Requirement
	var devName [numNodes]string
	for i := 0; i < numNodes; i++ {
		devName[i] = fmt.Sprintf("edge-dev%d", i+1)
		req := clusterDeviceRequirements(devName[i], withTPM, filesystem, false)
		// Raised past the 4 vCPU/8 GiB floor: a quorum recovery leaves the
		// survivor as the cluster's sole etcd voter, running the whole
		// stack (kubevirt, Longhorn, multus, traefik) alone rather than
		// sharing it with peers the way the 3-node test's nodes do.
		req.MinCPUs = 8
		req.MinRAMInMiB = 16384
		if filesystem == evetest.FilesystemZFS {
			// The witness zvol can only be reserved at install time, so
			// ZFS runs go through the installer rather than a live image.
			req.DeviceReusePolicy = evetest.CreateFromScratchWithInstaller
			req.WithGrubOptions = append(req.WithGrubOptions,
				`set_global dom0_extra_args "$dom0_extra_args eve_install_k3s_witness "`)
		}
		requiredDevices[i] = req
	}
	netModel := netmodels.SeparateClusterPort(devName[:]...)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netModel,
	}
	var requirements []evetest.Requirement
	requirements = append(requirements, requiredDevices[:]...)
	requirements = append(requirements, requiredNetModel)
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	// Build the cluster configuration: edge-dev1 is the seed/bootstrap,
	// edge-dev2 is the non-seed.
	const witnessIP = "10.244.244.5"
	nodes := [numNodes]evetest.ClusterNode{
		{
			DevName:          devName[0],
			ClusterIP:        evetest.IPAddressWithPrefix("10.244.244.2/24"),
			ClusterInterface: "ethernet1",
			BootstrapNode:    true,
		},
		{
			DevName:          devName[1],
			ClusterIP:        evetest.IPAddressWithPrefix("10.244.244.3/24"),
			ClusterInterface: "ethernet1",
		},
	}
	clusterConfig := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE,
		nodes[:]...,
	)
	clusterConfig.SetWitness(evetest.IPAddress(witnessIP))

	// kubernetes.vmi.deschedule.events is deliberately left unset: in a
	// 2-node HA cluster every move of an app back to its designated node
	// must happen without it. Its settle period is shortened (see
	// placementSettle).
	configProps := types.NewConfigItemValueMap()
	configProps.SetGlobalValueInt(placementSettleKey,
		uint32(placementSettle.Seconds()))
	clusterConfig.SetConfigProperties(configProps)

	// Configure network adapters and networks (applied to all devices).
	dhcpNet := clusterConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	noIPNet := clusterConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet1",
			PhysicalLabel: "eth1",
			InterfaceName: "eth1",
			NetworkUUID:   noIPNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		})

	// Apply the initial configuration to each device in parallel.
	cluster := evetest.NewEdgeCluster("test-two-node-ha-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(30 * time.Minute)
	evetest.Checkpoint("nodes-are-ready")

	cluster.WaitUntilClusterInfoSatisfies(5*time.Minute, false,
		fmt.Sprintf("witness to join at %s", witnessIP), witnessJoined(witnessIP))
	evetest.Checkpoint("witness-is-ready")

	cluster.WaitUntilClusterInfoSatisfies(2*time.Minute, false,
		"the report to describe a healthy 2-node cluster", haStateIs(haHealthy, witnessIP))
	evetest.Checkpoint("cluster-reported-healthy")

	// Deploy the apps into the cluster, preferring the non-seed node.
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
	newAppConfig := func(displayName string, mode eveconfig.VmMode,
		sshPort uint16) evetest.ApplicationInstanceConfig {
		return evetest.ApplicationInstanceConfig{
			DisplayName:        displayName,
			Activate:           true,
			VirtualizationMode: mode,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				// 1.2+: init.sh keeps a NOHYPER container (no stdin) running.
				Tag: "1.3",
			},
			CPUs:        1,
			MemoryBytes: 500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: niUUID,
					PortFwdRules: []evetest.PortFwdRule{
						{
							Protocol:     evetest.NetworkProtocolTCP,
							EdgeNodePort: sshPort,
							AppPort:      22,
						},
					},
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
	shimVMApp := &haApp{
		displayName:    "shim-vm-app",
		config:         newAppConfig("shim-vm-app", eveconfig.VmMode_PV, 2222),
		diskMarkerPath: "/root/ha-disk-marker.txt",
	}
	nohyperApp := &haApp{
		displayName: "nohyper-app",
		config:      newAppConfig("nohyper-app", eveconfig.VmMode_NOHYPER, 2223),
		// See nohyperDataVolume.
		diskMarkerPath: "/dev/xvdb",
	}
	// A NOHYPER container's root filesystem is not replicated, so it keeps
	// its data on a volume of its own. Designated to the same node as the
	// app; UpdateApplication repoints it together with the app. Attached
	// raw (no MountDir): EVE-k creates every volume in Block mode, and a
	// mount point makes the pod mount it as a filesystem, which Kubernetes
	// refuses (lf-edge/eve#6145). domainmgr names the app's disks xvda,
	// xvdb, ... in order, and the image is the first.
	nohyperDataVolume := clusterConfig.AddBlankVolume(evetest.ClusterBlankVolumeConfig{
		DisplayName:        "nohyper-app-data",
		SizeBytes:          256 * evetest.MiB,
		DesignatedNodeName: devName[1], // non-seed
	})
	nohyperApp.config.Mounts = []evetest.MountConfig{
		{VolumeUUID: nohyperDataVolume},
	}
	apps := []*haApp{shimVMApp, nohyperApp}
	// Placed by plain node id. A pod's affinity is immutable once it is
	// running, so moving the app once the non-seed role changes hands is
	// the controller's job, not something the initial placement can do on
	// its own: after the quorum recovery below, the controller repoints
	// DesignatedNodeName at whichever device is the non-seed then, and that
	// device pulls the running app onto itself.
	//
	// DesignatedNodeName also names the node that downloads the volume,
	// and is the node the app first lands on.
	//
	// Deployed one at a time: the device converts the root volume of each
	// container image in turn, so deploying both at once could need twice
	// the standard timeout.
	log := evetest.Logger()
	timeoutExcludingDownload := 10 * time.Minute
	for _, app := range apps {
		app.uuid = clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
			ApplicationInstanceConfig: app.config,
			DesignatedNodeName:        devName[1], // non-seed
			Affinity:                  eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
		})
		cluster.ApplyConfig(clusterConfig, true, true)
		log.Infof("Submitted config with application %q UUID=%v", app.displayName, app.uuid)
		evetest.Checkpoint(app.displayName + "-config-is-submitted")
		cluster.WaitUntilAppIsRunning(app.uuid, timeoutExcludingDownload)
	}
	// A shim VM's hostname is the app UUID; a NOHYPER container's is its pod
	// name, which starts with the app's Kubernetes name.
	shimVMApp.hostname = shimVMApp.uuid.String()
	nohyperApp.hostname = base.GetAppKubeName(nohyperApp.displayName, nohyperApp.uuid)

	// waitUntilAppsOn waits until the cluster report places every app on
	// node.
	waitUntilAppsOn := func(timeout time.Duration, node, what string) {
		for _, app := range apps {
			cluster.WaitUntilClusterInfoSatisfies(timeout, false,
				fmt.Sprintf("app %q to %s %q", app.displayName, what, node),
				func(info *eveinfo.ZInfoKubeCluster) bool {
					return appNodeName(info, app.displayName) == node
				})
		}
	}

	waitUntilAppsOn(1*time.Minute, devName[1], "be reported on non-seed")
	evetest.Checkpoint("app-is-deployed")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	// verifyApps checks that every app is reachable and its disk marker is
	// intact.
	verifyApps := func() {
		for _, app := range apps {
			verifyAppReachable(t, cluster, app.uuid, app.hostname, appAuth, sshTimeout)
			verifyDiskMarker(t, cluster, app.uuid, app.diskMarkerPath, appAuth,
				sshTimeout, app.diskMarker)
		}
	}
	// expectNoRestart checks that no app restarted since its start-time
	// baseline.
	expectNoRestart := func(cause string) {
		for _, app := range apps {
			startTime := getAppStartTime(t, cluster, app.uuid, appAuth, sshTimeout)
			t.Expect(startTime).To(Equal(app.startTime),
				"app %q start time changed - %s caused unexpected app downtime",
				app.displayName, cause)
		}
	}
	for _, app := range apps {
		verifyAppReachable(t, cluster, app.uuid, app.hostname, appAuth, sshTimeout)
	}
	evetest.Checkpoint("app-verified-on-non-seed")

	// Write a disk marker now, before any failover. Every app-move checkpoint
	// below re-checks this same content, proving the write survives on
	// whichever node the app is rescheduled or moved to next - i.e. that
	// node's Longhorn replica was already in sync, not a fresh empty volume.
	for _, app := range apps {
		app.diskMarker = writeDiskMarker(t, cluster, app.uuid, app.diskMarkerPath,
			appAuth, sshTimeout, "initial")
	}
	evetest.Checkpoint("disk-marker-written")

	// setClusterLinkUp takes dev's cluster port up or down in the SDN,
	// leaving its management port alone. A cut link is remembered so that
	// a test failing before it brings the link back up does not leave the
	// network model behind with the link down.
	var cutLinkDev string
	setClusterLinkUp := func(dev string, up bool) {
		model := proto.Clone(netModel).(*api.NetworkModel)
		for _, port := range model.Ports {
			if port.LogicalLabel == dev+"-eth1" {
				port.AdminUp = up
			}
		}
		evetest.UpdateNetworkModel(model)
		if up {
			cutLinkDev = ""
		} else {
			cutLinkDev = dev
		}
	}
	defer func() {
		if cutLinkDev != "" {
			setClusterLinkUp(cutLinkDev, true)
		}
	}()
	// appAnswersOn reports whether an instance of app answers on dev's own
	// forwarded SSH port, whatever the cluster report says about where the
	// app runs.
	appAnswersOn := func(dev *evetest.EdgeDevice, app *haApp) error {
		output, _, err := dev.RunShellScriptInsideApp(app.uuid, appAuth,
			"hostname", sshTimeout, 0)
		if err != nil {
			return err
		}
		if !strings.Contains(output, app.hostname) {
			return fmt.Errorf("unexpected hostname %q", strings.TrimSpace(output))
		}
		return nil
	}

	// Phases 8-23 repeat failoverCycles times, with the seed/non-seed roles
	// swapped between the two devices at the end of each cycle (see "Test
	// parameters" above).
	curSeed, curNonSeed := devName[0], devName[1]
	var recoveryGeneration uint32
	for cycle := uint32(1); cycle <= failoverCycles; cycle++ {
		checkpointSuffix := ""
		if failoverCycles > 1 {
			checkpointSuffix = fmt.Sprintf("-cycle-%d", cycle)
		}
		checkpoint := func(name string) {
			evetest.Checkpoint(name + checkpointSuffix)
		}

		// Kill the non-seed node. Quorum survives (seed + witness = 2 of 3),
		// so K3s reschedules the apps onto the seed automatically.
		nonSeedDevice := evetest.GetEdgeDevice(curNonSeed)
		nonSeedDevice.PowerOff()
		checkpoint("non-seed-powered-off")

		// The seed and the witness keep quorum, so they must report the loss:
		// the dead node no longer Ready and the cluster no longer healthy.
		nodeDownTimeout := 10 * time.Minute
		cluster.WaitUntilClusterInfoSatisfies(nodeDownTimeout, false,
			fmt.Sprintf("non-seed %q to be reported as not Ready", curNonSeed),
			func(info *eveinfo.ZInfoKubeCluster) bool {
				return !nodeIsReady(info, curNonSeed) &&
					haStateFromReport(info, witnessIP) != haHealthy
			})
		checkpoint("non-seed-reported-down")

		rescheduleTimeout := 10 * time.Minute // no image download needed, just a K8s reschedule
		waitUntilAppsOn(rescheduleTimeout, curSeed, "be rescheduled onto seed")
		verifyApps()
		checkpoint("app-failed-over-to-seed")

		// Bring the non-seed node back. It should pull the apps back once it
		// has been healthy for a while.
		nonSeedDevice.PowerOn(true)
		checkpoint("non-seed-powered-on")

		failbackTimeout := 15 * time.Minute // boot, node health checks, settle period, move
		waitUntilAppsOn(failbackTimeout, curNonSeed, "be moved back onto non-seed")
		verifyApps()
		checkpoint("app-failed-back-to-non-seed")

		cluster.WaitUntilClusterInfoSatisfies(5*time.Minute, false,
			"the report to describe a healthy 2-node cluster again",
			haStateIs(haHealthy, witnessIP))
		checkpoint("cluster-reported-healthy-again")

		// Cut the cluster link between the nodes, leaving both of them
		// running and reachable from the controller over their management
		// ports. The seed and the witness keep quorum, the non-seed loses it.
		seedDevice := evetest.GetEdgeDevice(curSeed)
		setClusterLinkUp(curNonSeed, false)
		checkpoint("cluster-link-cut")

		cluster.WaitUntilClusterInfoSatisfies(nodeDownTimeout, false,
			fmt.Sprintf("non-seed %q to be reported as not Ready after the link cut",
				curNonSeed),
			func(info *eveinfo.ZInfoKubeCluster) bool {
				return !nodeIsReady(info, curNonSeed)
			})
		checkpoint("cluster-link-cut-reported")

		// The seed cannot tell a cut link from a dead node, so it fails the
		// apps over to itself. The isolated non-seed has no quorum, so
		// nothing stops the instances it runs: each app now runs on both.
		waitUntilAppsOn(rescheduleTimeout, curSeed, "be failed over to seed")
		for _, app := range apps {
			for _, dev := range []*evetest.EdgeDevice{seedDevice, nonSeedDevice} {
				t.Eventually(func() error { return appAnswersOn(dev, app) },
					3*time.Minute, 5*time.Second).Should(Succeed(),
					"app %q to run on %q while the cluster link is cut",
					app.displayName, dev.Name())
			}
		}
		checkpoint("app-running-on-both-nodes")

		// Each instance changes its own copy of the app's volume.
		type splitMarkers struct{ seed, nonSeed string }
		written := make(map[*haApp]splitMarkers)
		for _, app := range apps {
			written[app] = splitMarkers{
				seed: writeDiskMarker(t, seedDevice, app.uuid, app.diskMarkerPath,
					appAuth, sshTimeout, "split-seed"+checkpointSuffix),
				nonSeed: writeDiskMarker(t, nonSeedDevice, app.uuid, app.diskMarkerPath,
					appAuth, sshTimeout, "split-non-seed"+checkpointSuffix),
			}
		}
		checkpoint("split-disk-markers-written")

		setClusterLinkUp(curNonSeed, true)
		checkpoint("cluster-link-restored")

		cluster.WaitUntilClusterInfoSatisfies(10*time.Minute, false,
			"the report to describe a healthy 2-node cluster after the link is restored",
			haStateIs(haHealthy, witnessIP))

		// The non-seed comes back without a reboot, so nothing but the
		// placement enforcement of a 2-node HA cluster brings the apps back
		// to it. Once there, each app must have no instance left on the seed:
		// a stale one must stay gone, not just miss one probe.
		//
		// An estimate rather than a measurement, pending a hardware run.
		linkFailbackTimeout := 15 * time.Minute
		waitUntilAppsOn(linkFailbackTimeout, curNonSeed,
			"be moved back onto non-seed after the link is restored")
		for _, app := range apps {
			t.Eventually(func() error { return appAnswersOn(seedDevice, app) },
				3*time.Minute, 5*time.Second).ShouldNot(Succeed(),
				"app %q to stop running on seed %q", app.displayName, curSeed)
			t.Consistently(func() error { return appAnswersOn(seedDevice, app) },
				time.Minute, 10*time.Second).ShouldNot(Succeed(),
				"app %q to stay off seed %q", app.displayName, curSeed)
		}
		// Only the side with quorum can record which replica of the volume
		// failed, so the seed's copy is kept and the non-seed's rebuilt
		// from it: what the isolated instance wrote is lost.
		for _, app := range apps {
			got := readDiskMarker(t, cluster, app.uuid, app.diskMarkerPath,
				appAuth, sshTimeout)
			t.Expect(got).To(Equal(written[app].seed),
				"app %q: expected the seed's write during the link cut to survive "+
					"(seed wrote %q, non-seed wrote %q, before the cut %q)",
				app.displayName, written[app].seed, written[app].nonSeed, app.diskMarker)
			app.diskMarker = got
		}
		verifyApps()
		checkpoint("app-only-on-non-seed")

		// Re-baseline start times here. Valid only through the seed-death/
		// quorum-recovery checks below (steps 16-20) - the apps are
		// deliberately moved again afterward (once their DesignatedNodeName is
		// swapped in step 22), which restarts them and invalidates this
		// baseline for anything checked after that point.
		for _, app := range apps {
			app.startTime = getAppStartTime(t, cluster, app.uuid, appAuth, sshTimeout)
		}

		// Kill the seed node. The co-located witness dies with it - 2 of 3
		// votes gone, quorum lost - but the apps were never running on the seed.
		// Watch the survivor before the seed goes down: the stream carries only
		// reports that arrive after subscribing.
		survivorUpdates, stopSurvivorWatch := nonSeedDevice.WatchClusterNodeInfo()
		defer stopSurvivorWatch()
		seedDevice.PowerOff()
		checkpoint("seed-powered-off")

		// Without quorum the survivor's apiserver is down, and with it the
		// cluster-wide report, whose sender is elected through the API: the
		// controller keeps showing the last healthy one. The survivor must
		// say on its own that it lost quorum, which it finds by asking its
		// etcd every 10 seconds and reports after three failed probes in a
		// row.
		const lossReportTimeout = 3 * time.Minute
		lastReport, lost := waitForQuorumLostReport(survivorUpdates, lossReportTimeout)
		t.Expect(lost).To(BeTrue(),
			"surviving non-seed %q to report quorum lost within %v of the seed's "+
				"loss, last report: %v", curNonSeed, lossReportTimeout, lastReport)
		checkpoint("seed-loss-reported")

		// Confirm the apps were never interrupted: their start times must be
		// unchanged.
		expectNoRestart("the seed outage")
		checkpoint("no-downtime-confirmed")

		// Confirm the control plane is stuck without quorum: kubectl against
		// the surviving node's local apiserver must fail/timeout.
		_, _, err := nonSeedDevice.RunShellScript(
			"eve exec kube kubectl get nodes", 30*time.Second, 0)
		t.Expect(err).To(HaveOccurred(),
			"kubectl succeeded despite lost quorum - k3s apiserver should be unresponsive")
		checkpoint("k3s-unresponsive-confirmed")

		// Recover: promote the non-seed to be the new seed. TriggerQuorumRecovery
		// also withdraws the dead seed's cluster config outright in the same
		// config change, so it converts back to single-node on its own - the
		// same mechanism TestClusterToSingleConversion exercises.
		//
		// The recovery generation is a cluster-wide counter that keeps
		// incrementing across cycles, not a per-cycle value.
		recoveryGeneration++
		clusterConfig.TriggerQuorumRecovery(curNonSeed)
		// Published without waiting: the old seed is powered off until step 21
		// and could never fetch, and the survivor needs no separate wait since
		// the convergence check below cannot pass until it has acted on this.
		cluster.ApplyConfig(clusterConfig, false, false)
		checkpoint("quorum-recovery-triggered")

		// Covers the whole chain, not just the reset: config to cluster
		// status, a graceful k3s stop, the datastore snapshot, the forced
		// reset itself, then a full configure/start/ready cycle where ready
		// means the node and its kube-system pods, and the witness
		// rejoining behind it. On top of that sits a fixed reporting
		// latency of roughly a minute, since the status is stamped on a
		// 15s health tick and collected on zedkube's 30s one.
		//
		// An estimate rather than a measurement, pending a hardware run.
		recoveryTimeout := 10 * time.Minute
		cluster.WaitUntilClusterInfoSatisfies(recoveryTimeout, false,
			fmt.Sprintf("quorum recovery (generation %d) to complete on new seed %q",
				recoveryGeneration, curNonSeed),
			func(info *eveinfo.ZInfoKubeCluster) bool {
				return nodeRecoveryConverged(curNonSeed, recoveryGeneration)(info) &&
					witnessJoined(witnessIP)(info)
			})
		// One Ready node with the witness as its second vote: no physical
		// redundancy, but quorum. A listing that still carries the dead seed
		// would read as restoring instead. The seed's Node object goes when
		// the survivor prunes control-plane nodes missing from
		// master_node_uuids, on a 10 minute sweep unless it won the stats
		// lease only after the config arrived.
		cluster.WaitUntilClusterInfoSatisfies(12*time.Minute, false,
			fmt.Sprintf("the report to list only the new seed %q as Ready", curNonSeed),
			func(info *eveinfo.ZInfoKubeCluster) bool {
				return haStateFromReport(info, witnessIP) == haDegraded &&
					nodeIsReady(info, curNonSeed)
			})
		expectNoRestart("the quorum recovery")
		checkpoint("cluster-reset-completed")

		// Bring the old seed back. Its cluster config was withdrawn above, so
		// once it fetches that, kube-init converts it back to a standalone
		// node exactly as TestClusterToSingleConversion does: mark
		// ConvertToSingleNode, reboot, and restore the pre-cluster /var/lib.
		// That reboot is required behaviour, not a crash - declare it, or
		// Close reports the conversion working as a failure.
		seedDevice.ExpectAdditionalReboots(1)
		seedDevice.PowerOn(true)
		checkpoint("old-seed-powered-on")

		// The device boot, vault unseal and install come first, then the
		// conversion's own reboot and the restore before k3s ever starts in
		// cluster mode again.
		//
		// An estimate rather than a measurement, pending a hardware run.
		conversionTimeout := 20 * time.Minute
		cluster.WaitUntilClusterInfoSatisfies(conversionTimeout, false,
			fmt.Sprintf("old seed %q to report itself as a standalone node", curSeed),
			func(info *eveinfo.ZInfoKubeCluster) bool {
				return soleNodeReady(info, curSeed)
			})
		checkpoint("old-seed-converted-to-single")

		// Rejoin the old seed as a plain (non-bootstrap) member through the
		// same mechanism any device joins for the first time - a rejoin is
		// not a distinct operation - and repoint the apps' designated node at
		// it in the same config change: the controller has to say explicitly
		// that curSeed is the non-seed again, since nothing else determines
		// where the apps run.
		clusterConfig.RestoreClusterConfig(curSeed)
		for _, app := range apps {
			clusterConfig.UpdateApplication(app.uuid, evetest.ClusterApplicationInstanceConfig{
				ApplicationInstanceConfig: app.config,
				DesignatedNodeName:        curSeed,
				Affinity:                  eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
			})
		}
		cluster.ApplyConfig(clusterConfig, true, true)
		checkpoint("old-seed-rejoin-triggered")

		// Same budget as the earlier cluster formation: a fresh join plus full
		// node readiness.
		rejoinTimeout := 30 * time.Minute
		cluster.WaitUntilNodesAreReady(rejoinTimeout)
		checkpoint("old-seed-rejoined")

		// curSeed pulls the apps onto itself once it has been healthy for a
		// while after the join. The running instances still prefer the other
		// node, as they started before the apps were designated to curSeed,
		// so this is the move the descheduler cannot make: zedkube retargets
		// each app's ReplicaSet and replaces the running instance itself.
		finalMoveTimeout := 20 * time.Minute
		waitUntilAppsOn(finalMoveTimeout, curSeed, "move to new non-seed")
		// The old seed was wiped back to single-node state in the steps above, so
		// its Longhorn replica here was rebuilt from scratch from the surviving
		// node's copy after rejoining, not left over from before. Finding the
		// current marker proves that rebuild completed correctly before the app
		// started on it.
		verifyApps()
		checkpoint("app-moved-to-new-non-seed")

		cluster.WaitUntilClusterInfoSatisfies(5*time.Minute, false,
			"the report to describe a healthy 2-node cluster after the rejoin",
			haStateIs(haHealthy, witnessIP))
		checkpoint("cluster-reported-healthy-after-rejoin")

		// The old seed is now the non-seed and vice versa; the next cycle
		// repeats the same steps with the physical devices reversed.
		curSeed, curNonSeed = curNonSeed, curSeed
	}
}
