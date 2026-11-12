// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestAppOOMKillReported verifies that EVE reports the kernel's OOM killer
// killing processes of a container application that runs without a shim VM.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the app needs no connectivity.
//
// Device configuration
// --------------------
//   - eth0 as a DHCP mgmt+apps port and a NOHYPER container app (1 vCPU,
//     256 MiB) without network adapters.
//
// Fault injection
// ---------------
//   - A worker: a device shell starts a process that moves itself into the
//     app's cgroup, raises its own oom_score_adj to 1000 and allocates until
//     the OOM killer kills it. The container's main process is untouched.
//   - The main process: a pinned process (oom_score_adj -1000, never chosen)
//     moves into the app's cgroup and holds 8 MiB; then the cgroup's
//     memory.max is lowered to 4 MiB. Reclaim cannot get below that, so the
//     OOM killer kills every other process in the cgroup, the container's
//     main process included. The script then kills the pinned process.
//
// Assertions
// ----------
//   - Worker: the cgroup's oom_kill count rises by one and the worker died
//     of SIGKILL; the app stays RUNNING; its DomainMetric counts the kill;
//     domainmgr logs "reached its memory limit of <N> MiB" naming the app,
//     with N the cgroup's memory.max.
//   - Main process: the cgroup's oom_kill count rises again, and the app's
//     error names the OOM killer, the 4 MiB limit and that count (the
//     worker's kill included) instead of the generic "one of the
//     application's tasks has crashed".
//
// Test params
// -----------
//   - HYPERVISOR. Skipped on kubevirt, whose apps run in Kubernetes cgroups
//     that EVE does not read for OOM kills.
//
// Suite placement
// ---------------
//   - TestAppsSuite, after TestCgroupTree (same network model and device).
func TestAppOOMKillReported(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor == evetest.HypervisorKubevirt {
		evetestT.Skipf("HYPERVISOR is %s: EVE-k apps run in Kubernetes cgroups, "+
			"which EVE does not read for OOM kills", hypervisor)
	}

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	addMgmtPort(devConfig)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "oom-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: loggerCtrImage,
			Tag:       loggerCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_NOHYPER,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
	})
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 10*time.Minute)
	evetest.Checkpoint("app-is-running")

	start := time.Now()
	f := deviceFacts(t, device, oomWorkerScript(appUUID))
	evetest.Logger().Infof("worker OOM injection: %v", f)
	t.Expect(f["dir"]).ToNot(BeEmpty(), "no cgroup for the app under /eve-user-apps")
	t.Expect(f["rc"]).To(Equal("137"), "the worker did not die of SIGKILL")
	before, err := strconv.Atoi(f["before"])
	t.Expect(err).ToNot(HaveOccurred(), "oom_kill before: %q", f["before"])
	t.Expect(f["after"]).To(Equal(strconv.Itoa(before+1)), "oom_kill after the worker's kill")
	limit, err := strconv.ParseUint(f["memory.max"], 10, 64)
	t.Expect(err).ToNot(HaveOccurred(), "the app cgroup's memory.max: %q", f["memory.max"])

	t.Eventually(func() string {
		return deviceFacts(t, device, domainMetricOOMScript(appUUID))["oomkills"]
	}, 2*time.Minute, 10*time.Second).ShouldNot(Or(BeEmpty(), Equal("0")),
		"the app's DomainMetric does not count the OOM kill")

	t.Eventually(func() int {
		return len(device.GetLogs(evetest.LogMsgMatch{
			Source:          "domainmgr",
			MsgHasSubstring: fmt.Sprintf("(%s) reached its memory limit of %d MiB", appUUID, limit>>20),
			NotBefore:       start,
		}))
	}, 5*time.Minute, 15*time.Second).Should(BeNumerically(">", 0),
		"domainmgr did not log the OOM kill and the %d MiB limit of the running app", limit>>20)
	t.Expect(device.GetAppInfo(appUUID).GetState()).To(Equal(eveinfo.ZSwState_RUNNING),
		"the app must keep running after losing a worker")
	evetest.Checkpoint("worker-kill-reported")

	f = deviceFacts(t, device, oomSqueezeScript(appUUID))
	evetest.Logger().Infof("main-process OOM injection: %v", f)
	kills, err := strconv.Atoi(f["oom_kill"])
	t.Expect(err).ToNot(HaveOccurred(), "oom_kill after the squeeze: %q", f["oom_kill"])
	t.Expect(kills).To(BeNumerically(">", before+1), "the squeeze killed no process")
	want := fmt.Sprintf("reached its memory limit of 4 MiB and the kernel's OOM killer killed %d of its processes", kills)
	t.Eventually(func() string {
		return appError(device.GetAppInfo(appUUID))
	}, 5*time.Minute, 10*time.Second).Should(ContainSubstring(want),
		"the crashed app's error does not name the OOM killer, the 4 MiB limit and the kill count")
	evetest.Checkpoint("crash-reported")

	deleteAppAndWait(t, device, devConfig, appUUID)
}

// oomWorkerScript runs a process in the app's cgroup until the OOM killer
// kills it, and prints the cgroup's oom_kill count before and after.
// oom_score_adj 1000 makes it the victim over the container's main process.
func oomWorkerScript(appUUID uuid.UUID) string {
	return fmt.Sprintf(`d=$(ls -d /sys/fs/cgroup/eve-user-apps/%s.* 2>/dev/null | head -1)
echo "dir=$d"
[ -n "$d" ] || exit 0
echo "memory.max=$(cat $d/memory.max)"
echo "before=$(awk '$1 == "oom_kill" {print $2}' $d/memory.events)"
sh -c 'echo 1000 > /proc/self/oom_score_adj && echo $$ > "$1/cgroup.procs" &&
    exec awk "BEGIN { s = \"x\"; while (1) s = s s }"' worker "$d"
echo "rc=$?"
echo "after=$(awk '$1 == "oom_kill" {print $2}' $d/memory.events)"
`, appUUID)
}

// domainMetricOOMScript prints the OOMKills field of the app's DomainMetric.
func domainMetricOOMScript(appUUID uuid.UUID) string {
	return fmt.Sprintf(`echo "oomkills=$(grep -o '"OOMKills":[0-9]*' /run/domainmgr/DomainMetric/%s.json | cut -d: -f2)"
`, appUUID)
}

// oomSqueezeScript makes the OOM killer kill the app's main process: a
// process the OOM killer never chooses (oom_score_adj -1000) holds 8 MiB in
// the app's cgroup, whose memory.max is then lowered to 4 MiB, so every other
// process in it is killed. A container whose own use reclaim can bring under
// any limit cannot be OOM-killed by lowering memory.max alone.
func oomSqueezeScript(appUUID uuid.UUID) string {
	return fmt.Sprintf(`d=$(ls -d /sys/fs/cgroup/eve-user-apps/%s.* 2>/dev/null | head -1)
echo "dir=$d"
[ -n "$d" ] || exit 0
echo "procs.before=$(tr '\n' ' ' < $d/cgroup.procs)"
sh -c 'echo -1000 > /proc/self/oom_score_adj && echo $$ > "$1/cgroup.procs" &&
    exec awk "BEGIN { s = \"x\"; for (i = 0; i < 23; i++) s = s s; system(\"sleep 600\") }"' pin "$d" &
for i in $(seq 30); do
    [ "$(cat $d/memory.current)" -gt 8388608 ] && break
    sleep 1
done
echo "memory.current=$(cat $d/memory.current)"
echo 4M > $d/memory.max
echo "rc=$?"
echo "oom_kill=$(awk '$1 == "oom_kill" {print $2}' $d/memory.events)"
for p in $(cat $d/cgroup.procs); do
    [ "$(cat /proc/$p/oom_score_adj 2>/dev/null)" = -1000 ] && kill -9 $p
done
echo "procs.after=$(tr '\n' ' ' < $d/cgroup.procs)"
`, appUUID)
}
