// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test of the cgroup v2 tree EVE builds at boot and of where its processes run.

package apps_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestCgroupTree verifies the cgroup v2 tree 010-eve-cgroup builds and where
// EVE's processes run in it, with an application deployed.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the app needs no connectivity.
//
// Device configuration
// --------------------
//   - eth0 as a DHCP mgmt+apps port, a local NI, and a small container app
//     (1 vCPU, 256 MiB), so that a task, its shim and its cgroup exist.
//
// Assertions
// ----------
//   - /sys/fs/cgroup is cgroup2; every controller the kernel offers is
//     enabled below the root, /eve and /eve/services; /eve and /eve/services
//     hold no process.
//   - /eve, /eve/services and /eve/containerd carry memory.max and memory.low
//     from the hard and soft values of dom0_mem, eve_mem and ctrd_mem, and the
//     CPUs of dom0_max_vcpus, eve_max_vcpus and ctrd_max_vcpus (capped at the
//     parent's) -- all read from the device's kernel command line.
//   - pillar's cgroup claims the memory.low of /eve/services, so the
//     aggregate's protection reaches the services.
//   - EVE never sets memory.high on pillar's cgroup.
//   - zedbox runs in /eve/services/pillar, and a command run with
//     "eve exec pillar" in the root cgroup ("0::/"). Where containerd and its
//     shims run is TestContainerdCPUs' question.
//   - memory-monitor runs where images/rootfs.yml.in puts its service,
//     /eve-memory-monitor, beside /eve: every memory-monitor process is in
//     "0::/eve-memory-monitor" and in no cgroup under /eve, and
//     /eve/services/memory-monitor does not exist. The group has no memory
//     limit; its cpuset.cpus, kept by runc when the service started, and its
//     effective CPUs are /eve's, and so are the CPUs memory-monitor may run
//     on. The device has more CPUs than /eve, so that differs from the
//     root's. The group holds no containerd shim.
//   - KVM: the app's QEMU runs in the app's own cgroup under /eve-user-apps
//     (from the qemu service's rootfs, but not in /eve/services/qemu); that
//     cgroup has memory.max and the cpu.max of one vCPU ("100000 100000"),
//     and the app's DomainMetric reports non-zero memory use and CPU time
//     (the cgroup v2 stats of its shim decode).
//   - Kubevirt: kube-init's first-boot CPU loan widened /eve/containerd and
//     was restored (/persist/kubelog/k3s-install.log).
//
// Test params
// -----------
//   - HYPERVISOR.
//
// Suite placement
// ---------------
//   - TestAppsSuite, after TestAppLogs (same network model and device).
func TestCgroupTree(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

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
	appUUID := addLoggerApp(devConfig)
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	device.WaitUntilAppIsRunning(appUUID, 10*time.Minute)
	evetest.Checkpoint("app-is-running")

	f := deviceFacts(t, device, cgroupTreeScript(appUUID))
	cmdline := f["cmdline"]

	t.Expect(f["fstype"]).To(Equal("cgroup2"), "/sys/fs/cgroup is not cgroup v2")
	for _, cg := range []string{"/", "/eve", "/eve/services"} {
		t.Expect(f["subtree["+cg+"]"]).To(Equal(f["controllers["+cg+"]"]),
			"not every controller is enabled below %s", cg)
	}
	for _, cg := range []string{"/eve", "/eve/services"} {
		t.Expect(f["procs["+cg+"]"]).To(BeEmpty(), "%s holds processes", cg)
	}

	// 010-eve-cgroup's default when no memory argument is given.
	defMem := uint64(800 * evetest.MiB)
	if hypervisor == evetest.HypervisorKubevirt {
		defMem = uint64(8000 * evetest.MiB)
	}
	nproc, err := strconv.Atoi(f["nproc"])
	t.Expect(err).ToNot(HaveOccurred(), "nproc %q", f["nproc"])
	dom0 := cpusArg(cmdline, "dom0_max_vcpus", nproc)
	want := map[string]struct {
		memArg string
		cpus   string
	}{
		"/eve":            {"dom0_mem", cpuList(dom0)},
		"/eve/services":   {"eve_mem", cpuList(cpusArg(cmdline, "eve_max_vcpus", dom0))},
		"/eve/containerd": {"ctrd_mem", cpuList(cpusArg(cmdline, "ctrd_max_vcpus", dom0))},
	}
	for cg, w := range want {
		soft, hard := memArg(cmdline, w.memArg, defMem)
		t.Expect(f["memory.max["+cg+"]"]).To(Equal(strconv.FormatUint(hard, 10)), "%s memory.max", cg)
		t.Expect(f["memory.low["+cg+"]"]).To(Equal(strconv.FormatUint(soft, 10)), "%s memory.low", cg)
		t.Expect(f["cpus["+cg+"]"]).To(Equal(w.cpus), "%s CPUs", cg)
	}
	t.Expect(f["memory.low[/eve/services/pillar]"]).To(Equal(f["memory.low[/eve/services]"]),
		"pillar's memory.low")
	t.Expect(f["memory.high[/eve/services/pillar]"]).To(Equal("max"))
	t.Expect(f["zedbox"]).To(Equal("/eve/services/pillar"))
	t.Expect(f["eve-exec"]).To(Equal("0::/"), "cgroup of a command run with eve exec")
	checkMemoryMonitorCgroup(t, f, nproc, dom0)

	if hypervisor == evetest.HypervisorKubevirt {
		t.Expect(f["loan.widened"]).To(ContainSubstring("eve/containerd"),
			"kube-init's first-boot CPU loan did not widen /eve/containerd")
		t.Expect(f["loan.restored"]).ToNot(BeEmpty(), "kube-init's CPU loan was not restored")
	} else {
		t.Expect(f["app.dir"]).ToNot(BeEmpty(), "no cgroup for the app under /eve-user-apps")
		t.Expect(f["app.qemu"]).To(Equal(strings.TrimPrefix(f["app.dir"], "/sys/fs/cgroup")),
			"the cgroup of the app's QEMU")
		t.Expect(f["app.memory.max"]).ToNot(Equal("max"), "the app has no memory limit")
		t.Expect(f["app.cpu.max"]).To(Equal("100000 100000"), "cpu.max of a 1-vCPU app")
		var metric struct {
			CPUTotalNs uint64
			UsedMemory uint32
		}
		t.Expect(json.Unmarshal([]byte(f["app.metric"]), &metric)).To(Succeed(),
			"the app's DomainMetric %q", f["app.metric"])
		t.Expect(metric.UsedMemory).To(BeNumerically(">", 0), "the app's DomainMetric: memory use")
		t.Expect(metric.CPUTotalNs).To(BeNumerically(">", 0), "the app's DomainMetric: CPU time")
	}
	evetest.Checkpoint("tree-verified")

	deleteAppAndWait(t, device, devConfig, appUUID)
}

// checkMemoryMonitorCgroup asserts where memory-monitor runs; see
// TestCgroupTree. dom0 is the number of /eve's CPUs.
func checkMemoryMonitorCgroup(t *WithT, f map[string]string, nproc, dom0 int) {
	mm := make(map[string]string)
	for k, v := range f {
		if strings.HasPrefix(k, "mm.") || strings.HasPrefix(k, "cpus[") {
			mm[k] = v
		}
	}
	evetest.Logger().Infof("memory-monitor's cgroup on the device: %v", mm)

	eveCPUs := f["cpus[/eve]"]
	t.Expect(nproc).To(BeNumerically(">", dom0),
		"the device has no CPU outside /eve, so memory-monitor's CPUs prove nothing")
	t.Expect(eveCPUs).ToNot(Equal(f["cpus[/]"]), "/eve has the root's CPUs: %v", mm)

	pids := strings.Fields(f["mm.pids"])
	t.Expect(pids).ToNot(BeEmpty(), "no memory-monitor process")
	for _, pid := range pids {
		t.Expect(f["mm.cgroup["+pid+"]"]).To(Equal("0::/eve-memory-monitor"),
			"/proc/%s/cgroup of memory-monitor", pid)
		t.Expect(f["mm.in-eve["+pid+"]"]).To(BeEmpty(),
			"memory-monitor (pid %s) is in a cgroup under /eve", pid)
		t.Expect(f["mm.cpus["+pid+"]"]).To(Equal(eveCPUs),
			"Cpus_allowed_list of memory-monitor (pid %s) is not /eve's CPUs", pid)
	}
	t.Expect(f["mm.services-leaf"]).To(BeEmpty(), "/eve/services/memory-monitor exists")
	t.Expect(f["mm.cpuset.cpus"]).To(Equal(eveCPUs),
		"/eve-memory-monitor cpuset.cpus is not /eve's CPUs after the service started")
	t.Expect(f["mm.cpus"]).To(Equal(eveCPUs), "/eve-memory-monitor cpuset.cpus.effective")
	t.Expect(f["mm.memory.max"]).To(Equal("max"), "/eve-memory-monitor has a memory limit")

	procs := strings.Fields(f["mm.procs"])
	for _, pid := range pids {
		t.Expect(procs).To(ContainElement(pid+":memory-monitor"),
			"memory-monitor (pid %s) is not in /eve-memory-monitor/cgroup.procs", pid)
	}
	for _, proc := range procs {
		t.Expect(proc).ToNot(ContainSubstring(":containerd"),
			"a containerd process is in /eve-memory-monitor: %v", procs)
	}
}

// cgroupTreeScript prints the facts TestCgroupTree asserts, as key=value lines.
// The app's QEMU is the process with the app's -uuid; the bracket keeps
// pgrep -f from matching the shell that runs this script. The app's
// DomainMetric is published every 10 s and its first publications can lack
// the memory figures; the script waits up to 60 s for one with both CPU time
// and memory use.
func cgroupTreeScript(appUUID uuid.UUID) string {
	return fmt.Sprintf(`CG=/sys/fs/cgroup
echo "cmdline=$(cat /proc/cmdline)"
echo "nproc=$(grep -c ^processor /proc/cpuinfo)"
echo "fstype=$(awk '$2 == "/sys/fs/cgroup" {print $3}' /proc/mounts | head -1)"
for cg in "" /eve /eve/services; do
    echo "controllers[${cg:-/}]=$(cat $CG$cg/cgroup.controllers)"
    echo "subtree[${cg:-/}]=$(cat $CG$cg/cgroup.subtree_control)"
done
for cg in /eve /eve/services; do
    echo "procs[$cg]=$(tr '\n' ' ' < $CG$cg/cgroup.procs)"
done
for cg in /eve /eve/containerd /eve/services; do
    echo "memory.max[$cg]=$(cat $CG$cg/memory.max)"
    echo "memory.low[$cg]=$(cat $CG$cg/memory.low)"
    echo "cpus[$cg]=$(cat $CG$cg/cpuset.cpus.effective)"
done
echo "memory.low[/eve/services/pillar]=$(cat $CG/eve/services/pillar/memory.low)"
echo "memory.high[/eve/services/pillar]=$(cat $CG/eve/services/pillar/memory.high)"
echo "zedbox=$(tail -1 /proc/$(pgrep -o zedbox)/cgroup | cut -d: -f3)"
echo "cpus[/]=$(cat $CG/cpuset.cpus.effective)"
MM=$CG/eve-memory-monitor
echo "mm.cpuset.cpus=$(cat $MM/cpuset.cpus)"
echo "mm.cpus=$(cat $MM/cpuset.cpus.effective)"
echo "mm.memory.max=$(cat $MM/memory.max)"
echo "mm.frozen=$(awk '$1 == "frozen" {print $2}' $MM/cgroup.events)"
echo "mm.services-leaf=$(ls -d $CG/eve/services/memory-monitor 2>/dev/null)"
echo "mm.pids=$(pgrep -x memory-monitor | tr '\n' ' ')"
for p in $(pgrep -x memory-monitor); do
    echo "mm.cgroup[$p]=$(tr '\n' ' ' < /proc/$p/cgroup)"
    echo "mm.cpus[$p]=$(awk '$1 == "Cpus_allowed_list:" {print $2}' /proc/$p/status)"
    echo "mm.in-eve[$p]=$(for g in $(find $CG/eve -name cgroup.procs); do grep -qx $p $g && echo ${g%%/cgroup.procs}; done | tr '\n' ' ')"
done
echo "mm.procs=$(for p in $(cat $MM/cgroup.procs); do echo $p:$(cat /proc/$p/comm); done | tr '\n' ' ')"
echo "eve-exec=$(eve exec pillar cat /proc/self/cgroup | tr '\n' ' ')"
d=$(ls -d $CG/eve-user-apps/%[1]s.* 2>/dev/null | head -1)
echo "app.dir=$d"
if [ -n "$d" ]; then
    echo "app.memory.max=$(cat $d/memory.max)"
    echo "app.cpu.max=$(cat $d/cpu.max)"
    echo "app.qemu=$(for p in $(pgrep -f '[q]emu-system.*-uuid %[1]s'); do tail -1 /proc/$p/cgroup | cut -d: -f3; done | tr '\n' ' ')"
    m=/run/domainmgr/DomainMetric/%[1]s.json
    for i in 1 2 3 4 5 6; do
        grep -q '"CPUTotalNs":[1-9]' $m 2>/dev/null && grep -q '"UsedMemory":[1-9]' $m && break
        sleep 10
    done
    echo "app.metric=$(tr -d '\n' < $m 2>/dev/null)"
fi
echo "loan.widened=$(grep -h 'cpuset: widened' /persist/kubelog/k3s-install.log* 2>/dev/null | tail -1)"
echo "loan.restored=$(grep -h 'cpuset: restored' /persist/kubelog/k3s-install.log* 2>/dev/null | tail -1)"
`, appUUID)
}
