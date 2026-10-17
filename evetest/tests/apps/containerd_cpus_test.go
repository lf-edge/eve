// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test that containerd runs on the CPUs ctrd_max_vcpus gives it.

package apps_test

import (
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// containerdCPUsScript prints, for every containerd daemon and shim, its
// cpuset cgroup (cgroup v1: the cpuset hierarchy; v2: the unified one) and
// its allowed CPUs, plus zedbox's allowed CPUs.
const containerdCPUsScript = `for p in $(pgrep containerd); do
    cg=$(awk -F: '$2 ~ /cpuset/ || $1 == 0 {print $3; exit}' /proc/$p/cgroup 2>/dev/null)
    cpus=$(awk '/Cpus_allowed_list/ {print $2}' /proc/$p/status 2>/dev/null)
    [ -n "$cg" ] && [ -n "$cpus" ] || continue # exited meanwhile
    echo "containerd[$p]=$cg $cpus"
done
echo "zedbox=$(awk '/Cpus_allowed_list/ {print $2}' /proc/$(pgrep -o zedbox)/status)"`

// TestContainerdCPUs verifies that both containerd daemons and every shim run
// on the CPUs ctrd_max_vcpus assigns (docs/BOOTING.md, docs/README.md),
// separately from EVE's services (eve_max_vcpus). It holds on cgroup v1 and v2.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP.
//
// Device configuration
// --------------------
//   - Boot options dom0_max_vcpus=2, eve_max_vcpus=1, ctrd_max_vcpus=2 on a
//     4-CPU device, so containerd's CPUs (0-1) differ from the services' (0).
//   - eth0 as a DHCP mgmt+apps port, a local NI and a small container app, so
//     that an app shim runs too.
//
// Assertions
// ----------
//   - Every containerd process is in /eve/containerd and allowed on CPUs 0-1;
//     at least three of them (two daemons and the app's shim), two on
//     eve-k where the app is a k3s pod. On eve-k the k3s containerd and its
//     pods' shims (cgroups under /eve/services or kubepods) are skipped: they
//     are not EVE's containerd.
//   - zedbox is allowed on CPU 0 only.
//
// Test params
// -----------
//   - HYPERVISOR.
//
// Suite placement
// ---------------
//   - Last in TestAppsSuite: its boot options differ, so the framework
//     creates a new device for it.
func TestContainerdCPUs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:           devName,
			WithHypervisor: hypervisor,
			MinCPUs:        4,
			WithGrubOptions: []string{
				`set_global hv_dom0_cpu_settings "dom0_max_vcpus=2"`,
				`set_global hv_eve_cpu_settings "eve_max_vcpus=1"`,
				`set_global hv_ctrd_cpu_settings "ctrd_max_vcpus=2"`,
			},
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

	f := deviceFacts(t, device, containerdCPUsScript)
	evetest.Logger().Infof("containerd CPUs on the device: %v", f)
	// EVE's own containerd daemons and the shims of its apps are in
	// /eve/containerd, on ctrd_max_vcpus CPUs. On eve-k the k3s containerd
	// and its pods' shims are EVE services (cgroups under /eve/services,
	// eve_max_vcpus CPUs) or kubepods, and that is not what is tested here.
	containerds := 0
	for k, v := range f {
		if !strings.HasPrefix(k, "containerd[") {
			continue
		}
		fields := strings.Fields(v)
		t.Expect(fields).To(HaveLen(2), "%s: unexpected facts %q", k, v)
		cgroup, cpus := fields[0], fields[1]
		switch {
		case cgroup == "/eve/containerd":
			containerds++
			t.Expect(cpus).To(Equal("0-1"), "%s CPUs; device facts: %v", k, f)
		case hypervisor == evetest.HypervisorKubevirt &&
			(strings.HasPrefix(cgroup, "/eve/services") || strings.Contains(cgroup, "kubepods")):
			// Not containerd's to confine.
		default:
			t.Expect(cgroup).To(Equal("/eve/containerd"),
				"%s is not in /eve/containerd; device facts: %v", k, f)
		}
	}
	minContainerds := 3 // two daemons and the app's shim
	if hypervisor == evetest.HypervisorKubevirt {
		minContainerds = 2 // the app is a pod, not a shim of EVE's containerd
	}
	t.Expect(containerds).To(BeNumerically(">=", minContainerds),
		"expected EVE's containerd daemons (and the app's shim on kvm) in /eve/containerd; device facts: %v", f)
	t.Expect(f["zedbox"]).To(Equal("0"), "zedbox CPUs (eve_max_vcpus=1); device facts: %v", f)
	evetest.Checkpoint("containerd-cpus-verified")

	deleteAppAndWait(t, device, devConfig, appUUID)
}
