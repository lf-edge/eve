// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test where EVE's containerd daemons and the shims run, and on which CPUs.

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
// its allowed CPUs, plus zedbox's allowed CPUs and the apps' effective CPUs.
const containerdCPUsScript = `for p in $(pgrep containerd); do
    cg=$(awk -F: '$2 ~ /cpuset/ || $1 == 0 {print $3; exit}' /proc/$p/cgroup 2>/dev/null)
    cpus=$(awk '/Cpus_allowed_list/ {print $2}' /proc/$p/status 2>/dev/null)
    [ -n "$cg" ] && [ -n "$cpus" ] || continue # exited meanwhile
    echo "containerd[$p]=$cg $cpus"
done
echo "zedbox=$(awk '/Cpus_allowed_list/ {print $2}' /proc/$(pgrep -o zedbox)/status)"
echo "apps=$(cat /sys/fs/cgroup/eve-user-apps/cpuset.cpus.effective 2>/dev/null)"`

// TestContainerdCPUs verifies that EVE's system containerd and the shims of
// its services run on the CPUs ctrd_max_vcpus assigns (docs/BOOTING.md,
// docs/README.md), separately from EVE's services (eve_max_vcpus), while the
// apps' containerd and the apps' shims run beside the apps, on the apps' CPUs.
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
//   - EVE's system containerd, at least, is in /eve/containerd, and every
//     process there is allowed on CPUs 0-1. The apps' containerd is in
//     /eve-user-apps/containerd and, on kvm, the app's shim in the helpers
//     child of the app's cgroup; both are allowed on the apps' CPUs, the
//     effective CPUs of /eve-user-apps. Nothing else matches containerd,
//     except on eve-k, where the app is a k3s pod and the k3s containerd and
//     its pods' shims (cgroups under /eve/services or kubepods) are skipped:
//     they are not EVE's containerd.
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
	// EVE's system containerd and the shims of its services are in
	// /eve/containerd, on ctrd_max_vcpus CPUs. The apps' containerd runs
	// beside the apps in /eve-user-apps/containerd, and an app's shim in the
	// helpers child of the app's own cgroup, both on the apps' CPUs. On eve-k
	// the k3s containerd and its pods' shims are EVE services (cgroups under
	// /eve/services, eve_max_vcpus CPUs) or kubepods, and that is not what is
	// tested here.
	containerds, appsContainerds, appShims := 0, 0, 0
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
		case cgroup == "/eve-user-apps/containerd":
			appsContainerds++
			t.Expect(cpus).To(Equal(f["apps"]), "%s CPUs; device facts: %v", k, f)
		case strings.HasPrefix(cgroup, "/eve-user-apps/") && strings.HasSuffix(cgroup, "/helpers"):
			appShims++
			t.Expect(cpus).To(Equal(f["apps"]), "%s CPUs; device facts: %v", k, f)
		case hypervisor == evetest.HypervisorKubevirt &&
			(strings.HasPrefix(cgroup, "/eve/services") || strings.Contains(cgroup, "kubepods")):
			// Not containerd's to confine.
		default:
			t.Expect(cgroup).To(Equal("/eve/containerd"),
				"%s is not in /eve/containerd; device facts: %v", k, f)
		}
	}
	t.Expect(containerds).To(BeNumerically(">=", 1),
		"expected EVE's system containerd in /eve/containerd; device facts: %v", f)
	t.Expect(appsContainerds).To(Equal(1),
		"expected the apps' containerd in /eve-user-apps/containerd; device facts: %v", f)
	if hypervisor != evetest.HypervisorKubevirt {
		t.Expect(appShims).To(BeNumerically(">=", 1),
			"expected the app's shim in a helpers child under /eve-user-apps; device facts: %v", f)
	}
	t.Expect(f["zedbox"]).To(Equal("0"), "zedbox CPUs (eve_max_vcpus=1); device facts: %v", f)
	evetest.Checkpoint("containerd-cpus-verified")

	deleteAppAndWait(t, device, devConfig, appUUID)
}
