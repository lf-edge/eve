// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// tpmGetRandomScript consumes the application's TPM with tpm2-tools: it asks
// the TPM for 8 random bytes and prints them as "RAND=<hex>", which the test
// parses. The device check up front tells a missing vTPM (domainmgr booted
// the domain without a TPM device) apart from a tpm2_getrandom failure.
const tpmGetRandomScript = `
[ -c /dev/tpmrm0 ] || [ -c /dev/tpm0 ] || { echo "NO_TPM_DEVICE" >&2; exit 1; }
rand="$(tpm2_getrandom --hex 8)" || exit 1
echo "RAND=$rand"
`

// swtpmCheckScriptFmt (format argument: the app UUID) inspects the app's
// SWTPM instance from a host shell. It locates the SWTPM process by the app
// UUID in its command line -- the pid file under /run/swtpm cannot be used
// here, because the vtpm container runs in its own PID namespace and the pid
// it records is meaningless in the host namespace this script runs in.
//
// uid/gid 101 is the vtpm user/group (pkg/dom0-ztools): the vtpm service and
// every SWTPM instance it spawns run under it, never as root. The script
// compares all SWTPM pids for the app against those whose real UID and GID
// are both 101 (pgrep -U/-G) and prints a single verdict: "none" if the app
// has no SWTPM process, "vtpm" if every one of them runs as the vtpm user,
// "other" otherwise (listing the offending pids). It also reports whether
// the vtpm service marked the instance's state as encrypted, which it does
// right before handing SWTPM the state-encryption key unsealed from the
// device TPM.
const swtpmCheckScriptFmt = `
uuid=%s
all=$(pgrep -f "swtpm socket.*$uuid" | sort -n)
vtpm=$(pgrep -U 101 -G 101 -f "swtpm socket.*$uuid" | sort -n)
if [ -z "$all" ]; then
	echo "SWTPM_OWNER=none"
elif [ "$all" = "$vtpm" ]; then
	echo "SWTPM_OWNER=vtpm pids=$(echo $all | tr '\n' ' ')"
else
	echo "SWTPM_OWNER=other pids=$(echo $all | tr '\n' ' ') vtpm_pids=$(echo $vtpm | tr '\n' ' ')"
fi
if [ -f "/persist/swtpm/$uuid.encrypted" ]; then
	echo "STATE_ENCRYPTED=true"
else
	echo "STATE_ENCRYPTED=false"
fi
`

// TestAppVTPM verifies that an application consumes its per-app vTPM
// (pkg/vtpm) end to end and that the SWTPM instance backing it runs
// unprivileged.
//
// The vtpm service runs under a non-root user and, on a device with a TPM,
// unseals the vault key from the device TPM to encrypt each SWTPM instance's
// on-disk state. Both properties are easy to break from the outside (e.g. by
// tightening permissions of a file the unprivileged service must read), and
// a broken SWTPM launch does NOT fail the application -- domainmgr only logs
// the error and boots the domain without a TPM device -- so only checks like
// the ones below catch a regression.
//
// The vTPM is only implemented by the KVM hypervisor backend (the xen,
// kubevirt and containerd backends return "not implemented", and domainmgr
// then boots domains without a TPM), so the test skips on other hypervisors.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- controller reachability. The app image
//     is served from evetest's own OCI registry, so no Internet egress is
//     required.
//
// Phases
// ------
//  1. Deploy a container app (vTPM is enabled by default for every domain;
//     the container's shim VM gets a QEMU TPM-TIS device backed by the
//     app's SWTPM instance) on a Local NI with a 2222->22 port-forward, on
//     a device with an (emulated) TPM. Wait for it to reach RUNNING.
//  2. On the EVE host: find the app's SWTPM process and assert it runs as
//     the vtpm user (uid/gid 101), never root, and that its state is marked
//     encrypted -- i.e. the unprivileged vtpm service successfully unsealed
//     the state-encryption key from the device TPM.
//  3. Inside the app: ask the TPM for random bytes with tpm2_getrandom (the
//     evetest-ubuntu-ctr image carries tpm2-tools from :1.1; the shim VM
//     rbind-mounts its /dev, with the TPM device, into the container) --
//     i.e. the guest actually consumes the vTPM through QEMU and SWTPM.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM; the test skips unless KVM).
func TestAppVTPM(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor != evetest.HypervisorKVM {
		evetestT.Skipf("HYPERVISOR is %s: the per-app vTPM is only implemented "+
			"by the KVM hypervisor backend", hypervisor)
	}

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			WithTPM:           true,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// One mgmt+apps port, one Local NI and one container app connected to it.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	eth0Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})

	niUUID := addLocalNI(devConfig)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vtpm-test-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
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
	})
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, appRunningTimeout)
	evetest.Checkpoint("app-running")

	log := evetest.Logger()

	// Phase 2: the SWTPM instance as seen from the EVE host. SWTPM starts
	// before the domain, so it is already up once the app is RUNNING; the
	// retry only absorbs transient SSH failures.
	log.Infof("Checking the app's SWTPM process on the EVE host...")
	swtpmCheckScript := fmt.Sprintf(swtpmCheckScriptFmt, appUUID.String())
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScript(swtpmCheckScript, appSSHTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).ToNot(ContainSubstring("SWTPM_OWNER=none"),
			"no SWTPM process for app %s found on the host: %s", appUUID, out)
		g.Expect(out).To(ContainSubstring("SWTPM_OWNER=vtpm "),
			"an SWTPM instance for app %s does not run as the vtpm user "+
				"(uid/gid 101): %s", appUUID, out)
		g.Expect(out).To(ContainSubstring("STATE_ENCRYPTED=true"),
			"SWTPM state is not encrypted -- the vtpm service did not unseal "+
				"the state-encryption key from the device TPM: %s", out)
	}, 2*time.Minute, pollingInterval).Should(Succeed())
	evetest.Checkpoint("swtpm-unprivileged-verified")

	// Phase 3: consume the vTPM from inside the application. RUNNING only
	// means the domain was created; sshd inside the container needs more
	// time to accept connections.
	log.Infof("Waiting for app SSH to become reachable...")
	t.Eventually(func(g Gomega) {
		_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"echo ok", appSSHTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
	}, 5*time.Minute, pollingInterval).Should(Succeed())

	log.Infof("Running tpm2_getrandom inside the app...")
	out, errOut, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		tpmGetRandomScript, time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "TPM check script failed: %s", errOut)
	t.Expect(out).To(MatchRegexp(`RAND=[0-9a-f]{16}`),
		"tpm2_getrandom did not return 8 random bytes: %s", out)
	evetest.Checkpoint("guest-tpm-verified")
}
