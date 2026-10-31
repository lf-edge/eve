// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

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

// tpmDevicePresenceScript reports whether the guest has a TPM character
// device at all, for the app that must not have one.
const tpmDevicePresenceScript = `
if [ -c /dev/tpmrm0 ] || [ -c /dev/tpm0 ]; then
	echo "TPM_DEVICE=present"
else
	echo "TPM_DEVICE=absent"
fi
`

// TestAppVTPM verifies that an application consumes its per-app vTPM, that
// the hypervisor backend sets the vTPM up the way it is meant to, and that
// disable_vtpm in the app config leaves the guest without a TPM.
//
// On KVM the vTPM is a host-side SWTPM instance (pkg/vtpm). The vtpm service
// runs under a non-root user and, on a device with a TPM, unseals the vault
// key from the device TPM to encrypt each SWTPM instance's on-disk state.
// Both properties are easy to break from the outside (e.g. by tightening
// permissions of a file the unprivileged service must read), and a broken
// SWTPM launch does NOT fail the application -- domainmgr only logs the
// error and boots the domain without a TPM device -- so only checks like
// the ones below catch a regression.
//
// On kubevirt, KubeVirt runs the SWTPM inside the virt-launcher pod of a VMI
// whose spec carries a TPM device, so what EVE contributes is the VMI spec
// domainmgr renders (hypervisor/kubevirt.go, addTPMDevice). The state is
// ephemeral by design: KubeVirt keys persistent state to the VMI name, which
// the VMIRS regenerates on every restart. The test therefore asserts the
// presence and usability of the device, not persistence.
//
// The xen and containerd backends have no vTPM, so the test skips there.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- controller reachability. The app image
//     is served from evetest's own OCI registry, so no Internet egress is
//     required.
//
// Phases
// ------
//  1. Deploy two container apps on a Local NI, each with a port-forward to
//     its sshd, on a device with an (emulated) TPM: "vtpm-on" with the
//     default vTPM setting (vTPM is enabled by default for every domain; the
//     container's shim VM gets a TPM device) and "vtpm-off" with disable_vtpm
//     set. Wait for both to reach RUNNING.
//  2. Hypervisor side. KVM: find vtpm-on's SWTPM process on the EVE host and
//     assert it runs as the vtpm user (uid/gid 101), never root, and that its
//     state is marked encrypted -- i.e. the unprivileged vtpm service
//     successfully unsealed the state-encryption key from the device TPM;
//     assert vtpm-off has no SWTPM process. kubevirt: vtpm-on's VMI spec has
//     a TPM device that is not persistent, vtpm-off's has none.
//  3. Inside the apps: vtpm-on asks its TPM for random bytes with
//     tpm2_getrandom (the evetest-ubuntu-ctr image carries tpm2-tools from
//     :1.1; the shim VM rbind-mounts its /dev, with the TPM device, into the
//     container) -- i.e. the guest actually consumes the vTPM; vtpm-off has
//     no /dev/tpm* device.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM; kvm and kubevirt run, others skip).
func TestAppVTPM(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor != evetest.HypervisorKVM &&
		hypervisor != evetest.HypervisorKubevirt {
		evetestT.Skipf("HYPERVISOR is %s: only the KVM and kubevirt backends "+
			"provide a per-app vTPM", hypervisor)
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

	// Phase 1: one mgmt+apps port, one Local NI, one app with the default
	// vTPM and one with it disabled.
	devConfig, niUUID := singleMgmtPortWithLocalNI(device, hypervisor)
	onID := addVTPMTestApp(devConfig, niUUID, "vtpm-on", 2222)
	offConfig := vtpmTestAppConfig(niUUID, "vtpm-off", 2223)
	offConfig.DisableVTPM = true
	offID := devConfig.AddApplication(offConfig)
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(onID, appRunningTimeout)
	device.WaitUntilAppIsRunning(offID, appRunningTimeout)
	evetest.Checkpoint("apps-running")

	log := evetest.Logger()

	// Phase 2: the vTPM as the hypervisor backend set it up.
	switch hypervisor {
	case evetest.HypervisorKVM:
		// SWTPM starts before the domain, so it is already up once the app
		// is RUNNING; the retry only absorbs transient SSH failures.
		log.Infof("Checking the apps' SWTPM processes on the EVE host...")
		swtpmCheckScript := fmt.Sprintf(swtpmCheckScriptFmt, onID.String())
		t.Eventually(func(g Gomega) {
			out, _, err := device.RunShellScript(swtpmCheckScript, appSSHTimeout, 0)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out).ToNot(ContainSubstring("SWTPM_OWNER=none"),
				"no SWTPM process for app %s found on the host: %s", onID, out)
			g.Expect(out).To(ContainSubstring("SWTPM_OWNER=vtpm "),
				"an SWTPM instance for app %s does not run as the vtpm user "+
					"(uid/gid 101): %s", onID, out)
			g.Expect(out).To(ContainSubstring("STATE_ENCRYPTED=true"),
				"SWTPM state is not encrypted -- the vtpm service did not unseal "+
					"the state-encryption key from the device TPM: %s", out)
		}, 2*time.Minute, pollingInterval).Should(Succeed())
		expectSwtpmProcessCount(t, device, offID, 0)
	case evetest.HypervisorKubevirt:
		log.Infof("Checking the TPM device in the VMI specs...")
		t.Eventually(func(g Gomega) {
			devs, err := appVMITPMDevices(device, onID)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(devs).To(HaveLen(1), "vtpm-on must have exactly one VMI")
			g.Expect(devs[0]).ToNot(BeNil(), "the vtpm-on VMI has no TPM device")
			g.Expect(devs[0].Persistent == nil || !*devs[0].Persistent).To(BeTrue(),
				"the vtpm-on VMI asks for persistent TPM state")

			devs, err = appVMITPMDevices(device, offID)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(devs).To(HaveLen(1), "vtpm-off must have exactly one VMI")
			g.Expect(devs[0]).To(BeNil(),
				"the vtpm-off VMI has a TPM device despite disable_vtpm")
		}, 2*time.Minute, pollingInterval).Should(Succeed())
	}
	evetest.Checkpoint("vtpm-backend-verified")

	// Phase 3: consume the vTPM from inside the applications. RUNNING only
	// means the domain was created; sshd inside the container needs more
	// time to accept connections.
	log.Infof("Running tpm2_getrandom inside vtpm-on...")
	waitForAppSSH(t, device, onID)
	out, errOut, err := device.RunShellScriptInsideApp(onID, appAuth,
		tpmGetRandomScript, time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "TPM check script failed: %s", errOut)
	t.Expect(out).To(MatchRegexp(`RAND=[0-9a-f]{16}`),
		"tpm2_getrandom did not return 8 random bytes: %s", out)

	log.Infof("Checking that vtpm-off has no TPM device...")
	waitForAppSSH(t, device, offID)
	out, errOut, err = device.RunShellScriptInsideApp(offID, appAuth,
		tpmDevicePresenceScript, time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "TPM presence script failed: %s", errOut)
	t.Expect(out).To(ContainSubstring("TPM_DEVICE=absent"),
		"the vtpm-off guest sees a TPM device: %s", out)
	evetest.Checkpoint("guest-tpm-verified")
}
