// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test what becomes of an entry of runcmd whose value has a space, when a
// container application and a VM application get the same cloud-config.

package apps_test

import (
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	// Environment variable which an entry of runcmd sets.
	runcmdSpacesEnvKey = "EVETEST_TWO_WORDS"

	// Its value as written in the user-data: two words with a space between
	// them and no quotes around them.
	runcmdSpacesEnvValue = "a b"

	// File into which the last entry of runcmd writes the variables of the
	// shell that runs it.
	runcmdSpacesDumpPath = "/envs.txt"

	// Port on the edge node forwarded to the sshd of the VM application.
	runcmdSpacesVMSSHFwdPort = 2223
)

// runcmdSpacesUserData is the cloud-config which both applications of
// TestAppUserDataRuncmdSpaces get.
//
// Every entry of its runcmd starts with NAME=value, because EVE accepts
// nothing else in the runcmd of a container. The first and the last entry go
// on with a command. To EVE that command is part of the value. To a shell it
// is a command to run with the variable set, and so the guest of the VM
// restarts its sshd and writes the dump.
//
// The lines above runcmd let the test log in to the VM as the user which the
// image of the container has. EVE ignores ssh_pwauth and chpasswd for a
// container, and the file of write_files does not change what its sshd allows.
var runcmdSpacesUserData = encodeUserData(`#cloud-config
ssh_pwauth: true
chpasswd:
  list: |
    ` + appAuth.Username + `:` + appAuth.Password + `
  expire: false
write_files:
  - path: /etc/ssh/sshd_config.d/99-allow-root-password.conf
    permissions: '0644'
    content: |
      PermitRootLogin yes
runcmd:
- EVETEST_SSHD=restart rc-service sshd restart
- ` + runcmdSpacesEnvKey + `=` + runcmdSpacesEnvValue + `
- EVETEST_DUMP=done set > ` + runcmdSpacesDumpPath + `
`)

// TestAppUserDataRuncmdSpaces verifies what the runcmd entry
//
//	EVETEST_TWO_WORDS=a b
//
// does in a container application and in a VM application which get the same
// "#cloud-config" user-data. The two differ.
//
// For a container EVE reads the entry itself and takes everything behind the
// equals sign as the value, so the container starts with the variable set to
// "a b". EVE runs nothing.
//
// For a VM EVE only hands the user-data to the guest, whose cloud-init treats
// an entry of runcmd as a line of shell. A shell takes b for a command to run
// with the variable set to "a". There is no such command, and the variable is
// gone with it: the shell which runs the following entry does not have it.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- user-data delivery is not network
//     topology dependent; a single mgmt+apps port with DHCP is enough to run
//     the apps and reach them over SSH.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - Local NI "local-ni" (10.11.12.0/24, gateway .1) on ethernet0.
//   - Container app "runcmd-spaces-app" (lfedge/evetest-ubuntu-ctr) with a
//     single VIF on the NI, port-fwd 2222->22 and an allow-all ACL. It runs
//     inside a shim VM.
//   - VM app "runcmd-spaces-vm" (pinned Alpine Linux cloud-init image for the
//     arch of the device) with a single VIF on the NI, port-fwd 2223->22 and
//     an allow-all ACL.
//   - Both have runcmdSpacesUserData as their user-data. Its runcmd has the
//     entry above between one which restarts sshd and one which writes the
//     variables of the shell to /envs.txt.
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied -> apps-are-running: deploy both apps and
//     wait for RUNNING.
//  2. container-started: commands can be executed inside the container over
//     SSH. Read the variable from /proc/1/environ inside the container and
//     assert that it holds both words, and assert that there is no
//     /envs.txt. /proc/1 is used rather than the SSH session environment
//     because sshd sanitizes the environment it hands to login sessions.
//  3. vm-runcmd-done: commands can be executed inside the VM over SSH and
//     /envs.txt is there, which the last entry of runcmd writes.
//  4. Assert that /envs.txt lists variables of the shell, and that
//     EVETEST_TWO_WORDS is none of them. What the shell said about the entry
//     is looked up in the logs of the VM and written to the test log; it is
//     not asserted, as where a guest keeps it is up to its image.
//  5. Delete both apps and wait for ZSwState_INVALID.
//
// Test params
// -----------
//   - HYPERVISOR. Under Kubevirt the test waits for the cluster node to
//     become ready before deploying the apps.
//
// Suite placement
// ---------------
//   - TestAppsSuite, right after TestAppUserDataRuncmdExpansion, whose device
//     it reuses.
func TestAppUserDataRuncmdSpaces(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
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

	vmImage, known := alpineCloudImages[device.GetArch()]
	t.Expect(known).To(BeTrue(), "no pinned Alpine cloud image for arch %q", device.GetArch())

	// Build and apply the device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	niUUID := addLocalNI(devConfig)

	const (
		sshTimeout               = 20 * time.Second
		vmRuncmdTimeout          = 5 * time.Minute
		vmRuncmdPolling          = 10 * time.Second
		timeoutExcludingDownload = 10 * time.Minute
	)

	ctrUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "runcmd-spaces-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		NetworkAdapters:    singleVIFWithSSH(niUUID),
		UserData:           runcmdSpacesUserData,
	})
	vmUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "runcmd-spaces-vm",
		Activate:    true,
		Image: evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_QCOW2,
			ImageSHA256:       vmImage.sha256,
			MaxDownloadBytes:  vmImage.sizeBytes,
			ImageRelativePath: vmImage.relativePath,
			ServerAddress:     "dl-cdn.alpinelinux.org",
			UseHTTPS:          true,
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
						EdgeNodePort: runcmdSpacesVMSSHFwdPort,
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
		UserData: runcmdSpacesUserData,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	// Phase 1: both domains exist.
	device.WaitUntilAppIsRunning(ctrUUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(vmUUID, timeoutExcludingDownload)
	evetest.Checkpoint("apps-are-running")

	// Phase 2: the container has the variable with both words, and nothing
	// was run for it.
	waitForAppSSH(t, device, ctrUUID)
	evetest.Checkpoint("container-started")
	value, _, err := device.RunShellScriptInsideApp(ctrUUID, appAuth,
		"tr '\\0' '\\n' < /proc/1/environ | sed -n 's/^"+runcmdSpacesEnvKey+"=//p'",
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSuffix(value, "\n")).To(Equal(runcmdSpacesEnvValue),
		"%s did not reach the container as the user-data spells it; the "+
			"whole rest of an entry of runcmd is the value, spaces included",
		runcmdSpacesEnvKey)
	dumpInContainer, _, err := device.RunShellScriptInsideApp(ctrUUID, appAuth,
		"test -e "+runcmdSpacesDumpPath+" && echo there || echo missing",
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSpace(dumpInContainer)).To(Equal("missing"),
		"the container has %s, which only a shell running the last entry "+
			"of runcmd writes", runcmdSpacesDumpPath)

	// Phase 3: the guest of the VM has run its runcmd up to the last entry.
	// That the test can log in takes the first one.
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(vmUUID, appAuth,
			"test -s "+runcmdSpacesDumpPath+" && echo written", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring("written"))
	}, vmRuncmdTimeout, vmRuncmdPolling).Should(Succeed(),
		"the VM did not let the test log in, or its runcmd did not write %s",
		runcmdSpacesDumpPath)
	evetest.Checkpoint("vm-runcmd-done")

	// Phase 4: for the guest the entry was a line of shell, which left no
	// variable behind.
	dump, _, err := device.RunShellScriptInsideApp(vmUUID, appAuth,
		"cat "+runcmdSpacesDumpPath, sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(dump).To(MatchRegexp(`(?m)^PATH=`),
		"%s of the VM does not list the variables of a shell", runcmdSpacesDumpPath)
	t.Expect(dump).ToNot(MatchRegexp(`(?m)^`+runcmdSpacesEnvKey+`=`),
		"the shell which ran the runcmd of the VM has the variable %s; a "+
			"shell sets it for the command b only", runcmdSpacesEnvKey)

	complaint, _, err := device.RunShellScriptInsideApp(vmUUID, appAuth,
		"grep -rhsE '(^|[ :])b: (command )?not found' /var/log | head -n 1",
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Logger().Infof("VM: what its logs hold about the command b of the "+
		"entry %s=%s: %q", runcmdSpacesEnvKey, runcmdSpacesEnvValue,
		strings.TrimSpace(complaint))

	// Phase 5: clean up.
	deleteAppAndWait(t, device, devConfig, vmUUID)
	deleteAppAndWait(t, device, devConfig, ctrUUID)
}
