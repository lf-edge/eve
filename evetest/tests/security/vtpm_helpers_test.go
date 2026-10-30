// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	vtpmNVIndex       = "0x01500016"
	vtpmMarkerSize    = 32
	vtpmStateRoot     = "/persist/swtpm"
	vtpmLogSizeLimit  = 10 * 1024 * 1024
	vtpmLogBackupMax  = 3
	vtpmGuestWaitTime = 5 * time.Minute
)

func setupVTPMDevice(t *evetest.T, withTPM bool) (*evetest.EdgeDevice, *evetest.EdgeDeviceConfig, uuid.UUID) {
	return setupVTPMDeviceWithPCRBanks(t, withTPM, nil)
}

func setupVTPMDeviceWithPCRBanks(t *evetest.T, withTPM bool, banks []api.TPMPCRBank) (*evetest.EdgeDevice, *evetest.EdgeDeviceConfig, uuid.UUID) {
	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor != evetest.HypervisorKVM {
		t.Skipf("the host-side vtpm service exists only on KVM, got %s", hypervisor)
	}
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			WithTPM:           withTPM,
			WithTPMPCRBanks:   banks,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	config, niUUID := singleMgmtPortWithLocalNI(device, hypervisor)
	evetest.Checkpoint("vtpm-device-ready")
	return device, config, niUUID
}

func addVTPMTestApp(config *evetest.EdgeDeviceConfig, niUUID uuid.UUID,
	name string, sshPort uint16) uuid.UUID {
	return config.AddApplication(vtpmTestAppConfig(niUUID, name, sshPort))
}

// vtpmTestAppConfig is the app the vTPM tests deploy: the evetest-ubuntu-ctr
// image (sshd, tpm2-tools) run as a shim VM, with a port-forward to its sshd.
func vtpmTestAppConfig(niUUID uuid.UUID, name string,
	sshPort uint16) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName: name,
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
				PortFwdRules: []evetest.PortFwdRule{{
					Protocol:     evetest.NetworkProtocolTCP,
					EdgeNodePort: sshPort,
					AppPort:      22,
				}},
				ACLAllowRules: []evetest.ACLAllowRule{{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				}},
			},
		},
	}
}

// waitForAppSSH waits until sshd inside the app accepts connections: RUNNING
// only means the domain was created.
func waitForAppSSH(t *WithT, device *evetest.EdgeDevice, id uuid.UUID) {
	t.Eventually(func(g Gomega) {
		_, _, err := device.RunShellScriptInsideApp(id, appAuth,
			"echo ok", appSSHTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
	}, vtpmGuestWaitTime, pollingInterval).Should(Succeed())
}

// vmiTPMDevice is the TPM device entry of a KubeVirt VMI spec.
type vmiTPMDevice struct {
	Persistent *bool `json:"persistent"`
}

// appVMITPMDevices returns the TPM device of every VMI of the app, nil for a
// VMI without one. An error means the VMIs could not be listed, which a caller
// inside Eventually should retry.
func appVMITPMDevices(device *evetest.EdgeDevice,
	id uuid.UUID) ([]*vmiTPMDevice, error) {
	items, err := device.ListAppVMIs(id, appSSHTimeout)
	if err != nil {
		return nil, err
	}
	var devs []*vmiTPMDevice
	for _, item := range items {
		var vmi struct {
			Spec struct {
				Domain struct {
					Devices struct {
						TPM *vmiTPMDevice `json:"tpm"`
					} `json:"devices"`
				} `json:"domain"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(item, &vmi); err != nil {
			return nil, fmt.Errorf("parsing VMI: %w", err)
		}
		devs = append(devs, vmi.Spec.Domain.Devices.TPM)
	}
	return devs, nil
}

func waitForVTPMGuest(t *WithT, device *evetest.EdgeDevice, id uuid.UUID) {
	t.Eventually(func(g Gomega) {
		_, _, err := device.RunShellScriptInsideApp(id, appAuth,
			"test -c /dev/tpmrm0 -o -c /dev/tpm0", appSSHTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
	}, vtpmGuestWaitTime, pollingInterval).Should(Succeed())
}

func newVTPMMarker(t *evetest.T) string {
	buf := make([]byte, vtpmMarkerSize/2)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("make guest TPM marker: %v", err)
	}
	return hex.EncodeToString(buf)
}

// writeGuestTPMMarker places the marker in TPM NV, not the app filesystem.
// The index is fresh because each test uses a new application UUID.
func writeGuestTPMMarker(t *WithT, device *evetest.EdgeDevice, id uuid.UUID, marker string) {
	if len(marker) != vtpmMarkerSize {
		panic("guest TPM marker has the wrong length")
	}
	waitForVTPMGuest(t, device, id)
	script := fmt.Sprintf(`set -eu
printf '%%s' '%s' > /tmp/evetest-vtpm-marker
tpm2_nvdefine -C o -s %d -a 'ownerread|ownerwrite' %s
tpm2_nvwrite -C o -i /tmp/evetest-vtpm-marker %s
rm -f /tmp/evetest-vtpm-marker`, marker, vtpmMarkerSize, vtpmNVIndex, vtpmNVIndex)
	_, stderr, err := device.RunShellScriptInsideApp(id, appAuth, script, time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "write guest TPM NV marker: %s", stderr)
}

func expectGuestTPMMarker(t *WithT, device *evetest.EdgeDevice, id uuid.UUID, marker string) {
	t.Eventually(func(g Gomega) {
		out, stderr, err := device.RunShellScriptInsideApp(id, appAuth,
			fmt.Sprintf("tpm2_nvread -C o -s %d %s", vtpmMarkerSize, vtpmNVIndex),
			appSSHTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred(), "read guest TPM NV marker: %s", stderr)
		g.Expect(strings.TrimSpace(out)).To(Equal(marker), "guest TPM identity changed")
	}, vtpmGuestWaitTime, pollingInterval).Should(Succeed())
}

func vtpmStatePath(id uuid.UUID) string {
	return fmt.Sprintf("%s/tpm-state-%s", vtpmStateRoot, id)
}

func vtpmProtectedMarkerPath(id uuid.UUID) string {
	return vtpmStatePath(id) + "/.pcr-protected"
}

func expectDevicePath(t *WithT, device *evetest.EdgeDevice, path string, present bool) {
	t.Eventually(func(g Gomega) {
		exists, err := device.PathExists(path)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(exists).To(Equal(present), "path %s", path)
	}, 2*time.Minute, pollingInterval).Should(Succeed())
}

func expectSwtpmProcessCount(t *WithT, device *evetest.EdgeDevice, id uuid.UUID, want int) {
	// Keep the UUID out of the pgrep pattern in the shell's own command line.
	// Otherwise pgrep can count the shell executing this check as swtpm.
	script := fmt.Sprintf("uuid=%s; pgrep -f \"swtpm socket.*$uuid\" | wc -l", id)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScript(script, appSSHTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		count, parseErr := strconv.Atoi(strings.TrimSpace(out))
		g.Expect(parseErr).ToNot(HaveOccurred())
		g.Expect(count).To(Equal(want), "unexpected number of swtpm processes for app %s", id)
	}, 2*time.Minute, pollingInterval).Should(Succeed())
}

func expectOneSwtpmProcess(t *WithT, device *evetest.EdgeDevice, id uuid.UUID) {
	expectSwtpmProcessCount(t, device, id, 1)
}
