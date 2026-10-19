// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// vcomCheckScript is a self-contained (stdlib-only) Python script that
// exercises vcomlink's TPM ActivateCredParams endpoint over vsock from
// inside the guest.
//
// vcomlink (pkg/pillar/cmd/vcomlink) serves a plain HTTP/1.1 API tunneled
// over an AF_VSOCK connection to the host (CID=VMADDR_CID_HOST, port 2000;
// see vsocksrv.go), with protobuf-encoded request/response bodies (see
// pkg/pillar/vcom/api/proto/messages.proto). vcomRequestBody below is the
// precomputed protobuf encoding of
// vcom.TpmRequestActivateCredParams{Index: 0x81000003} -- 0x81000003 is
// evetpm.TpmAIKHdl, the well-known permanent handle for EVE's AIK -- so this
// script needs no protobuf library. The response is parsed just far enough
// (a minimal length-delimited-field walk) to read the length of the "ek"
// field (field 1), which is all this test needs to assert.
const vcomCheckScript = `#!/usr/bin/env python3
import socket
import sys

# protobuf encoding of TpmRequestActivateCredParams{Index: 0x81000003}
REQUEST_BODY = bytes([0x08, 0x83, 0x80, 0x80, 0x88, 0x08])

def read_varint(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def bytes_field_len(data, field_num):
    pos = 0
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field, wire_type = tag >> 3, tag & 0x7
        if wire_type == 0:
            _, pos = read_varint(data, pos)
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            if field == field_num:
                return length
            pos += length
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            raise ValueError("unsupported wire type %d" % wire_type)
    return None

s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.connect((socket.VMADDR_CID_HOST, 2000))
request = (
    b"POST /tpm/activatecredparams HTTP/1.1\r\n"
    b"Host: vcom\r\n"
    b"Content-Type: application/x-proto-binary\r\n"
    b"Content-Length: " + str(len(REQUEST_BODY)).encode() + b"\r\n"
    b"Connection: close\r\n\r\n"
) + REQUEST_BODY
s.sendall(request)

data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
s.close()

header_end = data.index(b"\r\n\r\n")
status_line = data[:header_end].split(b"\r\n")[0].decode()
body = data[header_end + 4:]

if " 200 " not in status_line:
    print("STATUS=%s BODY=%s" % (status_line, body.decode(errors="replace")))
    sys.exit(1)

print("STATUS=200 EK_LEN=%d" % bytes_field_len(body, 1))
`

var vcomEKLenRegexp = regexp.MustCompile(`EK_LEN=(\d+)`)

// alpineCloudImage describes the arch-specific pinned Alpine Linux
// cloud-init qcow2 image used to boot the VM app in this test.
type alpineCloudImage struct {
	relativePath string
	sha256       string
	sizeBytes    uint64
}

// Alpine 3.24.1 cloud images, pinned by release version (not a rolling
// "latest" alias) so the SHA256 below stays valid indefinitely. See
// https://alpinelinux.org/cloud/ for the full image list.
//
// amd64 uses the "bios-cloudinit" variant, not "uefi-cloudinit": pillar only
// attaches OVMF/UEFI firmware automatically for VmMode_FML on amd64 (see
// handledomainmgr.go), so a VmMode_HVM VM on amd64 gets legacy SeaBIOS, which
// cannot boot a UEFI-only image. arm64 has no legacy BIOS at all, so pillar
// always attaches OVMF there regardless of VirtualizationMode, and the
// "uefi-cloudinit" variant is the correct (only) choice.
var alpineCloudImages = map[string]alpineCloudImage{
	"amd64": {
		relativePath: "/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2",
		sha256:       "6e2e6fe0572b6632527f268d3659e8fccebda4e1ee470fafe2c4d7b85b6a4df6",
		sizeBytes:    183697408,
	},
	"arm64": {
		relativePath: "/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-aarch64-uefi-cloudinit-r0.qcow2",
		sha256:       "3059a6280977c2122982632e0317c5ddbd39069d46ca1e60480de283091f720f",
		sizeBytes:    239271936,
	},
}

// TestVCom verifies that vcomlink (pkg/pillar/cmd/vcomlink), EVE's
// vsock-based host<->VM communication agent, is running and correctly
// serves a TPM request from inside a guest VM.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- controller reachability plus Internet
//     access, needed to pull the Alpine cloud image below.
//
// Phases
// ------
//  1. Confirm vcomlink is actually listening on the host side (the device
//     always has TPM emulation enabled -- vcomlink's TPM handlers depend
//     on one being present): `eve exec pillar ss -l --vsock` must report
//     a listener on CID:port "2:2000" (VMADDR_CID_HOST, vcomlink's fixed
//     port -- see vsocksrv.go).
//  2. Deploy a VM app (VirtualizationMode=HVM) from the pinned Alpine
//     Linux cloud image (matching the device's actual arch, device.GetArch()),
//     on a Local NI with a 2222->22 port-forward. UserData is a cloud-config
//     enabling password SSH login for root (disabled by default).
//     Wait for the app to reach RUNNING, then for SSH to become reachable.
//  3. Write vcomCheckScript into the guest over SSH and run it with
//     python3 (present by default on the Alpine cloud image; AF_VSOCK
//     needs Python >= 3.9, satisfied by Alpine 3.24's default 3.12).
//     Assert the script's own output reports HTTP 200 and a non-zero EK
//     length -- i.e. vcomlink actually returned real TPM-backed data to
//     the VM over vsock, not just accepted the connection.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestVCom(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()

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

	log := evetest.Logger()
	log.Infof("Checking if vComLink is running on EVE...")
	t.Eventually(func(gt Gomega) {
		out, _, err := device.RunShellScript(
			"eve exec pillar ss -l --vsock", 20*time.Second, 0)
		gt.Expect(err).ToNot(HaveOccurred())
		gt.Expect(out).To(
			ContainSubstring("2:2000"), "vComLink is not listening on vsock")
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
	evetest.Checkpoint("vcomlink-listening")

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
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.254"),
		},
		Gateway: evetest.IPAddress("10.50.0.1"),
		MTU:     1500,
	})

	image := alpineCloudImages[device.GetArch()]
	vmAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	cloudConfig := fmt.Sprintf(`#cloud-config
ssh_pwauth: true
chpasswd:
  list: |
    root:%s
  expire: false
write_files:
  - path: /etc/ssh/sshd_config.d/99-allow-root-password.conf
    content: |
      PermitRootLogin yes
runcmd:
  - rc-service sshd restart
`, vmAuth.Password)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vcom-test-vm",
		Activate:    true,
		Image: evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_QCOW2,
			ImageSHA256:       image.sha256,
			MaxDownloadBytes:  image.sizeBytes,
			ImageRelativePath: image.relativePath,
			ServerAddress:     "dl-cdn.alpinelinux.org",
			UseHTTPS:          true,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		UserData:           base64.StdEncoding.EncodeToString([]byte(cloudConfig)),
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
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(appUUID, 8*time.Minute)
	evetest.Checkpoint("vm-running")

	sshTimeout := 20 * time.Second
	polling := 5 * time.Second
	log.Infof("Waiting for VM SSH to become reachable...")
	t.Eventually(func(gt Gomega) {
		_, _, err := device.RunShellScriptInsideApp(appUUID, vmAuth,
			"echo ok", sshTimeout, 0)
		gt.Expect(err).ToNot(HaveOccurred())
	}, 5*time.Minute, polling).Should(Succeed())
	evetest.Checkpoint("vm-ssh-ready")

	log.Infof("Running the vComLink TPM check script inside the VM...")
	encoded := base64.StdEncoding.EncodeToString([]byte(vcomCheckScript))
	script := "echo " + encoded + " | base64 -d > vcomcheck.py && python3 vcomcheck.py"
	checkOut, checkErr, err := device.RunShellScriptInsideApp(
		appUUID, vmAuth, script, 60*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred(), "vComLink check script failed: %s", checkErr)
	t.Expect(checkOut).To(
		ContainSubstring("STATUS=200"), "unexpected vComLink response: %s", checkOut)

	match := vcomEKLenRegexp.FindStringSubmatch(checkOut)
	t.Expect(match).To(HaveLen(2), "could not find EK_LEN in script output: %s", checkOut)
	ekLen, err := strconv.Atoi(match[1])
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(ekLen).To(BeNumerically(">", 0), "vComLink returned an empty EK")
	evetest.Checkpoint("vcom-tpm-request-verified")
}
