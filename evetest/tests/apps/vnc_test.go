// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/amitbet/vncproxy/client"
	"github.com/amitbet/vncproxy/logger"
	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// X11/RFB keysym constants used to drive the shim-VM console switch
// documented in docs/VNC.md ("Switching between the container and the shim
// VM session"): Ctrl+Alt+2 then Enter.
const (
	keysymControlL = 0xffe3
	keysymAltL     = 0xffe9
	keysym2        = 0x0032
	keysymReturn   = 0xff0d
)

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

// TestVNC verifies VNC access to EVE application consoles: a VM app's own
// display, a container app's display, and the container app's underlying
// shim VM console (reached via the documented key-combo switch once shim-VM
// VNC access is enabled).
//
// Under KVM the VNC server is a raw QEMU socket reachable directly on the
// device's uplink IP. Under Kubevirt there is no such socket: zedkube starts
// a `virtctl vnc --proxy-only` process (see pkg/pillar/docs/
// vnc-workflows.md) that bridges the VMI's console onto a TCP port bound to
// 127.0.0.1 only, gated by AppInstanceConfig.RemoteConsole rather than
// EnableVNC. This test reaches that port through an SSH tunnel to the device
// (EdgeDevice.DialViaSSH) instead of a direct dial, and falls back to VNC's
// "none" security type when the server doesn't offer password auth (virtctl
// relies on Kubernetes RBAC for access control, not a VNC password) -- see
// connectVNC.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- only needed for controller reachability
//     and Internet access (to pull the Alpine cloud image and the
//     evetest-ubuntu-ctr container image). VNC itself is never reached
//     through an app network, so neither app in this test is given a network
//     adapter of its own.
//
// Phases
// ------
//  1. Global config: enable app.allow.vnc (opens the device's uplink
//     firewall for TCP ports 5900-5999 -- see
//     pkg/pillar/dpcreconciler/linux.go) and debug.enable.vnc.shim.vm (a
//     per-node flag which, combined with a VM's own EnableVnc, additionally
//     allows switching into the shim VM console -- see
//     pkg/pillar/hypervisor/kvm.go, isVncShimVMEnabled). Both are KVM-only
//     knobs (harmless, but ineffective, under Kubevirt).
//  2. VM app: deploy an Alpine Linux VM (VirtualizationMode=HVM, image from
//     alpineCloudImages matching the device's actual arch (device.GetArch()),
//     EnableVNC=true, VNCDisplay=1, a fixed VNCPassword). No UserData/
//     cloud-init is configured -- VNC reaches the QEMU console as soon as
//     the VM starts, independent of what the guest OS is doing.
//     WaitUntilAppIsRunning, then (under Kubevirt) enable RemoteConsole on
//     the app config and re-apply, connect a real VNC/RFB client to port
//     5901 (directly under KVM, through an SSH tunnel under Kubevirt),
//     authenticate, and assert the handshake succeeds. Delete the app
//     afterwards (disabling RemoteConsole first under Kubevirt, since only
//     one remote-console session is allowed on the device at a time).
//  3. Container app: deploy lfedge/evetest-ubuntu-ctr:1.0 with EnableVNC=true,
//     VNCDisplay=2, the same VNCPassword. WaitUntilAppIsRunning, then connect
//     to port 5902 (same per-hypervisor path as above) and assert the same
//     successful handshake -- proving VNC also works for container apps
//     (viewing the shim VM's console showing the container's entry point).
//  4. Shim VM console switch: on that same VNC connection, send the
//     documented key combo (Ctrl+Alt+2, then Enter -- see docs/VNC.md,
//     "Switching between the container and the shim VM session") via RFB
//     KeyEvent messages, then issue a fresh FramebufferUpdateRequest and a
//     benign follow-up call, asserting neither errors -- i.e. the session
//     stays healthy across the console switch. Note: asserting that the
//     *displayed content* actually changed to the shim VM's login prompt
//     would need pixel-level framebuffer decoding, which the available Go
//     VNC client library does not expose at a level convenient enough to
//     verify robustly here; left as a known scope limit.
//  5. Cleanup: delete the container app.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestAppsSuite.
func TestVNC(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
		evetest.RequireInternetConnectivity{},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// Phase 1: allow external VNC access to the device's uplink ports and
	// enable node-wide shim-VM VNC access.
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueBool(pillartypes.AllowAppVnc, true)
	cfgProps.SetGlobalValueBool(pillartypes.VncShimVMAccess, true)
	devConfig.SetConfigProperties(cfgProps)

	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	const vncPassword = "12345678" // classic VNC (DES) auth is limited to 8 chars
	timeout := 3 * time.Minute
	timeoutExcludingDownload := 8 * time.Minute
	log := evetest.Logger()

	// arch selects which pinned Alpine image matches the device's actual
	// CPU architecture.
	arch := device.GetArch()
	image, ok := alpineCloudImages[arch]
	t.Expect(ok).To(BeTrue(), "no pinned Alpine cloud image for arch %q", arch)

	var deviceIP []net.IP
	if hypervisor != evetest.HypervisorKubevirt {
		deviceIP = device.GetDeviceIPAddress("ethernet0")
		t.Expect(deviceIP).ToNot(BeEmpty())
	}

	// vncDialer returns a description (for log/error messages) and a dial
	// function for the VNC endpoint at 5900+vncDisplay: a direct dial to the
	// device's uplink IP under KVM/Xen, or a dial tunneled over SSH to the
	// device's own loopback under Kubevirt (see the doc comment above).
	vncDialer := func(vncDisplay uint) (string, func() (net.Conn, error)) {
		port := fmt.Sprintf("%d", 5900+vncDisplay)
		if hypervisor == evetest.HypervisorKubevirt {
			addr := net.JoinHostPort("127.0.0.1", port)
			return addr + " (via SSH tunnel)", func() (net.Conn, error) {
				return device.DialViaSSH("tcp", addr)
			}
		}
		addr := net.JoinHostPort(deviceIP[0].String(), port)
		return addr, func() (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 5*time.Second)
		}
	}

	// setRemoteConsole toggles AppInstanceConfig.RemoteConsole for the app
	// identified by appUUIDStr and re-applies the device config. This is the
	// field that gates Kubevirt's virtctl-based VNC proxy (see
	// ApplicationInstanceConfig.RemoteConsole).
	setRemoteConsole := func(appUUIDStr string, enable bool) {
		found := false
		for _, app := range devConfig.Apps {
			if app.GetUuidandversion().GetUuid() == appUUIDStr {
				app.RemoteConsole = enable
				found = true
				break
			}
		}
		t.Expect(found).To(BeTrue(), "app %q not found in device config", appUUIDStr)
		device.ApplyConfig(devConfig, false, false)
	}

	// waitRemoteConsoleReleased polls (via the same SSH-tunneled dial used to
	// reach it) until the Kubevirt VNC proxy for vncDisplay has stopped
	// listening, i.e. zedkube has torn it down after RemoteConsole was
	// disabled. Only one remote-console session is allowed on the device at
	// a time (see pkg/pillar/docs/vnc-workflows.md, canClaimVNCFile), so the
	// next app's setRemoteConsole(true) would otherwise be silently ignored
	// while the previous proxy is still up.
	waitRemoteConsoleReleased := func(vncDisplay uint) {
		_, dial := vncDialer(vncDisplay)
		t.Eventually(func() error {
			conn, err := dial()
			if err == nil {
				_ = conn.Close()
				return fmt.Errorf("VNC proxy for display %d is still listening", vncDisplay)
			}
			return nil
		}, 30*time.Second, 2*time.Second).Should(Succeed())
	}

	// Phase 2: VM app VNC access.
	vmAppUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vnc-vm-app",
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
		EnableVNC:          true,
		VNCDisplay:         1,
		VNCPassword:        vncPassword,
	})
	vmAppUpdates, stopVMAppWatch := device.WatchAppInfo(vmAppUUID)
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(vmAppUUID, timeoutExcludingDownload)
	evetest.Checkpoint("vm-app-running")

	vmAppUUIDStr := vmAppUUID.String()
	if hypervisor == evetest.HypervisorKubevirt {
		setRemoteConsole(vmAppUUIDStr, true)
	}
	log.Infof("Testing VNC access to the VM app")
	vmVNCDesc, vmVNCDial := vncDialer(1)
	vmConn := connectVNC(t, vmVNCDesc, vmVNCDial, vncPassword)
	log.Infof("Connected to VM app VNC desktop %q", vmConn.DesktopName)
	t.Expect(vmConn.Close()).To(Succeed())
	evetest.Checkpoint("vm-app-vnc-verified")

	if hypervisor == evetest.HypervisorKubevirt {
		// Release the remote-console session before deleting the app: only
		// one is allowed on the device at a time, and the container app's
		// session below would otherwise be silently blocked.
		setRemoteConsole(vmAppUUIDStr, false)
		waitRemoteConsoleReleased(1)
	}

	devConfig.DeleteApplication(vmAppUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(vmAppUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"VM app state is UNSPECIFIED",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopVMAppWatch()

	// Phase 3: container app VNC access.
	ctrAppUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vnc-ctr-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		EnableVNC:          true,
		VNCDisplay:         2,
		VNCPassword:        vncPassword,
	})
	ctrAppUUIDStr := ctrAppUUID.String()
	ctrAppUpdates, stopCtrAppWatch := device.WatchAppInfo(ctrAppUUID)
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(ctrAppUUID, timeoutExcludingDownload)
	evetest.Checkpoint("container-app-running")

	if hypervisor == evetest.HypervisorKubevirt {
		setRemoteConsole(ctrAppUUIDStr, true)
	}
	log.Infof("Testing VNC access to the container app")
	ctrVNCDesc, ctrVNCDial := vncDialer(2)
	ctrConn := connectVNC(t, ctrVNCDesc, ctrVNCDial, vncPassword)
	log.Infof("Connected to container app VNC desktop %q", ctrConn.DesktopName)
	evetest.Checkpoint("container-app-vnc-verified")

	// Phase 4: switch to the shim VM console (Ctrl+Alt+2, then Enter -- see
	// docs/VNC.md) and confirm the session stays healthy across the switch.
	log.Infof("Switching to the shim VM console")
	t.Expect(pressKeyCombo(ctrConn, keysymControlL, keysymAltL, keysym2)).To(Succeed())
	t.Expect(pressKeyCombo(ctrConn, keysymReturn)).To(Succeed())
	t.Expect(ctrConn.FramebufferUpdateRequest(
		false, 0, 0, ctrConn.FrameBufferWidth, ctrConn.FrameBufferHeight)).To(Succeed())
	time.Sleep(2 * time.Second)
	// A benign follow-up call: if the console switch broke the session, the
	// underlying connection would already be closed and this would error.
	t.Expect(ctrConn.FramebufferUpdateRequest(
		true, 0, 0, ctrConn.FrameBufferWidth, ctrConn.FrameBufferHeight)).To(Succeed())
	t.Expect(ctrConn.Close()).To(Succeed())
	evetest.Checkpoint("shim-vm-switch-verified")

	// Cleanup.
	if hypervisor == evetest.HypervisorKubevirt {
		setRemoteConsole(ctrAppUUIDStr, false)
	}
	devConfig.DeleteApplication(ctrAppUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(ctrAppUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Container app state is UNSPECIFIED",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopCtrAppWatch()
}

// connectVNC calls dial (retrying while the endpoint isn't reachable yet --
// under Kubevirt the virtctl proxy takes a few seconds to start after
// RemoteConsole is enabled), then performs the full RFB handshake and
// returns the connected client. dialDesc identifies the endpoint in log/error
// messages. It fails the test (via t) rather than returning an error, since a
// broken VNC connection always indicates a test failure at the call sites
// above.
func connectVNC(t *WithT, dialDesc string, dial func() (net.Conn, error),
	password string) *client.ClientConn {
	// The client's background mainLoop goroutine logs an Error-level message
	// whenever its blocking read unblocks because the connection was closed
	// -- including on an intentional Close() from our side. Silence it here
	// (matching eden's own pkg/utils/vnc.go, which does the same) so a clean
	// shutdown doesn't look like a failure in the test output.
	logger.SetLogLevel("fatal")

	var conn net.Conn
	t.Eventually(func() error {
		var err error
		conn, err = dial()
		return err
	}, 90*time.Second, 3*time.Second).Should(Succeed(),
		"failed to dial VNC endpoint %s", dialDesc)

	clientConn, err := client.NewClientConn(conn, &client.ClientConfig{
		// A raw QEMU VNC socket (KVM) offers VNC password auth; Kubevirt's
		// virtctl proxy offers only the "none" security type, relying on
		// Kubernetes RBAC instead of a VNC password. Offering both lets the
		// client pick whichever the server actually supports.
		Auth:      []client.ClientAuth{&client.PasswordAuth{Password: password}, new(client.ClientAuthNone)},
		Exclusive: false,
	})
	t.Expect(err).ToNot(HaveOccurred())

	t.Expect(clientConn.Connect()).To(Succeed(),
		"VNC RFB handshake with %s failed", dialDesc)
	return clientConn
}

// pressKeyCombo sends a key-down event for every keysym in order, then a
// key-up event in reverse order, emulating a user holding several keys
// together (e.g. Ctrl+Alt+2).
func pressKeyCombo(conn *client.ClientConn, keysyms ...uint32) error {
	for _, keysym := range keysyms {
		if err := conn.KeyEvent(keysym, true); err != nil {
			return fmt.Errorf("key-down for keysym 0x%x: %w", keysym, err)
		}
	}
	for i := len(keysyms) - 1; i >= 0; i-- {
		if err := conn.KeyEvent(keysyms[i], false); err != nil {
			return fmt.Errorf("key-up for keysym 0x%x: %w", keysyms[i], err)
		}
	}
	return nil
}
