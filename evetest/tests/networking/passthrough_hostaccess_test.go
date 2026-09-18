// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

// Tracer phases of TestVGAPassthroughNoHostAccess; a recorded access to a
// PCI device is attributed to the phase it fell into. The names travel
// through a path (see pciAccessTracer.mark), hence no spaces. The tracer's
// own phases, the self-test and the end, are defined with it.
const (
	phaseQuietWindow = "quiet-window"
	phaseDNSChange   = "mgmt-port-dns-change"
	phaseUSBToggle   = "usb-access-toggle"
	phaseVGAToggle   = "vga-access-toggle"
	phaseAppRestart  = "app-restart"
)

// vgaLabel is the logical and physical label of the passed-through VGA
// controller in the device model.
const vgaLabel = "vga0"

// TestVGAPassthroughNoHostAccess verifies that once the device's VGA
// controller is passed through to an application, no process on the EVE host
// touches the PCI device any more: only the guest, through qemu and vfio, may
// drive it. Host-side meddling -- re-binding the driver, resetting the device,
// changing its power state, poking its config space -- disturbs or breaks the
// guest's use of the adapter. EVE has components that legitimately manage PCI
// devices at other times (domainmgr's port-versus-pciback reconciliation and
// its handling of the host's VGA and USB access, udev rules, the wwan
// container's modem recovery), so the test provokes the events that make them
// re-evaluate the device and checks that they leave it alone.
//
// How host access is observed
// ---------------------------
// The bpftrace script testdata/pciaccess.bt runs on the host through
// bpftrace-aotrt in the debug container (see pciAccessTracer). It records
// every open() of a PCI device attribute with the process (name and pid, plus
// those of its parent and grandparent as far as the tracer saw them forked,
// so a short-lived tool can be traced back through an intermediate shell to
// the service that spawned it), the path and the open flags, and every call
// of the kernel functions that reset a PCI device,
// write its config space or map one of its BARs. Opens for writing are
// violations, as are those kernel calls by any process other than qemu, which
// drives the device on the guest's behalf; opens for reading are logged for
// information only, because EVE reads sysfs to report on the device. The
// script also records the console attach points through which the host takes
// a VGA device's framebuffer for its own console (the framebuffer drivers' and
// vtconsole bind files); EVE is expected to use them when debug.enable.vga is
// switched, so those are reported but not counted as violations. The tracer
// first proves itself on a harmless write to the management NIC's
// power/control attribute, so a broken tracer cannot pass the test.
//
// Of everything recorded, only what may involve the passed-through controller
// is reported and judged: opens naming its PCI address, opens naming no device
// at all (drivers_probe, rescan, a driver's bind and unbind files, /dev/mem,
// whose target is written into the file rather than visible in the path), the
// console attach points and the kernel functions, which do not reveal their
// device. Opens naming other PCI devices are left out.
//
// The debug container ships only the AOT runtime of bpftrace, so the script
// is driven by eve-tools/bpftrace-compiler's run-via-ssh command: it learns
// the device's kernel over SSH, compiles the script for it (building a small
// VM image around that kernel, booting it under QEMU and running bpftrace
// inside, unless its cache already holds the result), uploads it and runs it
// on the device, and prints the script's output once the run ends. The test
// ends the run through a marker the script exits on, so all output, including
// the self-test write, is checked at the end. That needs docker, qemu, Go and
// the OpenSSH client tools on the test runner; the evetest container has them,
// and make evetest mounts the compiler sources and persists its caches.
//
// Network model
// -------------
// TwoMgmtPorts, of which only eth0 is used, for management (DHCP, controller
// reachability); eth1 is left out of the device model. eth0's network offers
// the DNS server dns-server0-alt (10.16.18.25), which is not advertised by
// DHCP and therefore usable as a pure port-config change.
//
// Device configuration
// --------------------
//   - debug.enable.vga=false: the host gives up its VGA console, as EVE
//     otherwise keeps the boot VGA controller for itself.
//   - eth0: PhyIoUsageMgmtAndApps with a SystemAdapter (DHCP).
//   - vga0: the device's VGA controller, found through sysfs, as a PhyIoHDMI
//     PhysicalIO with dedicated usage.
//   - One container app (EVE wraps it in a shim VM, the actual passthrough
//     target) with a virtual NIC on a Local NI for SSH access (port
//     forwarding) and vga0 directly assigned. VNC stays off, so the guest has
//     no virtual display adapter and its only VGA device is the passed-through
//     one.
//
// Phases
// ------
//  1. Find the VGA controller on the device and apply the configuration;
//     vga0 must be reported among the assignable adapters as unused. Skips
//     when the device has no VGA controller or when EVE reports that it
//     shares a PCI controller with another device.
//  2. Deploy the app; vga0 must be reported as used by the app, the device
//     must be bound to vfio-pci on the host, and the guest must see a VGA
//     controller with the host device's vendor and device id.
//  3. Start the tracer and perform its self-test write, which the output
//     collected in phase 9 must show. Phases 4 to 8 below are each a named
//     tracer phase, so a recorded access is attributed to one of them.
//  4. Quiet window: nothing is changed for 90 seconds, to catch periodic host
//     activity.
//  5. Management port DNS change: a DNS server is added to and removed again
//     from eth0, which changes DeviceNetworkStatus and makes domainmgr re-run
//     its port-versus-pciback reconciliation for every adapter.
//  6. debug.enable.usb toggle: switched off and back on, which makes
//     domainmgr re-run the same reconciliation and its I/O bundle
//     consistency check directly.
//  7. debug.enable.vga toggle: switched on and back off, which makes
//     domainmgr revisit the assigned VGA controller and bind and unbind the
//     host's framebuffer console; the console accesses are recorded for
//     information, the controller itself must be left alone.
//  8. Application restart, across which domainmgr must keep the controller
//     assigned; the guest must see it again afterwards.
//  9. End the tracer and collect its output: in phases 4 to 8 no host process
//     may have opened an attribute of the controller, or a bus-wide control
//     file, for writing,
//     and none but qemu may have reset a PCI device, written its config space
//     or mapped a BAR. The device must still be bound to vfio-pci and the
//     guest must still see it.
//
// Parameters: HYPERVISOR; BPFTRACE_COMPILER_DIR, the sources of
// eve-tools/bpftrace-compiler (default: their location in an EVE checkout,
// relative to this package).
//
// The test skips itself when the broker does not expose a vIOMMU to the EVE
// VM (see the note on TestNetworkAdapterPassthrough), when the EVE VM has no
// VGA controller, when the device is not amd64 (the script traces the amd64
// syscalls), and when the test runner lacks the compiler sources or the tools
// to run it: docker, qemu, Go, ssh-keyscan and the EVE SSH key.
func TestVGAPassthroughNoHostAccess(test *testing.T) {
	evetestT := evetest.Init(test)
	log := evetest.Logger()
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter(), bpftraceCompilerDirParam)
	hypervisor := evetest.GetHypervisorParameterValue()
	compilerDir := evetest.GetTestParameter[string](bpftraceCompilerDirParamKey)

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.TwoMgmtPorts,
		})
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Nested VFIO passthrough only works when the broker exposes a vIOMMU
	// to the EVE VM; skip when it does not.
	iommus, err := device.ListDirEntries("/sys/class/iommu")
	if err != nil {
		evetestT.Fatalf("Failed to check the device for a vIOMMU: %v", err)
	}
	if len(iommus) == 0 {
		test.Skip("the broker provider does not expose a vIOMMU to the EVE VM, " +
			"which nested VFIO passthrough requires")
	}

	const (
		timeout     = 5 * time.Minute
		sshTimeout  = 20 * time.Second
		polling     = 3 * time.Second
		quietWindow = 90 * time.Second
		// settleDelay gives domainmgr time to act on one config-property
		// change before the next one supersedes it.
		settleDelay = 10 * time.Second
		// altDNSServer is dns-server0-alt of the TwoMgmtPorts model.
		altDNSServer = "10.16.18.25"
	)

	// Phase 1: the VGA controller to pass through is whatever the EVE VM
	// has; its vendor and device id identify it again inside the guest.
	hostDevices, err := listPCIDevices(device)
	if err != nil {
		evetestT.Fatalf("Failed to list the PCI devices of %s: %v", devName, err)
	}
	vga := findVGADevice(hostDevices)
	if vga == nil {
		test.Skipf("the EVE VM has no VGA controller to pass through; its PCI devices:\n%s",
			formatPCIDevices(hostDevices))
	}
	log.Infof("Passing through the VGA controller %s", vga)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	setBoolConfigProperty(devConfig, pillartypes.VgaAccess, false)
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
	devConfig.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:  vgaLabel,
		PhysicalLabel: vgaLabel,
		Type:          evecommon.PhyIoType_PhyIoHDMI,
		PCIAddress:    vga.BDF,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)

	var sharedControllerErr string
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"the VGA controller is reported as an unused assignable adapter",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			bundle := lookupAssignableAdapter(dinfo, vgaLabel)
			if bundle == nil {
				return false
			}
			// Devices on one PCI controller form a single assignment group;
			// passing through only one of them is impossible, so skip below.
			if err := bundle.GetErr(); err != nil {
				if strings.Contains(err.GetDescription(), "same PCI controller") {
					sharedControllerErr = err.GetDescription()
					return true
				}
				return false
			}
			return bundle.GetUsedByAppUUID() == ""
		})))
	if sharedControllerErr != "" {
		test.Skipf("VGA passthrough is not possible on this host, the controller "+
			"shares a PCI controller with another device: %s", sharedControllerErr)
	}
	evetest.Checkpoint("adapter-available")

	// Phase 2: deploy the app with the VGA controller directly assigned and
	// a virtual NIC for SSH access.
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
	})
	appConfig := evetest.ApplicationInstanceConfig{
		DisplayName: "vga-passthrough-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				MAC:                 evetest.MACAddress("02:16:3e:00:00:01"),
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
		IOAdapters: []evetest.IOAdapterConfig{
			{
				LogicalLabel: vgaLabel,
				Type:         evecommon.PhyIoType_PhyIoHDMI,
			},
		},
	}
	appUUID := devConfig.AddApplication(appConfig)
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, timeout)

	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"the VGA controller is reported as assigned to the application",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			bundle := lookupAssignableAdapter(dinfo, vgaLabel)
			return bundle != nil && bundle.GetUsedByAppUUID() == appUUID.String()
		})))
	evetest.Checkpoint("adapter-assigned")

	// PCI addresses as domainmgr sees them: the VGA controller is the device
	// under test, eth0 the control device for the tracer's self-test.
	var eth0PCI string
	t.Eventually(func(g Gomega) {
		vgaBundle, err := readAssignableAdapter(device, vgaLabel)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(vgaBundle.UsedByUUID).To(Equal(appUUID))
		g.Expect(vgaBundle.PciLong).To(Equal(vga.BDF))
		eth0, err := readAssignableAdapter(device, "eth0")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(eth0.PciLong).ToNot(BeEmpty())
		eth0PCI = eth0.PciLong
	}, timeout, polling).Should(Succeed())
	log.Infof("Management NIC eth0 is PCI device %s", eth0PCI)

	t.Eventually(func(g Gomega) {
		expectVfioOwnsPCIDevice(g, device, vga.BDF)
	}, timeout, polling).Should(Succeed())

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	guestSeesVGA := func(g Gomega) {
		stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			listPCIDevicesScript, sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		guestDevices, err := parsePCIDeviceList(stdout)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hasVGADeviceOfModel(guestDevices, *vga)).To(BeTrue(),
			"no VGA controller of model %s among the guest's PCI devices:\n%s",
			vga, formatPCIDevices(guestDevices))
	}
	log.Infof("Waiting for the passed-through VGA controller to appear in the guest...")
	t.Eventually(guestSeesVGA, timeout, polling).Should(Succeed())
	evetest.Checkpoint("guest-owns-vga")

	// Phase 3: from here on, every access to a PCI device on the host is
	// recorded.
	tracer := startPCIAccessTracer(evetestT, device, compilerDir)
	defer tracer.stop()
	controlAttr := tracer.selfTestWrite(t, eth0PCI)
	evetest.Checkpoint("tracer-running")

	// Phase 4.
	tracer.mark(phaseQuietWindow)
	log.Infof("Observing the host for %v without any configuration change...",
		quietWindow)
	time.Sleep(quietWindow)

	// Phase 5: a static DNS server appended to eth0's DHCP-provided one is
	// a new DPC for nim to test and apply, and every resulting
	// DeviceNetworkStatus update runs domainmgr's reconciliation.
	tracer.mark(phaseDNSChange)
	devConfig.UpdateNetwork(dhcpNet, evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		DNSServers:  []net.IP{evetest.IPAddress(altDNSServer)},
	})
	device.ApplyConfig(devConfig, true, true)
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"management port eth0 reports the added DNS server",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			port := getDevicePort("ethernet0", dinfo)
			return port != nil &&
				slices.Contains(port.GetDns().GetDNSservers(), altDNSServer)
		})))
	devConfig.UpdateNetwork(dhcpNet, evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	device.ApplyConfig(devConfig, true, true)
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"management port eth0 no longer reports the added DNS server",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			port := getDevicePort("ethernet0", dinfo)
			return port != nil && len(port.GetDns().GetDNSservers()) > 0 &&
				!slices.Contains(port.GetDns().GetDNSservers(), altDNSServer)
		})))

	// Phase 6: each change of debug.enable.usb makes domainmgr revisit the
	// pciback placement of every adapter. Switching off first and then on
	// guarantees a change whichever value the device started with.
	tracer.mark(phaseUSBToggle)
	setBoolConfigProperty(devConfig, pillartypes.UsbAccess, false)
	device.ApplyConfig(devConfig, true, true)
	time.Sleep(settleDelay)
	setBoolConfigProperty(devConfig, pillartypes.UsbAccess, true)
	device.ApplyConfig(devConfig, true, true)
	time.Sleep(settleDelay)

	// Phase 7: with debug.enable.vga on, domainmgr wants the boot VGA
	// controller back for the host console; it must notice the controller
	// is in use and leave it alone, whatever it does to its console.
	tracer.mark(phaseVGAToggle)
	setBoolConfigProperty(devConfig, pillartypes.VgaAccess, true)
	device.ApplyConfig(devConfig, true, true)
	time.Sleep(settleDelay)
	setBoolConfigProperty(devConfig, pillartypes.VgaAccess, false)
	device.ApplyConfig(devConfig, true, true)
	time.Sleep(settleDelay)

	// Phase 8.
	tracer.mark(phaseAppRestart)
	device.RebootApplication(appUUID, true, timeout)
	log.Infof("Waiting for the passed-through VGA controller to be back in the " +
		"guest after the restart...")
	t.Eventually(guestSeesVGA, timeout, polling).Should(Succeed())

	evetest.Checkpoint("observation-done")

	// Phase 9. Ending the tracer yields everything it recorded, which must
	// include the self-test write. Only accesses that may involve the
	// passed-through controller matter: those naming its address, those
	// naming no device (whose target the path does not reveal), console
	// attach points and kernel functions.
	allAccesses, err := tracer.finish()
	t.Expect(err).ToNot(HaveOccurred())
	expectSelfTestRecorded(t, allAccesses, controlAttr)
	accesses := pciAccessesConcerning(allAccesses, vga.BDF)
	log.Infof("Recorded %d accesses on the host that may involve the VGA controller %s "+
		"(%d accesses naming other PCI devices left out):\n%s",
		len(accesses), vga.BDF, len(allAccesses)-len(accesses), formatPCIAccesses(accesses))
	if consoleWrites := pciConsoleWrites(accesses); len(consoleWrites) > 0 {
		log.Infof("The host bound or unbound its framebuffer console %d times:\n%s",
			len(consoleWrites), formatPCIAccesses(consoleWrites))
	}
	if violations := pciAccessViolations(accesses); len(violations) > 0 {
		kmsg, _, _ := device.RunShellScript(
			fmt.Sprintf("dmesg | grep -F %s | tail -n 30", vga.BDF), sshTimeout, 0)
		evetestT.Fatalf("Host processes interfered with PCI devices while the VGA "+
			"controller %s was passed through to the application:\n%s\n"+
			"Kernel messages mentioning %s:\n%s",
			vga.BDF, formatPCIAccesses(violations), vga.BDF, kmsg)
	}

	t.Eventually(func(g Gomega) {
		expectVfioOwnsPCIDevice(g, device, vga.BDF)
	}, timeout, polling).Should(Succeed())
	t.Eventually(guestSeesVGA, timeout, polling).Should(Succeed())
}
