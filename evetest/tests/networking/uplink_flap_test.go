// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// alpineCloudImages pins the Alpine Linux cloud-init qcow2 image used to boot
// the app in this test, per architecture (same pinned images as
// tests/apps/vnc_test.go and tests/security/vcom_test.go). A real cloud VM is
// used here deliberately instead of the evetest-ubuntu-ctr container: that
// container gets its address injected once at boot by EVE's own
// container-shim init and never runs a DHCP client afterward, so it has
// no DHCP client to ever lose or reacquire a lease in the first place.
// Alpine's cloud image configures eth0 via `ifupdown`+dhcpcd, a genuine DHCP
// client this test can explicitly tell to release and reacquire its lease
// (`ifdown`/`ifup eth0`, see flapUplink below).
var alpineCloudImages = map[string]struct {
	relativePath string
	sha256       string
	sizeBytes    uint64
}{
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

// TestLocalNIUplinkFlap exercises repeated flaps of a Local Network
// Instance's own uplink port (losing and re-acquiring its address, with a
// different advertised DNS server each time) and checks that the NI itself
// stays unaffected: its dnsmasq instance must not restart (same PID
// throughout) and any app attached to it must keep its DHCP-assigned IP
// across every flap, even after being forced to release and reacquire its
// lease. Only the uplink's own upstream connectivity is expected to be
// affected while it is down.
//
// Every IP check is made twice, independently: once against EVE's own
// published ZInfoApp, and once by SSH-ing into the guest and reading its own
// `ip addr show eth0` directly, since zedrouter's state tracking has
// deliberate resilience that could otherwise mask a real loss. Any DHCPNAK
// the NI's dnsmasq logs during a reacquisition is surfaced via EVE's own
// device logs (device.GetLogs).
//
// Network model
// -------------
//   - netmodels.TwoMgmtPorts -- two isolated Ethernet ports, each with DHCP,
//     its own SDN DNS server and controller/http-server.test reachability.
//     Reused here for its topology only. network1 (eth1) additionally has a
//     second, "dns-server1-alt" DNS endpoint defined -- see flapUplink below
//     for why.
//
// Device configuration
// --------------------
//   - ethernet0 (eth0, DHCP, PhyIoUsageMgmtOnly) -- the device's sole
//     management uplink. Never touched after setup.
//   - ethernet1 (eth1, DHCP, PhyIoUsageShared) -- a dedicated, non-management
//     app uplink. This is the port that gets flapped.
//   - One Local NI ("local-ni") on ethernet1, subnet 10.1.0.0/24, DHCP range
//     .100-.254, gateway .1.
//   - One Alpine Linux VM app (cloud-init enables root/password SSH) on the
//     NI with a plain, dynamically pool-assigned IP (no StaticIP/dhcp-host
//     reservation), a port-fwd 2222->22 ACE and a default-allow ACL.
//
// Phases
// ------
//  1. Baseline: wait for the NI ONLINE and the app RUNNING, wait for SSH to
//     become reachable, then record whatever IP the app gets assigned from
//     the DHCP pool and confirm the guest's own `ip addr` agrees with it,
//     and that the app can reach http-server.test through ethernet1. Record
//     the NI's dnsmasq PID. The device is ONLINE.
//  2. phase2 (flapUplink): the outage is injected directly on the EVE host
//     over SSH (`ip link set eth1 down && ip addr flush dev eth1`),
//     confirmed from the EVE API. While the link is down, ethernet1's SDN
//     network is switched to advertise a *different* DNS server
//     ("dns-server1-alt" instead of "dns-server1") via UpdateNetworkModel --
//     an SDN/status-level change, not an EVE-side config edit. The link is
//     then brought back up (`ip link set eth1 up`), letting EVE's own DHCP
//     client re-acquire a lease on its own; the fresh lease carries the
//     different DNS server, confirmed via the EVE API
//     (DevicePort.Dns.DNSservers). Once ethernet1 and the NI are back, the
//     guest is explicitly told to release and reacquire its own DHCP lease
//     (`ifdown`/`ifup eth0`), since its own bridge connection never actually
//     went down during the flap. EVENTUALLY: the app ends up with *the
//     same* IP it had before the flap, confirmed both via EVE's published
//     info and directly over SSH; the NI's dnsmasq PID is unchanged;
//     reachability to http-server.test is reconfirmed.
//  3. phase3, phase4, ...: the same sequence is repeated for a total of
//     UPLINK_FLAP_COUNT flaps (3 by default), alternating the advertised DNS
//     server back and forth so each flap is again a genuine change relative
//     to the one before it.
//  4. Throughout every flap phase, ethernet0 is never touched; the device is
//     expected to stay reachable (ONLINE) at every point checked above.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//   - UPLINK_FLAP_COUNT (defaults to 3): number of flap cycles to exercise,
//     set via EVETEST_UPLINK_FLAP_COUNT.
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite (deploys an app, hence
//     hypervisor-parameterized).
func TestLocalNIUplinkFlap(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	const uplinkFlapCountParamKey = "UPLINK_FLAP_COUNT"
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          uplinkFlapCountParamKey,
			DefaultValue: 3,
			Description: evetest.TestParameterDescription{
				Summary: "Number of uplink flap cycles to exercise",
				Default: "3",
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	flapCount := evetest.GetTestParameter[int](uplinkFlapCountParamKey)
	t.Expect(flapCount).To(BeNumerically(">", 0),
		"EVETEST_UPLINK_FLAP_COUNT must be a positive number of flaps")

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.TwoMgmtPorts,
		},
		evetest.RequireInternetConnectivity{},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	image, known := alpineCloudImages[device.GetArch()]
	if !known {
		test.Skipf("no pinned Alpine cloud image for %s", device.GetArch())
	}

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// ethernet0: the only management-capable port. Left untouched for the
	// rest of the test.
	eth0Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
	})

	// ethernet1: app-only uplink (not usable for management), hosting the
	// Local NI. This is the port that gets flapped below.
	eth1Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   eth1Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("port-config-applied")

	niSubnet := evetest.IPSubnet("10.1.0.0/24")
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet1",
		Subnet:      niSubnet,
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.1.0.100"),
			End:   evetest.IPAddress("10.1.0.254"),
		},
		Gateway: evetest.IPAddress("10.1.0.1"),
		MTU:     1500,
	})

	const (
		appMAC      = "5e:91:cb:6a:a5:02"
		appPassword = "testpassword"
	)
	cloudConfig := `#cloud-config
ssh_pwauth: true
chpasswd:
  list: |
    root:` + appPassword + `
  expire: false
write_files:
  - path: /etc/ssh/sshd_config.d/99-allow-root-password.conf
    content: |
      PermitRootLogin yes
runcmd:
  - rc-service sshd restart
`
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "uplink-flap-app",
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
				MAC:                 evetest.MACAddress(appMAC),
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

	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	defer stopNIWatch()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, false, false)

	log := evetest.Logger()
	timeout := 3 * time.Minute
	recoveryTimeout := 5 * time.Minute

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: appPassword,
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second

	fetchHelloworld := func() {
		t.Eventually(func(g Gomega) {
			output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				"wget -qO- -T 10 http://http-server.test/helloworld", sshTimeout, 0)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(output).To(ContainSubstring("Hello world!"))
		}, timeout, polling).Should(Succeed())
	}

	// guestIP reads the guest's own idea of its address directly over SSH
	// (`ip addr show eth0`), independent of anything EVE itself publishes.
	// Returns "" (never matching a real IP) if the command fails, e.g.
	// because the port-forward NAT itself is unreachable right now.
	guestIP := func() string {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1", sshTimeout, 0)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(output)
	}

	// appNetwork extracts the single reported IP from a ZInfoApp, requiring
	// it to be an address from the NI's own subnet with no reported error.
	appNetwork := func(info *eveinfo.ZInfoApp) (ip string, ok bool) {
		if len(info.GetNetwork()) != 1 {
			return "", false
		}
		netInfo := info.GetNetwork()[0]
		if len(netInfo.GetIPAddrs()) != 1 {
			return "", false
		}
		addr := netInfo.GetIPAddrs()[0]
		if !niSubnet.Contains(evetest.IPAddress(addr)) ||
			netInfo.GetNetworkErr() != nil || netInfo.GetIpAddrMisMatch() {
			return "", false
		}
		return addr, true
	}

	// appIP is set once, from whatever address the app is first assigned in
	// Phase 1, and is expected to stay identical for the rest of the test:
	// a flap recovering connectivity via a *different* address is treated
	// the same as recovering no address at all.
	var appIP string
	appKeptIP := func(info *eveinfo.ZInfoApp) bool {
		ip, ok := appNetwork(info)
		return ok && ip == appIP
	}

	// Phase 1: baseline.
	log.Infof("Phase 1: verifying baseline connectivity and recording the app's DHCP IP...")
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI is ONLINE", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.GetState() == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	device.WaitUntilAppIsRunning(appUUID, 8*time.Minute)
	evetest.Checkpoint("phase1-app-running")

	log.Infof("Phase 1: waiting for SSH to become reachable...")
	t.Eventually(func(g Gomega) {
		_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth, "echo ok", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
	}, 5*time.Minute, polling).Should(Succeed())
	evetest.Checkpoint("phase1-ssh-ready")

	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app gets a DHCP-assigned IP from the Local NI's pool",
		func(info *eveinfo.ZInfoApp) bool {
			ip, ok := appNetwork(info)
			if ok {
				appIP = ip
			}
			return ok
		}).StopIf(appHasError)))
	log.Infof("Phase 1: app acquired DHCP IP %s (published); "+
		"this address must stay unchanged across every flap below", appIP)
	t.Expect(guestIP()).To(Equal(appIP), "guest's own `ip addr` must agree with EVE's published IP")
	fetchHelloworld()

	// Record the NI's dnsmasq PID so every later check can detect whether it
	// restarted: dnsmasq rewrites its own pid file on every (re)start, but
	// not on a SIGHUP-only reload.
	niBridge := device.GetNetworkInstanceInfo(niUUID).GetBridgeName()
	t.Expect(niBridge).ToNot(BeEmpty(), "NI info must report its bridge interface name")
	dnsmasqPID := func() string {
		output, _, err := device.RunShellScript(
			fmt.Sprintf("cat /run/zedrouter/dnsmasq.%s.pid", niBridge), sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred(), "failed to read dnsmasq PID file for bridge %s", niBridge)
		return strings.TrimSpace(output)
	}
	niDnsmasqPID := dnsmasqPID()
	log.Infof("Phase 1: NI dnsmasq (bridge %s) PID is %s; must stay unchanged "+
		"across every flap below", niBridge, niDnsmasqPID)

	t.Expect(device.GetState()).To(Equal(api.EVEDeviceState_EVE_DEVICE_STATE_ONLINE))
	evetest.Checkpoint("phase1-baseline-complete")

	// setEth1DNSServer points ethernet1's SDN network at the given DNS
	// server endpoint ("dns-server1" or "dns-server1-alt", both already
	// defined in netmodels.TwoMgmtPorts). This mutates only the SDN model
	// (the stand-in for the uplink's own network environment), never EVE's
	// own device config -- so the resulting change in ethernet1's upstream
	// DNS server is a live *status* change (observed by EVE through its next
	// DHCP renewal), matching how a real uplink might hand out different
	// DNS servers across a reconnect.
	setEth1DNSServer := func(dnsServerLabel string) {
		model := proto.Clone(netmodels.TwoMgmtPorts).(*api.NetworkModel)
		for _, network := range model.Networks {
			if network.LogicalLabel == "network1" {
				network.Ipv4.Dhcp.Dns.PrivateDns = []string{dnsServerLabel}
			}
		}
		evetest.UpdateNetworkModel(model)
	}
	// Always restore the model on exit so a mid-test failure does not leave
	// the SDN in an altered state for subsequent suite tests.
	defer evetest.UpdateNetworkModel(netmodels.TwoMgmtPorts)

	// flapUplink takes ethernet1 down and flushes its address directly on
	// the EVE host over SSH, switches ethernet1's SDN-advertised DNS server
	// to dnsServerLabel/dnsServerIP while it is down, then brings it back
	// up, asserting each step via the EVE API. phase names the calling
	// phase for log/checkpoint messages.
	flapUplink := func(phase, dnsServerLabel, dnsServerIP string) {
		log.Infof("%s: taking ethernet1 down and flushing its address "+
			"(simulated uplink flap)...", phase)
		_, _, err := device.RunShellScript(
			"ip link set dev eth1 down && ip addr flush dev eth1",
			sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())

		t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
			"ethernet1 has no IPv4 address",
			func(info *eveinfo.ZInfoDevice) bool {
				port := getDevicePort("ethernet1", info)
				return port != nil && !port.GetUp() &&
					getPortIPv4Addr("ethernet1", info) == nil
			})))
		evetest.Checkpoint(phase + "-outage")

		log.Infof("%s: switching ethernet1's advertised DNS server to %q...",
			phase, dnsServerLabel)
		setEth1DNSServer(dnsServerLabel)

		log.Infof("%s: bringing ethernet1 back up (fresh DHCP lease)...", phase)
		_, _, err = device.RunShellScript("ip link set dev eth1 up", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())

		// The IPv4 address and the new DNS server may arrive in a single
		// device info message (zedagent publishes only on change), so they
		// must be checked together: a separate wait for the DNS server would
		// starve if the previous wait consumed the only message carrying it.
		// The port's live DNS-server status must genuinely differ from before
		// the flap, not just its IP address.
		t.Eventually(devUpdates, recoveryTimeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("ethernet1 has an IPv4 address again and reports the "+
				"new DNS server (%s)", dnsServerIP),
			func(info *eveinfo.ZInfoDevice) bool {
				port := getDevicePort("ethernet1", info)
				return port != nil &&
					getPortIPv4Addr("ethernet1", info) != nil &&
					generics.ContainsItem(port.GetDns().GetDNSservers(), dnsServerIP)
			})))

		// Poll the current info (rather than waiting for a fresh pubsub
		// message on niUpdates/appUpdates) because "recovered" here means
		// the NI/app end up back at the *same* ONLINE/IP state they were
		// already in before the flap -- zedrouter has no reason to publish
		// a new message if, from its own point of view, nothing about that
		// final state actually changed. A channel-Receive wait for that
		// exact content can then starve forever even though the
		// device-reported state is (and may have been the whole time)
		// already correct. Do not bail out early on a transient ERROR:
		// zedrouter/NIM races while the uplink is re-bridged can briefly
		// flag the NI/app as errored before settling, same as in
		// TestLocalNI.
		t.Eventually(func() *eveinfo.ZInfoNetworkInstance {
			return device.GetNetworkInstanceInfo(niUUID)
		}, recoveryTimeout, polling).Should(matchers.SatisfyPredicate(
			"NI is ONLINE again",
			func(info *eveinfo.ZInfoNetworkInstance) bool {
				return info.GetState() == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
			}))

		// A renewal (dhcpcd -N) landing inside the Delete->Create gap just
		// gets no reply and silently retries -- it does not by itself make
		// the guest lose its configured address, since nothing told it to
		// give that address up. To actually exercise "the app loses its IP
		// and must reacquire it", explicitly force that here: release the
		// lease and deconfigure eth0, then bring it back up, so the guest
		// performs a genuine fresh DISCOVER against the now-restarted
		// dnsmasq. Not asserted on directly: ifup's own
		// timeout budget may be shorter than this test's, so a non-zero
		// exit here is only logged; the Eventually checks below (which poll
		// for up to recoveryTimeout) are the actual pass/fail signal.
		log.Infof("%s: forcing the guest to release and reacquire its DHCP lease "+
			"(ifdown/ifup eth0)...", phase)
		reacquireStart := time.Now()
		out, errOut, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"ifdown eth0; ifup eth0", 45*time.Second, 0)
		if err != nil {
			log.Warnf("%s: ifdown/ifup eth0 reported an error (stdout: %q, stderr: %q): %v",
				phase, out, errOut, err)
		}

		// Surface (not assert on -- a NAK is valid DHCP protocol behavior;
		// what matters is whether the client ultimately recovers, checked
		// below) any DHCPNAK bn1's dnsmasq logged while the guest was
		// reacquiring: quiet-dhcp in its generated config (dnsmasq.bn1.conf)
		// suppresses routine per-transaction logging, but not errors, so a
		// NAK still shows up here if dnsmasq rejected the request.
		for _, msg := range device.GetLogs(evetest.LogMsgMatch{
			Source:          "dnsmasq",
			MsgHasSubstring: "NAK",
			NotBefore:       reacquireStart,
		}) {
			log.Warnf("%s: dnsmasq logged during reacquisition: %s", phase, msg.Message)
		}

		// The crux of this test: the app must end up with the *same* IP it
		// had before the flap -- not a different one from the fresh DISCOVER
		// just forced above, and not none at all. Checked twice,
		// independently: first against EVE's own published info, then
		// directly over SSH against the guest's own view, since zedrouter's
		// state tracking has deliberate resilience that could otherwise mask
		// a real loss by continuing to report the last known-good address.
		t.Eventually(func() *eveinfo.ZInfoApp {
			return device.GetAppInfo(appUUID)
		}, recoveryTimeout, polling).Should(matchers.SatisfyPredicate(
			"app keeps its DHCP-assigned IP "+appIP+" again (published info)",
			appKeptIP))

		log.Infof("%s: cross-checking the guest's own `ip addr` over SSH...", phase)
		t.Eventually(func(g Gomega) {
			g.Expect(guestIP()).To(Equal(appIP))
		}, recoveryTimeout, polling).Should(Succeed(),
			"guest's own `ip addr` must still report %s after the flap", appIP)

		t.Expect(dnsmasqPID()).To(Equal(niDnsmasqPID),
			"NI's dnsmasq (bridge %s) must not restart due to an uplink-only flap", niBridge)

		log.Infof("%s: verifying http-server.test remains reachable...", phase)
		fetchHelloworld()

		t.Expect(device.GetState()).To(Equal(api.EVEDeviceState_EVE_DEVICE_STATE_ONLINE),
			"device management (ethernet0) must stay unaffected by the ethernet1 flap")
		evetest.Checkpoint(phase + "-recovered")
	}

	// Phases 2.. (EVETEST_UPLINK_FLAP_COUNT of them, 3 by default): flapCount
	// flaps in a row, alternating the advertised DNS server each time so
	// every single one is a genuine change relative to whichever server the
	// previous flap left it on.
	for i := 0; i < flapCount; i++ {
		phase := fmt.Sprintf("phase%d", i+2)
		if i%2 == 0 {
			flapUplink(phase, "dns-server1-alt", "10.16.19.25")
		} else {
			flapUplink(phase, "dns-server1", "10.16.17.25")
		}
	}
}
