// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// ipv6Identity is what a management port presents on an IPv6 network: its
// MAC, its IPv6 addresses split by scope, and dhcpcd's DHCPv6 DUID.
type ipv6Identity struct {
	mac        net.HardwareAddr
	linkLocal  []string
	global     []string
	duid       string
	scriptDump string
}

// ipv6IdentityScript prints the eth0 MAC, every IPv6 address on eth0 and
// dhcpcd's DUID. dhcpcd runs in the pillar container, so its state directory
// is only visible through "eve exec pillar".
const ipv6IdentityScript = `
echo "mac $(cat /sys/class/net/eth0/address)"
ip -6 -o addr show dev eth0 | sed 's/^/addr /'
echo "duid $(eve exec pillar cat /var/lib/dhcpcd/duid 2>/dev/null | tail -1)"
`

func readIPv6Identity(device *evetest.EdgeDevice) (ipv6Identity, error) {
	out, _, err := device.RunShellScript(ipv6IdentityScript, 20*time.Second, 0)
	id := ipv6Identity{scriptDump: out}
	if err != nil {
		return id, err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "mac":
			if id.mac, err = net.ParseMAC(fields[1]); err != nil {
				return id, err
			}
		case "duid":
			id.duid = strings.ToLower(fields[1])
		case "addr":
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] != "inet6" {
					continue
				}
				ip, _, err := net.ParseCIDR(fields[i+1])
				if err != nil {
					return id, err
				}
				if ip.IsLinkLocalUnicast() {
					id.linkLocal = append(id.linkLocal, ip.String())
				} else if ip.IsGlobalUnicast() {
					id.global = append(id.global, ip.String())
				}
			}
		}
	}
	sort.Strings(id.linkLocal)
	sort.Strings(id.global)
	if id.mac == nil {
		return id, fmt.Errorf("no MAC in output:\n%s", out)
	}
	return id, nil
}

// eui64InterfaceID returns the modified EUI-64 interface identifier
// (RFC 4291 appendix A) for a 48-bit MAC.
func eui64InterfaceID(mac net.HardwareAddr) []byte {
	return []byte{mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

// TestDeviceIPv6StableAddresses verifies that a management port keeps the
// same IPv6 addresses and DHCPv6 DUID across a reboot. dhcpcd, not the
// kernel, forms these addresses, and nothing under its state directory
// survives a reboot, so they must be derived from the port's MAC: EUI-64
// interface identifiers and a DUID-LL.
//
// Network model
// -------------
//   - netmodels.SingleEthIPv6Only -- one eth0 port, IPv6-only segment
//     (fd3f:89fd:78c5::/64, SLAAC, DHCPv6 for DNS options).
//
// Phases
// ------
//  1. Apply DHCPNetworkConfig{V6Only} on ethernet0 and wait for a
//     global-unicast IPv6 and a default router in DevicePortStatus.
//  2. Over SSH, record the eth0 MAC, link-local and global IPv6 addresses,
//     and /var/lib/dhcpcd/duid from the pillar container.
//  3. Reboot through the controller and record the same again once eth0 has
//     a global address.
//  4. Assert the addresses and DUID are unchanged, every address uses the
//     EUI-64 interface identifier of the MAC, and the DUID is DUID-LL
//     (type 3, hardware type 1) carrying the MAC.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestDeviceIPv6StableAddresses(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	// Upstream DNS servers are cleared for the reason given in
	// TestDeviceIPv6Connectivity.
	networkModel := proto.Clone(netmodels.SingleEthIPv6Only).(*api.NetworkModel)
	networkModel.Endpoints.DnsServers[0].UpstreamServers = nil
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: networkModel,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V6Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	log := evetest.Logger()
	timeout := 5 * time.Minute

	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"ethernet0 has global-unicast IPv6 and a default router",
		func(info *eveinfo.ZInfoDevice) bool {
			port := getDevicePort("ethernet0", info)
			return getPortIPv6GlobalAddr("ethernet0", info) != nil &&
				port != nil && len(port.GetDefaultRouters()) > 0
		})))
	evetest.Checkpoint("ipv6-addr-acquired")

	waitForIdentity := func(phase string) ipv6Identity {
		var id ipv6Identity
		t.Eventually(func() error {
			var err error
			id, err = readIPv6Identity(device)
			if err != nil {
				return err
			}
			if len(id.global) == 0 || len(id.linkLocal) == 0 ||
				!strings.HasPrefix(id.duid, "00:") {
				return fmt.Errorf("eth0 not fully configured yet:\n%s",
					id.scriptDump)
			}
			return nil
		}, timeout, 10*time.Second).Should(Succeed())
		log.Infof("%s: mac=%s link-local=%v global=%v duid=%s",
			phase, id.mac, id.linkLocal, id.global, id.duid)
		return id
	}

	before := waitForIdentity("before reboot")
	evetest.Checkpoint("identity-recorded")

	device.RequestReboot(true, true)
	evetest.Checkpoint("rebooted")
	after := waitForIdentity("after reboot")

	t.Expect(after.mac.String()).To(Equal(before.mac.String()))
	t.Expect(after.linkLocal).To(Equal(before.linkLocal),
		"link-local IPv6 changed across reboot")
	t.Expect(after.global).To(Equal(before.global),
		"global IPv6 changed across reboot")
	t.Expect(after.duid).To(Equal(before.duid),
		"DHCPv6 DUID changed across reboot")

	iid := eui64InterfaceID(after.mac)
	for _, addr := range append(append([]string{}, after.linkLocal...), after.global...) {
		t.Expect([]byte(net.ParseIP(addr).To16()[8:])).To(Equal(iid),
			"%s does not use the EUI-64 interface identifier of %s", addr, after.mac)
	}
	t.Expect(after.duid).To(Equal("00:03:00:01:"+after.mac.String()),
		"DUID is not a DUID-LL of the eth0 MAC")
}
