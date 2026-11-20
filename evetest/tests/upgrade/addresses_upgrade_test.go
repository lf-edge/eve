// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// portAddressesScript prints the eth0 MAC, its addresses and dhcpcd's DUID.
// dhcpcd's state directory is only reachable through the pillar container.
const portAddressesScript = `
echo "mac $(cat /sys/class/net/eth0/address)"
ip -o addr show dev eth0 | sed 's/^/addr /'
echo "duid $(eve exec pillar cat /var/lib/dhcpcd/duid 2>/dev/null | tail -1)"
`

// dhcpv4ClientIDScript captures the DHCPv4 exchange of a dhcpcd rebind on
// eth0. A rebind can restart the whole exchange and briefly leave eth0
// without addresses, so it runs only after portAddressesScript.
const dhcpv4ClientIDScript = `
rm -f /tmp/dhcpv4-probe.txt
nohup timeout 30 tcpdump -i eth0 -n -vv -c 2 'udp port 67 or udp port 68' \
    > /tmp/dhcpv4-probe.txt 2>&1 < /dev/null &
sleep 3
eve exec pillar dhcpcd -n eth0 > /dev/null 2>&1
sleep 15
cat /tmp/dhcpv4-probe.txt
`

var dhcpv4ClientIDRe = regexp.MustCompile(`Client-ID \(61\), length \d+: (.+)$`)

type ipv4Identity struct {
	addr     string
	clientID string
}

type ipv6Identity struct {
	linkLocal []string
	global    []string
	duid      string
}

// portAddresses is what eth0 presents to the network: the DHCPv4 lease and
// Client ID, and the IPv6 addresses and DHCPv6 DUID.
type portAddresses struct {
	mac string
	v4  ipv4Identity
	v6  ipv6Identity
}

// readPortAddresses returns an error until eth0 has an IPv4 address, a
// link-local and a global IPv6 address, and dhcpcd has a DUID. The Client ID
// is left empty.
func readPortAddresses(device *evetest.EdgeDevice) (portAddresses, error) {
	var pa portAddresses
	out, _, err := device.RunShellScript(portAddressesScript, 30*time.Second, 0)
	if err != nil {
		return pa, err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "mac":
			pa.mac = fields[1]
		case "duid":
			pa.v6.duid = strings.ToLower(fields[1])
		case "addr":
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] != "inet" && fields[i] != "inet6" {
					continue
				}
				ip, _, err := net.ParseCIDR(fields[i+1])
				if err != nil {
					return pa, err
				}
				switch {
				case ip.To4() != nil:
					pa.v4.addr = ip.String()
				case ip.IsLinkLocalUnicast():
					pa.v6.linkLocal = append(pa.v6.linkLocal, ip.String())
				case ip.IsGlobalUnicast():
					pa.v6.global = append(pa.v6.global, ip.String())
				}
			}
		}
	}
	sort.Strings(pa.v6.linkLocal)
	sort.Strings(pa.v6.global)
	if pa.v4.addr == "" || len(pa.v6.linkLocal) == 0 || len(pa.v6.global) == 0 ||
		!strings.HasPrefix(pa.v6.duid, "00:") {
		return pa, fmt.Errorf("eth0 not fully configured yet:\n%s", out)
	}
	return pa, nil
}

// captureDHCPv4ClientID returns the DHCPv4 Client ID (option 61) that dhcpcd
// sends on eth0, as tcpdump prints it.
func captureDHCPv4ClientID(device *evetest.EdgeDevice) (string, error) {
	out, _, err := device.RunShellScript(dhcpv4ClientIDScript, 90*time.Second, 0)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		if m := dhcpv4ClientIDRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			return m[1], nil
		}
	}
	return "", fmt.Errorf("no DHCPv4 Client-ID captured:\n%s", out)
}

// TestDeviceAddressesAcrossUpgrade verifies that upgrading EVE, and then
// rebooting the upgraded device, changes neither the IPv4 nor the IPv6
// identity of a dual-stack management port: the DHCPv4 Client ID and lease,
// the IPv6 link-local and global addresses, and the DHCPv6 DUID.
//
// The target version must derive its IPv6 addresses (EUI-64) and DUID
// (DUID-LL) from the port MAC. An initial version that does not (its DUID is
// not a DUID-LL) changes its IPv6 addresses on every boot, so for it the
// IPv6 identity is only compared between the upgraded and the rebooted
// device.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCPAndIPv6 -- one eth0 port, DHCPv4 plus SLAAC
//     and DHCPv6 on fd3f:89fd:78c5::/64.
//
// Phases
// ------
//  1. Boot INITIAL_EVE_VERSION with a dual-stack DHCP network on eth0.
//  2. Probe: record the IPv4 address, IPv6 addresses and DUID, then
//     capture a dhcpcd rebind on eth0 with tcpdump for the DHCPv4 Client ID
//     (option 61).
//  3. Upgrade to EVE_VERSION and probe again.
//  4. Reboot through the controller and probe again.
//  5. Assert the IPv4 identity never changed and the Client ID is the eth0
//     MAC; the IPv6 identity is unchanged by the reboot, by the upgrade too
//     when the initial DUID is a DUID-LL, and the DUID is the eth0 MAC's
//     DUID-LL.
//
// Suite placement
// ---------------
//   - TestUpgradeSuite.
//
// Test params
// -----------
//   - EVE_VERSION: target version.
//   - INITIAL_EVE_VERSION / INITIAL_EVE_REPO: version to upgrade from.
func TestDeviceAddressesAcrossUpgrade(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          initialEVEVersionParamKey,
			DefaultValue: "16.0.0-lts",
			Description: evetest.TestParameterDescription{
				Summary: "EVE version to upgrade from",
				Default: "16.0.0-lts",
			},
		},
		evetest.TestParameterDefinition{
			Key:          initialEVERepoParamKey,
			DefaultValue: "lfedge/eve",
			Description: evetest.TestParameterDescription{
				Summary: "Container image repository for the initial EVE version",
				Default: "lfedge/eve",
			},
		},
	)
	initialVersion := evetest.GetTestParameter[string](initialEVEVersionParamKey)
	initialRepo := evetest.GetTestParameter[string](initialEVERepoParamKey)
	targetVersion := evetest.GetEVEVersionParameterValue()
	hypervisor := evetest.GetHypervisorParameterValue()

	const devName = "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithEVEVersion:    initialVersion,
			WithEVERepo:       initialRepo,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.CreateFromScratchWithInstaller,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCPAndIPv6},
	)
	device := evetest.GetEdgeDevice(devName)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	// Legacy V4 runs dhcpcd dual-stack; 16.0 does not know DualV4V6.
	networkUUID := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "eth0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   networkUUID,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)

	log := evetest.Logger()
	probe := func(phase string) portAddresses {
		var pa portAddresses
		t.Eventually(func() error {
			var err error
			pa, err = readPortAddresses(device)
			return err
		}, 5*time.Minute, 10*time.Second).Should(Succeed())
		t.Eventually(func() error {
			var err error
			pa.v4.clientID, err = captureDHCPv4ClientID(device)
			return err
		}, 5*time.Minute, 10*time.Second).Should(Succeed())
		log.Infof("%s: mac=%s ipv4=%s client-id=%q link-local=%v global=%v duid=%s",
			phase, pa.mac, pa.v4.addr, pa.v4.clientID, pa.v6.linkLocal,
			pa.v6.global, pa.v6.duid)
		return pa
	}

	initial := probe("initial " + initialVersion)
	evetest.Checkpoint("initial-probed")

	device.UpgradeEVE(targetVersion, hypervisor, evetest.BaseOSDatastoreHTTP, true, false)
	evetest.Checkpoint("upgrade-complete")
	upgraded := probe("upgraded " + targetVersion)

	device.RequestReboot(true, true)
	evetest.Checkpoint("rebooted")
	rebooted := probe("rebooted " + targetVersion)

	duidLL := "00:03:00:01:" + initial.mac
	t.Expect(initial.v4.clientID).To(Equal("ether "+initial.mac),
		"initial DHCPv4 Client ID is not the hardware address")
	t.Expect(upgraded.mac).To(Equal(initial.mac))
	t.Expect(rebooted.mac).To(Equal(initial.mac))
	t.Expect(upgraded.v4).To(Equal(initial.v4), "IPv4 identity changed by the upgrade")
	t.Expect(rebooted.v4).To(Equal(initial.v4), "IPv4 identity changed by the reboot")
	t.Expect(upgraded.v6.duid).To(Equal(duidLL), "DUID is not a DUID-LL of the eth0 MAC")
	t.Expect(rebooted.v6).To(Equal(upgraded.v6), "IPv6 identity changed by the reboot")
	if initial.v6.duid == duidLL {
		t.Expect(upgraded.v6).To(Equal(initial.v6), "IPv6 identity changed by the upgrade")
	} else {
		log.Infof("%s does not use a DUID-LL; IPv6 not compared across the upgrade",
			initialVersion)
	}
}
