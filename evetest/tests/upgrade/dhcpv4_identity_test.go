// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// dhcpv4ProbeScript captures the DHCPv4 exchange of a dhcpcd rebind on eth0
// and prints it together with the eth0 MAC and IPv4 address. tcpdump runs in
// the SSH namespace; dhcpcd is controlled from the pillar container.
const dhcpv4ProbeScript = `
rm -f /tmp/dhcpv4-probe.txt
nohup timeout 30 tcpdump -i eth0 -n -vv -c 2 'udp port 67 or udp port 68' \
    > /tmp/dhcpv4-probe.txt 2>&1 < /dev/null &
sleep 3
eve exec pillar dhcpcd -n eth0 > /dev/null 2>&1
sleep 15
echo "mac $(cat /sys/class/net/eth0/address)"
ip -4 -o addr show dev eth0 | sed 's/^/addr /'
cat /tmp/dhcpv4-probe.txt
`

var (
	dhcpv4AddrRe     = regexp.MustCompile(`^addr .* inet (\S+)/`)
	dhcpv4ClientIDRe = regexp.MustCompile(`Client-ID \(61\), length \d+: (.+)$`)
)

type dhcpv4Identity struct {
	mac      string
	addr     string
	clientID string
}

func probeDHCPv4Identity(device *evetest.EdgeDevice) (dhcpv4Identity, error) {
	var id dhcpv4Identity
	out, _, err := device.RunShellScript(dhcpv4ProbeScript, 90*time.Second, 0)
	if err != nil {
		return id, err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "mac ") {
			id.mac = strings.TrimPrefix(line, "mac ")
		} else if m := dhcpv4AddrRe.FindStringSubmatch(line); m != nil {
			id.addr = m[1]
		} else if m := dhcpv4ClientIDRe.FindStringSubmatch(line); m != nil &&
			id.clientID == "" {
			id.clientID = m[1]
		}
	}
	if id.addr == "" || id.clientID == "" {
		return id, fmt.Errorf("no IPv4 address or Client-ID captured:\n%s", out)
	}
	return id, nil
}

// TestDHCPv4IdentityAcrossUpgrade verifies that upgrading EVE, and then
// rebooting the upgraded device, changes neither the DHCPv4 Client ID the
// device sends nor the IPv4 address the DHCP server leases to it. It guards
// dhcpcd.conf changes such as the DUID type, which can move the DHCPv4
// Client ID from the hardware address to an RFC 4361 DUID + IAID.
//
// Phases
// ------
//  1. Boot INITIAL_EVE_VERSION with DHCPv4 on eth0 (netmodels.SingleEthWithDHCP).
//  2. Probe: capture a dhcpcd rebind on eth0 with tcpdump; record the Client
//     ID (option 61) and the leased IPv4 address.
//  3. Upgrade to EVE_VERSION and probe again.
//  4. Reboot through the controller and probe again.
//  5. Assert all three probes match and the Client ID is the eth0 MAC.
//
// Test params
// -----------
//   - EVE_VERSION: target version.
//   - INITIAL_EVE_VERSION / INITIAL_EVE_REPO: version to upgrade from.
func TestDHCPv4IdentityAcrossUpgrade(test *testing.T) {
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
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
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
	probe := func(phase string) dhcpv4Identity {
		var id dhcpv4Identity
		t.Eventually(func() error {
			var err error
			id, err = probeDHCPv4Identity(device)
			return err
		}, 5*time.Minute, 10*time.Second).Should(Succeed())
		log.Infof("%s: mac=%s addr=%s client-id=%q", phase, id.mac, id.addr, id.clientID)
		return id
	}

	initial := probe("initial " + initialVersion)
	evetest.Checkpoint("initial-probed")

	device.UpgradeEVE(targetVersion, hypervisor, evetest.BaseOSDatastoreHTTP, true, false)
	evetest.Checkpoint("upgrade-complete")
	upgraded := probe("upgraded " + targetVersion)

	device.RequestReboot(true, true)
	evetest.Checkpoint("rebooted")
	rebooted := probe("rebooted " + targetVersion)

	t.Expect(initial.clientID).To(Equal("ether "+initial.mac),
		"initial DHCPv4 Client ID is not the hardware address")
	t.Expect(upgraded).To(Equal(initial), "DHCPv4 identity changed by the upgrade")
	t.Expect(rebooted).To(Equal(initial), "DHCPv4 identity changed by the reboot")
}
