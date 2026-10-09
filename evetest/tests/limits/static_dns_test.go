// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package limits_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// staticDNSEntriesParamKey selects how many static DNS entries
// TestManyStaticDNSEntries gives its network instance.
const staticDNSEntriesParamKey = "STATIC_DNS_ENTRIES"

// defaultStaticDNSEntries is the entry count at which the network instance
// configuration outgrows a pubsub message with margin; see the test's
// description.
const defaultStaticDNSEntries = 800

// TestManyStaticDNSEntries verifies that a network instance with many static
// DNS entries is handled without crashing the device: it comes up, or reports
// an error, and the device stays up either way.
//
// The static DNS entries of a network instance, host names the instance's
// DNS server answers itself and that ACLs may refer to, travel inside the
// NetworkInstanceConfig zedagent publishes, and again inside the status
// zedrouter publishes, which embeds the configuration. Nothing limits their
// number. Measured on the real types, with entries of a 30-character name and
// two addresses: 600 entries put the configuration at 64.7 KB on the wire,
// a hair under the 64 KiB a pubsub message may carry, so the default of 800
// (86 KB) is where an unfixed zedagent exits with "Too large message" while
// publishing the configuration -- and keeps doing so after every reboot,
// since the device configuration is checkpointed and re-read.
//
// Network model: netmodels.SingleEthWithDHCP.
//
// Device config: one DHCP management port, a 5-second metrics interval, and
// one local network instance with STATIC_DNS_ENTRIES static DNS entries.
//
// Phases:
//  1. Apply the base configuration and wait until it is processed.
//  2. Add the network instance, apply, and wait until it is reported online
//     or in error, with the device still reporting metrics afterwards. Stop
//     at once if the device crashes.
//  3. Delete the network instance.
//
// Parameters: HYPERVISOR (shared with the suite), STATIC_DNS_ENTRIES
// (default 800).
//
// Suite placement: TestLimitsSuite.
func TestManyStaticDNSEntries(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          staticDNSEntriesParamKey,
			DefaultValue: defaultStaticDNSEntries,
			Description: evetest.TestParameterDescription{
				Summary: "Number of static DNS entries of the network instance",
				Default: fmt.Sprint(defaultStaticDNSEntries),
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	numEntries := evetest.GetTestParameter[int](staticDNSEntriesParamKey)

	device := setupDevice(hypervisor, 0)
	evetest.Checkpoint("setup-done")
	log := evetest.Logger()
	devConfig, _ := applyBaseConfig(device, hypervisor)
	evetest.Checkpoint("base-config-applied")
	crash := device.WatchForCrash()
	defer crash.Stop()

	// Phase 2: the network instance with its entries.
	entries := make([]types.DNSNameToIP, 0, numEntries)
	for i := 1; i <= numEntries; i++ {
		entries = append(entries, types.DNSNameToIP{
			HostName: fmt.Sprintf("host-%04d.static.example.test", i),
			IPs: []net.IP{
				net.IPv4(10, 22, byte(i/256), byte(i%256)),
				net.IPv4(10, 23, byte(i/256), byte(i%256)),
			},
		})
	}
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "static-dns-ni",
		Port:        mgmtPort,
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:          evetest.IPAddress("10.11.12.1"),
		StaticDNSEntries: entries,
		MTU:              1500,
	})
	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	defer stopNIWatch()
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("ni-deployed")

	var latest *eveinfo.ZInfoNetworkInstance
	awaitWhileAlive(t, device, crash,
		"the network instance is reported online or in error", 10*time.Minute,
		func() bool {
			for drained := false; !drained; {
				select {
				case info, ok := <-niUpdates:
					drained = !ok
					if ok {
						latest = info
					}
				default:
					drained = true
				}
			}
			return latest.GetState() == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE ||
				latest.GetState() == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ERROR ||
				len(latest.GetNetworkErr()) > 0
		})
	log.Infof("The network instance with %d static DNS entries is reported in state %s "+
		"with %d error(s)", numEntries, latest.GetState(), len(latest.GetNetworkErr()))
	evetest.Checkpoint("ni-reported")

	// Phase 3: cleanup.
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, true, true)
}
