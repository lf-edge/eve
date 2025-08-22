// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	zconfig "github.com/lf-edge/eve-api/go/config"
	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

func initGetConfigCtx(g *GomegaWithT) *getconfigContext {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "zedagent", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)
	pubIOAdapters, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.PhysicalIOAdapterList{},
	})
	g.Expect(err).To(BeNil())
	pubDPC, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DevicePortConfig{},
	})
	g.Expect(err).To(BeNil())
	pubNetworks, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkXObjectConfig{},
	})
	pubPatchEnvelopes, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.PatchEnvelopeInfoList{},
	})
	g.Expect(err).To(BeNil())
	getconfigCtx := &getconfigContext{
		pubDevicePortConfig:     pubDPC,
		pubPhysicalIOAdapters:   pubIOAdapters,
		pubNetworkXObjectConfig: pubNetworks,
		pubPatchEnvelopeInfo:    pubPatchEnvelopes,
		zedagentCtx: &zedagentContext{
			physicalIoAdapterMap: make(map[string]types.PhysicalIOAdapter),
		},
	}
	// cleanup between tests
	deviceIoListPrevConfigHash = nil
	bondsPrevConfigHash = nil
	vlansPrevConfigHash = nil
	networkConfigPrevConfigHash = nil
	return getconfigCtx
}

// Sort DPC ports to make the port order deterministic and thus easier
// to check for expected content.
func sortDPCPorts(dpc *types.DevicePortConfig) {
	sort.Slice(dpc.Ports, func(i, j int) bool {
		return dpc.Ports[i].Logicallabel < dpc.Ports[j].Logicallabel
	})
}

func getPortError(dpc *types.DevicePortConfig, portName string) string {
	for _, port := range dpc.Ports {
		if port.Logicallabel == portName {
			if port.HasError() {
				return port.LastError
			}
			break
		}
	}
	return ""
}

func TestParsePhysicalNetworkAdapters(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	const networkUUID = "572cd3bc-ade6-42ad-97a0-22cd24fed1a0"
	config := &zconfig.EdgeDevConfig{
		Networks: []*zconfig.NetworkConfig{
			{
				Id:   networkUUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
		},
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-shopfloor",
				Uplink:         true,
				NetworkUUID:    networkUUID,
				Alias:          "shopfloor-alias",
				LowerLayerName: "shopfloor",
				Cost:           0,
			},
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)
	parseNetworkXObjectConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Version).To(Equal(types.DPCIsMgmt))
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(1))
	port := dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor"))
	g.Expect(port.Phylabel).To(Equal("ethernet0"))
	g.Expect(port.IfName).To(Equal("eth0"))
	g.Expect(port.Alias).To(Equal("shopfloor-alias"))
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.NetworkUUID.String()).To(Equal(networkUUID))
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeClient))
	g.Expect(port.DhcpConfig.DomainName).To(BeEmpty())
	g.Expect(port.DhcpConfig.AddrSubnet).To(BeEmpty())
	g.Expect(port.DhcpConfig.DNSServers).To(BeEmpty())
	g.Expect(port.DhcpConfig.Gateway).To(BeNil())
	g.Expect(port.DhcpConfig.NTPServers).To(BeNil())
	g.Expect(port.ProxyConfig.Proxies).To(BeEmpty())
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
}

// Test DPC with recorded parsing error (missing network configuration)
func TestDPCWithError(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	config := &zconfig.EdgeDevConfig{
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-shopfloor",
				Uplink:         true,
				NetworkUUID:    "572cd3bc-ade6-42ad-97a0-22cd24fed1a0",
				Alias:          "shopfloor-alias",
				LowerLayerName: "shopfloor",
				Cost:           0,
			},
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)
	parseNetworkXObjectConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Version).To(Equal(types.DPCIsMgmt))
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(dpc.LastFailed).ToNot(BeZero())
	g.Expect(dpc.LastSucceeded).To(BeZero())
	g.Expect(getPortError(&dpc, "adapter-shopfloor")).
		To(ContainSubstring("Port adapter-shopfloor configured with unknown Network UUID"))
	g.Expect(dpc.Ports).To(HaveLen(1))
	port := dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor"))
	g.Expect(port.Phylabel).To(Equal("ethernet0"))
	g.Expect(port.IfName).To(Equal("eth0"))
	g.Expect(port.Alias).To(Equal("shopfloor-alias"))
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
}

func TestParseVlans(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	const (
		network1UUID = "572cd3bc-ade6-42ad-97a0-22cd24fed1a0"
		network2UUID = "0c1a98fb-85fa-421d-943e-8d4e469bea8f"
		network3UUID = "bd5a8c26-67ed-458e-be3b-0478d1b7c094"
	)
	config := &zconfig.EdgeDevConfig{
		Networks: []*zconfig.NetworkConfig{
			{
				Id:   network1UUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
			{
				Id:   network2UUID,
				Type: zcommon.NetworkType_V6,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
			{
				Id:   network3UUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp:    zcommon.DHCPType_Static,
					Subnet:  "192.168.1.0/24",
					Gateway: "192.168.1.1",
					DhcpRange: &zcommon.IpRange{
						Start: "192.168.1.10",
						End:   "192.168.1.100",
					},
				},
			},
		},
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet1",
				Logicallabel: "warehouse",
				Assigngrp:    "eth-grp-2",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageShared,
			},
		},
		Vlans: []*zconfig.VlanAdapter{
			{
				Logicallabel:   "shopfloor-vlan100",
				InterfaceName:  "shopfloor.100",
				LowerLayerName: "shopfloor",
				VlanId:         100,
			},
			{
				Logicallabel:   "shopfloor-vlan200",
				InterfaceName:  "shopfloor.200",
				LowerLayerName: "shopfloor",
				VlanId:         200,
			},
			{
				Logicallabel:   "warehouse-vlan100",
				InterfaceName:  "warehouse.100",
				LowerLayerName: "warehouse",
				VlanId:         100,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-shopfloor-vlan100",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "shopfloor-vlan100",
				Cost:           10,
			},
			{
				Name:           "adapter-shopfloor-vlan200",
				Uplink:         true,
				NetworkUUID:    network2UUID,
				LowerLayerName: "shopfloor-vlan200",
				Cost:           20,
			},
			// no adapter for warehouse initially
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)
	parseVlans(getconfigCtx, config)
	parseNetworkXObjectConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Version).To(Equal(types.DPCIsMgmt))
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(3))
	sortDPCPorts(&dpc)
	// VLAN shopfloor.100
	port := dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-vlan100"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.IfName).To(Equal("shopfloor.100"))
	g.Expect(port.NetworkUUID.String()).To(Equal(network1UUID))
	g.Expect(port.Cost).To(BeEquivalentTo(10))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeClient))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeVLAN))
	g.Expect(port.L2LinkConfig.VLAN.ParentPort).To(Equal("shopfloor"))
	g.Expect(port.L2LinkConfig.VLAN.ID).To(BeEquivalentTo(100))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// VLAN shopfloor.200
	port = dpc.Ports[1]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-vlan200"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.IfName).To(Equal("shopfloor.200"))
	g.Expect(port.NetworkUUID.String()).To(Equal(network2UUID))
	g.Expect(port.Cost).To(BeEquivalentTo(20))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPV6))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeClient))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeVLAN))
	g.Expect(port.L2LinkConfig.VLAN.ParentPort).To(Equal("shopfloor"))
	g.Expect(port.L2LinkConfig.VLAN.ID).To(BeEquivalentTo(200))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// the underlying physical "shopfloor" adapter
	port = dpc.Ports[2]
	g.Expect(port.Logicallabel).To(Equal("shopfloor"))
	g.Expect(port.Phylabel).To(Equal("ethernet0"))
	g.Expect(port.IsL3Port).To(BeFalse())
	g.Expect(port.IfName).To(Equal("eth0"))
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeNOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))

	// With VLAN sub-interfaces configured, the parent interface can be used
	// for the untagged traffic.
	config.SystemAdapterList = append(config.SystemAdapterList, &zconfig.SystemAdapter{
		Name:           "adapter-shopfloor-untagged",
		Uplink:         false,
		NetworkUUID:    network1UUID,
		LowerLayerName: "shopfloor",
		Cost:           5,
	})
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	// The number of ports has not changed, just the shopfloor ethernet port was
	// elevated to L3.
	g.Expect(dpc.Ports).To(HaveLen(3))
	sortDPCPorts(&dpc)
	port = dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-untagged"))
	g.Expect(port.Phylabel).To(Equal("ethernet0"))
	g.Expect(port.IsL3Port).To(BeTrue()) // This changed from false to true
	g.Expect(port.IfName).To(Equal("eth0"))
	g.Expect(port.NetworkUUID.String()).To(Equal(network1UUID))
	g.Expect(port.Cost).To(BeEquivalentTo(5))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeClient))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	port = dpc.Ports[1]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-vlan100"))
	port = dpc.Ports[2]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-vlan200"))

	// Add adapter for "warehouse-vlan100"
	config.SystemAdapterList = append(config.SystemAdapterList, &zconfig.SystemAdapter{
		Name:           "adapter-warehouse-vlan100",
		Uplink:         true,
		NetworkUUID:    network3UUID,
		LowerLayerName: "warehouse-vlan100",
		Cost:           30,
		Addr:           "192.168.1.150",
	})
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	// Added one physical and one VLAN adapter
	g.Expect(dpc.Ports).To(HaveLen(5))
	sortDPCPorts(&dpc)
	// VLAN warehouse.100
	port = dpc.Ports[3]
	g.Expect(port.Logicallabel).To(Equal("adapter-warehouse-vlan100"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.IfName).To(Equal("warehouse.100"))
	g.Expect(port.NetworkUUID.String()).To(Equal(network3UUID))
	g.Expect(port.Cost).To(BeEquivalentTo(30))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeStatic))
	g.Expect(port.DhcpConfig.AddrSubnet).To(Equal("192.168.1.150/24"))
	g.Expect(port.DhcpConfig.Gateway.String()).To(Equal("192.168.1.1"))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeVLAN))
	g.Expect(port.L2LinkConfig.VLAN.ParentPort).To(Equal("warehouse"))
	g.Expect(port.L2LinkConfig.VLAN.ID).To(BeEquivalentTo(100))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// the underlying "warehouse" adapter
	port = dpc.Ports[4]
	g.Expect(port.Logicallabel).To(Equal("warehouse"))
	g.Expect(port.Phylabel).To(Equal("ethernet1"))
	g.Expect(port.IsL3Port).To(BeFalse())
	g.Expect(port.IfName).To(Equal("eth1"))
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeNOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
}

func TestParseBonds(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	const networkUUID = "572cd3bc-ade6-42ad-97a0-22cd24fed1a0"
	config := &zconfig.EdgeDevConfig{
		Networks: []*zconfig.NetworkConfig{
			{
				Id:   networkUUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
		},
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor0",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet1",
				Logicallabel: "shopfloor1",
				Assigngrp:    "eth-grp-2",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		Bonds: []*zconfig.BondAdapter{
			{
				Logicallabel:    "bond-shopfloor",
				InterfaceName:   "bond",
				LowerLayerNames: []string{"shopfloor1", "shopfloor0"}, // order matters in Active-Backup mode
				BondMode:        zconfig.BondMode_BOND_MODE_ACTIVE_BACKUP,
				Monitoring: &zconfig.BondAdapter_Mii{
					Mii: &zconfig.MIIMonitor{
						Interval:  400,
						Updelay:   800,
						Downdelay: 1200,
					},
				},
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-shopfloor",
				Uplink:         true,
				NetworkUUID:    networkUUID,
				LowerLayerName: "bond-shopfloor",
				Cost:           10,
			},
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)
	parseBonds(getconfigCtx, config)
	parseNetworkXObjectConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Version).To(Equal(types.DPCIsMgmt))
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(3))
	sortDPCPorts(&dpc)
	// System adapter for shopfloor (bond)
	port := dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.IfName).To(Equal("bond"))
	g.Expect(port.NetworkUUID.String()).To(Equal(networkUUID))
	g.Expect(port.Cost).To(BeEquivalentTo(10))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeClient))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeBond))
	g.Expect(port.L2LinkConfig.Bond.AggregatedPorts).To(Equal([]string{"shopfloor1", "shopfloor0"}))
	g.Expect(port.L2LinkConfig.Bond.Mode).To(Equal(types.BondModeActiveBackup))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.Enabled).To(BeTrue())
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.Interval).To(BeEquivalentTo(400))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.UpDelay).To(BeEquivalentTo(800))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.DownDelay).To(BeEquivalentTo(1200))
	g.Expect(port.L2LinkConfig.Bond.ARPMonitor.Enabled).To(BeFalse())
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// underlying physical "shopfloor0" adapter
	port = dpc.Ports[1]
	g.Expect(port.Logicallabel).To(Equal("shopfloor0"))
	g.Expect(port.Phylabel).To(Equal("ethernet0"))
	g.Expect(port.IsL3Port).To(BeFalse())
	g.Expect(port.IfName).To(Equal("eth0"))
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeNOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// underlying physical "shopfloor1" adapter
	port = dpc.Ports[2]
	g.Expect(port.Logicallabel).To(Equal("shopfloor1"))
	g.Expect(port.Phylabel).To(Equal("ethernet1"))
	g.Expect(port.IsL3Port).To(BeFalse())
	g.Expect(port.IfName).To(Equal("eth1"))
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeNOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))

	// It is not allowed to use physical port with IP if it is under a bond.
	config.SystemAdapterList = append(config.SystemAdapterList, &zconfig.SystemAdapter{
		Name:        "shopfloor0",
		Uplink:      true,
		NetworkUUID: networkUUID,
	})
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Ports).To(HaveLen(3))
	sortDPCPorts(&dpc)
	// underlying physical "shopfloor0" adapter
	port = dpc.Ports[1]
	g.Expect(port.HasError()).To(BeTrue())
	g.Expect(port.LastError).To(Equal(
		"Port shopfloor0 aggregated by bond (adapter-shopfloor) cannot be used with IP configuration"))
}

func TestParseVlansOverBonds(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	const (
		network1UUID = "572cd3bc-ade6-42ad-97a0-22cd24fed1a0"
		network2UUID = "0c1a98fb-85fa-421d-943e-8d4e469bea8f"
	)
	config := &zconfig.EdgeDevConfig{
		Networks: []*zconfig.NetworkConfig{
			{
				Id:   network1UUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
			{
				Id:   network2UUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
		},
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor0",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet1",
				Logicallabel: "shopfloor1",
				Assigngrp:    "eth-grp-2",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		Bonds: []*zconfig.BondAdapter{
			{
				Logicallabel:    "bond-shopfloor",
				InterfaceName:   "bond",
				LowerLayerNames: []string{"shopfloor1", "shopfloor0"}, // order matters in Active-Backup mode
				BondMode:        zconfig.BondMode_BOND_MODE_ACTIVE_BACKUP,
				Monitoring: &zconfig.BondAdapter_Mii{
					Mii: &zconfig.MIIMonitor{
						Interval:  400,
						Updelay:   800,
						Downdelay: 1200,
					},
				},
			},
		},
		Vlans: []*zconfig.VlanAdapter{
			{
				Logicallabel:   "shopfloor-vlan100",
				InterfaceName:  "shopfloor.100",
				LowerLayerName: "bond-shopfloor",
				VlanId:         100,
			},
			{
				Logicallabel:   "shopfloor-vlan200",
				InterfaceName:  "shopfloor.200",
				LowerLayerName: "bond-shopfloor",
				VlanId:         200,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-shopfloor-vlan100",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "shopfloor-vlan100",
				Cost:           10,
			},
			{
				Name:           "adapter-shopfloor-vlan200",
				Uplink:         true,
				NetworkUUID:    network2UUID,
				LowerLayerName: "shopfloor-vlan200",
				Cost:           20,
			},
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)
	parseBonds(getconfigCtx, config)
	parseVlans(getconfigCtx, config)
	parseNetworkXObjectConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Version).To(Equal(types.DPCIsMgmt))
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(5))
	sortDPCPorts(&dpc)
	// System adapter for shopfloor VLAN100
	port := dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-vlan100"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.IsMgmt).To(BeTrue())
	g.Expect(port.IfName).To(Equal("shopfloor.100"))
	g.Expect(port.NetworkUUID.String()).To(Equal(network1UUID))
	g.Expect(port.Cost).To(BeEquivalentTo(10))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeClient))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeVLAN))
	g.Expect(port.L2LinkConfig.VLAN.ParentPort).To(Equal("bond-shopfloor"))
	g.Expect(port.L2LinkConfig.VLAN.ID).To(BeEquivalentTo(100))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// System adapter for shopfloor VLAN100
	port = dpc.Ports[1]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-vlan200"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.IsMgmt).To(BeTrue())
	g.Expect(port.IfName).To(Equal("shopfloor.200"))
	g.Expect(port.NetworkUUID.String()).To(Equal(network2UUID))
	g.Expect(port.Cost).To(BeEquivalentTo(20))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeClient))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeVLAN))
	g.Expect(port.L2LinkConfig.VLAN.ParentPort).To(Equal("bond-shopfloor"))
	g.Expect(port.L2LinkConfig.VLAN.ID).To(BeEquivalentTo(200))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// Bond aggregating shopfloor0 and shopfloor1
	port = dpc.Ports[2]
	g.Expect(port.Logicallabel).To(Equal("bond-shopfloor"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeFalse())
	g.Expect(port.IsMgmt).To(BeFalse())
	g.Expect(port.IfName).To(Equal("bond"))
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeNOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeBond))
	g.Expect(port.L2LinkConfig.Bond.AggregatedPorts).To(Equal([]string{"shopfloor1", "shopfloor0"}))
	g.Expect(port.L2LinkConfig.Bond.Mode).To(Equal(types.BondModeActiveBackup))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.Enabled).To(BeTrue())
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.Interval).To(BeEquivalentTo(400))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.UpDelay).To(BeEquivalentTo(800))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.DownDelay).To(BeEquivalentTo(1200))
	g.Expect(port.L2LinkConfig.Bond.ARPMonitor.Enabled).To(BeFalse())
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// underlying physical "shopfloor0" adapter
	port = dpc.Ports[3]
	g.Expect(port.Logicallabel).To(Equal("shopfloor0"))
	g.Expect(port.Phylabel).To(Equal("ethernet0"))
	g.Expect(port.IsL3Port).To(BeFalse())
	g.Expect(port.IsMgmt).To(BeFalse())
	g.Expect(port.IfName).To(Equal("eth0"))
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeNOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	// underlying physical "shopfloor1" adapter
	port = dpc.Ports[4]
	g.Expect(port.Logicallabel).To(Equal("shopfloor1"))
	g.Expect(port.Phylabel).To(Equal("ethernet1"))
	g.Expect(port.IsL3Port).To(BeFalse())
	g.Expect(port.IsMgmt).To(BeFalse())
	g.Expect(port.IfName).To(Equal("eth1"))
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeNOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))

	// With VLAN sub-interfaces configured, the parent interface can be used
	// for the untagged traffic.
	config.SystemAdapterList = append(config.SystemAdapterList, &zconfig.SystemAdapter{
		Name:           "adapter-shopfloor-untagged",
		Uplink:         false,
		NetworkUUID:    network1UUID,
		LowerLayerName: "bond-shopfloor",
		Cost:           2,
	})
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	// The number of ports has not changed, just the shopfloor bond was elevated to L3.
	g.Expect(dpc.Ports).To(HaveLen(5))
	sortDPCPorts(&dpc)
	port = dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-untagged"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.IsMgmt).To(BeFalse())
	g.Expect(port.IfName).To(Equal("bond"))
	g.Expect(port.NetworkUUID.String()).To(Equal(network1UUID))
	g.Expect(port.Cost).To(BeEquivalentTo(2))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DhcpTypeClient))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeBond))
	g.Expect(port.L2LinkConfig.Bond.AggregatedPorts).To(Equal([]string{"shopfloor1", "shopfloor0"}))
	g.Expect(port.L2LinkConfig.Bond.Mode).To(Equal(types.BondModeActiveBackup))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.Enabled).To(BeTrue())
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.Interval).To(BeEquivalentTo(400))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.UpDelay).To(BeEquivalentTo(800))
	g.Expect(port.L2LinkConfig.Bond.MIIMonitor.DownDelay).To(BeEquivalentTo(1200))
	g.Expect(port.L2LinkConfig.Bond.ARPMonitor.Enabled).To(BeFalse())
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
	port = dpc.Ports[1]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-vlan100"))
	port = dpc.Ports[2]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor-vlan200"))
	port = dpc.Ports[3]
	g.Expect(port.Logicallabel).To(Equal("shopfloor0"))
	port = dpc.Ports[4]
	g.Expect(port.Logicallabel).To(Equal("shopfloor1"))

	// It is not allowed to use physical port with IP if it is under a bond.
	config.SystemAdapterList = append(config.SystemAdapterList, &zconfig.SystemAdapter{
		Name:           "adapter-ethernet0",
		Uplink:         true,
		LowerLayerName: "shopfloor0",
		NetworkUUID:    network1UUID,
	})
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Ports).To(HaveLen(5))
	sortDPCPorts(&dpc)
	port = dpc.Ports[0]
	fmt.Printf("%+v\n", dpc)
	g.Expect(port.Logicallabel).To(Equal("adapter-ethernet0"))
	g.Expect(port.HasError()).To(BeTrue())
	g.Expect(port.LastError).To(Equal(
		"Port adapter-ethernet0 aggregated by bond (adapter-shopfloor-untagged) cannot be used with IP configuration"))

}

func TestInvalidLowerLayerReferences(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	const (
		network1UUID = "572cd3bc-ade6-42ad-97a0-22cd24fed1a0"
		network2UUID = "0c1a98fb-85fa-421d-943e-8d4e469bea8f"
	)
	baseConfig := &zconfig.EdgeDevConfig{
		Networks: []*zconfig.NetworkConfig{
			{
				Id:   network1UUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
			{
				Id:   network2UUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
		},
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet1",
				Logicallabel: "warehouse",
				Assigngrp:    "eth-grp-2",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
	}

	// IO and networks do not change between scenarios
	parseDeviceIoListConfig(getconfigCtx, baseConfig)
	parseNetworkXObjectConfig(getconfigCtx, baseConfig)

	// Scenario 1: System adapters referencing the same underlying port
	config := &zconfig.EdgeDevConfig{
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter1",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "shopfloor",
				Cost:           10,
			},
			{
				Name:           "adapter2",
				Uplink:         true,
				NetworkUUID:    network2UUID,
				LowerLayerName: "shopfloor",
				Cost:           20,
			},
		},
	}
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(getPortError(&dpc, "adapter1")).
		To(ContainSubstring("Port collides with another port with the same interface name"))
	g.Expect(getPortError(&dpc, "adapter2")).
		To(ContainSubstring("Port collides with another port with the same interface name"))
	g.Expect(dpc.Ports).To(HaveLen(2))

	// fix:
	config.SystemAdapterList[1].LowerLayerName = "warehouse"
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(2))

	// Scenario 2: Lower layer reference matching multiple adapters
	config = &zconfig.EdgeDevConfig{
		Bonds: []*zconfig.BondAdapter{
			{
				Logicallabel:    "shopfloor", // collides with shopfloor from physicalIO
				InterfaceName:   "bond",
				LowerLayerNames: []string{"shopfloor", "warehouse"},
				BondMode:        zconfig.BondMode_BOND_MODE_ACTIVE_BACKUP,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "shopfloor", // matches bond and physical IO
			},
		},
	}
	parseBonds(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(dpc.LastError).To(ContainSubstring("multiple lower-layer adapters match"))
	g.Expect(dpc.Ports).To(BeEmpty())

	// fix:
	config.Bonds[0].Logicallabel = "bond-shopfloor"
	config.SystemAdapterList[0].LowerLayerName = "bond-shopfloor"
	parseBonds(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(3))

	// Scenario 3: Missing lower-layer adapter
	config = &zconfig.EdgeDevConfig{
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "bond-shopfloor", // bond is missing from config
			},
		},
	}
	parseBonds(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(dpc.LastError).To(ContainSubstring("missing lower-layer adapter"))
	g.Expect(dpc.Ports).To(BeEmpty())

	// fix:
	config.Bonds = []*zconfig.BondAdapter{
		{
			Logicallabel:    "bond-shopfloor",
			InterfaceName:   "bond",
			LowerLayerNames: []string{"shopfloor", "warehouse"},
			BondMode:        zconfig.BondMode_BOND_MODE_ACTIVE_BACKUP,
		},
	}
	parseBonds(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(3))

	// Scenario 4: interface referenced by both a system adapter and a bond
	config = &zconfig.EdgeDevConfig{
		Bonds: []*zconfig.BondAdapter{
			{
				Logicallabel:    "bond-shopfloor",
				InterfaceName:   "bond",
				LowerLayerNames: []string{"shopfloor", "warehouse"},
				BondMode:        zconfig.BondMode_BOND_MODE_ACTIVE_BACKUP,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-bond-shopfloor",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "bond-shopfloor",
			},
			{
				Name:           "adapter-warehouse", // warehouse port is already part of a LAG, cannot be L3
				Uplink:         true,
				NetworkUUID:    network2UUID,
				LowerLayerName: "warehouse",
			},
		},
	}
	parseBonds(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(getPortError(&dpc, "adapter-warehouse")).
		To(Equal("Port adapter-warehouse aggregated by bond (adapter-bond-shopfloor) cannot be used with IP configuration"))
	g.Expect(dpc.Ports).To(HaveLen(3))

	// fix:
	config.Bonds[0].LowerLayerNames = []string{"shopfloor"}
	parseBonds(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(3))

	// Scenario 5: Duplicate VLAN IDs
	config = &zconfig.EdgeDevConfig{
		Vlans: []*zconfig.VlanAdapter{
			{
				Logicallabel:   "shopfloor-vlan100",
				InterfaceName:  "shopfloor.100",
				LowerLayerName: "shopfloor",
				VlanId:         100,
			},
			{
				Logicallabel:   "shopfloor-vlan200",
				InterfaceName:  "shopfloor.200",
				LowerLayerName: "shopfloor",
				VlanId:         100, // 100 entered instead of 200 by mistake
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-shopfloor-vlan100",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "shopfloor-vlan100",
			},
			{
				Name:           "adapter-shopfloor-vlan200",
				Uplink:         true,
				NetworkUUID:    network2UUID,
				LowerLayerName: "shopfloor-vlan200",
			},
		},
	}
	parseBonds(getconfigCtx, config)
	parseVlans(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(getPortError(&dpc, "adapter-shopfloor-vlan100")).
		To(ContainSubstring("duplicate VLAN sub-interfaces"))
	g.Expect(getPortError(&dpc, "adapter-shopfloor-vlan200")).
		To(ContainSubstring("duplicate VLAN sub-interfaces"))
	g.Expect(dpc.Ports).To(HaveLen(3))

	// fix:
	config.Vlans[1].VlanId = 200
	parseBonds(getconfigCtx, config)
	parseVlans(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(3))

	// Scenario 6: VLAN referencing port aggregated by a bond
	config = &zconfig.EdgeDevConfig{
		Bonds: []*zconfig.BondAdapter{
			{
				Logicallabel:    "bond0",
				InterfaceName:   "bond",
				LowerLayerNames: []string{"shopfloor", "warehouse"},
				BondMode:        zconfig.BondMode_BOND_MODE_ACTIVE_BACKUP,
			},
		},
		Vlans: []*zconfig.VlanAdapter{
			{
				Logicallabel:   "warehouse-vlan100",
				InterfaceName:  "warehouse.100",
				LowerLayerName: "warehouse", // warehouse referenced by both a VLAN and a bond
				VlanId:         100,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-bond0",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "bond0",
			},
			{
				Name:           "adapter-warehouse-vlan100",
				Uplink:         true,
				NetworkUUID:    network2UUID,
				LowerLayerName: "warehouse-vlan100",
			},
		},
	}
	parseBonds(getconfigCtx, config)
	parseVlans(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(getPortError(&dpc, "adapter-bond0")).
		To(ContainSubstring("referenced by both bond (adapter-bond0) and VLAN (adapter-warehouse-vlan100)"))
	g.Expect(getPortError(&dpc, "adapter-warehouse-vlan100")).
		To(ContainSubstring("referenced by both bond (adapter-bond0) and VLAN (adapter-warehouse-vlan100)"))
	g.Expect(dpc.Ports).To(HaveLen(4))

	// fix:
	config.Bonds[0].LowerLayerNames = []string{"shopfloor"} // remove warehouse from the LAG
	parseBonds(getconfigCtx, config)
	parseVlans(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(4))

	// Scenario 7: overlapping LAGs
	config = &zconfig.EdgeDevConfig{
		Bonds: []*zconfig.BondAdapter{
			{
				Logicallabel:    "bond0",
				InterfaceName:   "bond",
				LowerLayerNames: []string{"shopfloor", "warehouse"},
				BondMode:        zconfig.BondMode_BOND_MODE_ACTIVE_BACKUP,
			},
			{
				Logicallabel:    "bond1",
				InterfaceName:   "bond1",
				LowerLayerNames: []string{"shopfloor", "warehouse"},
				BondMode:        zconfig.BondMode_BOND_MODE_ACTIVE_BACKUP,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-bond0",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "bond0",
			},
			{
				Name:           "adapter-bond1",
				Uplink:         true,
				NetworkUUID:    network2UUID,
				LowerLayerName: "bond1",
			},
		},
	}
	parseBonds(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(getPortError(&dpc, "adapter-bond0")).
		To(ContainSubstring("aggregated by multiple bond interfaces"))
	g.Expect(getPortError(&dpc, "adapter-bond1")).
		To(ContainSubstring("aggregated by multiple bond interfaces"))
	g.Expect(dpc.Ports).To(HaveLen(4))

	// fix
	config.Bonds[0].LowerLayerNames = []string{"shopfloor"}
	config.Bonds[1].LowerLayerNames = []string{"warehouse"}
	parseBonds(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(4))

	// Scenario 9: Out-of-range VLAN ID
	config = &zconfig.EdgeDevConfig{
		Vlans: []*zconfig.VlanAdapter{
			{
				Logicallabel:   "shopfloor-vlan1000",
				InterfaceName:  "shopfloor.1000",
				LowerLayerName: "shopfloor",
				VlanId:         10000, // out-of-range VLAN ID entered by mistake
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-shopfloor-vlan1000",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "shopfloor-vlan1000",
			},
		},
	}
	parseBonds(getconfigCtx, config)
	parseVlans(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(getPortError(&dpc, "adapter-shopfloor-vlan1000")).
		To(ContainSubstring("VLAN ID out of range: 10000"))
	g.Expect(dpc.Ports).To(HaveLen(2))

	// fix:
	config.Vlans[0].VlanId = 1000
	parseBonds(getconfigCtx, config)
	parseVlans(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(2))

	// Scenario 10: System adapters referencing the same underlying port by physical addresses
	// Note that we allow only wwan ports to be defined without interface name.
	config = &zconfig.EdgeDevConfig{
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetWWAN,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor",
				Phyaddrs: map[string]string{
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetWWAN,
				Phylabel:     "ethernet1",
				Logicallabel: "warehouse",
				Phyaddrs: map[string]string{
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter1",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				LowerLayerName: "shopfloor",
				Cost:           10,
			},
			{
				Name:           "adapter2",
				Uplink:         true,
				NetworkUUID:    network2UUID,
				LowerLayerName: "shopfloor",
				Cost:           20,
			},
		},
	}
	parseDeviceIoListConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(getPortError(&dpc, "adapter1")).
		To(ContainSubstring("Port collides with another port with the same physical address"))
	g.Expect(getPortError(&dpc, "adapter2")).
		To(ContainSubstring("Port collides with another port with the same physical address"))
	g.Expect(dpc.Ports).To(HaveLen(2))

	// fix:
	config.SystemAdapterList[1].LowerLayerName = "warehouse"
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)
	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(2))
}

func TestParseSRIOV(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	config := &zconfig.EdgeDevConfig{
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEthPF,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Vflist: &zconfig.VfList{
					VfCount: 2,
					Data: []*zconfig.EthVF{
						{
							Index: 0,
						},
						{
							Index: 1,
						},
					},
				},
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "no_ethVF",
				Logicallabel: "warehouse",
				Assigngrp:    "eth-grp-2",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "bad_vlan_id",
				Logicallabel: "warehouse",
				Assigngrp:    "eth-grp-2",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Vflist: &zconfig.VfList{
					VfCount: 1,
					Data: []*zconfig.EthVF{
						{
							Index:  0,
							VlanId: 5000,
						},
					},
				},
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "mismatch_len",
				Logicallabel: "warehouse",
				Assigngrp:    "eth-grp-2",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Vflist: &zconfig.VfList{
					VfCount: 2,
					Data: []*zconfig.EthVF{
						{
							Index:  1,
							VlanId: 2,
						},
					},
				},
			},
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)

	physicalIOs, err := getconfigCtx.pubPhysicalIOAdapters.Get("zedagent")
	g.Expect(err).To(BeNil())
	ios, ok := physicalIOs.(types.PhysicalIOAdapterList)
	g.Expect(ok).To(BeTrue())
	g.Expect(ios.Initialized).To(BeTrue())
	// One less because the invalid cases will cause them to be skipped.
	g.Expect(ios.AdapterList).To(HaveLen(len(config.DeviceIoList) - 1))
	g.Expect(ios.AdapterList[0].Vfs).To(BeEquivalentTo(
		sriov.VFList{
			Count: 2,
			Data: []sriov.EthVF{
				{
					Index: 0,
				},
				{
					Index: 1,
				},
			},
		},
	))
	g.Expect(ios.AdapterList[1].Vfs).To(BeEquivalentTo(sriov.VFList{}))
	// Unspecified VFs will be generated.
	g.Expect(ios.AdapterList[2].Vfs).To(BeEquivalentTo(sriov.VFList{
		Count: 2,
		Data: []sriov.EthVF{
			{
				Index:  1,
				VlanID: 2,
			},
			{
				Index: 0,
			},
		},
	}))
}

func TestParsePatchEnvelope(t *testing.T) {
	t.Parallel()

	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	appU1 := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	appU2 := "60331c10-9dad-182g-80b4-00123ga430c8"

	patchID := "uuid1"
	displayName := "test"
	patchVersion := "version1"
	artiactMetadata := "Artifact metadata"

	fileData := "textdata"
	fileMetadata := "metadata"
	inlineFileName := "inline-query-name"

	config := &zconfig.EdgeDevConfig{
		PatchEnvelopes: []*zconfig.EvePatchEnvelope{
			{
				DisplayName: displayName,
				Uuid:        patchID,
				Version:     &patchVersion,
				Action:      zconfig.EVE_PATCH_ENVELOPE_ACTION_ACTIVATE,
				Artifacts: []*zconfig.EveBinaryArtifact{
					{
						Format: zconfig.EVE_OPAQUE_OBJECT_CATEGORY_BASE64,
						BinaryBlob: &zconfig.EveBinaryArtifact_Inline{
							Inline: &zconfig.InlineOpaqueBase64Data{
								Base64Data:     fileData,
								Base64MetaData: &fileMetadata,
								FileNameToUse:  inlineFileName,
							},
						},
						ArtifactMetaData: &artiactMetadata,
					},
				},
				AppInstIdsAllowed: []string{appU1, appU2},
			},
		},
	}

	persistCacheFolder, err := os.MkdirTemp("", "testPersist")
	g.Expect(err).To(BeNil())

	// Impl because we have to change filepath of persist cache for testing
	parsePatchEnvelopesImpl(getconfigCtx, config, persistCacheFolder)

	patchEnvelopes, err := getconfigCtx.pubPatchEnvelopeInfo.Get("global")

	g.Expect(err).To(BeNil())
	pes, ok := patchEnvelopes.(types.PatchEnvelopeInfoList)
	g.Expect(ok).To(BeTrue())
	shaBytes := sha256.Sum256([]byte(fileData))
	g.Expect(pes.Get(appU1).Envelopes).To(BeEquivalentTo([]types.PatchEnvelopeInfo{
		{
			PatchID:     patchID,
			Name:        displayName,
			Version:     patchVersion,
			AllowedApps: []string{appU1, appU2},
			State:       types.PatchEnvelopeStateActive,
			BinaryBlobs: []types.BinaryBlobCompleted{
				{
					FileName:         inlineFileName,
					FileSha:          hex.EncodeToString(shaBytes[:]),
					FileMetadata:     fileMetadata,
					ArtifactMetadata: artiactMetadata,
					URL:              filepath.Join(persistCacheFolder, inlineFileName),
					Size:             int64(len(fileData)),
				},
			},
		},
	}))

	os.RemoveAll(persistCacheFolder)
}

func TestParseSharedLabels(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx := initGetConfigCtx(g)

	const (
		network1UUID = "572cd3bc-ade6-42ad-97a0-22cd24fed1a0"
		network2UUID = "0c1a98fb-85fa-421d-943e-8d4e469bea8f"
	)
	config := &zconfig.EdgeDevConfig{
		Networks: []*zconfig.NetworkConfig{
			{
				Id:   network1UUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
			{
				Id:   network2UUID,
				Type: zcommon.NetworkType_V4,
				Ip: &zcommon.Ipspec{
					Dhcp: zcommon.DHCPType_Client,
				},
			},
		},
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:f4:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet1",
				Logicallabel: "warehouse",
				Assigngrp:    "eth-grp-2",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-shopfloor",
				Uplink:         true,
				NetworkUUID:    network1UUID,
				Alias:          "shopfloor-alias",
				LowerLayerName: "shopfloor",
				Cost:           0,
				// error: "adapter-warehouse" is logical label
				SharedLabels: []string{"portfwd", "netinst1", "adapter-warehouse"},
			},
			{
				Name:           "adapter-warehouse",
				Uplink:         true,
				NetworkUUID:    network2UUID,
				Alias:          "warehouse-alias",
				LowerLayerName: "warehouse",
				Cost:           10,
				// error: "uplink" is reserved
				SharedLabels: []string{"portfwd", "netinst2", "uplink"},
			},
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)
	parseNetworkXObjectConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Version).To(Equal(types.DPCIsMgmt))
	g.Expect(dpc.HasError()).To(BeTrue())
	g.Expect(dpc.LastFailed).ToNot(BeZero())
	g.Expect(dpc.LastSucceeded).To(BeZero())
	g.Expect(getPortError(&dpc, "adapter-shopfloor")).
		To(ContainSubstring("Port adapter-shopfloor: It is forbidden to use port name 'adapter-warehouse' as shared label"))
	g.Expect(getPortError(&dpc, "adapter-warehouse")).
		To(ContainSubstring("Port adapter-warehouse: It is forbidden to assign reserved port label 'uplink'"))

	// EVE-defined labels are not added when user-defined labels are invalid.
	g.Expect(dpc.Ports).To(HaveLen(2))
	port := dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor"))
	g.Expect(port.SharedLabels).To(Equal([]string{"portfwd", "netinst1", "adapter-warehouse"}))
	g.Expect(port.InvalidConfig).To(BeTrue())
	port = dpc.Ports[1]
	g.Expect(port.Logicallabel).To(Equal("adapter-warehouse"))
	g.Expect(port.SharedLabels).To(Equal([]string{"portfwd", "netinst2", "uplink"}))
	g.Expect(port.InvalidConfig).To(BeTrue())

	// Fix config errors.
	config.SystemAdapterList[0].SharedLabels = []string{"portfwd", "netinst1"}
	config.SystemAdapterList[1].SharedLabels = []string{"portfwd", "netinst2"}
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Version).To(Equal(types.DPCIsMgmt))
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.LastFailed).To(BeZero())

	// EVE-defined labels were automatically added
	g.Expect(dpc.Ports).To(HaveLen(2))
	port = dpc.Ports[0]
	g.Expect(port.Logicallabel).To(Equal("adapter-shopfloor"))
	g.Expect(port.SharedLabels).To(Equal([]string{"portfwd", "netinst1", "all", "uplink", "freeuplink"}))
	g.Expect(port.InvalidConfig).To(BeFalse())
	port = dpc.Ports[1]
	g.Expect(port.Logicallabel).To(Equal("adapter-warehouse"))
	g.Expect(port.SharedLabels).To(Equal([]string{"portfwd", "netinst2", "all", "uplink"}))
	g.Expect(port.InvalidConfig).To(BeFalse())
}

func TestParseIpspecNetworkXObject_ValidConfig(t *testing.T) {
	g := NewGomegaWithT(t)

	subnetStr := "192.168.1.0/24"
	_, subnet, _ := net.ParseCIDR(subnetStr)

	ipspec := &zcommon.Ipspec{
		Dhcp:    zcommon.DHCPType_Static,
		Subnet:  subnetStr,
		Gateway: "192.168.1.1",
		Domain:  "test.local",
		Ntp:     "192.168.1.10",
		MoreNtp: []string{"192.168.1.11"},
		Dns:     []string{"192.168.1.2"},
		DhcpRange: &zcommon.IpRange{
			Start: "192.168.1.100",
			End:   "192.168.1.120",
		},
		DhcpOptionsIgnore: &zcommon.DhcpOptionsIgnore{
			NtpServerExclusively: true,
		},
	}

	var config types.NetworkXObjectConfig
	err := parseIpspecNetworkXObject(ipspec, &config)

	g.Expect(err).To(BeNil())
	g.Expect(config.Dhcp).To(Equal(types.DhcpTypeStatic))
	g.Expect(config.DomainName).To(Equal("test.local"))
	g.Expect(config.Gateway.String()).To(Equal("192.168.1.1"))
	g.Expect(config.Subnet.String()).To(Equal(subnet.String()))
	g.Expect(config.DNSServers).To(HaveLen(1))
	g.Expect(config.DNSServers[0].String()).To(Equal("192.168.1.2"))
	g.Expect(config.DhcpRange.Start.String()).To(Equal("192.168.1.100"))
	g.Expect(config.DhcpRange.End.String()).To(Equal("192.168.1.120"))
	g.Expect(config.IgnoreDhcpNtpServers).To(BeTrue())
	expNTPs := netutils.NewHostnameOrIPs("192.168.1.10", "192.168.1.11")
	g.Expect(generics.EqualSetsFn(config.NTPServers, expNTPs, netutils.EqualHostnameOrIPs)).To(BeTrue())
}

func TestParseIpspecNetworkXObject_ValidConfig_IPv6(t *testing.T) {
	RegisterTestingT(t)

	subnetStr := "fd00::/64"
	_, subnet, _ := net.ParseCIDR(subnetStr)

	ipspec := &zcommon.Ipspec{
		Dhcp:    zcommon.DHCPType_Static,
		Subnet:  subnetStr,
		Gateway: "fd00::1",
		Domain:  "ipv6.local",
		Ntp:     "fd00::123",
		MoreNtp: []string{"fd00::124"},
		Dns:     []string{"fd00::53"},
		DhcpRange: &zcommon.IpRange{
			Start: "fd00::100",
			End:   "fd00::1ff",
		},
		DhcpOptionsIgnore: &zcommon.DhcpOptionsIgnore{
			NtpServerExclusively: true,
		},
	}

	var config types.NetworkXObjectConfig
	err := parseIpspecNetworkXObject(ipspec, &config)

	Expect(err).To(BeNil())
	Expect(config.Dhcp).To(Equal(types.DhcpTypeStatic))
	Expect(config.Subnet.String()).To(Equal(subnet.String()))
	Expect(config.Gateway.String()).To(Equal("fd00::1"))
	Expect(config.DomainName).To(Equal("ipv6.local"))

	Expect(config.DNSServers).To(HaveLen(1))
	Expect(config.DNSServers[0].String()).To(Equal("fd00::53"))

	Expect(config.DhcpRange.Start.String()).To(Equal("fd00::100"))
	Expect(config.DhcpRange.End.String()).To(Equal("fd00::1ff"))

	Expect(config.IgnoreDhcpNtpServers).To(BeTrue())
	expNTPs := netutils.NewHostnameOrIPs("fd00::123", "fd00::124")
	Expect(generics.EqualSetsFn(config.NTPServers, expNTPs, netutils.EqualHostnameOrIPs)).To(BeTrue())
}

func TestParseIpspecNetworkXObject_InvalidSubnet(t *testing.T) {
	g := NewGomegaWithT(t)

	ipspec := &zcommon.Ipspec{
		Subnet: "not_a_cidr",
	}

	var config types.NetworkXObjectConfig
	err := parseIpspecNetworkXObject(ipspec, &config)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("invalid subnet"))
}

func TestParseIpspecNetworkXObject_InvalidGateway(t *testing.T) {
	g := NewGomegaWithT(t)

	ipspec := &zcommon.Ipspec{
		Subnet:  "192.168.1.0/24",
		Gateway: "bad_ip",
	}

	var config types.NetworkXObjectConfig
	err := parseIpspecNetworkXObject(ipspec, &config)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("invalid gateway"))
}

func TestParseIpspecNetworkXObject_DNSMismatch(t *testing.T) {
	g := NewGomegaWithT(t)

	ipspec := &zcommon.Ipspec{
		Subnet: "192.168.1.0/24",
		Dns:    []string{"2001:db8::1"}, // IPv6 in IPv4 subnet
	}

	var config types.NetworkXObjectConfig
	err := parseIpspecNetworkXObject(ipspec, &config)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("IP version mismatch"))
}

func TestParseIpspecNetworkXObject_InvalidDHCPRange(t *testing.T) {
	g := NewGomegaWithT(t)

	ipspec := &zcommon.Ipspec{
		Subnet: "192.168.1.0/24",
		DhcpRange: &zcommon.IpRange{
			Start: "192.168.1.250",
			End:   "192.168.1.240", // start > end
		},
	}

	var config types.NetworkXObjectConfig
	err := parseIpspecNetworkXObject(ipspec, &config)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("greater than end IP"))
}

func TestParseIpspec_Valid(t *testing.T) {
	g := NewGomegaWithT(t)

	ipspec := &zcommon.Ipspec{
		Subnet:  "192.168.0.0/24",
		Gateway: "192.168.0.1",
		Domain:  "test.local",
		Ntp:     "192.168.0.5",
		Dns:     []string{"192.168.0.2"},
	}

	var config types.NetworkInstanceConfig
	err := parseIpspec(ipspec, &config)

	g.Expect(err).To(BeNil())
	g.Expect(config.DomainName).To(Equal("test.local"))
	g.Expect(config.Gateway.String()).To(Equal("192.168.0.1"))
	expNTPs := netutils.NewHostnameOrIPs("192.168.0.5")
	Expect(generics.EqualSetsFn(config.NtpServers, expNTPs, netutils.EqualHostnameOrIPs)).To(BeTrue())
	g.Expect(config.DnsServers[0].String()).To(Equal("192.168.0.2"))
	g.Expect(config.DhcpRange.Start).ToNot(BeNil())
	g.Expect(config.DhcpRange.End).ToNot(BeNil())
}

func TestParseIpspec_MissingSubnet(t *testing.T) {
	g := NewGomegaWithT(t)

	ipspec := &zcommon.Ipspec{}

	var config types.NetworkInstanceConfig
	err := parseIpspec(ipspec, &config)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("missing network instance subnet"))
}

func TestParseIpspec_GatewayVersionMismatch(t *testing.T) {
	g := NewGomegaWithT(t)

	ipspec := &zcommon.Ipspec{
		Subnet:  "192.168.1.0/24",
		Gateway: "2001:db8::1", // mismatch
	}

	var config types.NetworkInstanceConfig
	err := parseIpspec(ipspec, &config)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("IP version mismatch"))
}
