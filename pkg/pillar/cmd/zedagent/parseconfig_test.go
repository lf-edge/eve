// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"sort"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	zconfig "github.com/lf-edge/eve/api/go/config"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	"github.com/lf-edge/eve/pkg/pillar/types"
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
	getconfigCtx := &getconfigContext{
		pubDevicePortConfig:     pubDPC,
		pubPhysicalIOAdapters:   pubIOAdapters,
		pubNetworkXObjectConfig: pubNetworks,
		zedagentCtx: &zedagentContext{
			physicalIoAdapterMap: make(map[string]types.PhysicalIOAdapter),
		},
		cipherContexts: make(map[string]types.CipherContext),
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
				Type: zconfig.NetworkType_V4,
				Ip: &zconfig.Ipspec{
					Dhcp: zconfig.DHCPType_Client,
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_IPV4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_CLIENT))
	g.Expect(port.DhcpConfig.DomainName).To(BeEmpty())
	g.Expect(port.DhcpConfig.AddrSubnet).To(BeEmpty())
	g.Expect(port.DhcpConfig.DnsServers).To(BeEmpty())
	g.Expect(port.DhcpConfig.Gateway).To(BeNil())
	g.Expect(port.DhcpConfig.NtpServer).To(BeNil())
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
		To(ContainSubstring("UNKNOWN Network UUID"))
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
				Type: zconfig.NetworkType_V4,
				Ip: &zconfig.Ipspec{
					Dhcp: zconfig.DHCPType_Client,
				},
			},
			{
				Id:   network2UUID,
				Type: zconfig.NetworkType_V6,
				Ip: &zconfig.Ipspec{
					Dhcp: zconfig.DHCPType_Client,
				},
			},
			{
				Id:   network3UUID,
				Type: zconfig.NetworkType_V4,
				Ip: &zconfig.Ipspec{
					Dhcp:    zconfig.DHCPType_Static,
					Subnet:  "192.168.1.0/24",
					Gateway: "192.168.1.1",
					DhcpRange: &zconfig.IpRange{
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_IPV4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_CLIENT))
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_IPV6))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_CLIENT))
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_NOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_NOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))

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
	port = dpc.Ports[2]
	g.Expect(port.Logicallabel).To(Equal("adapter-warehouse-vlan100"))
	g.Expect(port.Phylabel).To(BeEmpty())
	g.Expect(port.IsL3Port).To(BeTrue())
	g.Expect(port.IfName).To(Equal("warehouse.100"))
	g.Expect(port.NetworkUUID.String()).To(Equal(network3UUID))
	g.Expect(port.Cost).To(BeEquivalentTo(30))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_IPV4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_STATIC))
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_NOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_NOOP))
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
				Type: zconfig.NetworkType_V4,
				Ip: &zconfig.Ipspec{
					Dhcp: zconfig.DHCPType_Client,
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
				InterfaceName:   "bond0",
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
	g.Expect(port.IfName).To(Equal("bond0"))
	g.Expect(port.NetworkUUID.String()).To(Equal(networkUUID))
	g.Expect(port.Cost).To(BeEquivalentTo(10))
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_IPV4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_CLIENT))
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_NOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_NOOP))
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_NOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_NOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
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
				Type: zconfig.NetworkType_V4,
				Ip: &zconfig.Ipspec{
					Dhcp: zconfig.DHCPType_Client,
				},
			},
			{
				Id:   network2UUID,
				Type: zconfig.NetworkType_V4,
				Ip: &zconfig.Ipspec{
					Dhcp: zconfig.DHCPType_Client,
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
				InterfaceName:   "bond0",
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_IPV4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_CLIENT))
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_IPV4))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_CLIENT))
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
	g.Expect(port.IfName).To(Equal("bond0"))
	g.Expect(port.NetworkUUID).To(BeZero())
	g.Expect(port.Cost).To(BeZero())
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_NOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_NOOP))
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_NOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_NOOP))
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
	g.Expect(port.DhcpConfig.Type).To(BeEquivalentTo(types.NT_NOOP))
	g.Expect(port.DhcpConfig.Dhcp).To(Equal(types.DT_NOOP))
	g.Expect(port.L2LinkConfig.L2Type).To(Equal(types.L2LinkTypeNone))
	g.Expect(port.WirelessCfg.WType).To(Equal(types.WirelessTypeNone))
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
				Type: zconfig.NetworkType_V4,
				Ip: &zconfig.Ipspec{
					Dhcp: zconfig.DHCPType_Client,
				},
			},
			{
				Id:   network2UUID,
				Type: zconfig.NetworkType_V4,
				Ip: &zconfig.Ipspec{
					Dhcp: zconfig.DHCPType_Client,
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
		To(ContainSubstring("Port collides with another port"))
	g.Expect(getPortError(&dpc, "adapter2")).
		To(ContainSubstring("Port collides with another port"))
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
				InterfaceName:   "bond0",
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
			InterfaceName:   "bond0",
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

	// Scenario 4: interface referenced by both a system adapter and a L2 object
	config = &zconfig.EdgeDevConfig{
		Bonds: []*zconfig.BondAdapter{
			{
				Logicallabel:    "bond-shopfloor",
				InterfaceName:   "bond0",
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
		To(ContainSubstring("Port collides with another port"))
	g.Expect(getPortError(&dpc, "adapter-bond-shopfloor")).
		To(ContainSubstring("Port collides with another port"))
	g.Expect(dpc.Ports).To(HaveLen(4))

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
				InterfaceName:   "bond0",
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
				InterfaceName:   "bond0",
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
