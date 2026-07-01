// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lf-edge/eve-api/go/config"
	zconfig "github.com/lf-edge/eve-api/go/config"
	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/localcommand"
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
	pubSCEPProfile, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.SCEPProfile{},
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
		pubSCEPProfile:          pubSCEPProfile,
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
	parseVlans(getconfigCtx, config, false)
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
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
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
	parseBonds(getconfigCtx, config, false)
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
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
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
	parseBonds(getconfigCtx, config, false)
	parseVlans(getconfigCtx, config, false)
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
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
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
	parseBonds(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
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
			BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
		},
	}
	parseBonds(getconfigCtx, config, false)
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
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
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
	parseBonds(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
	parseVlans(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
	parseVlans(getconfigCtx, config, false)
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
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
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
	parseBonds(getconfigCtx, config, false)
	parseVlans(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
	parseVlans(getconfigCtx, config, false)
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
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
			},
			{
				Logicallabel:    "bond1",
				InterfaceName:   "bond1",
				LowerLayerNames: []string{"shopfloor", "warehouse"},
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
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
	parseBonds(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
	parseVlans(getconfigCtx, config, false)
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
	parseBonds(getconfigCtx, config, false)
	parseVlans(getconfigCtx, config, false)
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

func TestParsePNAC(t *testing.T) {
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
				Phylabel:     "eth0",
				Logicallabel: "ethernet0",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:04:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "eth1",
				Logicallabel: "ethernet1",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-ethernet0",
				Uplink:         true,
				NetworkUUID:    networkUUID,
				Alias:          "ethernet0-alias",
				LowerLayerName: "ethernet0",
				Cost:           0,
			},
			{
				Name:           "adapter-ethernet1",
				Uplink:         true,
				NetworkUUID:    networkUUID,
				Alias:          "ethernet1-alias",
				LowerLayerName: "ethernet1",
				Cost:           10,
			},
		},
		Pnacs: []*zconfig.PNAC{
			{
				Logicallabel:              "ethernet0",
				EapIdentity:               "123456789",
				EapMethod:                 zconfig.EAPMethod_EAP_METHOD_TLS,
				CertEnrollmentProfileName: "scep-profile1",
			},
		},
		ScepProfiles: []*zconfig.SCEPProfile{
			{
				ProfileName:        "scep-profile1",
				ScepUrl:            "https://ca.example.com/scep",
				UseControllerProxy: true,
				CsrProfile: &zconfig.CSRProfile{
					CommonName:         "123456789",
					Organization:       "Test Organization",
					OrganizationalUnit: "Unit Test",
					Country:            "US",
					State:              "TestState",
					Locality:           "TestCity",
					SanUri:             []string{"urn:test:device:123456789"},
					RenewPeriodPercent: 60,
					KeyType:            zconfig.KeyType_KEY_TYPE_RSA_4096,
					HashAlgorithm:      zconfig.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)
	parseSCEPProfiles(getconfigCtx, config)
	parsePNACConfig(getconfigCtx, config, true)
	parseNetworkXObjectConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Version).To(Equal(types.DPCIsMgmt))
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(2))
	port0 := dpc.Ports[0]
	g.Expect(port0.Logicallabel).To(Equal("adapter-ethernet0"))
	g.Expect(port0.PNAC.Enabled).To(BeTrue())
	g.Expect(port0.PNAC.CertEnrollmentProfileName).To(Equal("scep-profile1"))
	g.Expect(port0.PNAC.EAPMethod).To(Equal(zconfig.EAPMethod_EAP_METHOD_TLS))
	g.Expect(port0.PNAC.EAPIdentity).To(Equal("123456789"))
	port1 := dpc.Ports[1]
	g.Expect(port1.Logicallabel).To(Equal("adapter-ethernet1"))
	g.Expect(port1.PNAC.Enabled).To(BeFalse())
	g.Expect(port1.PNAC.CertEnrollmentProfileName).To(BeEmpty())
	g.Expect(port1.PNAC.EAPMethod).To(Equal(zconfig.EAPMethod_EAP_METHOD_UNSPECIFIED))
	g.Expect(port1.PNAC.EAPIdentity).To(BeEmpty())

	scepProfileObj, err := getconfigCtx.pubSCEPProfile.Get("scep-profile1")
	g.Expect(err).To(BeNil())
	scepProfile := scepProfileObj.(types.SCEPProfile)
	g.Expect(scepProfile.ProfileName).To(Equal("scep-profile1"))
	g.Expect(scepProfile.SCEPServerURL).To(Equal("https://ca.example.com/scep"))
	g.Expect(scepProfile.UseControllerProxy).To(BeTrue())

	// No parsing errors expected
	g.Expect(scepProfile.ParsingError.Error).To(BeEmpty())

	// CA certs were not provided
	g.Expect(scepProfile.CACertPEM).To(BeEmpty())

	// CSR Subject checks
	g.Expect(scepProfile.CSRProfile.Subject.CommonName).To(Equal("123456789"))
	g.Expect(scepProfile.CSRProfile.Subject.Organization).To(Equal([]string{"Test Organization"}))
	g.Expect(scepProfile.CSRProfile.Subject.OrganizationalUnit).To(Equal([]string{"Unit Test"}))
	g.Expect(scepProfile.CSRProfile.Subject.Country).To(Equal([]string{"US"}))
	g.Expect(scepProfile.CSRProfile.Subject.State).To(Equal([]string{"TestState"}))
	g.Expect(scepProfile.CSRProfile.Subject.Locality).To(Equal([]string{"TestCity"}))

	// CSR SAN checks
	g.Expect(scepProfile.CSRProfile.SAN.DNSNames).To(BeEmpty())
	g.Expect(scepProfile.CSRProfile.SAN.EmailAddresses).To(BeEmpty())
	g.Expect(scepProfile.CSRProfile.SAN.IPAddresses).To(BeNil())
	g.Expect(scepProfile.CSRProfile.SAN.URIs).
		To(Equal([]string{"urn:test:device:123456789"}))

	// Renewal + crypto parameters
	g.Expect(scepProfile.CSRProfile.RenewPeriodPercent).To(Equal(uint8(60)))
	g.Expect(scepProfile.CSRProfile.KeyType).
		To(Equal(zconfig.KeyType_KEY_TYPE_RSA_4096))
	g.Expect(scepProfile.CSRProfile.HashAlgorithm).
		To(Equal(zconfig.HashAlgorithm_HASH_ALGORITHM_SHA256))

	// Clear PNAC/SCEP config.
	config.Pnacs = nil
	config.ScepProfiles = nil
	parseSCEPProfiles(getconfigCtx, config)
	parsePNACConfig(getconfigCtx, config, true)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err = getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.Ports).To(HaveLen(2))
	port0 = dpc.Ports[0]
	g.Expect(port0.Logicallabel).To(Equal("adapter-ethernet0"))
	g.Expect(port0.PNAC.Enabled).To(BeFalse())
	port1 = dpc.Ports[1]
	g.Expect(port1.Logicallabel).To(Equal("adapter-ethernet1"))
	g.Expect(port1.PNAC.Enabled).To(BeFalse())

	g.Expect(getconfigCtx.pubSCEPProfile.GetAll()).To(BeEmpty())
}

func TestParseInvalidPNAC(t *testing.T) {
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
				Phylabel:     "eth0",
				Logicallabel: "ethernet0",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth0",
					"pcilong": "0000:04:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "eth1",
				Logicallabel: "ethernet1",
				Assigngrp:    "eth-grp-1",
				Phyaddrs: map[string]string{
					"ifname":  "eth1",
					"pcilong": "0000:05:00.0",
				},
				Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		// Test error propagation to higher-layer adapters.
		Vlans: []*zconfig.VlanAdapter{
			{
				Logicallabel:   "ethernet1.10",
				InterfaceName:  "ethernet1.10",
				LowerLayerName: "ethernet1",
				VlanId:         10,
			},
			{
				Logicallabel:   "ethernet1.20",
				InterfaceName:  "ethernet1.20",
				LowerLayerName: "ethernet1",
				VlanId:         20,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:        "ethernet0",
				Uplink:      true,
				NetworkUUID: networkUUID,
				Cost:        0,
			},
			{
				Name:        "ethernet1",
				Uplink:      true,
				NetworkUUID: networkUUID,
				Cost:        10,
			},
			{
				Name:        "ethernet1.10",
				Uplink:      true,
				NetworkUUID: networkUUID,
				Cost:        10,
			},
			{
				Name:        "ethernet1.20",
				Uplink:      true,
				NetworkUUID: networkUUID,
				Cost:        10,
			},
		},
		Pnacs: []*zconfig.PNAC{
			{
				Logicallabel:              "ethernet0",
				EapIdentity:               "123456789",
				EapMethod:                 zconfig.EAPMethod_EAP_METHOD_TLS,
				CertEnrollmentProfileName: "scep-profile1",
			},
			{
				Logicallabel: "ethernet1",
				// Empty EapIdentity is valid.
				EapMethod:                 zconfig.EAPMethod_EAP_METHOD_TLS,
				CertEnrollmentProfileName: "scep-profile3", // non-existent profile
			},
		},
		ScepProfiles: []*zconfig.SCEPProfile{
			{
				ProfileName:        "scep-profile1",
				ScepUrl:            "https://ca.example.com/scep",
				UseControllerProxy: true,
				CsrProfile: &zconfig.CSRProfile{
					CommonName:         "123456789",
					Organization:       "Test Organization",
					OrganizationalUnit: "Unit Test",
					Country:            "US",
					State:              "TestState",
					Locality:           "TestCity",
					SanUri:             []string{"urn:test:device:123456789"},
					RenewPeriodPercent: 60,
					KeyType:            zconfig.KeyType_KEY_TYPE_RSA_4096,
					HashAlgorithm:      zconfig.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
			{
				ProfileName:        "scep-profile2",
				ScepUrl:            "invalid-URL",
				UseControllerProxy: true,
				CsrProfile: &zconfig.CSRProfile{
					CommonName:         "ABCDEF",
					Organization:       "Test Organization",
					OrganizationalUnit: "Unit Test",
					Country:            "US",
					State:              "TestState",
					Locality:           "TestCity",
					SanUri:             []string{"urn:test:device:ABCDEF"},
					RenewPeriodPercent: 80,
					KeyType:            zconfig.KeyType_KEY_TYPE_ECDSA_P384,
					HashAlgorithm:      zconfig.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
	}

	parseDeviceIoListConfig(getconfigCtx, config)
	parseSCEPProfiles(getconfigCtx, config)
	parsePNACConfig(getconfigCtx, config, true)
	parseVlans(getconfigCtx, config, false)
	parseNetworkXObjectConfig(getconfigCtx, config)
	parseSystemAdapterConfig(getconfigCtx, config, fromController, true)

	portConfig, err := getconfigCtx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)

	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(dpc.Ports).To(HaveLen(4))

	// ethernet0 (valid PNAC + valid SCEP profile)
	var eth0 types.NetworkPortConfig
	for _, p := range dpc.Ports {
		if p.Logicallabel == "ethernet0" {
			eth0 = p
			break
		}
	}
	g.Expect(eth0.Logicallabel).To(Equal("ethernet0"))
	g.Expect(eth0.HasError()).To(BeFalse())
	g.Expect(eth0.PNAC.Enabled).To(BeTrue())
	g.Expect(eth0.PNAC.CertEnrollmentProfileName).To(Equal("scep-profile1"))

	// scep-profile1 (valid)
	scepProfile1Obj, err := getconfigCtx.pubSCEPProfile.Get("scep-profile1")
	g.Expect(err).To(BeNil())
	scepProfile1 := scepProfile1Obj.(types.SCEPProfile)
	g.Expect(scepProfile1.ParsingError.Error).To(BeEmpty())

	// ethernet1 (references non-existent profile)
	var eth1 types.NetworkPortConfig
	for _, p := range dpc.Ports {
		if p.Logicallabel == "ethernet1" {
			eth1 = p
			break
		}
	}
	g.Expect(eth1.HasError()).To(BeTrue())
	g.Expect(eth1.LastError).To(ContainSubstring(
		"PNAC config with logical label \"ethernet1\" references non-existent " +
			"certificate enrollment profile \"scep-profile3\""))

	// VLAN adapters (should inherit ethernet1 error)
	var vlan10, vlan20 types.NetworkPortConfig
	for _, p := range dpc.Ports {
		switch p.Logicallabel {
		case "ethernet1.10":
			vlan10 = p
		case "ethernet1.20":
			vlan20 = p
		}
	}

	g.Expect(vlan10.HasError()).To(BeTrue())
	g.Expect(vlan10.LastError).To(ContainSubstring(
		"Lower-layer adapter ethernet1 has an error (PNAC config with logical label " +
			"\"ethernet1\" references non-existent certificate enrollment " +
			"profile \"scep-profile3\""))

	g.Expect(vlan20.HasError()).To(BeTrue())
	g.Expect(vlan20.LastError).To(ContainSubstring(
		"Lower-layer adapter ethernet1 has an error (PNAC config with logical label " +
			"\"ethernet1\" references non-existent certificate enrollment " +
			"profile \"scep-profile3\""))

	// scep-profile2 (invalid URL)
	scepProfile2Obj, err := getconfigCtx.pubSCEPProfile.Get("scep-profile2")
	g.Expect(err).To(BeNil())
	scepProfile2 := scepProfile2Obj.(types.SCEPProfile)
	g.Expect(scepProfile2.ParsingError.Error).ToNot(BeEmpty())
	g.Expect(scepProfile2.ParsingError.Error).To(ContainSubstring(
		"Invalid SCEP URL \"invalid-URL\""))
}

// TestBondMemberSwap verifies that swapping physical adapters between two bonds
// produces a correct DPC with no "aggregated by multiple bonds" error.
//
// The key scenario: bond2 has no direct system adapter (it is only reachable via
// VLANs). When bond membership changes but the VLAN config is identical, the VLAN
// hash is unchanged. Without forceParse, parseVlans would skip its re-parsing and
// keep stale lowerL2Ports pointers to the old bond2, causing the old bond2
// (with its old members) to appear in the DPC alongside the updated bond1,
// making one adapter appear in both bonds.
func TestBondMemberSwap(t *testing.T) {
	g := NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	const networkUUID = "572cd3bc-ade6-42ad-97a0-22cd24fed1a0"

	config := &zconfig.EdgeDevConfig{
		Networks: []*zconfig.NetworkConfig{
			{
				Id:   networkUUID,
				Type: zcommon.NetworkType_V4,
				Ip:   &zcommon.Ipspec{Dhcp: zcommon.DHCPType_Client},
			},
		},
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "eth0",
				Logicallabel: "eth0",
				Assigngrp:    "eth-grp-1",
				Phyaddrs:     map[string]string{"ifname": "eth0", "pcilong": "0000:01:00.0"},
				Usage:        zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "eth1",
				Logicallabel: "eth1",
				Assigngrp:    "eth-grp-2",
				Phyaddrs:     map[string]string{"ifname": "eth1", "pcilong": "0000:02:00.0"},
				Usage:        zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "eth2",
				Logicallabel: "eth2",
				Assigngrp:    "eth-grp-3",
				Phyaddrs:     map[string]string{"ifname": "eth2", "pcilong": "0000:03:00.0"},
				Usage:        zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "eth3",
				Logicallabel: "eth3",
				Assigngrp:    "eth-grp-4",
				Phyaddrs:     map[string]string{"ifname": "eth3", "pcilong": "0000:04:00.0"},
				Usage:        zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		Bonds: []*zconfig.BondAdapter{
			{
				Logicallabel:    "bond1",
				InterfaceName:   "bond1",
				LowerLayerNames: []string{"eth0", "eth1"},
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
				Monitoring:      &zconfig.BondAdapter_Mii{Mii: &zconfig.MIIMonitor{Interval: 100}},
			},
			{
				Logicallabel:    "bond2",
				InterfaceName:   "bond2",
				LowerLayerNames: []string{"eth2", "eth3"},
				BondMode:        zcommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
				Monitoring:      &zconfig.BondAdapter_Mii{Mii: &zconfig.MIIMonitor{Interval: 100}},
			},
		},
		// bond2 has no direct system adapter — it is only accessible via VLANs.
		// This is the configuration that exercises the stale-pointer path.
		Vlans: []*zconfig.VlanAdapter{
			{
				Logicallabel:   "vlan20",
				InterfaceName:  "bond2.20",
				LowerLayerName: "bond2",
				VlanId:         20,
			},
			{
				Logicallabel:   "vlan21",
				InterfaceName:  "bond2.21",
				LowerLayerName: "bond2",
				VlanId:         21,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "adapter-bond1",
				Uplink:         true,
				NetworkUUID:    networkUUID,
				LowerLayerName: "bond1",
			},
			{
				Name:           "adapter-vlan20",
				Uplink:         true,
				NetworkUUID:    networkUUID,
				LowerLayerName: "vlan20",
			},
			{
				Name:           "adapter-vlan21",
				Uplink:         true,
				NetworkUUID:    networkUUID,
				LowerLayerName: "vlan21",
			},
		},
	}

	// parseAll runs the parse functions in the same dependency order as parseConfig.
	parseAll := func(cfg *zconfig.EdgeDevConfig) {
		physioChanged := parseDeviceIoListConfig(ctx, cfg)
		bondsChanged := parseBonds(ctx, cfg, physioChanged)
		vlansChanged := parseVlans(ctx, cfg, physioChanged || bondsChanged)
		parseNetworkXObjectConfig(ctx, cfg)
		parseSystemAdapterConfig(ctx, cfg, fromController,
			physioChanged || bondsChanged || vlansChanged)
	}

	// Round 1: initial config — bond1=[eth0,eth1], bond2=[eth2,eth3]
	parseAll(config)
	portConfig, err := ctx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc := portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	bond1Port := dpc.LookupPortByLogicallabel("adapter-bond1")
	g.Expect(bond1Port).ToNot(BeNil())
	g.Expect(bond1Port.L2LinkConfig.Bond.AggregatedPorts).To(ConsistOf("eth0", "eth1"))
	bond2Port := dpc.LookupPortByLogicallabel("bond2")
	g.Expect(bond2Port).ToNot(BeNil())
	g.Expect(bond2Port.L2LinkConfig.Bond.AggregatedPorts).To(ConsistOf("eth2", "eth3"))

	// Round 2: swap eth1↔eth2 — bond1=[eth0,eth2], bond2=[eth1,eth3].
	// The VLAN config is identical so parseVlans detects no hash change.
	// Without forceParse the stale vlan→old-bond2 pointer would leave
	// old bond2 (carrying eth2) in the DPC alongside new bond1 (also carrying
	// eth2), triggering "Port eth2 is aggregated by multiple bond interfaces".
	config.Bonds[0].LowerLayerNames = []string{"eth0", "eth2"}
	config.Bonds[1].LowerLayerNames = []string{"eth1", "eth3"}
	parseAll(config)
	portConfig, err = ctx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(BeNil())
	dpc = portConfig.(types.DevicePortConfig)
	g.Expect(dpc.HasError()).To(BeFalse())
	g.Expect(getPortError(&dpc, "eth1")).To(BeEmpty())
	g.Expect(getPortError(&dpc, "eth2")).To(BeEmpty())
	bond1Port = dpc.LookupPortByLogicallabel("adapter-bond1")
	g.Expect(bond1Port).ToNot(BeNil())
	g.Expect(bond1Port.L2LinkConfig.Bond.AggregatedPorts).To(ConsistOf("eth0", "eth2"))
	bond2Port = dpc.LookupPortByLogicallabel("bond2")
	g.Expect(bond2Port).ToNot(BeNil())
	g.Expect(bond2Port.L2LinkConfig.Bond.AggregatedPorts).To(ConsistOf("eth1", "eth3"))
}

// newPublication is a small helper that creates a pubsub.Publication on top of
// the EmptyDriver, failing the test on error.
func newPublication(tb testing.TB, ps *pubsub.PubSub, topicType interface{}) pubsub.Publication {
	tb.Helper()
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: topicType,
	})
	if err != nil {
		tb.Fatalf("NewPublication(%T): %v", topicType, err)
	}
	return pub
}

// mustPublish publishes item under key, failing the test on error.
func mustPublish(tb testing.TB, pub pubsub.Publication, key string, item interface{}) {
	tb.Helper()
	if err := pub.Publish(key, item); err != nil {
		tb.Fatalf("Publish(%s, %T): %v", key, item, err)
	}
}

// newSubscription is a small helper that creates a pubsub.Subscription on top of
// the EmptyDriver, failing the test on error. It is intentionally left inactive
// (Activate:false): the parse path only ever calls GetAll() on these, which is
// safe regardless of activation, and the EmptyDriver reports no items so GetAll()
// yields an empty map.
func newSubscription(tb testing.TB, ps *pubsub.PubSub, ctx interface{},
	srcAgent string, topicImpl interface{}) pubsub.Subscription {
	tb.Helper()
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   srcAgent,
		MyAgentName: agentName,
		TopicImpl:   topicImpl,
		Activate:    false,
		Ctx:         ctx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		tb.Fatalf("NewSubscription(%T): %v", topicImpl, err)
	}
	return sub
}

// newFuzzGetConfigCtx builds a getconfigContext populated with everything that
// parseConfig (and all of its callees) dereference, so that fuzzing the config
// parser exercises the actual parsing logic instead of crashing on nil pubsub
// handles, nil maps, the nil cipherCtx, or the nil localCmdAgent pointer. It
// returns the context together with the list of publications it created, so the
// caller can wipe accumulated state between fuzz iterations (see resetFuzzState).
//
// Publications/subscriptions are backed by pubsub.MemoryDriver. Most carry no
// data (nothing is published into them), but the MemoryDriver - unlike the
// EmptyDriver - lets us round-trip a few published items into a subscription,
// which is needed to seed subZbootStatus with a realistic current partition (see
// below).
//
// The context is built ONCE and reused across fuzz iterations. This is deliberate:
// NewLocalCmdAgent creates several flextimer range tickers, and each of those
// starts a background goroutine that is only stopped by the (never-called) task
// shutdown path. Rebuilding the context per iteration would therefore leak a
// handful of goroutines per call. Reuse is safe because Go's fuzzing engine
// invokes the fuzz target sequentially within a worker process (no concurrent
// calls), and resetFuzzState makes each iteration independent.
//
// The zedagentCtx.trigger* channels are left nil on purpose: every send to them is
// guarded by select/default, so a nil channel just skips the (parsing-irrelevant)
// info trigger. Likewise localCmdAgent's per-LPS-change ticker pokes go through
// flextimer.TickNow, which is itself a non-blocking select/default, so they never
// block even though no task goroutine is consuming the ticks here.
func newFuzzGetConfigCtx(tb testing.TB) (*getconfigContext, []pubsub.Publication) {
	tb.Helper()
	logger = logrus.StandardLogger()
	// Keep the fuzzer output quiet; parseConfig logs verbosely on bad input.
	logger.SetLevel(logrus.FatalLevel)
	log = base.NewSourceLogObject(logger, "zedagent", 1234)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	zedagentCtx := &zedagentContext{
		ps:                   ps,
		physicalIoAdapterMap: make(map[string]types.PhysicalIOAdapter),
		globalConfig:         *types.DefaultConfigItemValueMap(),
		specMap:              types.NewConfigItemSpecMap(),
		assignableAdapters:   &types.AssignableAdapters{},
		DevicePortConfigList: &types.DevicePortConfigList{},
	}
	getconfigCtx := &getconfigContext{
		zedagentCtx: zedagentCtx,
	}
	zedagentCtx.getconfigCtx = getconfigCtx
	// cipherCtx is dereferenced by handleControllerCertsSha / parseCipherContext.
	// Its trigger channels are left nil: every send is guarded by select/default.
	zedagentCtx.cipherCtx = &cipherContext{zedagentCtx: zedagentCtx}

	// Publications owned by zedagentContext.
	zedagentCtx.pubGlobalConfig = newPublication(tb, ps, types.ConfigItemValueMap{})
	zedagentCtx.pubMetricsMap = newPublication(tb, ps, types.MetricsMap{})
	zedagentCtx.pubEdgeNodeClusterConfig = newPublication(tb, ps, types.EdgeNodeClusterConfig{})

	// Publications owned by getconfigContext.
	getconfigCtx.pubZedAgentStatus = newPublication(tb, ps, types.ZedAgentStatus{})
	getconfigCtx.pubPhysicalIOAdapters = newPublication(tb, ps, types.PhysicalIOAdapterList{})
	getconfigCtx.pubSCEPProfile = newPublication(tb, ps, types.SCEPProfile{})
	getconfigCtx.pubDevicePortConfig = newPublication(tb, ps, types.DevicePortConfig{})
	getconfigCtx.pubNetworkXObjectConfig = newPublication(tb, ps, types.NetworkXObjectConfig{})
	getconfigCtx.pubNetworkInstanceConfig = newPublication(tb, ps, types.NetworkInstanceConfig{})
	getconfigCtx.pubAppInstanceConfig = newPublication(tb, ps, types.AppInstanceConfig{})
	getconfigCtx.pubAppNetworkConfig = newPublication(tb, ps, types.AppNetworkConfig{})
	getconfigCtx.pubBaseOsConfig = newPublication(tb, ps, types.BaseOsConfig{})
	getconfigCtx.pubDatastoreConfig = newPublication(tb, ps, types.DatastoreConfig{})
	getconfigCtx.pubLOCConfig = newPublication(tb, ps, types.LOCConfig{})
	getconfigCtx.pubCollectInfoCmd = newPublication(tb, ps, types.CollectInfoCmd{})
	getconfigCtx.pubControllerCert = newPublication(tb, ps, types.ControllerCert{})
	getconfigCtx.pubCipherContext = newPublication(tb, ps, types.CipherContext{})
	getconfigCtx.pubContentTreeConfig = newPublication(tb, ps, types.ContentTreeConfig{})
	getconfigCtx.pubVolumeConfig = newPublication(tb, ps, types.VolumeConfig{})
	getconfigCtx.pubDisksConfig = newPublication(tb, ps, types.EdgeNodeDisks{})
	getconfigCtx.pubEdgeNodeInfo = newPublication(tb, ps, types.EdgeNodeInfo{})
	getconfigCtx.pubPatchEnvelopeInfo = newPublication(tb, ps, types.PatchEnvelopeInfoList{})

	allPubs := []pubsub.Publication{
		zedagentCtx.pubGlobalConfig, zedagentCtx.pubMetricsMap,
		zedagentCtx.pubEdgeNodeClusterConfig,
		getconfigCtx.pubZedAgentStatus, getconfigCtx.pubPhysicalIOAdapters,
		getconfigCtx.pubSCEPProfile, getconfigCtx.pubDevicePortConfig,
		getconfigCtx.pubNetworkXObjectConfig, getconfigCtx.pubNetworkInstanceConfig,
		getconfigCtx.pubAppInstanceConfig, getconfigCtx.pubAppNetworkConfig,
		getconfigCtx.pubBaseOsConfig, getconfigCtx.pubDatastoreConfig,
		getconfigCtx.pubLOCConfig, getconfigCtx.pubCollectInfoCmd,
		getconfigCtx.pubControllerCert, getconfigCtx.pubCipherContext,
		getconfigCtx.pubContentTreeConfig, getconfigCtx.pubVolumeConfig,
		getconfigCtx.pubDisksConfig, getconfigCtx.pubEdgeNodeInfo,
		getconfigCtx.pubPatchEnvelopeInfo,
	}

	// Subscriptions read (via GetAll) by the parse path; empty is fine for these.
	getconfigCtx.subAppInstanceStatus = newSubscription(tb, ps, zedagentCtx,
		"zedmanager", types.AppInstanceStatus{})
	getconfigCtx.subContentTreeStatus = newSubscription(tb, ps, zedagentCtx,
		"volumemgr", types.ContentTreeStatus{})
	getconfigCtx.subVolumeStatus = newSubscription(tb, ps, zedagentCtx,
		"volumemgr", types.VolumeStatus{})

	// parseBaseOS reads subZbootStatus (via getZbootCurrentPartition /
	// getZbootPartitionStatus) and dereferences the returned *ZbootStatus. On a
	// real device baseosmgr always publishes the IMGA/IMGB partition statuses, so
	// seed the subscription with a realistic current partition; an empty one would
	// make getZbootPartitionStatus return nil and crash parseBaseOS. The statuses
	// are published and then loaded into the (persistent, activated) subscription
	// by the MemoryDriver - keyed by partition label, which is what Get() uses.
	zbootPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "baseosmgr",
		TopicType: types.ZbootStatus{},
	})
	if err != nil {
		tb.Fatalf("NewPublication(ZbootStatus): %v", err)
	}
	mustPublish(tb, zbootPub, "IMGA", types.ZbootStatus{
		PartitionLabel:   "IMGA",
		PartitionState:   "active",
		ShortVersion:     "0.0.0-fuzz",
		CurrentPartition: true,
	})
	mustPublish(tb, zbootPub, "IMGB", types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "inprogress",
		ShortVersion:   "0.0.0-other",
	})
	subZboot, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "baseosmgr",
		MyAgentName: agentName,
		TopicImpl:   types.ZbootStatus{},
		Persistent:  true, // so Activate() loads the published statuses via the driver
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		tb.Fatalf("NewSubscription(ZbootStatus): %v", err)
	}
	zedagentCtx.subZbootStatus = subZboot

	// parseConfig calls localCmdAgent.Pause()/UpdateLpsConfig()/IsAppRunningLps();
	// the field is a concrete *LocalCmdAgent, so it must be a real (initialized)
	// instance. ps satisfies the Watchdog interface and zedagentCtx the ConfigAgent
	// interface, mirroring the production wiring in zedagent.go.
	getconfigCtx.localCmdAgent = localcommand.NewLocalCmdAgent(
		localcommand.ConstructorArgs{
			Log:         log,
			Watchdog:    ps,
			ConfigAgent: zedagentCtx,
		})

	resetFuzzState(getconfigCtx, allPubs)
	return getconfigCtx, allPubs
}

// resetFuzzState makes a reused getconfigContext behave as if freshly built, so
// that each fuzz iteration is independent of the inputs that preceded it. Without
// this:
//   - published items would accumulate forever in the (in-memory) publications,
//     growing memory without bound over a long fuzzing campaign, and
//   - a single input carrying a far-future ConfigTimestamp would latch
//     lastConfigTimestamp, making every later input get rejected early as an
//     "obsolete configuration" and starving the rest of parseConfig of coverage.
//
// It also resets the maintenance-mode flags (recomputed from each config) and the
// package-level config-hash caches that gate re-parsing of individual sections.
func resetFuzzState(getconfigCtx *getconfigContext, allPubs []pubsub.Publication) {
	for _, pub := range allPubs {
		for key := range pub.GetAll() {
			_ = pub.Unpublish(key)
		}
	}

	getconfigCtx.lastConfigTimestamp = time.Time{}
	getconfigCtx.lastReceivedConfig = time.Time{}
	getconfigCtx.lastProcessedConfig = time.Time{}
	getconfigCtx.lastConfigSource = fromController

	getconfigCtx.zedagentCtx.apiMaintenanceMode = false
	getconfigCtx.zedagentCtx.maintenanceMode = false

	deviceIoListPrevConfigHash = nil
	bondsPrevConfigHash = nil
	vlansPrevConfigHash = nil
	networkConfigPrevConfigHash = nil
}

func FuzzParseConfig(f *testing.F) {
	getconfigCtx, allPubs := newFuzzGetConfigCtx(f)

	exampleConfigs := []*zconfig.EdgeDevConfig{
		{},
		{
			Id:                       &zconfig.UUIDandVersion{},
			Apps:                     []*zconfig.AppInstanceConfig{},
			Networks:                 []*zconfig.NetworkConfig{},
			Datastores:               []*zconfig.DatastoreConfig{},
			Base:                     []*zconfig.BaseOSConfig{},
			Reboot:                   &zconfig.DeviceOpsCmd{},
			Backup:                   &zconfig.DeviceOpsCmd{},
			ConfigItems:              []*zconfig.ConfigItem{},
			SystemAdapterList:        []*zconfig.SystemAdapter{},
			DeviceIoList:             []*zconfig.PhysicalIO{},
			Manufacturer:             "",
			ProductName:              "",
			NetworkInstances:         []*zconfig.NetworkInstanceConfig{},
			CipherContexts:           []*zcommon.CipherContext{},
			ContentInfo:              []*zconfig.ContentTree{},
			Volumes:                  []*zconfig.Volume{},
			ControllercertConfighash: "",
			MaintenanceMode:          false,
			ControllerEpoch:          0,
			Baseos:                   &zconfig.BaseOS{},
			GlobalProfile:            "",
			LocalProfileServer:       "",
			ProfileServerToken:       "",
			Vlans:                    []*zconfig.VlanAdapter{},
			Bonds:                    []*zconfig.BondAdapter{},
			Edgeview:                 &zconfig.EdgeViewConfig{},
			Disks:                    &zconfig.DisksConfig{},
			Shutdown:                 &zconfig.DeviceOpsCmd{},
			DeviceName:               "",
			ProjectName:              "",
			ProjectId:                "",
			EnterpriseName:           "",
			EnterpriseId:             "",
			ConfigTimestamp:          &timestamppb.Timestamp{},
			LocConfig:                &zconfig.LOCConfig{},
			PatchEnvelopes:           []*zconfig.EvePatchEnvelope{},
			Cluster:                  &zconfig.EdgeNodeCluster{},
			Pnacs:                    []*zconfig.PNAC{},
			ScepProfiles:             []*zconfig.SCEPProfile{},
		}}

	for _, exampleConfig := range exampleConfigs {
		exampleConfigJSON, err := marshalJSONIgnoreOmitEmpty(exampleConfig)
		if err != nil {
			f.Fatal(err)
		}

		f.Add(string(exampleConfigJSON), uint8(0))
	}
	f.Add("", uint8(0))

	f.Fuzz(func(t *testing.T, edgeDevJSON string, cs uint8) {
		config := &zconfig.EdgeDevConfig{}
		err := json.Unmarshal([]byte(edgeDevJSON), config)
		if err != nil {
			return
		}

		source := cs % uint8(civmOnly+1)

		resetFuzzState(getconfigCtx, allPubs)
		parseConfig(getconfigCtx, config, configSource(source))
	})
}

// TestParseConfigHarness validates that newFuzzGetConfigCtx mocks everything
// parseConfig needs: it drives a minimal but valid config through parseConfig for
// every configSource and asserts that none of them panics or hangs. The fuzzer
// itself cannot prove this, because it stops at the first crashing seed (currently
// an empty config, which trips a genuine nil-pointer bug in parseEdgeNodeInfo on
// config.GetId().Uuid). Setting a non-nil Id steers past that real bug so the
// remainder of the parse path - including localCmdAgent.UpdateLpsConfig and the
// per-section parsers - is exercised here deterministically.
func TestParseConfigHarness(t *testing.T) {
	getconfigCtx, allPubs := newFuzzGetConfigCtx(t)

	const deviceUUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	validID := &zconfig.UUIDandVersion{Uuid: deviceUUID, Version: "1"}

	configs := map[string]*zconfig.EdgeDevConfig{
		"minimal": {Id: validID},
		// Exercises localCmdAgent.UpdateLpsConfig's "LPS address changed" branch,
		// which fires the (non-blocking) ticker pokes.
		"with-lps": {Id: validID, LocalProfileServer: "192.0.2.1:8888", GlobalProfile: "prod"},
		// Toggles maintenance mode so mergeMaintenanceMode runs.
		"maint-mode": {Id: validID, MaintenanceMode: true},
		// Exercises parseBaseOS's populated path (getZbootCurrentPartition /
		// getZbootPartitionStatus), which reads subZbootStatus.
		"with-baseos": {Id: validID, Baseos: &zconfig.BaseOS{BaseOsVersion: "9.9.9", Activate: true}},
	}

	sources := []configSource{fromController, fromLOC, savedConfig, fromBootstrap, civmOnly}
	for name, config := range configs {
		for _, source := range sources {
			t.Run(fmt.Sprintf("%s/%v", name, source), func(t *testing.T) {
				resetFuzzState(getconfigCtx, allPubs)
				// A panic here is a harness gap (a missing mock) or a genuine
				// nil-deref in the parse code - either way the test fails loudly.
				parseConfig(getconfigCtx, config, source)
			})
		}
	}
}

// TestParseEdgeNodeClusterLB verifies that the LoadBalancerService is parsed
// into EdgeNodeClusterConfig.LBInterfaces exactly when native k8s orchestration
// is enabled: always for K3S_BASE, and for REPLICATED_STORAGE only when the
// enable_native_k8s_orchestration flag is set.
func TestParseEdgeNodeClusterLB(t *testing.T) {
	g := NewGomegaWithT(t)
	getconfigCtx, allPubs := newFuzzGetConfigCtx(t)

	const clusterID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	lbSvc := &zconfig.LoadBalancerService{
		Interfaces: []*zconfig.LoadBalancerInterface{
			{InterfaceName: "eth1", AddressCidrs: []string{"192.168.1.24/29"}},
		},
	}

	cases := []struct {
		name        string
		clusterType zconfig.ClusterType
		flag        bool
		wantLB      bool
	}{
		{"k3s-base populates LB", zconfig.ClusterType_CLUSTER_TYPE_K3S_BASE, false, true},
		{"replicated-storage without flag drops LB", zconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE, false, false},
		{"replicated-storage with flag populates LB", zconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetFuzzState(getconfigCtx, allPubs)
			devConfig := &zconfig.EdgeDevConfig{
				Cluster: &zconfig.EdgeNodeCluster{
					ClusterId:                    clusterID,
					ClusterIpPrefix:              "10.0.0.1/24",
					JoinServerIp:                 "10.0.0.1",
					ClusterType:                  tc.clusterType,
					EnableNativeK8SOrchestration: tc.flag,
					LoadBalancerService:          lbSvc,
				},
			}
			parseEdgeNodeClusterConfig(getconfigCtx, devConfig)

			item, err := getconfigCtx.zedagentCtx.pubEdgeNodeClusterConfig.Get("global")
			g.Expect(err).ToNot(HaveOccurred())
			cfg := item.(types.EdgeNodeClusterConfig)
			g.Expect(cfg.Valid).To(BeTrue())
			g.Expect(cfg.EnableNativeK8SOrchestration).To(Equal(tc.flag))
			if tc.wantLB {
				g.Expect(cfg.LBInterfaces).To(HaveLen(1))
				g.Expect(cfg.LBInterfaces[0].Interface).To(Equal("eth1"))
				g.Expect(cfg.LBInterfaces[0].IPPrefix).To(Equal("192.168.1.24/29"))
			} else {
				g.Expect(cfg.LBInterfaces).To(BeEmpty())
			}
		})
	}
}

// marshalJSONIgnoreOmitEmpty marshals an EdgeDevConfig to JSON like encoding/json would, except
// that it ignores the ",omitempty" option on the (top-level) struct fields, so
// zero-valued fields are emitted instead of dropped. This produces a "fat" JSON
// document naming every top-level field, which is useful as a FuzzParseConfig seed.
//
// It works by rebuilding the struct type with the omitempty option stripped from
// each json tag and marshaling a value converted to that type. Note this only
// strips omitempty at the top level; fields of nested messages keep theirs.
func marshalJSONIgnoreOmitEmpty(u *config.EdgeDevConfig) ([]byte, error) {
	// Dereference through the pointer with Elem() rather than copying via
	// reflect.ValueOf(*u): EdgeDevConfig embeds a sync.Mutex and must not be copied.
	value := reflect.ValueOf(u).Elem()
	t := value.Type()
	fields := make([]reflect.StructField, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if jsonTag, ok := field.Tag.Lookup("json"); ok {
			// Keep just the json name, dropping ",omitempty" (and any other
			// options) so the field is always emitted.
			name, _, _ := strings.Cut(jsonTag, ",")
			field.Tag = reflect.StructTag(fmt.Sprintf(`json:"%s"`, name))
		}
		fields[i] = field
	}
	newType := reflect.StructOf(fields)
	return json.Marshal(value.Convert(newType).Interface())
}
