// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
)

// RegisterItems : register all configurators implemented by this package.
func RegisterItems(
	registry *reconciler.DefaultRegistry, macLookup *maclookup.MacLookup,
	pnacEventWatcherCh chan<- PNACEvent) error {
	type configurator struct {
		c reconciler.Configurator
		t string
	}
	configurators := []configurator{
		{c: &SysctlConfigurator{}, t: SysctlTypename},
		{c: &NetNamespaceConfigurator{}, t: NetNamespaceTypename},
		{c: &IfHandleConfigurator{MacLookup: macLookup}, t: IfHandleTypename},
		{c: &DhcpClientConfigurator{MacLookup: macLookup}, t: DhcpClientTypename},
		{c: &DhcpServerConfigurator{}, t: DhcpServerTypename},
		{c: &DNSServerConfigurator{}, t: DNSServerTypename},
		{c: &BondConfigurator{MacLookup: macLookup}, t: BondTypename},
		{c: &BridgeConfigurator{MacLookup: macLookup}, t: BridgeTypename},
		{c: &VethConfigurator{}, t: VethTypename},
		{c: &RouteConfigurator{MacLookup: macLookup}, t: RouteTypename},
		{c: &IPRuleConfigurator{}, t: IPRuleTypename},
		{c: &IptablesChainConfigurator{}, t: IPtablesChainTypename},
		{c: &IptablesChainConfigurator{}, t: IP6tablesChainTypename},
		{c: &HTTPProxyConfigurator{}, t: HTTPProxyTypename},
		{c: &HTTPServerConfigurator{}, t: HTTPServerTypename},
		{c: &TrafficControlConfigurator{MacLookup: macLookup}, t: TrafficControlTypename},
		{c: &RadvdConfigurator{}, t: RadvdTypename},
		{c: &TunConfigurator{}, t: TunTypename},
		{c: &SCEPServerConfigurator{}, t: SCEPServerTypename},
		{c: &HostapdConfigurator{
			PNACEventPublishCh: pnacEventWatcherCh}, t: HostapdTypename},
	}
	for _, configurator := range configurators {
		err := registry.Register(configurator.c, configurator.t)
		if err != nil {
			return err
		}
	}
	return nil
}
