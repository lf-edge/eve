// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
)

// RegisterItems : register all configurators implemented by this package.
func RegisterItems(log *base.LogObject, registry *reconciler.DefaultRegistry,
	monitor netmonitor.NetworkMonitor) error {
	type configurator struct {
		c reconciler.Configurator
		t string
	}
	configurators := []configurator{
		{c: &AdapterConfigurator{Log: log, NetworkMonitor: monitor}, t: genericitems.AdapterTypename},
		{c: &ArpConfigurator{Log: log}, t: genericitems.ArpTypename},
		{c: &BondConfigurator{Log: log, NetworkMonitor: monitor}, t: genericitems.BondTypename},
		{c: &LocalIPRuleConfigurator{Log: log}, t: LocalIPRuleTypename},
		{c: &RouteConfigurator{Log: log}, t: genericitems.IPv4RouteTypename},
		{c: &RouteConfigurator{Log: log}, t: genericitems.IPv6RouteTypename},
		{c: &SrcIPRuleConfigurator{Log: log, NetworkMonitor: monitor}, t: SrcIPRuleTypename},
		{c: &VlanConfigurator{Log: log, NetworkMonitor: monitor}, t: genericitems.VlanTypename},
		{c: &WlanConfigurator{Log: log}, t: genericitems.WlanTypename},
	}
	for _, configurator := range configurators {
		err := registry.Register(configurator.c, configurator.t)
		if err != nil {
			return err
		}
	}
	return nil
}
