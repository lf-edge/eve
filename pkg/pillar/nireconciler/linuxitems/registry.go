// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
)

// RegisterItems : register all configurators implemented by this package.
func RegisterItems(log *base.LogObject, registry *reconciler.DefaultRegistry,
	monitor netmonitor.NetworkMonitor) error {
	type configurator struct {
		c reconciler.Configurator
		t string
	}
	configurators := []configurator{
		{c: &BridgeConfigurator{Log: log}, t: BridgeTypename},
		{c: &BridgePortConfigurator{Log: log}, t: BridgePortTypename},
		{c: &DummyIfConfigurator{Log: log}, t: DummyIfTypename},
		{c: &IPRuleConfigurator{Log: log}, t: IPRuleTypename},
		{c: &IPSetConfigurator{Log: log}, t: generic.IPSetTypename},
		{c: &RouteConfigurator{Log: log, NetworkMonitor: monitor}, t: generic.IPv4RouteTypename},
		{c: &RouteConfigurator{Log: log, NetworkMonitor: monitor}, t: generic.IPv6RouteTypename},
		{c: &VLANBridgeConfigurator{Log: log, NetworkMonitor: monitor}, t: VLANBridgeTypename},
		{c: &VLANPortConfigurator{Log: log, NetworkMonitor: monitor}, t: VLANPortTypename},
		{c: &SysctlConfigurator{Log: log}, t: SysctlTypename},
		{c: &VIFConfigurator{Log: log}, t: VIFTypename},
	}
	for _, configurator := range configurators {
		err := registry.Register(configurator.c, configurator.t)
		if err != nil {
			return err
		}
	}
	return nil
}
