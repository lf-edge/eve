// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// RegisterItems : register all configurators implemented by this package.
func RegisterItems(log *base.LogObject, registry *reconciler.DefaultRegistry,
	pubWwanConfig pubsub.Publication) error {
	type configurator struct {
		c reconciler.Configurator
		t string
	}
	configurators := []configurator{
		{c: &IOHandleConfigurator{Log: log}, t: IOHandleTypename},
		{c: &DhcpcdConfigurator{Log: log}, t: DhcpcdTypename},
		{c: &ResolvConfConfigurator{Log: log}, t: ResolvConfTypename},
		{c: &SSHAuthKeysConfigurator{Log: log}, t: SSHAuthKeysTypename},
		{c: &WwanConfigurator{Log: log, PubWwanConfig: pubWwanConfig}, t: WwanTypename},
	}
	for _, configurator := range configurators {
		err := registry.Register(configurator.c, configurator.t)
		if err != nil {
			return err
		}
	}
	return nil
}
