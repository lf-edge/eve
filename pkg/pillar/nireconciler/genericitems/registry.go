// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

// RegisterItems : register all configurators implemented by this package.
func RegisterItems(log *base.LogObject, logger *logrus.Logger,
	registry *reconciler.DefaultRegistry) error {
	type configurator struct {
		c reconciler.Configurator
		t string
	}
	configurators := []configurator{
		{c: &DnsmasqConfigurator{Log: log, Logger: logger}, t: DnsmasqTypename},
		{c: &HTTPServerConfigurator{Log: log, Logger: logger}, t: HTTPServerTypename},
		{c: &RadvdConfigurator{Log: log}, t: RadvdTypename},
	}
	for _, configurator := range configurators {
		err := registry.Register(configurator.c, configurator.t)
		if err != nil {
			return err
		}
	}
	return nil
}
