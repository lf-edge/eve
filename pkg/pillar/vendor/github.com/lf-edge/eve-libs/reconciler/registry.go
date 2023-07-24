// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"fmt"

	"github.com/lf-edge/eve-libs/depgraph"
)

// DefaultRegistry implements ConfiguratorRegistry.
// It maps configurators to items based on item types, i.e. one Configurator for each
// item type (excluding external items).
type DefaultRegistry struct {
	reg map[string]Configurator
}

// Register configurator for a given item type.
func (r *DefaultRegistry) Register(configurator Configurator, itemType string) error {
	if r.reg == nil {
		r.reg = make(map[string]Configurator)
	}
	if _, exists := r.reg[itemType]; exists {
		return fmt.Errorf("configurator is already registered for item type: %s",
			itemType)
	}
	r.reg[itemType] = configurator
	return nil
}

// GetConfigurator returns configurator registered for the given item.
// Returns nil if there is no configurator registered.
func (r *DefaultRegistry) GetConfigurator(item depgraph.Item) Configurator {
	return r.reg[item.Type()]
}
