// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	pubsubWwanKey = "global"
)

// Wwan : WWAN (LTE) configuration (read by wwan microservice).
// This is a singleton item, grouping configuration for all LTE modems on the device.
type Wwan struct {
	Config types.WwanConfig
}

// Name returns the key under which the WWAN config is published through pubsub.
func (w Wwan) Name() string {
	return pubsubWwanKey
}

// Label is not defined.
func (w Wwan) Label() string {
	return ""
}

// Type of the item.
func (w Wwan) Type() string {
	return WwanTypename
}

// Equal compares two WWAN configs.
func (w Wwan) Equal(other depgraph.Item) bool {
	w2, isWwan := other.(Wwan)
	if !isWwan {
		return false
	}
	return w.Config.Equal(w2.Config)
}

// External is false.
func (w Wwan) External() bool {
	return false
}

// String describes wwan config.
func (w Wwan) String() string {
	return fmt.Sprintf("WWAN configuration: %+v", w.Config)
}

// Dependencies return empty list - wwan config can be published even before
// the referenced wwanX interface(s) are ready (the wwan microservice can deal with it).
func (w Wwan) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

// WwanConfigurator implements Configurator interface (libs/reconciler) for WWAN config.
type WwanConfigurator struct {
	Log           *base.LogObject
	PubWwanConfig pubsub.Publication
}

// Create publishes config for wwan microservice.
func (c *WwanConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	wwan, isWwan := item.(Wwan)
	if !isWwan {
		return errors.New("unexpected item type")
	}
	return c.publishWwanConfig(wwan.Config)
}

// Modify publishes updated config for wwan microservice.
func (c *WwanConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	wwan, isWwan := newItem.(Wwan)
	if !isWwan {
		return errors.New("unexpected item type")
	}
	return c.publishWwanConfig(wwan.Config)
}

// Delete publishes empty config for wwan microservice.
func (c *WwanConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	return c.publishWwanConfig(types.WwanConfig{})
}

// NeedsRecreate returns false - Modify can apply any change.
func (c *WwanConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}

// Publish cellular config to wwan microservice via pubsub.
func (c *WwanConfigurator) publishWwanConfig(config types.WwanConfig) (err error) {
	return c.PubWwanConfig.Publish(pubsubWwanKey, config)
}
