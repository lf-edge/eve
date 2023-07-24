// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// Wwan : WWAN (LTE) configuration (read by wwan microservice).
// This is a singleton item, grouping configuration for all LTE modems on the device.
type Wwan struct {
	Config types.WwanConfig
}

// Name returns the full path to the wwan config file.
func (w Wwan) Name() string {
	return devicenetwork.WwanConfigPath
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
	w2 := other.(Wwan)
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

// Dependencies lists every adapter referenced from the wwan config
// as a dependency.
func (w Wwan) Dependencies() (deps []depgraph.Dependency) {
	for _, network := range w.Config.Networks {
		if network.PhysAddrs.Interface == "" {
			continue
		}
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: AdapterTypename,
				ItemName: network.PhysAddrs.Interface,
			},
			Description: "The referenced (LTE) adapter must exist",
		})
	}
	return deps
}

// WwanConfigurator implements Configurator interface (libs/reconciler) for WWAN config.
type WwanConfigurator struct {
	Log *base.LogObject
	// LastChecksum : checksum of the last written wwan configuration.
	LastChecksum string
}

// Create writes config for wwan microservice.
func (c *WwanConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	wwan := item.(Wwan)
	return c.installWwanConfig(wwan.Config)
}

// Modify writes updated config for wwan microservice.
func (c *WwanConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	wwan := newItem.(Wwan)
	return c.installWwanConfig(wwan.Config)
}

// Delete writes empty config for wwan microservice.
func (c *WwanConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	return c.installWwanConfig(types.WwanConfig{})
}

// NeedsRecreate returns false - Modify can apply any change.
func (c *WwanConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}

// Write cellular config into /run/wwan/config.json
func (c *WwanConfigurator) installWwanConfig(config types.WwanConfig) (err error) {
	bytes, hash, err := MarshalWwanConfig(config)
	if err != nil {
		c.Log.Error(err)
		return err
	}
	err = fileutils.WriteRename(devicenetwork.WwanConfigPath, bytes)
	if err != nil {
		c.Log.Error(err)
		return err
	}
	c.LastChecksum = hash
	return nil
}

// MarshalWwanConfig is exposed only for unit-testing purposes.
func MarshalWwanConfig(config types.WwanConfig) (bytes []byte, hash string, err error) {
	bytes, err = json.MarshalIndent(config, "", "    ")
	if err != nil {
		err = fmt.Errorf("failed to serialize wwan config: %w", err)
		return nil, "", err
	}
	shaHash := sha256.Sum256(bytes)
	hash = hex.EncodeToString(shaHash[:])
	return bytes, hash, err
}
