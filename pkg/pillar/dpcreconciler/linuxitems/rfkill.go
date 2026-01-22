// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// RFKill (radio frequency kill) is a singleton representing the Linux rfkill subsystem.
// In EVE, it is primarily used to enable or disable radio transmission for Wi-Fi devices.
//
// Note that Wi-Fi radio control is global: unlike cellular modems, RF transmission
// cannot be controlled per adapter. All Wi-Fi adapters are either enabled or disabled
// together. As a result, when radio silence is disabled, all Wi-Fi adapters will be
// enabled, even if only a subset of them is configured.
type RFKill struct {
	// EnableWlanRF enables or disables radio transmission for all Wi-Fi devices.
	EnableWlanRF bool
}

// Name returns the fixed identifier "rfkill".
// This is a singleton item, so the name is constant.
func (r RFKill) Name() string {
	return "rfkill"
}

// Label is not defined.
func (r RFKill) Label() string {
	return ""
}

// Type of the item.
func (r RFKill) Type() string {
	return RFKillTypename
}

// Equal compares two instances of RFKill for equality.
func (r RFKill) Equal(other depgraph.Item) bool {
	r2, isRFKill := other.(RFKill)
	if !isRFKill {
		return false
	}
	return r.EnableWlanRF == r2.EnableWlanRF
}

// External returns false.
func (r RFKill) External() bool {
	return false
}

// String describes the rfkill config.
func (r RFKill) String() string {
	return fmt.Sprintf("Enable WLAN RF: %t", r.EnableWlanRF)
}

// Dependencies returns nothing.
func (r RFKill) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

// RFKillConfigurator implements Configurator interface (libs/reconciler) for RFKill.
type RFKillConfigurator struct {
	Log *base.LogObject
}

// Create applies the rfkill config.
func (c *RFKillConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	rfkill, isRFKill := item.(RFKill)
	if !isRFKill {
		err := fmt.Errorf("invalid item type: %T (expected RFKill)", item)
		c.Log.Error(err)
		return err
	}
	err := c.toggleRF("wlan", rfkill.EnableWlanRF)
	if err != nil {
		c.Log.Error(err)
		return err
	}
	return nil
}

// Modify applies modified rfkill config.
func (c *RFKillConfigurator) Modify(ctx context.Context,
	oldItem, newItem depgraph.Item) error {
	rfkill, isRFKill := newItem.(RFKill)
	if !isRFKill {
		err := fmt.Errorf("invalid item type: %T (expected RFKill)", newItem)
		c.Log.Error(err)
		return err
	}
	err := c.toggleRF("wlan", rfkill.EnableWlanRF)
	if err != nil {
		c.Log.Error(err)
		return err
	}
	return nil
}

// Enable or disable radio transmission.
func (c *RFKillConfigurator) toggleRF(devType string, enableRF bool) error {
	op := "block"
	if enableRF {
		op = "un" + op
	}
	args := []string{op, devType}
	c.Log.Noticef("Running rfkill %v", args)
	out, err := base.Exec(c.Log, "rfkill", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("'rfkill %s' command failed with err=%v, output=%s",
			strings.Join(args, " "), err, out)
	}
	return nil
}

// Delete always returns error.
// NIM never removes RFKill config item.
func (c *RFKillConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	return errors.New("not implemented")
}

// NeedsRecreate returns false - Modify is able to apply any change.
func (c *RFKillConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}
