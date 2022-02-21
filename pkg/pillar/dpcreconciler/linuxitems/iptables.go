// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// IptablesChain : single iptables chain.
type IptablesChain struct {
	ChainName string
	Table     string
	ForIPv6   bool
	Rules     []IptablesRule
	// RefersChains : names of chains referred from rules.
	// We could probably extract this from IptablesRule.Args, but let's keep things
	// simple and not dive into the iptables semantics too much.
	RefersChains []string
	// PreCreated : a custom chain which already exists (as empty).
	PreCreated bool
}

// IptablesRule : single iptables rule.
type IptablesRule struct {
	// Args : any arguments except for -t, -A, -D, -I, -R.
	Args []string
	// Description : optionally describe the rule.
	Description string
}

// Name returns unique identifier for an iptables chain.
func (ch IptablesChain) Name() string {
	return fmt.Sprintf("%s/%s", ch.Table, ch.ChainName)
}

// Label is not defined.
func (ch IptablesChain) Label() string {
	return ""
}

// Type of the item.
// We use the same structure for both IPv4 and IPv6 iptables.
func (ch IptablesChain) Type() string {
	if ch.ForIPv6 {
		return IP6tablesChainTypename
	}
	return IPtablesChainTypename
}

// Equal compares content of two instances of the same iptables chain.
func (ch IptablesChain) Equal(other depgraph.Item) bool {
	ch2 := other.(IptablesChain)
	// If rules are equal than surely RefersChains are equal.
	// "PreCreated" is also not compared as it makes no sense to change it.
	return reflect.DeepEqual(ch.Rules, ch2.Rules)
}

// External returns false.
func (ch IptablesChain) External() bool {
	return false
}

// String describes content of iptables chain.
func (ch IptablesChain) String() string {
	str := fmt.Sprintf("%s chain %s for table %s with rules:",
		ch.command(), ch.ChainName, ch.table())
	for _, rule := range ch.Rules {
		str += fmt.Sprintf("\n  *  %s", strings.Join(rule.Args, " "))
		if rule.Description != "" {
			str += fmt.Sprintf("\n     (%s)", rule.Description)
		}
	}
	return str
}

// Dependencies lists all referenced chains as dependencies.
func (ch IptablesChain) Dependencies() (deps []depgraph.Dependency) {
	for _, referredChain := range ch.RefersChains {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.Reference(IptablesChain{
				ChainName: referredChain,
				Table:     ch.Table,
				ForIPv6:   ch.ForIPv6,
			}),
		})
	}
	return deps
}

func (ch IptablesChain) command() string {
	cmd := "iptables"
	if ch.ForIPv6 {
		cmd = "ip6tables"
	}
	return cmd
}

func (ch IptablesChain) table() string {
	table := "filter"
	if ch.Table != "" {
		table = ch.Table
	}
	return table
}

func (ch IptablesChain) customChain() bool {
	return ch.ChainName != "INPUT" &&
		ch.ChainName != "OUTPUT" &&
		ch.ChainName != "FORWARD" &&
		ch.ChainName != "PREROUTING" &&
		ch.ChainName != "POSTROUTING"
}

// IptablesChainConfigurator implements Configurator interface (libs/reconciler)
// for both iptables and ip6tables chains.
type IptablesChainConfigurator struct {
	Log *base.LogObject
}

// Create creates and populates ip(6)tables chain.
func (c *IptablesChainConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	chain := item.(IptablesChain)
	// Create the chain first.
	// Even if it is marked as PreCreated make sure that it actually exists.
	if chain.customChain() {
		args := []string{"-N", chain.ChainName, "-t", chain.Table}
		out, err := base.Exec(c.Log, chain.command(), args...).CombinedOutput()
		if err != nil && !chain.PreCreated {
			err = fmt.Errorf("failed to create iptables chain: %v, output: %s",
				err, out)
			c.Log.Error(err)
			return err
		}
	}
	// Make sure we start with empty content.
	args := []string{"-F", chain.ChainName, "-t", chain.Table}
	out, err := base.Exec(c.Log, chain.command(), args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to flush the iptables chain: %v, output: %s",
			err, out)
		c.Log.Error(err)
		return err
	}
	// Add rules one by one.
	for _, rule := range chain.Rules {
		args := []string{"-A", chain.ChainName, "-t", chain.Table}
		args = append(args, rule.Args...)
		out, err := base.Exec(c.Log, chain.command(), args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to add iptables rule: %v, output: %s",
				err, out)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Modify rules by recreating them.
// But do not re-create the entire chain, that would recreate everything that depends on it.
func (c *IptablesChainConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	chain := newItem.(IptablesChain)
	// Flush the old content first.
	args := []string{"-F", chain.ChainName, "-t", chain.Table}
	out, err := base.Exec(c.Log, chain.command(), args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to flush the iptables chain: %v, output: %s",
			err, out)
		c.Log.Error(err)
		return err
	}
	// Add rules one by one.
	for _, rule := range chain.Rules {
		args := []string{"-A", chain.ChainName, "-t", chain.Table}
		args = append(args, rule.Args...)
		out, err := base.Exec(c.Log, chain.command(), args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to add iptables rule: %v, output: %s",
				err, out)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Delete flushes the chain content and removes it unless it is a pre-created chain.
func (c *IptablesChainConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	chain := item.(IptablesChain)
	// Flush the old content first.
	args := []string{"-F", chain.ChainName, "-t", chain.Table}
	out, err := base.Exec(c.Log, chain.command(), args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to flush the iptables chain: %v, output: %s",
			err, out)
		c.Log.Error(err)
		return err
	}
	// Delete the chain if it is a custom one and not pre-created.
	if chain.customChain() && !chain.PreCreated {
		args = []string{"-X", chain.ChainName, "-t", chain.Table}
		out, err = base.Exec(c.Log, chain.command(), args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to delete the iptables chain: %v, output: %s",
				err, out)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// NeedsRecreate returns false - configurator is able to modify the chain content.
func (c *IptablesChainConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}
