// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"fmt"
	"strings"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	log "github.com/sirupsen/logrus"
)

// IptablesChain : single iptables chain.
type IptablesChain struct {
	// NetNamespace : network namespace where the chain should be created.
	NetNamespace string
	ChainName    string
	Table        string
	ForIPv6      bool
	Rules        []IptablesRule
	// RefersChains : names of chains referred from rules.
	// We could probably extract this from IptablesRule.Args, but let's keep things
	// simple and not dive into the iptables semantics too much.
	RefersChains []string
	// RefersVeths : names of VETH interfaces referred from rules.
	RefersVeths []string
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

func equalRules(r1, r2 IptablesRule) bool {
	return generics.EqualLists(r1.Args, r2.Args) &&
		r1.Description == r2.Description
}

// Name returns the name of the iptables chain item.
func (ch IptablesChain) Name() string {
	return fmt.Sprintf("%s/%s/%s",
		normNetNsName(ch.NetNamespace), ch.Table, ch.ChainName)
}

// Label returns the label of the iptables chain item.
func (ch IptablesChain) Label() string {
	return fmt.Sprintf("%s (%s chain)", ch.Name(), ch.command())
}

// Type returns the typename of the iptables chain item.
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
	return generics.EqualListsFn(ch.Rules, ch2.Rules, equalRules)
}

// External returns false.
func (ch IptablesChain) External() bool {
	return false
}

// String describes content of iptables chain.
func (ch IptablesChain) String() string {
	str := fmt.Sprintf("%s chain %s in ns %s for table %s with rules:",
		ch.command(), ch.ChainName, normNetNsName(ch.NetNamespace), ch.table())
	for _, rule := range ch.Rules {
		str += fmt.Sprintf("\n  *  %s", strings.Join(rule.Args, " "))
		if rule.Description != "" {
			str += fmt.Sprintf("\n     (%s)", rule.Description)
		}
	}
	return str
}

// Dependencies lists all referenced chains + net namespace as dependencies.
func (ch IptablesChain) Dependencies() (deps []depgraph.Dependency) {
	for _, referredChain := range ch.RefersChains {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.Reference(IptablesChain{
				ChainName:    referredChain,
				NetNamespace: ch.NetNamespace,
				Table:        ch.Table,
				ForIPv6:      ch.ForIPv6,
			}),
		})
	}
	for _, referredVeth := range ch.RefersVeths {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: VethTypename,
				ItemName: referredVeth,
			},
			Description: "veth interface must exist",
		})
	}
	deps = append(deps, depgraph.Dependency{
		RequiredItem: depgraph.ItemRef{
			ItemType: NetNamespaceTypename,
			ItemName: normNetNsName(ch.NetNamespace),
		},
		Description: "Network namespace must exist",
	})
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

// IptablesChainConfigurator implements Configurator interface for both iptables
// and ip6tables chains.
type IptablesChainConfigurator struct{}

// Create creates and populates ip(6)tables chain.
func (c *IptablesChainConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	chain := item.(IptablesChain)
	// Create the chain first.
	// Even if it is marked as PreCreated make sure that it actually exists.
	if chain.customChain() {
		args := []string{"-N", chain.ChainName, "-t", chain.Table}
		out, err := namespacedCmd(chain.NetNamespace, chain.command(), args...).CombinedOutput()
		if err != nil && !chain.PreCreated {
			err = fmt.Errorf("failed to create iptables chain: %v, output: %s",
				err, out)
			log.Error(err)
			return err
		}
	}
	// Make sure we start with empty content.
	args := []string{"-F", chain.ChainName, "-t", chain.Table}
	out, err := namespacedCmd(chain.NetNamespace, chain.command(), args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to flush the iptables chain: %v, output: %s",
			err, out)
		log.Error(err)
		return err
	}
	// Add rules one by one.
	for _, rule := range chain.Rules {
		args := []string{"-A", chain.ChainName, "-t", chain.Table}
		args = append(args, rule.Args...)
		out, err := namespacedCmd(chain.NetNamespace, chain.command(), args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to add iptables rule: %v, output: %s",
				err, out)
			log.Error(err)
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
	out, err := namespacedCmd(chain.NetNamespace, chain.command(), args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to flush the iptables chain: %v, output: %s",
			err, out)
		log.Error(err)
		return err
	}
	// Add rules one by one.
	for _, rule := range chain.Rules {
		args := []string{"-A", chain.ChainName, "-t", chain.Table}
		args = append(args, rule.Args...)
		out, err := namespacedCmd(chain.NetNamespace, chain.command(), args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to add iptables rule: %v, output: %s",
				err, out)
			log.Error(err)
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
	out, err := namespacedCmd(chain.NetNamespace, chain.command(), args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to flush the iptables chain: %v, output: %s",
			err, out)
		log.Error(err)
		return err
	}
	// Delete the chain if it is a custom one and not pre-created.
	if chain.customChain() && !chain.PreCreated {
		args = []string{"-X", chain.ChainName, "-t", chain.Table}
		out, err = namespacedCmd(chain.NetNamespace, chain.command(), args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to delete the iptables chain: %v, output: %s",
				err, out)
			log.Error(err)
			return err
		}
	}
	return nil
}

// NeedsRecreate returns false - configurator is able to modify the chain content.
func (c *IptablesChainConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}
