// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package iptables

// This Go file implements Items (libs/depgraph) and Configurators (libs/reconciler)
// to be used for the reconciliation of the iptables configuration.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils"
)

const (
	// ChainV4Typename : typename for a single iptables chain (IPv4).
	ChainV4Typename = "Iptables-Chain"
	// ChainV6Typename : typename for a single ip6tables chain (IPv6).
	ChainV6Typename = "Ip6tables-Chain"
	// RuleV4Typename : typename for a single iptables rule (IPv4).
	RuleV4Typename = "Iptables-Rule"
	// RuleV6Typename : typename for a single ip6tables rule (IPv6).
	RuleV6Typename = "Ip6tables-Rule"
)

var (
	// Used as a constant.
	builtinChains = []string{"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}
	// Used as a constant.
	builtinTargets = []string{"ACCEPT", "DROP", "REJECT", "LOG", "DNAT", "SNAT",
		"MASQUERADE", "CONNMARK", "MARK"}
)

// RegisterItems : add Items and their Configurators into the provided registry.
func RegisterItems(log *base.LogObject, registry *reconciler.DefaultRegistry) error {
	type configurator struct {
		c reconciler.Configurator
		t string
	}
	configurators := []configurator{
		{c: &ChainConfigurator{Log: log}, t: ChainV4Typename},
		{c: &ChainConfigurator{Log: log}, t: ChainV6Typename},
		{c: &RuleConfigurator{Log: log}, t: RuleV4Typename},
		{c: &RuleConfigurator{Log: log}, t: RuleV6Typename},
	}
	for _, configurator := range configurators {
		err := registry.Register(configurator.c, configurator.t)
		if err != nil {
			return err
		}
	}
	return nil
}

// Chain : single iptables chain.
// This structure implements Item interface (libs/depgraph) and is used as the input
// to ChainConfigurator.
// This structure just represents the chain itself, while the rules inside are instances
// of the Rule struct (see below).
type Chain struct {
	ChainName string
	// Table is one of: raw, filter, nat, mangle, security.
	Table   string
	ForIPv6 bool
	// PreCreated : a custom chain which already exists (as empty).
	PreCreated bool
}

// Name returns unique identifier for an iptables chain.
func (ch Chain) Name() string {
	return fmt.Sprintf("%s/%s", ch.Table, ch.ChainName)
}

// Label is not defined.
func (ch Chain) Label() string {
	return ""
}

// Type of the item.
// We use the same structure for both IPv4 and IPv6 iptables chains.
func (ch Chain) Type() string {
	if ch.ForIPv6 {
		return ChainV6Typename
	}
	return ChainV4Typename
}

// Equal compares two iptables chains.
func (ch Chain) Equal(other depgraph.Item) bool {
	ch2, isChain := other.(Chain)
	if !isChain {
		return false
	}
	return ch == ch2
}

// External returns true if the chain is created outside ChainConfigurator.
func (ch Chain) External() bool {
	return !ch.customChain() || ch.PreCreated
}

// String describes iptables chain.
func (ch Chain) String() string {
	return fmt.Sprintf("%s chain %s for table %s ",
		ch.command(), ch.ChainName, ch.Table)
}

// Dependencies returns empty set.
func (ch Chain) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

func (ch Chain) command() string {
	cmd := iptablesCmd
	if ch.ForIPv6 {
		cmd = ip6tablesCmd
	}
	return cmd
}

func (ch Chain) customChain() bool {
	for _, builtin := range builtinChains {
		if ch.ChainName == builtin {
			return false
		}
	}
	return true
}

// Rule : single iptables rule.
// This structure implements Item interface (libs/depgraph) and is used as the input
// to RuleConfigurator.
type Rule struct {
	// RuleLabel is a mandatory argument.
	// It should be unique within the destination chain (Table/ChainName).
	RuleLabel string
	// Table : name of the table where this rule belongs to.
	Table string
	// ChainName : name of the chain where the rule is inserted into.
	ChainName string
	// ForIPv6 : if true this rule is submitted using ip6tables.
	ForIPv6 bool
	// AppliedBefore : List or RuleLabel-s of rules that should be inserted BELOW this
	// rule in the destination chain (Table/ChainName).
	AppliedBefore []string
	// MatchOpts : options to select the traffic for which this rule applies.
	// For example: {"-p", "80", "d", "192.168.1.1"}
	MatchOpts []string
	// Target is either a chain or a well-known action like ACCEPT, DROP, REJECT, etc.
	Target string
	// TargetOpts : options to further clarify how to apply the Target.
	// For example: {"--reject-with", "tcp-reset"}
	TargetOpts []string
	// Description : optionally describe the rule.
	Description string
}

// Name returns unique identifier for an iptables rule.
func (r Rule) Name() string {
	label := strings.ReplaceAll(r.RuleLabel, " ", "-")
	return fmt.Sprintf("%s/%s/%s", r.Table, r.ChainName, label)
}

// Label returns RuleLabel.
func (r Rule) Label() string {
	return r.RuleLabel
}

// Type of the item.
// We use the same structure for both IPv4 and IPv6 iptables rules.
func (r Rule) Type() string {
	if r.ForIPv6 {
		return RuleV6Typename
	}
	return RuleV4Typename
}

// Equal compares two iptables rules.
func (r Rule) Equal(other depgraph.Item) bool {
	r2, isRule := other.(Rule)
	if !isRule {
		return false
	}
	return r.RuleLabel == r2.RuleLabel &&
		r.Table == r2.Table &&
		r.ChainName == r2.ChainName &&
		r.ForIPv6 == r2.ForIPv6 &&
		utils.EqualSlices(r.AppliedBefore, r2.AppliedBefore) &&
		utils.EqualSlices(r.MatchOpts, r2.MatchOpts) &&
		utils.EqualSlices(r.TargetOpts, r2.TargetOpts) &&
		r.Target == r2.Target && r.Description == r2.Description
}

// External returns false.
func (r Rule) External() bool {
	return false
}

// String describes iptables rule.
func (r Rule) String() string {
	var descr string
	if r.Description != "" {
		descr = fmt.Sprintf(" (%s)", r.Description)
	}
	var matchOpts string
	if len(r.MatchOpts) > 0 {
		matchOpts = " " + strings.Join(r.MatchOpts, " ")
	}
	var targetOpts string
	if len(r.TargetOpts) > 0 {
		targetOpts = " " + strings.Join(r.TargetOpts, " ")
	}
	return fmt.Sprintf("%s rule: -t %s -I %s%s -j %s%s%s",
		r.command(), r.Table, r.ChainName, matchOpts, r.Target, targetOpts, descr)
}

// Dependencies for an iptables rule are:
//   - destination custom chain
//   - referenced target custom chain
//   - the rules referenced in AppliedBefore that this rule precedes
//     (rules are added by inserting at the top of the chain, hence we start
//     with the bottom ones)
func (r Rule) Dependencies() (deps []depgraph.Dependency) {
	if r.dstIsCustomChain() && len(r.AppliedBefore) == 0 {
		// No need to add this dependency for rules that depend on other rules
		// from the AppliedBefore set - they will depend on the destination chain
		// transitively.
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.Reference(Chain{
				ChainName: r.ChainName,
				Table:     r.Table,
				ForIPv6:   r.ForIPv6,
			}),
		})
	}
	for _, r2 := range r.AppliedBefore {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.Reference(Rule{
				RuleLabel: r2,
				ChainName: r.ChainName,
				Table:     r.Table,
				ForIPv6:   r.ForIPv6,
			}),
		})
	}
	if r.targetIsCustomChain() {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.Reference(Chain{
				ChainName: r.Target,
				Table:     r.Table,
				ForIPv6:   r.ForIPv6,
			}),
		})
	}
	return deps
}

func (r Rule) command() string {
	cmd := iptablesCmd
	if r.ForIPv6 {
		cmd = ip6tablesCmd
	}
	return cmd
}

func (r Rule) dstIsCustomChain() bool {
	for _, builtin := range builtinChains {
		if r.ChainName == builtin {
			return false
		}
	}
	return true
}

func (r Rule) targetIsCustomChain() bool {
	for _, builtin := range builtinTargets {
		if r.Target == builtin {
			return false
		}
	}
	for _, builtin := range builtinChains {
		if r.Target == builtin {
			return false
		}
	}
	return true
}

// ChainConfigurator implements Configurator interface (libs/reconciler)
// for both iptables and ip6tables chains.
// It just creates empty chains and then RuleConfigurator inserts rules.
type ChainConfigurator struct {
	Log *base.LogObject
}

// Create creates (custom) ip(6)tables chain.
func (c *ChainConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	chain, isChain := item.(Chain)
	if !isChain {
		return errors.New("invalid item type")
	}
	args := []string{"-N", chain.ChainName, "-t", chain.Table}
	fn := iptablesFn[chain.command()]
	err := fn(c.Log, args...)
	if err != nil {
		return err
	}
	// Make sure we start with empty content.
	args = []string{"-F", chain.ChainName, "-t", chain.Table}
	return fn(c.Log, args...)
}

// Modify is not needed (the content of the chain, i.e. the rules, are separate Items).
func (c *ChainConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete flushes the chain content and removes it.
func (c *ChainConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	chain, isChain := item.(Chain)
	if !isChain {
		return errors.New("invalid item type")
	}
	// Flush the old content first.
	args := []string{"-F", chain.ChainName, "-t", chain.Table}
	fn := iptablesFn[chain.command()]
	err := fn(c.Log, args...)
	if err != nil {
		return err
	}
	// Delete the chain.
	args = []string{"-X", chain.ChainName, "-t", chain.Table}
	return fn(c.Log, args...)
}

// NeedsRecreate returns true, but it does not really matter because chain modification
// is not possible (the content of the chain, i.e. the rules, are separate Items).
func (c *ChainConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}

// RuleConfigurator implements Configurator interface (libs/reconciler)
// for both iptables and ip6tables rules.
type RuleConfigurator struct {
	Log *base.LogObject
}

// Create adds ip(6)tables rule into the destination chain.
// Rules are added by inserting them at the top of the chain. AppliedBefore dependencies
// ensure we start with the bottom ones.
func (c *RuleConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	rule, isRule := item.(Rule)
	if !isRule {
		return errors.New("invalid item type")
	}
	args := c.composeRuleArgs(rule, "-I")
	fn := iptablesFn[rule.command()]
	return fn(c.Log, args...)
}

// Modify is not implemented. Rules are modified through re-creation.
func (c *RuleConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes the ip(6)tables rule.
func (c *RuleConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	rule, isRule := item.(Rule)
	if !isRule {
		return errors.New("invalid item type")
	}
	args := c.composeRuleArgs(rule, "-D")
	fn := iptablesFn[rule.command()]
	return fn(c.Log, args...)
}

func (c *RuleConfigurator) composeRuleArgs(rule Rule, op string) []string {
	args := []string{"-t", rule.Table, op, rule.ChainName}
	args = append(args, rule.MatchOpts...)
	args = append(args, "-j", rule.Target)
	args = append(args, rule.TargetOpts...)
	args = append(args, "-m", "comment", "--comment", rule.RuleLabel)
	return args
}

// NeedsRecreate returns true, in-place Modify for iptables rule is not possible without
// knowing the exact line number.
func (c *RuleConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
