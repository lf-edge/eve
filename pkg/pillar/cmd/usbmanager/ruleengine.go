// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"fmt"
)

type nullObjectPassthroughRule struct {
	passthroughRuleVMBase
}

func (pr *nullObjectPassthroughRule) priority() uint8 {
	return 0
}
func (pr *nullObjectPassthroughRule) evaluate(_ usbdevice) passthroughAction {
	return passthroughNo
}
func (pr *nullObjectPassthroughRule) String() string {
	return ""
}

type ruleEngine struct {
	rules map[string]passthroughRule
}

func newRuleEngine() *ruleEngine {
	var re ruleEngine

	re.rules = make(map[string]passthroughRule)

	return &re
}

func (re *ruleEngine) delRule(pr passthroughRule) {
	delete(re.rules, pr.String())
}

func (re *ruleEngine) addRule(pr passthroughRule) {
	re.rules[pr.String()] = pr
}

func (re *ruleEngine) apply(ud usbdevice) *virtualmachine {
	var maxRule passthroughRule
	maxRule = &nullObjectPassthroughRule{}

	for _, r := range re.rules {
		if r.evaluate(ud) == passthroughForbid {
			return nil
		}
		if r.evaluate(ud) == passthroughDo {
			if r.priority() > maxRule.priority() {
				maxRule = r
			}
		}
	}

	return maxRule.virtualMachine()
}

func (re *ruleEngine) String() string {
	var ret string

	ret = fmt.Sprintf("Rule Engine Rules (%d): |", len(re.rules))
	for _, rule := range re.rules {
		ret += fmt.Sprintf("%s|", rule)
	}

	return ret
}
