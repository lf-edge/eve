// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type passthroughAction uint8

const (
	// this rule applies
	passthroughDo = 0
	// this rule does not apply
	passthroughNo = iota
	// this rule forbids passthrough even if other rules apply
	passthroughForbid = iota
)

type virtualmachine struct {
	qmpSocketPath string
	adapters      []string
}

func newVirtualmachine(qmpSocketPath string, adapters []string) virtualmachine {
	vm := virtualmachine{
		qmpSocketPath: qmpSocketPath,
		adapters:      adapters,
	}

	if vm.adapters == nil {
		vm.adapters = make([]string, 0)
	}

	return vm
}

func (vm *virtualmachine) addAdapter(adapter string) {
	vm.adapters = append(vm.adapters, adapter)
}

func (vm virtualmachine) String() string {
	return fmt.Sprintf("vm-qmp: %s adapters: '%s'", vm.qmpSocketPath, strings.Join(vm.adapters, ", "))
}

type passthroughRule interface {
	evaluate(ud usbdevice) (passthroughAction, rulePriority)
	virtualMachine() *virtualmachine
	setVirtualMachine(vm *virtualmachine)
	String() string
}

// rulePriority ranks the rules that match a device. The usbaddr dimension is
// compared first, so a claim by port beats a claim by product however the
// rules are combined; the product dimension only breaks ties between equal
// port claims.
type rulePriority struct {
	addr    uint8
	product uint8
}

func (p rulePriority) add(o rulePriority) rulePriority {
	return rulePriority{addr: p.addr + o.addr, product: p.product + o.product}
}

func (p rulePriority) higherThan(o rulePriority) bool {
	if p.addr != o.addr {
		return p.addr > o.addr
	}
	return p.product > o.product
}

func (pr passthroughAction) String() string {
	if pr == passthroughDo {
		return "do passthrough"
	} else if pr == passthroughNo {
		return "no passthrough"
	} else if pr == passthroughForbid {
		return "forbid passthrough"
	}

	return ""
}

type passthroughRuleVMBase struct {
	vm *virtualmachine
}

func (pr *passthroughRuleVMBase) setVirtualMachine(vm *virtualmachine) {
	pr.vm = vm
}

func (pr *passthroughRuleVMBase) virtualMachine() *virtualmachine {
	return pr.vm
}

type pciPassthroughForbidRule struct {
	pciAddress string
	passthroughRuleVMBase
}

func (pr *pciPassthroughForbidRule) String() string {
	return fmt.Sprintf("PCI Passthrough Forbid Rule %s", pr.pciAddress)
}

func (pr *pciPassthroughForbidRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	if ud.usbControllerPCIAddress == pr.pciAddress && pr.virtualMachine() != nil {
		return passthroughForbid, rulePriority{}
	}

	return passthroughNo, pr.priority()
}

func (pr *pciPassthroughForbidRule) priority() rulePriority {
	return rulePriority{}
}

// this rule always returns passthroughForbid
// it is used when an ioBundle has a parentassigngrp that does not exist
type neverPassthroughRule struct {
	passthroughRuleVMBase
}

func (pr *neverPassthroughRule) priority() rulePriority {
	return rulePriority{addr: math.MaxUint8, product: math.MaxUint8}
}

func (pr *neverPassthroughRule) String() string {
	return "always no"
}

func (pr *neverPassthroughRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	return passthroughNo, pr.priority()
}

type pciPassthroughRule struct {
	pciAddress string
	passthroughRuleVMBase
}

func (pr *pciPassthroughRule) String() string {
	return fmt.Sprintf("PCI Passthrough Rule %s", pr.pciAddress)
}

func (pr *pciPassthroughRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	if ud.usbControllerPCIAddress == pr.pciAddress {
		return passthroughDo, pr.priority()
	}

	return passthroughNo, rulePriority{}
}

func (pr *pciPassthroughRule) priority() rulePriority {
	return rulePriority{}
}

type usbDevicePassthroughRule struct {
	vendorID  uint32
	productID uint32
	passthroughRuleVMBase
}

func (udpr *usbDevicePassthroughRule) String() string {
	return fmt.Sprintf("USB Device Passthrough Rule %x/%x", udpr.vendorID, udpr.productID)
}

func (udpr *usbDevicePassthroughRule) priority() rulePriority {
	return rulePriority{product: usbProductRulePriority}
}

func (udpr *usbDevicePassthroughRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	if udpr.vendorID != ud.vendorID ||
		udpr.productID != ud.productID {
		return passthroughNo, rulePriority{}
	}

	return passthroughDo, udpr.priority()
}

type compositionANDPassthroughRule struct {
	rules []passthroughRule
	passthroughRuleVMBase
}

func (cpr *compositionANDPassthroughRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	if len(cpr.rules) == 0 {
		return passthroughNo, rulePriority{}
	}

	var ret passthroughAction
	ret = passthroughDo

	var composedPriority rulePriority

	countUsbDevicePassthroughRule := 0
	countUsbPortPassthroughRule := 0
	for _, rule := range cpr.rules {
		switch rule.(type) {
		case *usbDevicePassthroughRule:
			countUsbDevicePassthroughRule++
		case *usbPortPassthroughRule:
			countUsbPortPassthroughRule++
		}

		action, priority := rule.evaluate(ud)
		if action == passthroughForbid {
			return action, rulePriority{}
		}
		if action == passthroughNo {
			return passthroughNo, rulePriority{}
		}
		composedPriority = composedPriority.add(priority)
	}

	if countUsbDevicePassthroughRule > 1 || countUsbPortPassthroughRule > 1 {
		log.Warnf("More than one USB passthrough rule in compositionAND rule: %+v", cpr.rules)
	}

	return ret, composedPriority
}

func (cpr *compositionANDPassthroughRule) String() string {
	var ret string

	for _, rule := range cpr.rules {
		ret += fmt.Sprintf("&%s", rule.String())
	}

	ret += "&"

	return ret
}

type compositionORPassthroughRule struct {
	rules []passthroughRule
	passthroughRuleVMBase
}

func (cpr *compositionORPassthroughRule) String() string {
	var ret string

	for _, rule := range cpr.rules {
		ret += fmt.Sprintf("|%s", rule.String())
	}

	ret += "|"

	return ret
}

func (cpr *compositionORPassthroughRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	if len(cpr.rules) == 0 {
		log.Warnf("assertion failed, there has to be at least one rule")
		return passthroughForbid, rulePriority{}
	}

	var ret passthroughAction
	ret = passthroughNo

	var highestPriority rulePriority

	for _, rule := range cpr.rules {
		action, priority := rule.evaluate(ud)
		switch action {
		case passthroughForbid:
			return passthroughForbid, rulePriority{}
		case passthroughDo:
			ret = passthroughDo
			if priority.higherThan(highestPriority) {
				highestPriority = priority
			}
		}
	}
	return ret, highestPriority
}

// usbPortWildcardRe accepts the port part of a wildcard usbaddr: "*" for every
// device on the bus or "<port path>.*" for every device below that port
var usbPortWildcardRe = regexp.MustCompile(`^(?:(\d+(?:\.\d+)*)\.)?\*$`)

const (
	// exact port, above every wildcard
	usbPortRulePriority = 10
	// plus the number of fixed components of the wildcard
	usbPortWildcardBasePriority = 1
	usbProductRulePriority      = 1
	// USB allows seven tiers with the root hub being the first, so a port
	// path has at most six components and a wildcard prefix at most five
	usbMaxPortDepth = 6
)

type usbPortPassthroughRule struct {
	busnum uint16
	// port path like "2.3"; with wildcard set only devices below it match
	// and "" stands for the whole bus
	portnum  string
	wildcard bool
	passthroughRuleVMBase
}

// usbAddr2passthroughRule converts an IoBundle usbaddr ("busnum:portnum", optionally with
// a trailing wildcard like "1:2.*" or "1:*") into a port passthrough rule
func usbAddr2passthroughRule(usbAddr string) (*usbPortPassthroughRule, error) {
	usbParts := strings.SplitN(usbAddr, ":", 2)
	if len(usbParts) != 2 {
		return nil, errors.New("expected busnum:portnum")
	}
	busnum, err := strconv.ParseUint(usbParts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("busnum %q not parseable", usbParts[0])
	}
	rule := &usbPortPassthroughRule{busnum: uint16(busnum), portnum: usbParts[1]}
	if !strings.Contains(usbParts[1], "*") {
		return rule, nil
	}
	matches := usbPortWildcardRe.FindStringSubmatch(usbParts[1])
	if matches == nil {
		return nil, errors.New("wildcard has to be the last port component, e.g. 1:2.* or 1:*")
	}
	rule.wildcard = true
	rule.portnum = matches[1]
	if components := portComponents(rule.portnum); components >= usbMaxPortDepth {
		return nil, fmt.Errorf("wildcard prefix with %d components cannot match, USB port paths have at most %d components",
			components, usbMaxPortDepth)
	}
	return rule, nil
}

func (uppr *usbPortPassthroughRule) portnumString() string {
	switch {
	case !uppr.wildcard:
		return uppr.portnum
	case uppr.portnum == "":
		return "*"
	default:
		return uppr.portnum + ".*"
	}
}

func (uppr *usbPortPassthroughRule) String() string {
	return fmt.Sprintf("USB Port Passthrough Rule %x/%s", uppr.busnum, uppr.portnumString())
}

// a wildcard ranks below an exact port match and a longer prefix above a
// shorter one; usbAddr2passthroughRule bounds the prefix depth so a wildcard
// stays below usbPortRulePriority. Product matching lives in the other
// dimension of rulePriority, so any port claim outranks a product claim
func (uppr *usbPortPassthroughRule) priority() rulePriority {
	if !uppr.wildcard {
		return rulePriority{addr: usbPortRulePriority}
	}
	return rulePriority{addr: uint8(usbPortWildcardBasePriority + portComponents(uppr.portnum))}
}

func portComponents(portnum string) int {
	if portnum == "" {
		return 0
	}
	return strings.Count(portnum, ".") + 1
}

func (uppr *usbPortPassthroughRule) matchesPort(portnum string) bool {
	switch {
	case !uppr.wildcard:
		return uppr.portnum == portnum
	case uppr.portnum == "":
		return portnum != ""
	default:
		return strings.HasPrefix(portnum, uppr.portnum+".")
	}
}

func (uppr *usbPortPassthroughRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	if uppr.busnum != ud.busnum || !uppr.matchesPort(ud.portnum) {
		return passthroughNo, uppr.priority()
	}

	return passthroughDo, uppr.priority()
}

type usbHubForbidPassthroughRule struct {
	passthroughRuleVMBase
}

func (uhfpr *usbHubForbidPassthroughRule) String() string {
	return "usbHubForbidPassthroughRule"
}

func (uhfpr *usbHubForbidPassthroughRule) priority() rulePriority {
	return rulePriority{}
}

func (uhfpr *usbHubForbidPassthroughRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	if strings.HasPrefix(ud.devicetype, "9/") {
		log.Tracef("usb hub forwarding is forbidden - %+v", ud)
		return passthroughForbid, uhfpr.priority()
	}

	return passthroughNo, uhfpr.priority()
}

func newUsbNetworkAdapterForbidPassthroughRule() usbNetworkAdapterForbidPassthroughRule {
	unafpr := usbNetworkAdapterForbidPassthroughRule{}
	unafpr.netDevPaths = unafpr.netDevPathsImpl

	return unafpr
}

type usbNetworkAdapterForbidPassthroughRule struct {
	netDevPaths func() []string
	passthroughRuleVMBase
}

func (unafpr *usbNetworkAdapterForbidPassthroughRule) String() string {
	return "usbNetworkAdapterForbidPassthroughRule"
}

func (unafpr *usbNetworkAdapterForbidPassthroughRule) priority() rulePriority {
	return rulePriority{}
}

func (unafpr *usbNetworkAdapterForbidPassthroughRule) evaluate(ud usbdevice) (passthroughAction, rulePriority) {
	netDevPaths := unafpr.netDevPaths()

	ueventDirname := filepath.Dir(ud.ueventFilePath) + "/"
	for _, path := range netDevPaths {
		if strings.HasPrefix(path, ueventDirname) {
			log.Tracef("usb network adapter forwarding is forbidden - %+v", ud)
			return passthroughForbid, unafpr.priority()
		}
	}

	return passthroughNo, unafpr.priority()
}

func (*usbNetworkAdapterForbidPassthroughRule) netDevPathsImpl() []string {
	netDir := filepath.Join(sysFSPath, "class", "net")
	netDevfiles, err := os.ReadDir(netDir)
	if err != nil {
		log.Warnf("readdir of %s failed: %v", netDir, err)
		return []string{}
	}

	netDevPaths := make([]string, 0)

	for _, file := range netDevfiles {
		// e.g. ../../devices/pci0000:00/0000:00:14.0/usb4/4-2/4-2.1/4-2.1:1.0/net/enp0s20f0u2u1/
		relPath, err := os.Readlink(filepath.Join(netDir, file.Name()))
		if errors.Is(err, os.ErrInvalid) {
			continue
		}
		if err != nil {
			log.Warnf("readlink of %s failed: %v", relPath, err)
			continue
		}

		// remove net/enp0s20f0u2u1/ and prefix with sysfs dir
		netDirPath := filepath.Join(netDir, relPath, "..", "..")
		absPath, err := filepath.Abs(netDirPath)
		if err != nil {
			log.Warnf("creating absolute filepath of %s failed: %v", netDirPath, err)
			continue
		}

		netDevPaths = append(netDevPaths, absPath)
	}
	return netDevPaths
}
