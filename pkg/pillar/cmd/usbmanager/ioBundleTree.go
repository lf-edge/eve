// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

type ioBundlesArray []*types.IoBundle

func (iba ioBundlesArray) Len() int {
	return len(iba)
}
func (iba ioBundlesArray) Swap(i, j int) {
	iba[i], iba[j] = iba[j], iba[i]
}
func (iba ioBundlesArray) Less(i, j int) bool {
	return strings.Compare(iba[i].Phylabel, iba[j].Phylabel) == -1
}

type ioBundlesElem struct {
	ioBundlesMap    map[string]*types.IoBundle // phylabel is key
	assignmentGroup string
	parent          *ioBundlesElem
	children        map[string]*ioBundlesElem // assignmentGroup of child is key
}

func (ibe *ioBundlesElem) ioBundles() []*types.IoBundle {
	ret := make([]*types.IoBundle, 0)

	for _, ioBundle := range ibe.ioBundlesMap {
		ret = append(ret, ioBundle)
	}

	sort.Sort(ioBundlesArray(ret))

	return ret
}

type ioBundleTree struct {
	root                      *ioBundlesElem
	elementsByAssignmentGroup map[string]*ioBundlesElem
	phylabel2ioBundle         map[string]*types.IoBundle
}

func newIOBundleTree() *ioBundleTree {
	iobt := ioBundleTree{}

	iobt.root = &ioBundlesElem{
		ioBundlesMap:    map[string]*types.IoBundle{},
		assignmentGroup: "",
		parent:          nil,
		children:        map[string]*ioBundlesElem{},
	}

	iobt.elementsByAssignmentGroup = make(map[string]*ioBundlesElem)
	iobt.elementsByAssignmentGroup[iobt.root.assignmentGroup] = iobt.root
	iobt.phylabel2ioBundle = make(map[string]*types.IoBundle)

	return &iobt
}

func (iobt ioBundleTree) ioBundle(phylabel string) *types.IoBundle {
	return iobt.phylabel2ioBundle[phylabel]
}

// groupParents returns assignment groups this assignment group is dependent on
func (iobt ioBundleTree) groupParents(assigngrp string) []string {
	ret := make([]string, 0)
	ioBundleElem := iobt.elementsByAssignmentGroup[assigngrp]
	if ioBundleElem == nil {
		return ret
	}

	ioBundleElem = ioBundleElem.parent
	for ioBundleElem != nil {
		ret = append(ret, ioBundleElem.assignmentGroup)
		ioBundleElem = ioBundleElem.parent
	}

	return ret
}

// groupDependents returns assignment groups that are dependent on this assignment group
func (iobt ioBundleTree) groupDependendents(assigngrp string) []string {
	groups := make(map[string]struct{})

	ioBundlesElem := iobt.elementsByAssignmentGroup[assigngrp]
	iobt.groupDependendentsImpl(groups, ioBundlesElem)

	ret := make([]string, 0)
	for assigngrp := range groups {
		ret = append(ret, assigngrp)
	}

	sort.Strings(ret)
	return ret
}

func (iobt ioBundleTree) groupDependendentsImpl(groups map[string]struct{}, ioBundlesElem *ioBundlesElem) {
	if ioBundlesElem == nil {
		return
	}

	for _, childioBundlesElem := range ioBundlesElem.children {
		groups[childioBundlesElem.assignmentGroup] = struct{}{}
		iobt.groupDependendentsImpl(groups, childioBundlesElem)
	}

}

func (iobt *ioBundleTree) removeIOBundle(ioBundle *types.IoBundle) {
	delete(iobt.phylabel2ioBundle, ioBundle.Phylabel)
	ibe := iobt.elementsByAssignmentGroup[ioBundle.AssignmentGroup]

	if ibe == nil {
		return
	}

	delete(ibe.ioBundlesMap, ioBundle.Phylabel)

	if len(ibe.ioBundlesMap) > 0 {
		return
	}

	if ibe.parent == nil {
		return
	}

	// if grandparent and parent have no ioBundles, then remove the grandparent
	// and put the parent under the root element
	if len(ibe.parent.ioBundlesMap) > 0 {
		return
	}

	var ioBundlesGrandParent *ioBundlesElem
	if ibe.parent != nil && ibe.parent.parent != nil {
		ioBundlesGrandParent = ibe.parent.parent
	}

	if ioBundlesGrandParent != nil {
		delete(ioBundlesGrandParent.children, ibe.parent.assignmentGroup)
	}

	ibe.parent = iobt.root
}

func (iobt *ioBundleTree) addIOBundle(ioBundle *types.IoBundle) {
	dependents := iobt.groupDependendents(ioBundle.AssignmentGroup)
	for _, dependee := range dependents {
		if dependee == ioBundle.ParentAssignmentGroup {
			log.Warnf("detected parentassigngrp circular dependency, not adding ioBundle %s", ioBundle.Phylabel)
			return
		}
	}

	iobt.phylabel2ioBundle[ioBundle.Phylabel] = ioBundle
	if ioBundle.AssignmentGroup == "" {
		iobt.root.ioBundlesMap[ioBundle.Phylabel] = ioBundle
		return
	}

	ibe := iobt.elementsByAssignmentGroup[ioBundle.AssignmentGroup]
	if ibe == nil {
		ioBundleMap := make(map[string]*types.IoBundle)
		ioBundleMap[ioBundle.Phylabel] = ioBundle
		ibe = &ioBundlesElem{
			ioBundlesMap:    ioBundleMap,
			assignmentGroup: ioBundle.AssignmentGroup,
			parent:          &ioBundlesElem{},
			children:        map[string]*ioBundlesElem{},
		}
		iobt.elementsByAssignmentGroup[ioBundle.AssignmentGroup] = ibe
	}

	parentIbe := iobt.elementsByAssignmentGroup[ioBundle.ParentAssignmentGroup]
	if parentIbe == nil {
		parentIbe = &ioBundlesElem{
			ioBundlesMap:    map[string]*types.IoBundle{},
			assignmentGroup: ioBundle.ParentAssignmentGroup,
			parent:          iobt.root,
			children:        map[string]*ioBundlesElem{},
		}

		iobt.elementsByAssignmentGroup[ioBundle.ParentAssignmentGroup] = parentIbe
		iobt.root.children[ioBundle.ParentAssignmentGroup] = parentIbe
	}

	if parentIbe.children[ibe.assignmentGroup] == nil {
		parentIbe.children[ibe.assignmentGroup] = ibe
	}

	if ibe.parent == nil && ibe.assignmentGroup != "" {
		ibe.parent = parentIbe
	}

	ibe.ioBundlesMap[ioBundle.Phylabel] = ioBundle

	if ibe.parent != nil && ibe.parent.assignmentGroup != ioBundle.ParentAssignmentGroup {
		if len(ibe.ioBundlesMap) == 1 {
			// as there is only one ioBundle where there is a misalignment between ioBundle parent and the ioBundleElem parent
			// we can fix this
			// this f.e. happens when:
			// add ioBundle with Parent X
			// ioBundleElem with ioBundle and parent ioBundleElem X is added
			// remove this ioBundle
			// ioBundleElem still exists and the parent still points to ioBundleElem X
			// add ioBundle with Parent Y
			// now we set the parent of the ioBundleElemn to the Y ioBundleElem

			ibe.parent = parentIbe
		} else {
			log.Warn("this should not happen, seems two ioBundles with same assignment group have two different parent assignment groups")
		}
	}

}

func (iobt *ioBundleTree) ioBundle2passthroughRule(ioBundle types.IoBundle) passthroughRule {
	rootPrs := make([]passthroughRule, 0)

	ioBundlesElem := iobt.elementsByAssignmentGroup[ioBundle.AssignmentGroup]

	childPr := iobt.singleIOBundle2PassthroughRule(ioBundle)
	if childPr != nil {
		rootPrs = append(rootPrs, childPr)
	}

	if ioBundlesElem == nil {
		return childPr
	}

	ioBundlesElem = ioBundlesElem.parent
	for ioBundlesElem != nil && ioBundlesElem.assignmentGroup != "" {
		elementPrs := make([]passthroughRule, 0)
		for _, ioBundle := range ioBundlesElem.ioBundles() {
			pr := iobt.singleIOBundle2PassthroughRule(*ioBundle)
			if pr != nil {
				elementPrs = append(elementPrs, pr)
			}
		}
		if len(ioBundlesElem.ioBundlesMap) == 0 {
			elementPrs = append(elementPrs, &neverPassthroughRule{})
		}

		elementPr := &compositionORPassthroughRule{
			rules: elementPrs,
		}
		if len(elementPrs) == 1 {
			rootPrs = append(rootPrs, elementPrs[0])
		} else if len(elementPrs) > 1 {
			rootPrs = append(rootPrs, elementPr)
		}
		ioBundlesElem = ioBundlesElem.parent

	}

	if len(rootPrs) == 0 {
		return nil
	} else if len(rootPrs) == 1 {
		pciRule, ok := rootPrs[0].(*pciPassthroughRule)
		if ok {
			// if it is a single pci passthrough rule, it means it is a pci passthrough
			// therefore convert it to a passthrough forbid rule
			return &pciPassthroughForbidRule{
				pciAddress: pciRule.pciAddress,
			}
		}
		return rootPrs[0]
	}

	ret := &compositionANDPassthroughRule{
		// level is AND
		// within ioBundleElem it is OR
		rules: rootPrs,
	}

	return ret
}

func (iobt *ioBundleTree) singleIOBundle2PassthroughRule(ioBundle types.IoBundle) passthroughRule {
	prs := make([]passthroughRule, 0)

	if ioBundle.PciLong != "" {
		pci := pciPassthroughRule{pciAddress: ioBundle.PciLong}

		prs = append(prs, &pci)
	}
	if ioBundle.UsbAddr != "" {
		usbParts := strings.SplitN(ioBundle.UsbAddr, ":", 2)
		if len(usbParts) != 2 {
			log.Warnf("usbaddr %s not parseable", ioBundle.UsbAddr)
			return nil
		}
		busnum, err := strconv.ParseUint(usbParts[0], 10, 16)
		if err != nil {
			log.Warnf("usbaddr busnum (%s) not parseable", usbParts[0])
			return nil
		}
		portnum := usbParts[1]

		usb := usbPortPassthroughRule{
			busnum:  uint16(busnum),
			portnum: portnum,
		}

		prs = append(prs, &usb)
	}
	if ioBundle.UsbProduct != "" {
		usbParts := strings.SplitN(ioBundle.UsbProduct, ":", 2)
		if len(usbParts) != 2 {
			log.Warnf("usbproduct %s not parseable", ioBundle.UsbProduct)
			return nil
		}

		vendorID, errVendor := strconv.ParseUint(usbParts[0], 16, 32)
		productID, errProduct := strconv.ParseUint(usbParts[1], 16, 32)
		if errVendor != nil || errProduct != nil {
			log.Warnf("extracting vendor/product id out of usbproduct %s (phylabel: %s) failed: %v/%v",
				ioBundle.UsbProduct, ioBundle.Phylabel, errVendor, errProduct)
			return nil
		}

		usb := usbDevicePassthroughRule{
			vendorID:  uint32(vendorID),
			productID: uint32(productID),
		}

		prs = append(prs, &usb)
	}

	if len(prs) == 0 {
		log.Tracef("cannot create rule out of adapter %+v\n", ioBundle)
		return nil
	}
	if len(prs) == 1 {
		return prs[0]
	}

	ret := compositionANDPassthroughRule{
		rules: prs,
	}

	return &ret
}
