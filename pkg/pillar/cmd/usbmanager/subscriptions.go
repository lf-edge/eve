// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"fmt"
	"reflect"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func (usbCtx *usbmanagerContext) process(ps *pubsub.PubSub) {
	stillRunning := time.NewTicker(stillRunningInterval)

	watches := make([]pubsub.ChannelWatch, 0)
	for i := range usbCtx.subscriptions {
		sub := usbCtx.subscriptions[i]
		watches = append(watches, pubsub.WatchAndProcessSubChanges(sub))
	}

	watches = append(watches, pubsub.ChannelWatch{
		Chan: reflect.ValueOf(stillRunning.C),
		Callback: func(_ interface{}) (exit bool) {
			ps.StillRunning(agentName, warningTime, errorTime)
			return false
		},
	})

	pubsub.MultiChannelWatch(watches)
}

func (usbCtx *usbmanagerContext) subscribe(ps *pubsub.PubSub) {
	subAssignableAdapters, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.AssignableAdapters{},
		Activate:      false,
		CreateHandler: usbCtx.handleAssignableAdaptersCreate,
		ModifyHandler: usbCtx.handleAssignableAdaptersModify,
		DeleteHandler: usbCtx.handleAssignableAdaptersDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	usbCtx.subscriptions = append(usbCtx.subscriptions, subAssignableAdapters)

	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.DomainStatus{},
		Activate:      false,
		CreateHandler: usbCtx.handleDomainStatusCreate,
		ModifyHandler: usbCtx.handleDomainStatusModify,
		DeleteHandler: usbCtx.handleDomainStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	usbCtx.subscriptions = append(usbCtx.subscriptions, subDomainStatus)

	for _, sub := range usbCtx.subscriptions {
		err := sub.Activate()
		if err != nil {
			log.Fatalf("cannot subscribe to %+v: %+v", sub, err)
		}
	}

	usbCtx.controller.listenUSBPorts()
}

func (usbCtx *usbmanagerContext) handleDomainStatusModify(_ interface{}, _ string,
	statusArg interface{}, _ interface{}) {
	newstatus, ok := statusArg.(types.DomainStatus)
	if !ok {
		log.Warnf("newstatus not OK, got %+v type %T\n", statusArg, statusArg)
		return
	}

	_, isRunningDomain := usbCtx.runningDomains[newstatus.DomainName]

	log.Noticef("domain modify (isRunning %v)'%s' state '%s' adapters '%+v'\n",
		isRunningDomain, newstatus.DisplayName, newstatus.State, newstatus.IoAdapterList)

	if newstatus.State == types.RUNNING && !isRunningDomain {
		usbCtx.runningDomains[newstatus.DomainName] = struct{}{}
		usbCtx.handleDomainStatusRunning(newstatus)
	}

	if newstatus.State != types.RUNNING && isRunningDomain {
		delete(usbCtx.runningDomains, newstatus.DomainName)
		usbCtx.handleDomainStatusNotRunning(newstatus)
	}

}

func (usbCtx *usbmanagerContext) handleDomainStatusNotRunning(status types.DomainStatus) {
	qmp := hypervisor.GetQmpExecutorSocket(status.DomainName)
	vm := newVirtualmachine(qmp, nil)

	for _, io := range status.IoAdapterList {
		vm.addAdapter(io.Name)
	}

	usbCtx.controller.removeVirtualmachine(vm)
}

func (usbCtx *usbmanagerContext) handleDomainStatusRunning(status types.DomainStatus) {
	qmp := hypervisor.GetQmpExecutorSocket(status.DomainName)
	vm := newVirtualmachine(qmp, nil)

	log.Tracef("display name: %+v\n", status.DisplayName)
	for _, io := range status.IoAdapterList {
		vm.addAdapter(io.Name)
	}

	usbCtx.controller.addVirtualmachine(vm)
	usbCtx.controller.Lock()
	log.Tracef("rule engine: %s\n", usbCtx.controller.ruleEngine)
	usbCtx.controller.Unlock()
}

func (usbCtx *usbmanagerContext) handleDomainStatusDelete(_ interface{}, _ string,
	statusArg interface{}) {

	status, ok := statusArg.(types.DomainStatus)
	if !ok {
		log.Warnf("status not OK, got %+v type %T\n", statusArg, statusArg)
		return
	}
	log.Noticef("domain delete '%s' state '%s' adapters '%+v'\n", status.DisplayName, status.State, status.IoAdapterList)

	usbCtx.handleDomainStatusNotRunning(status)
}

func (usbCtx *usbmanagerContext) handleDomainStatusCreate(_ interface{}, _ string,
	statusArg interface{}) {

	status, ok := statusArg.(types.DomainStatus)
	if !ok {
		log.Warnf("status not OK, got %+v type %T\n", statusArg, statusArg)
		return
	}

	log.Noticef("domain create '%s' state '%s' adapters '%+v'\n", status.DisplayName, status.State, status.IoAdapterList)

	if status.State == types.RUNNING {
		usbCtx.handleDomainStatusRunning(status)
	}
}

func ioBundleLogString(adapter types.IoBundle) string {
	return fmt.Sprintf("'%s' USBAddr '%s' USBProduct '%s' PCI '%s' Assigngrp '%s' Parentassigngrp '%s'",
		adapter.Phylabel,
		adapter.UsbAddr,
		adapter.UsbProduct,
		adapter.PciLong,
		adapter.AssignmentGroup,
		adapter.ParentAssignmentGroup)
}

func (usbCtx *usbmanagerContext) handleAssignableAdaptersCreate(_ interface{}, _ string,
	statusArg interface{}) {
	assignableAdapters, ok := statusArg.(types.AssignableAdapters)
	if !ok {
		log.Warnf("status not OK, got %+v type %T\n", statusArg, statusArg)
		return
	}

	for _, adapter := range assignableAdapters.IoBundleList {
		log.Noticef("AA create, add %s", ioBundleLogString(adapter))
		usbCtx.controller.addIOBundle(adapter)
	}
}

func (usbCtx *usbmanagerContext) handleAssignableAdaptersModify(_ interface{}, _ string,
	statusArg interface{}, oldStatusArg interface{}) {

	oldAssignableAdapters, ok := oldStatusArg.(types.AssignableAdapters)
	if !ok {
		log.Warnf("oldstatus not OK, got %+v type %T\n", oldStatusArg, oldStatusArg)
		return
	}
	newAssignableAdapters, ok := statusArg.(types.AssignableAdapters)
	if !ok {
		log.Warnf("newstatus not OK, got %+v type %T\n", statusArg, statusArg)
		return
	}

	oldAssignableAdaptersMap := make(map[string]types.IoBundle)

	for _, adapter := range oldAssignableAdapters.IoBundleList {
		oldAssignableAdaptersMap[adapter.Phylabel] = adapter
	}

	newAssignableAdaptersMap := make(map[string]types.IoBundle)

	for _, adapter := range newAssignableAdapters.IoBundleList {
		newAssignableAdaptersMap[adapter.Phylabel] = adapter
	}

	var removed, added []types.IoBundle
	for adapterName, adapter := range oldAssignableAdaptersMap {
		newAdapter, ok := newAssignableAdaptersMap[adapterName]
		if !ok {
			log.Noticef("AA modify, remove %s", ioBundleLogString(adapter))
			removed = append(removed, adapter)
		} else if ioBundleRuleChanged(adapter, newAdapter) {
			log.Noticef("AA modify, replace %s with %s",
				ioBundleLogString(adapter), ioBundleLogString(newAdapter))
			removed = append(removed, adapter)
			added = append(added, newAdapter)
		}
	}
	for adapterName, adapter := range newAssignableAdaptersMap {
		if _, ok := oldAssignableAdaptersMap[adapterName]; !ok {
			log.Noticef("AA modify, add %s", ioBundleLogString(adapter))
			added = append(added, adapter)
		}
	}
	if len(removed) == 0 && len(added) == 0 {
		return
	}
	usbCtx.controller.applyIOBundleChanges(removed, added)
}

// ioBundleRuleChanged reports whether the fields a passthrough rule is built
// from differ between two versions of the same ioBundle. Runtime fields such
// as UsedByUUID change with every assignment and do not matter here.
func ioBundleRuleChanged(before, after types.IoBundle) bool {
	return before.UsbAddr != after.UsbAddr ||
		before.UsbProduct != after.UsbProduct ||
		before.PciLong != after.PciLong ||
		before.AssignmentGroup != after.AssignmentGroup ||
		before.ParentAssignmentGroup != after.ParentAssignmentGroup
}

func (usbCtx *usbmanagerContext) handleAssignableAdaptersDelete(_ interface{}, _ string,
	statusArg interface{}) {

	assignableAdapters, ok := statusArg.(types.AssignableAdapters)
	if !ok {
		log.Warnf("status not OK, got %+v type %T\n", statusArg, statusArg)
		return
	}

	for _, adapter := range assignableAdapters.IoBundleList {
		log.Noticef("AA delete, remove %s", ioBundleLogString(adapter))
		usbCtx.controller.removeIOBundle(adapter)
	}
}
