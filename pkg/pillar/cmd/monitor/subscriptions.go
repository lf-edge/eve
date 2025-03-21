// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"reflect"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handlePhysicalIOAdapterCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handlePhysicalIOAdapterUpdate(ctxArg, statusArg)
}

func handlePhysicalIOAdapterModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handlePhysicalIOAdapterUpdate(ctxArg, statusArg)
}

func handlePhysicalIOAdapterUpdate(ctxArg interface{}, statusArg interface{}) {
	ctx := ctxArg.(*monitor)
	status := statusArg.(types.PhysicalIOAdapterList)
	ctx.IPCServer.sendIpcMessage("IOAdapters", status)
}

func handlePhysicalIOAdapterDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
}

func handleNetworkStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleNetworStatusUpdate(statusArg, ctxArg)

}
func handleNetworkStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

}

func handleNetworkStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleNetworStatusUpdate(statusArg, ctxArg)
}

func handleNetworStatusUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("NetworkStatus", status)
}

func handleDownloaderStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDownloaderStatusUpdate(statusArg, ctxArg)
}

func handleDownloaderStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleDownloaderStatusUpdate(statusArg, ctxArg)
}

func handleDownloaderStatusUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.DownloaderStatus)
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("DownloaderStatus", status)
}

func handleDownloaderStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
}

func handleDPCCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDPCUpdate(statusArg, ctxArg)

}
func handleDPCDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
}
func handleDPCModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleDPCUpdate(statusArg, ctxArg)
}

func handleDPCUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.DevicePortConfigList)
	if status.CurrentIndex == -1 {
		return
	}
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("DPCList", status)
}

func handleAppInstanceStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppInstanceStatusUpdate(statusArg, ctxArg)
}

func handleAppInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleAppInstanceStatusUpdate(statusArg, ctxArg)
}

func handleAppInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*monitor)
	// send updated status for all apps to detect deleted apps
	ctx.sendAppsList()
}

func handleAppInstanceStatusUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.AppInstanceStatus)
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("AppStatus", status)
}

func handleOnboardingStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleOnboardingStatusUpdate(statusArg, ctxArg)
}

func handleOnboardingStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleOnboardingStatusUpdate(statusArg, ctxArg)
}

func handleOnboardingStatusUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("OnboardingStatus", status)
}

func handleVaultStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVaultStatusUpdate(statusArg, ctxArg)
}

func handleVaultStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleVaultStatusUpdate(statusArg, ctxArg)
}

func handleVaultStatusUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.VaultStatus)
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("VaultStatus", status)

	if status.IsVaultInError() {
		ctx.sendTpmLogs()
	}
}

func handleAppInstanceSummaryCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppInstanceSummaryUpdate(statusArg, ctxArg)
}

func handleAppInstanceSummaryModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleAppInstanceSummaryUpdate(statusArg, ctxArg)
}
func handleAppInstanceSummaryUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.AppInstanceSummary)
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("AppSummary", status)
}

func handleLedBlinkCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleLedBlinkUpdate(statusArg, ctxArg)
}

func handleLedBlinkModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleLedBlinkUpdate(statusArg, ctxArg)
}
func handleLedBlinkUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.LedBlinkCounter)
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("LedBlinkCounter", status)
}

func handleZedAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleZedAgentStatusUpdate(statusArg, ctxArg)
}

func handleZedAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleZedAgentStatusUpdate(statusArg, ctxArg)
}

func handleZedAgentStatusUpdate(statusArg interface{}, ctxArg interface{}) {
	status := statusArg.(types.ZedAgentStatus)
	// Ignore if ConfigGetStatus is 0 which is incorrect value
	if status.ConfigGetStatus == 0 {
		return
	}
	ctx := ctxArg.(*monitor)
	ctx.IPCServer.sendIpcMessage("ZedAgentStatus", status)
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func getGlobalConfig(sub pubsub.Subscription) *types.ConfigItemValueMap {
	m, err := sub.Get("global")
	if err != nil {
		log.Errorf("GlobalConfig - Failed to get key global. err: %s", err)
		return nil
	}
	gc := m.(types.ConfigItemValueMap)
	return &gc
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}

	ctx := ctxArg.(*monitor)
	log.Functionf("handleGlobalConfigImpl for %s", key)

	// Get the global config
	globalConfig := getGlobalConfig(ctx.subscriptions["GlobalConfig"])
	ctx.processGlobalConfig(globalConfig)

	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func (ctx *monitor) subscribe(ps *pubsub.PubSub) error {
	var err error

	ctx.pubDevicePortConfig, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.DevicePortConfig{},
			Persistent: true,
		})
	if err != nil {
		log.Error("Cannot create DevicePortConfig publication")
		return err
	}
	if err = ctx.pubDevicePortConfig.ClearRestarted(); err != nil {
		log.Error("Cannot clear restarted for DevicePortConfig publication")
		return err
	}

	// Look for PhysicalIOAdapter from zedagent
	subPhysicalIOAdapter, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.PhysicalIOAdapterList{},
		Activate:      false,
		Ctx:           ctx,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		CreateHandler: handlePhysicalIOAdapterCreate,
		ModifyHandler: handlePhysicalIOAdapterModify,
		DeleteHandler: handlePhysicalIOAdapterDelete,
	})
	if err != nil {
		log.Error("Cannot create subscription for PhysicalIOAdapter")
		return err
	}

	subVaultStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "vaultmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VaultStatus{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleVaultStatusCreate,
		ModifyHandler: handleVaultStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Error("Cannot create subscription for VaultStatus")
		return err
	}

	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      false,
		Persistent:    true,
		Ctx:           ctx,
		CreateHandler: handleOnboardingStatusCreate,
		ModifyHandler: handleOnboardingStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Error("Cannot create subscription for OnboardingStatus")
		return err
	}

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleNetworkStatusCreate,
		ModifyHandler: handleNetworkStatusModify,
		DeleteHandler: handleNetworkStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Error("Cannot create subscription for DeviceNetworkStatus")
		return err
	}

	subDevicePortConfigList, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		Persistent:    true,
		TopicImpl:     types.DevicePortConfigList{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleDPCCreate,
		ModifyHandler: handleDPCModify,
		DeleteHandler: handleDPCDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Error("Cannot create subscription for DevicePortConfigList")
		return err
	}

	subAppInstanceSummary, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceSummary{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleAppInstanceSummaryCreate,
		ModifyHandler: handleAppInstanceSummaryModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Error("Cannot create subscription for AppInstanceSummary")
		return err
	}

	subAppInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceStatus{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleAppInstanceStatusCreate,
		ModifyHandler: handleAppInstanceStatusModify,
		DeleteHandler: handleAppInstanceStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Error("Cannot create subscription for AppInstanceStatus")
		return err
	}

	subDownloaderStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "downloader",
		MyAgentName:   agentName,
		TopicImpl:     types.DownloaderStatus{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleDownloaderStatusCreate,
		ModifyHandler: handleDownloaderStatusModify,
		DeleteHandler: handleDownloaderStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Error("Cannot create subscription for DownloaderStatus")
		return err
	}

	subLedBlinkCounter, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "",
			MyAgentName:   agentName,
			TopicImpl:     types.LedBlinkCounter{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleLedBlinkCreate,
			ModifyHandler: handleLedBlinkModify,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Error("Cannot create subscription for LedBlinkCounter")
		return err
	}

	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleZedAgentStatusCreate,
		ModifyHandler: handleZedAgentStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Error("Cannot create subscription for ZedAgentStatus")
		return err
	}

	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})

	ctx.subscriptions["IOAdapters"] = subPhysicalIOAdapter
	ctx.subscriptions["VaultStatus"] = subVaultStatus
	ctx.subscriptions["OnboardingStatus"] = subOnboardStatus
	ctx.subscriptions["NetworkStatus"] = subDeviceNetworkStatus
	ctx.subscriptions["DPCList"] = subDevicePortConfigList
	ctx.subscriptions["AppStatus"] = subAppInstanceStatus
	ctx.subscriptions["DownloaderStatus"] = subDownloaderStatus
	ctx.subscriptions["AppSummary"] = subAppInstanceSummary
	ctx.subscriptions["LedBlinkCounter"] = subLedBlinkCounter
	ctx.subscriptions["ZedAgentStatus"] = subZedAgentStatus
	ctx.subscriptions["GlobalConfig"] = subGlobalConfig
	return nil
}

func (ctx *monitor) handleClientConnected() {
	// go over all the subscriptions and process the current state
	log.Noticef("Client connected. Activating subscriptions")

	ctx.sendNodeStatus()
	ctx.sendAppsList()

	for _, sub := range ctx.subscriptions {
		if err := sub.Activate(); err != nil {
			log.Errorf("Failed to activate subscription %s", err)
		}
	}
}

func (ctx *monitor) process(ps *pubsub.PubSub) {
	stillRunning := time.NewTicker(stillRunningInterval)

	watches := make([]pubsub.ChannelWatch, 0)
	for i := range ctx.subscriptions {
		sub := ctx.subscriptions[i]
		watches = append(watches, pubsub.WatchAndProcessSubChanges(sub))
	}

	watches = append(watches, pubsub.ChannelWatch{
		Chan: reflect.ValueOf(stillRunning.C),
		Callback: func(_ interface{}) (exit bool) {
			ps.StillRunning(agentName, warningTime, errorTime)
			return false
		},
	})

	watches = append(watches, pubsub.ChannelWatch{
		Chan: reflect.ValueOf(ctx.clientConnected),
		Callback: func(_ interface{}) (exit bool) {
			ctx.handleClientConnected()
			return false
		},
	})

	pubsub.MultiChannelWatch(watches)
}
