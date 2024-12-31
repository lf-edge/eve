// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
)

func kubeClusterUpdateStatusTask(ctxPtr *zedagentContext, triggerClusterUpdateInfo <-chan destinationBitset) {
	wdName := agentName + "clusterupdatestatus"

	stillRunning := time.NewTicker(30 * time.Second)
	ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	ctxPtr.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case dest := <-triggerClusterUpdateInfo:
			start := time.Now()
			log.Function("kubeClusterUpdateStatusTask got message")

			publishKubeClusterUpdateStatus(ctxPtr, dest)
			ctxPtr.iteration++
			log.Function("kubeClusterUpdateStatusTask done with message")
			ctxPtr.ps.CheckMaxTimeTopic(wdName, "clusterupdatestatus", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// PublishHardwareInfoToZedCloud send ZInfoHardware message
func publishKubeClusterUpdateStatus(ctx *zedagentContext, dest destinationBitset) {
	items := ctx.subClusterUpdateStatus.GetAll()
	psKubeUpdateStatusGlb, ok := items["global"].(types.KubeClusterUpdateStatus)
	if !ok {
		return
	}

	// Setup Container
	var UpdateStatusInfo = &info.ZInfoMsg{}
	key := devUUID.String() + "kubeclusterupdatestatus"
	bailOnHTTPErr := true
	infoType := new(info.ZInfoTypes)
	*infoType = info.ZInfoTypes_ZiKubeClusterUpdateStatus
	UpdateStatusInfo.Ztype = *infoType
	UpdateStatusInfo.DevId = *proto.String(devUUID.String())
	UpdateStatusInfo.AtTimeStamp = ptypes.TimestampNow()
	log.Functionf("publishKubeClusterUpdateStatus uuid %s", key)

	updateStatus := new(info.ZInfoKubeClusterUpdateStatus)

	updateStatus.Component = psKubeUpdateStatusGlb.Component.KubeComp()
	updateStatus.Status = psKubeUpdateStatusGlb.Status.KubeCompUpdateStatus()
	updateStatus.CurrentNode = psKubeUpdateStatusGlb.CurrentNode
	updateStatus.Error = nil
	if !psKubeUpdateStatusGlb.ErrorTime.IsZero() {
		updateStatus.Error = encodeErrorInfo(psKubeUpdateStatusGlb.ErrorAndTime.ErrorDescription)
	}

	UpdateStatusInfo.InfoContent = new(info.ZInfoMsg_ClusterUpdateInfo)
	if x, ok := UpdateStatusInfo.GetInfoContent().(*info.ZInfoMsg_ClusterUpdateInfo); ok {
		x.ClusterUpdateInfo = updateStatus
	}

	log.Functionf("publishKubeClusterUpdateStatus sending %v", UpdateStatusInfo)
	data, err := proto.Marshal(UpdateStatusInfo)
	if err != nil {
		log.Errorf("publishKubeClusterUpdateStatus proto marshaling error: %v", err)
		return
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Errorf("publishKubeClusterUpdateStatus malloc error")
		return
	}
	size := int64(proto.Size(UpdateStatusInfo))

	log.Function("publishKubeClusterUpdateStatus to controller")
	queueInfoToDest(ctx, dest, key, buf, size, bailOnHTTPErr, false, false,
		info.ZInfoTypes_ZiKubeClusterUpdateStatus)
}

func isKubeClusterUpdating(ctx *zedagentContext) bool {
	if ctx == nil {
		return false
	}
	if ctx.subClusterUpdateStatus == nil {
		return false
	}
	items := ctx.subClusterUpdateStatus.GetAll()
	if status, ok := items["global"].(types.KubeClusterUpdateStatus); ok {
		if (status.Component == types.CompLonghorn) && (status.Status == types.CompStatusCompleted) {
			return false
		}
		return true
	}
	return false
}

func initKubeSubs(ctx *zedagentContext) {
	subClusterUpdateStatus, err := ctx.ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     agentName,
		MyAgentName:   agentName,
		TopicImpl:     types.KubeClusterUpdateStatus{},
		Persistent:    true,
		Activate:      false, //need to have the zedagentCtx.subClusterUpdateStatus set before activation
		Ctx:           ctx,
		CreateHandler: handleClusterUpdateStatusCreate,
		ModifyHandler: handleClusterUpdateStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subClusterUpdateStatus = subClusterUpdateStatus
	ctx.subClusterUpdateStatus.Activate()
}
