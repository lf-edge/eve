// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"

	"github.com/golang/protobuf/ptypes"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
)

func composePatchEnvelopeUsage(appUUID string, ctx *zedagentContext) []*metrics.AppPatchEnvelopeMetric {
	result := []*metrics.AppPatchEnvelopeMetric{}

	for _, c := range ctx.subPatchEnvelopeUsage.GetAll() {
		peUsage := c.(types.PatchEnvelopeUsage)
		if peUsage.AppUUID == appUUID {
			result = append(result, &metrics.AppPatchEnvelopeMetric{
				Uuid:              peUsage.PatchID,
				Version:           peUsage.Version,
				PatchApiCallCount: peUsage.PatchAPICallCount,
				DownloadCount:     peUsage.DownloadCount,
			})
		}
	}

	return result
}

func handlePatchEnvelopeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handlePatchEnvelopeStatusImpl(ctxArg, key, statusArg)
}

func handlePatchEnvelopeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handlePatchEnvelopeStatusImpl(ctxArg, key, statusArg)
}

func handlePatchEnvelopeStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	peStatus := composeZInfoPatchEnvelope(statusArg.(types.PatchEnvelopeInfo))
	ctx := ctxArg.(*zedagentContext)
	publishPatchEnvelopeStatus(ctx, peStatus, ctx.iteration, ControllerDest)
}

func composeZInfoPatchEnvelope(peStatus types.PatchEnvelopeInfo) *info.ZInfoPatchEnvelope {
	return &info.ZInfoPatchEnvelope{
		Name:    peStatus.Name,
		Id:      peStatus.PatchID,
		Version: peStatus.Version,
		State:   infoStateFromPatchEnvelopeState(peStatus.State),
		Size:    uint64(peStatus.Size()),
		Errors:  peStatus.Errors,
	}
}

func infoStateFromPatchEnvelopeState(state types.PatchEnvelopeState) info.EVE_PATCH_ENVELOPE_STATE {
	switch state {
	case types.PatchEnvelopeStateError:
		return info.EVE_PATCH_ENVELOPE_STATE_PATCH_ERROR
	case types.PatchEnvelopeStateRecieved:
		return info.EVE_PATCH_ENVELOPE_STATE_PATCH_RECEIVED
	case types.PatchEnvelopeStateDownloading:
		return info.EVE_PATCH_ENVELOPE_STATE_PATCH_DOWNLOADING
	case types.PatchEnvelopeStateDownloaded:
		return info.EVE_PATCH_ENVELOPE_STATE_PATCH_DOWNLOADED
	case types.PatchEnvelopeStateReady:
		return info.EVE_PATCH_ENVELOPE_STATE_PATCH_READY
	case types.PatchEnvelopeStateActive:
		return info.EVE_PATCH_ENVELOPE_STATE_PATCH_ACTIVE
	default:
		return info.EVE_PATCH_ENVELOPE_STATE_PATCH_UNKOWN
	}
}

func publishPatchEnvelopeStatus(ctx *zedagentContext, patchInfo *info.ZInfoPatchEnvelope,
	iteration int, dest destinationBitset) {
	log.Functionf("publishPatchEnvelopeOpaqueStatus: iteration %d", iteration)
	infoMsg := &info.ZInfoMsg{
		Ztype: info.ZInfoTypes_ZiPatchEnvelope,
		DevId: devUUID.String(),
		InfoContent: &info.ZInfoMsg_PatchInfo{
			PatchInfo: patchInfo,
		},
		AtTimeStamp: ptypes.TimestampNow(),
	}

	log.Functionf("publishPatchEnvelopeStatus: sending %v", infoMsg)
	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("publishPatchEnvelopeStatus: proto marshaling error: ", err)
	}
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(infoMsg))

	const bailOnHTTPErr = false
	const withNetTrace = false
	key := "publishPatchEnvelopeStatus:" + patchInfo.Id + "v" + patchInfo.Version

	const forcePeriodic = false
	queueInfoToDest(ctx, dest, key, buf, size, bailOnHTTPErr, withNetTrace,
		forcePeriodic, info.ZInfoTypes_ZiPatchEnvelope)
}
