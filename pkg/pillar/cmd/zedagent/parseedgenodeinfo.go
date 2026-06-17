// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Get the node information
func parseEdgeNodeInfo(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Tracef("Started parsing edge node information")

	uuidStr := config.GetId().GetUuid()
	if uuidStr == "" {
		log.Warn("received empty UUID from config")
		return
	}
	deviceID, _ := uuid.FromString(uuidStr)
	projectID, _ := uuid.FromString(config.GetProjectId())
	enInfo := types.EdgeNodeInfo{}
	enInfo = types.EdgeNodeInfo{
		DeviceName:     config.GetDeviceName(),
		DeviceID:       deviceID,
		ProjectName:    config.GetProjectName(),
		ProjectID:      projectID,
		EnterpriseName: config.GetEnterpriseName(),
		EnterpriseID:   config.GetEnterpriseId(),
	}

	publishEdgeNodeInfo(ctx, &enInfo)
}

func publishEdgeNodeInfo(ctx *getconfigContext, info *types.EdgeNodeInfo) {
	pub := ctx.pubEdgeNodeInfo
	pub.Publish("global", *info)
	log.Traceln("Done publishing node information")
}
