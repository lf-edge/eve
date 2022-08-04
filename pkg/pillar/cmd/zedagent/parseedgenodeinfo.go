// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Get the node information
func parseEdgeNodeInfo(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Tracef("Started parsing edge node information")

	enInfo := types.EdgeNodeInfo{}
	enInfo = types.EdgeNodeInfo{
		DeviceName:     config.GetDeviceName(),
		DeviceID:       config.GetId().Uuid,
		ProjectName:    config.GetProjectName(),
		ProjectID:      config.GetProjectId(),
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
