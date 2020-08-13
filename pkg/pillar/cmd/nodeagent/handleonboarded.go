// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Really a constant
var nilUUID = uuid.UUID{}

// Set onboarded if the UUID is not nil
func handleOnboardStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*nodeagentContext)

	if status.DeviceUUID == nilUUID {
		log.Infof("handleOnboardStatusModify nil UUID")
		return
	}
	ctx.onboarded = true
	log.Infof("handleOnboardStatusModify onboarded")
}
