// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Set onboarded if the UUID is not nil
func handleOnboardStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*domainContext)

	if status.DeviceUUID == nilUUID {
		log.Infof("handleOnboardStatusModify nil UUID")
		return
	}
	ctx.onboarded = true
	log.Infof("handleOnboardStatusModify onboarded")
}
