// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

func init() {
	logger, log = agentlog.Init(agentName)
}
