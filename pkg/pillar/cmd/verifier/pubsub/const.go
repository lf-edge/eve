// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"time"

	verifier "github.com/lf-edge/eve/pkg/pillar/cmd/verifier/lib"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	agentName = "verifier"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
	basePath    = types.SealedDirName + "/" + agentName
)

var v *verifier.Verifier
