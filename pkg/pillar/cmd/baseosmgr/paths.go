// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// pathConfig groups the on-disk paths baseosmgr persists across reboots,
// so unit tests can point them at a temporary directory.
type pathConfig struct {
	currentRetryUpdateCounter string
	configRetryUpdateCounter  string
	forceFallbackCounter      string
}

// defaultPathConfig returns the production paths under /persist/.
func defaultPathConfig() *pathConfig {
	return &pathConfig{
		currentRetryUpdateCounter: types.PersistStatusDir + "/current_retry_update_counter",
		configRetryUpdateCounter:  types.PersistStatusDir + "/config_retry_update_counter",
		forceFallbackCounter:      types.CheckpointDirname + "/forceFallbackCounter",
	}
}
