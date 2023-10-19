// Copyright (c) 2017-2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// RemoteAccessDisabled checks if remote access is enabled/disabled
// by checking if the file /config/remote_access_disabled exists or not.
func RemoteAccessDisabled() bool {
	if _, err := os.Stat(types.RemoteAccessFlagFileName); err == nil {
		// file exists, remote access is disabled
		return true
	} else {
		return false
	}
}
