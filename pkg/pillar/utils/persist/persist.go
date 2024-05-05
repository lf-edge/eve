// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package persist

import (
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	evePersistTypeFile = "/run/eve.persist_type"
)

// ReadPersistType returns the persist filesystem
func ReadPersistType() types.PersistType {
	persistFsType := ""
	pBytes, err := os.ReadFile(evePersistTypeFile)
	if err == nil {
		persistFsType = strings.TrimSpace(string(pBytes))
	}
	return types.ParsePersistType(persistFsType)
}
