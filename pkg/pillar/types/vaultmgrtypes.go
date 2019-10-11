// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve/api/go/info"
	"time"
)

// Indexed by Vault Name
type VaultStatus struct {
	Name      string
	Status    info.DataSecAtRestStatus
	Error     string
	ErrorTime time.Time
}

func (status VaultStatus) Key() string {
	return status.Name
}
