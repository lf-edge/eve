// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	uuid "github.com/satori/go.uuid"
)

// EdgeNodeInfo - edge node info from controller
type EdgeNodeInfo struct {
	DeviceName     string
	DeviceID       uuid.UUID
	ProjectName    string
	ProjectID      uuid.UUID
	EnterpriseName string
	EnterpriseID   string
}
