// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// AppSummary is the aggregate count of application instances by state.
type AppSummary struct {
	Starting uint32 `json:"starting"`
	Running  uint32 `json:"running"`
	Stopping uint32 `json:"stopping"`
	Error    uint32 `json:"error"`
}
