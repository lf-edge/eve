// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !cgo

package provider

import (
	"context"
	"encoding/json"
)

// ExecuteQMP is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) ExecuteQMP(_ context.Context, _, _ string,
	_ json.RawMessage) (json.RawMessage, error) {
	panic("unreachable")
}

// CreateScratchImage is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) CreateScratchImage(_ context.Context, _, _ string,
	_ uint64) (string, error) {
	panic("unreachable")
}

// DeleteScratchImage is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) DeleteScratchImage(_ context.Context, _, _ string) error {
	panic("unreachable")
}
