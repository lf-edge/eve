// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package provider

import (
	"context"
	"encoding/json"
	"errors"
)

// errLibvirtNoQMP is returned by the QMP-related methods: libvirt owns the
// domain's monitor and the provider does not advertise CAPABILITY_QMP.
var errLibvirtNoQMP = errors.New("QMP access is not supported by the libvirt provider")

// ExecuteQMP is not supported by the libvirt provider.
func (p *LibvirtProvider) ExecuteQMP(_ context.Context, _, _ string,
	_ json.RawMessage) (json.RawMessage, error) {
	return nil, errLibvirtNoQMP
}

// CreateScratchImage is not supported by the libvirt provider.
func (p *LibvirtProvider) CreateScratchImage(_ context.Context, _, _ string,
	_ uint64) (string, error) {
	return "", errLibvirtNoQMP
}

// DeleteScratchImage is not supported by the libvirt provider.
func (p *LibvirtProvider) DeleteScratchImage(_ context.Context, _, _ string) error {
	return errLibvirtNoQMP
}
