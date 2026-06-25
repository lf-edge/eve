// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !cgo

package provider

import (
	"context"
	"errors"
	"io"
	"net"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// LibvirtProvider is a stub for builds without CGO (libvirt requires CGO).
type LibvirtProvider struct{}

// LibvirtProviderConf is a stub for builds without CGO.
type LibvirtProviderConf struct {
	CommonProviderConf
}

// NewLibvirtProvider always returns an error when CGO is disabled.
func NewLibvirtProvider(_ LibvirtProviderConf) (*LibvirtProvider, error) {
	return nil, errors.New("libvirt provider is not available: binary was built without CGO support")
}

// The following methods implement DeviceProvider. They are never called because
// NewLibvirtProvider always returns an error.

// GetSupportedDeviceArchs is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) GetSupportedDeviceArchs() ([]api.ArchType, error) {
	panic("unreachable")
}

// SetupDevice is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) SetupDevice(_ context.Context, _ string, _ DeviceSpec) error {
	panic("unreachable")
}

// TeardownDevice is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) TeardownDevice(_ context.Context, _ string) error {
	panic("unreachable")
}

// PowerOnDevice is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) PowerOnDevice(_ context.Context, _ string) error {
	panic("unreachable")
}

// PowerOffDevice is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) PowerOffDevice(_ context.Context, _ string) error {
	panic("unreachable")
}

// ShutdownDevice is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) ShutdownDevice(_ context.Context, _ string) error {
	panic("unreachable")
}

// RebootDevice is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) RebootDevice(_ context.Context, _ string) error {
	panic("unreachable")
}

// GetDeviceConsoleOutput is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) GetDeviceConsoleOutput(_ context.Context, _ string) (string, error) {
	panic("unreachable")
}

// AttachToDeviceConsole is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) AttachToDeviceConsole(_ context.Context,
	_ string) (io.ReadWriteCloser, bool, bool, error) {
	panic("unreachable")
}

// GetDeviceStatus is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) GetDeviceStatus(_ context.Context, _ string) (DeviceStatus, error) {
	panic("unreachable")
}

// GetDeviceUplinkIPs is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) GetDeviceUplinkIPs(_ context.Context, _ string) ([]net.IP, error) {
	panic("unreachable")
}

// WatchDeviceStatus is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) WatchDeviceStatus(_ context.Context, _ string) <-chan DeviceStatus {
	panic("unreachable")
}

// ListDevices is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) ListDevices(_ context.Context) ([]string, error) {
	panic("unreachable")
}

// TeardownAll is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) TeardownAll(_ context.Context) error {
	panic("unreachable")
}

// ReconfigureDeviceDisks is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) ReconfigureDeviceDisks(_ context.Context, _ string, _ []DiskImage) error {
	panic("unreachable")
}

// Close is not implemented in CGO-disabled builds.
func (p *LibvirtProvider) Close() error {
	panic("unreachable")
}
