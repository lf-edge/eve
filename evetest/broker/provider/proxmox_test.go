// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"
)

func TestIsVMNotFoundErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			// Verbatim from PVE, as go-proxmox returns it (the HTTP status line).
			"missing VM",
			errors.New("500 Configuration file 'nodes/r660xs/qemu-server/99999.conf' does not exist"),
			true,
		},
		{
			"wrapped missing VM",
			fmt.Errorf("lookup: %w",
				errors.New("500 Configuration file 'nodes/pve/qemu-server/7.conf' does not exist")),
			true,
		},
		{
			// PVE failing to fork an API worker on a host out of memory.
			"worker failure",
			errors.New("500 got no worker upid - start worker failed"),
			false,
		},
		{
			"transport failure",
			&url.Error{Op: "Get", URL: "https://pve:8006/api2/json", Err: io.ErrUnexpectedEOF},
			false,
		},
		{
			"other missing object",
			errors.New("500 storage 'local-zfs' does not exist"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isVMNotFoundErr(tt.err); got != tt.want {
				t.Fatalf("isVMNotFoundErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
