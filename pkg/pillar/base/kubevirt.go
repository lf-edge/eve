// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"os"
	"strings"
)

const (
	// EveVirtTypeFile contains the virtualization type, ie kvm, xen or kubevirt
	EveVirtTypeFile = "/run/eve-hv-type"
)

// IsHVTypeKube - return true if the EVE image is kube cluster type.
func IsHVTypeKube() bool {
	retbytes, err := os.ReadFile(EveVirtTypeFile)
	if err != nil {
		return false
	}

	if strings.Contains(string(retbytes), "kubevirt") {
		return true
	}
	return false
}
