// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !faultinjection

package evetpm

import "github.com/google/go-tpm/tpmutil"

// checkDiskKeyPresence is the production variant: the TPM is asked directly.
// The fault-injecting one lives in faultinjection_keypresence.go.
func checkDiskKeyPresence(handle tpmutil.Handle) (bool, error) {
	return nvIndexWritten(handle)
}
