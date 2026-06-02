// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// EFIVariable is a single UEFI variable captured alongside a measured boot,
// used by the TUI to explain PCR mismatches. Value is raw bytes (base64 on the
// wire).
type EFIVariable struct {
	Name  string `json:"name,omitempty"`
	Value []byte `json:"value,omitempty"`
}

// TpmLogs carries the raw TPM measured-boot event logs and the UEFI boot
// variables for the last good and last failed boots. The TUI diffs these
// against the locked vault's PCRs to show what changed. The log payloads are
// opaque binary blobs (base64 on the wire); the TUI parses them client-side.
type TpmLogs struct {
	LastFailedLog   []byte        `json:"last_failed_log,omitempty"`
	LastGoodLog     []byte        `json:"last_good_log,omitempty"`
	BackupFailedLog []byte        `json:"backup_failed_log,omitempty"`
	BackupGoodLog   []byte        `json:"backup_good_log,omitempty"`
	EFIVarsSuccess  []EFIVariable `json:"efi_vars_success,omitempty"`
	EFIVarsFailed   []EFIVariable `json:"efi_vars_failed,omitempty"`
}
