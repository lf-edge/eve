// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package efi

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	guid "github.com/google/uuid"
	"github.com/robertmin1/u-root/v3/pkg/efivarfs"
)

const (
	kernelExtraCmdLineVarName = "eve-kernel-extra-cmdline"
	eveVarGUID                = "7ad58f29-2b49-4f5a-9f0b-4e7bf7c2c311" // keep lower-case for efivarfs key
	softLimit                 = 2048
)

// Pre-created descriptor (hidden; no parsing at call sites).
var extraKernelCmdLineVar = efivarfs.VariableDescriptor{
	Name: kernelExtraCmdLineVarName,
	GUID: guid.MustParse(eveVarGUID),
}

// Global efivarfs instance using hostfs path
var globalEfivarfs *efivarfs.EFIVarFS

func init() {
	var err error
	globalEfivarfs, err = efivarfs.NewPath(filepath.Join("/hostfs", efivarfs.DefaultVarFS))
	if err != nil {
		panic(fmt.Sprintf("failed to create efivarfs instance: %v", err))
	}
}

// GetEfivarfs returns the global efivarfs instance.
// This instance is configured to use the hostfs path and is guaranteed to be non-nil.
func GetEfivarfs() *efivarfs.EFIVarFS {
	return globalEfivarfs
}

// NON_VOLATILE | BOOTSERVICE | RUNTIME
var stdAttrs = efivarfs.AttributeNonVolatile |
	efivarfs.AttributeBootserviceAccess |
	efivarfs.AttributeRuntimeAccess

// SetKernelCmdline sets the kernel command line arguments via EFI variable.
// The function writes the provided arguments to the EFI variable 'eve-kernel-extra-cmdline'
// with GUID '7ad58f29-2b49-4f5a-9f0b-4e7bf7c2c311'. The content is stored as ASCII
// with exactly one trailing NUL terminator.
//
// The function validates that:
// - args does not contain newline characters (\r or \n)
// - args length does not exceed the soft limit of 2048 characters
//
// If the EFI variable already exists and has permission issues, the function will
// attempt to remove it and recreate it with the new value.
//
// Returns an error if validation fails, EFI operations fail, or the system
// does not support EFI variables.
func SetKernelCmdline(args string) error {
	if strings.ContainsAny(args, "\r\n") {
		return fmt.Errorf("efi: cmdline contains newline characters")
	}
	if len(args) > softLimit {
		return fmt.Errorf("efi: cmdline too long (%d > %d)", len(args), softLimit)
	}
	// ensure exactly one trailing NUL
	args = strings.TrimRight(args, "\x00") + "\x00"

	if err := efivarfs.WriteVariable(globalEfivarfs, extraKernelCmdLineVar, stdAttrs, []byte(args)); err != nil {
		// If immutable/permission, remove (library clears +i) then re-create.
		if errors.Is(err, efivarfs.ErrVarPermission) {
			_ = efivarfs.RemoveVariable(globalEfivarfs, extraKernelCmdLineVar)
			return efivarfs.WriteVariable(globalEfivarfs, extraKernelCmdLineVar, stdAttrs, []byte(args))
		}
		return err
	}
	return nil
}

// ResetKernelCmdline clears the kernel command line arguments while keeping the EFI variable.
// The function sets the EFI variable 'eve-kernel-extra-cmdline' to contain only a single
// NUL terminator, effectively making it empty but still present in the EFI variable store.
//
// This is useful when you want to clear the extra kernel arguments without completely
// removing the EFI variable from the system.
//
// Returns an error if EFI operations fail or the system does not support EFI variables.
func ResetKernelCmdline() error {
	return efivarfs.WriteVariable(globalEfivarfs, extraKernelCmdLineVar, stdAttrs, []byte{0x00})
}

// GetKernelCmdline retrieves the current kernel command line arguments from EFI variable.
// The function reads the EFI variable 'eve-kernel-extra-cmdline' and returns its content.
//
// Returns:
// - string: the command line arguments with NUL terminator stripped
// - bool: true if the variable exists and contains non-empty content (beyond NUL)
// - error: any error that occurred during the operation
//
// If the EFI variable does not exist, returns ("", false, nil).
// If the variable exists but is empty (only contains NUL), returns ("", false, nil).
// The function automatically strips any NUL terminators from the returned string.
func GetKernelCmdline() (string, bool, error) {
	_, b, err := efivarfs.ReadVariable(globalEfivarfs, extraKernelCmdLineVar) // <- use descriptor, not key
	if err != nil {
		if errors.Is(err, efivarfs.ErrVarNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	if i := bytes.IndexByte(b, 0x00); i >= 0 {
		b = b[:i]
	}
	return string(b), len(b) > 0, nil
}

// AppendKernelCmdline adds additional arguments to the existing kernel command line.
// The function retrieves the current kernel command line arguments, appends the new
// arguments with a space separator, and stores the combined result back to the EFI variable.
//
// The function handles the following cases:
// - If current cmdline is empty, sets it to the extra arguments
// - If extra arguments are empty, keeps the current cmdline unchanged
// - Otherwise, combines current and extra arguments with a space separator
//
// Both current and extra arguments are trimmed of leading/trailing whitespace
// before processing.
//
// Returns an error if reading or writing the EFI variable fails.
func AppendKernelCmdline(extra string) error {
	cur, _, err := GetKernelCmdline()
	if err != nil {
		return err
	}
	cur = strings.TrimSpace(cur)
	extra = strings.TrimSpace(extra)
	switch {
	case cur == "":
		return SetKernelCmdline(extra)
	case extra == "":
		return SetKernelCmdline(cur)
	default:
		return SetKernelCmdline(cur + " " + extra)
	}
}

// DeleteKernelCmdline completely removes the kernel command line EFI variable.
// The function deletes the EFI variable 'eve-kernel-extra-cmdline' from the
// EFI variable store, making it as if it never existed.
//
// This is different from ResetKernelCmdline(), which keeps the variable but
// makes it empty. Use this function when you want to completely remove any
// trace of the extra kernel command line configuration.
//
// Returns an error if the EFI variable removal fails or the system does not
// support EFI variables. If the variable does not exist, this may or may not
// return an error depending on the underlying EFI implementation.
func DeleteKernelCmdline() error {
	return efivarfs.RemoveVariable(globalEfivarfs, extraKernelCmdLineVar)
}
