// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
)

// HandlerOptions defines options for handler
type HandlerOptions struct {
	// TpmKeyOnlyMode will use only TPM key to generate vault key. It names the
	// derivation to try first rather than a fact: handlers probe the other
	// derivation before giving up and leave this at whichever one opened the
	// vault, for the caller to persist (see GetHandlerOptions).
	TpmKeyOnlyMode bool
	// CurrentPartitionCommitted reports that the A/B partition the device is
	// running has been marked active, i.e. the update that installed it is
	// committed and the device is not going to revert to the other one. A
	// pre-migration vault kept as a fallback is only worth keeping until then.
	CurrentPartitionCommitted bool
}

// Handler is an interface for handling vault operations.
//
// The vault lifecycle operations (SetupDefaultVault, UnlockDefaultVault,
// RemoveDefaultVault) may block for as long as the underlying storage takes:
// on EVE-k a vault carried over from EVE-kvm is copied into a new zvol, so
// the duration scales with the vault contents. Callers run them off the
// agent's main goroutine.
type Handler interface {
	RemoveDefaultVault() error
	UnlockDefaultVault() error
	SetupDeprecatedVaults() error
	SetupDefaultVault() error
	GetVaultStatuses() []*types.VaultStatus
	SetHandlerOptions(HandlerOptions)
	// GetHandlerOptions returns the options in effect, which for
	// TpmKeyOnlyMode is what unlocking resolved it to rather than what was
	// set.
	GetHandlerOptions() HandlerOptions
	GetOperationalInfo() (info.DataSecAtRestStatus, string)
	// TrimVault reclaims blocks freed in the vault filesystem that were not
	// returned to the underlying storage (e.g. a ZFS zvol mounted without
	// discard). It is a no-op for handlers/platforms where this does not apply.
	// timeout is the maximum duration to wait; 0 means run to completion.
	// May block for the duration of the trim; callers run it off the agent's
	// main goroutine.
	TrimVault(timeout time.Duration) error
}

// GetHandler returns Handler implementation for the current persist type
func GetHandler(log *base.LogObject) Handler {
	persistFsType := persist.ReadPersistType()
	switch persistFsType {
	case types.PersistZFS:
		return &ZFSHandler{log: log}
	case types.PersistExt4:
		return &Ext4Handler{log: log}
	default:
		log.Warnf("unsupported persist type: %s", persistFsType)
		return &UnsupportedHandler{log: log}
	}
}
