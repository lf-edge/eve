// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// resolveKeyMode opens the vault through unlock, which takes the
// tpmKeyOnlyMode to derive the key with, and reports the mode that worked.
//
// preferred is tried first; when it fails the other derivation is tried before
// giving up, whatever preferred came from. A recorded mode is no more
// trustworthy than the boot that recorded it: a device that lost its vault
// config under an EVE that wrote the guess out before trying it reads that
// guess back as a recorded mode, and a vault recreated with a different
// derivation leaves the recorded one stale. Neither case is distinguishable
// from a bad seal at the point of failure -- the TPM unseal succeeds and only
// the filesystem's own key check refuses -- and a key that does not match the
// vault changes nothing on disk, so the second attempt is safe and is the only
// thing that tells the two apart.
//
// If neither opens the vault, both errors are reported, because attributing
// the failure to either mode alone would be a guess.
func resolveKeyMode(log *base.LogObject, preferred bool,
	unlock func(tpmKeyOnlyMode bool) error) (bool, error) {
	err := unlock(preferred)
	if err == nil {
		return preferred, nil
	}
	other := !preferred
	log.Noticef("Vault did not open with tpmKeyOnly=%v (%v); trying tpmKeyOnly=%v",
		preferred, err, other)
	if otherErr := unlock(other); otherErr != nil {
		return preferred, fmt.Errorf("vault key derivation unresolved: tpmKeyOnly=%v: %v; tpmKeyOnly=%v: %w",
			preferred, err, other, otherErr)
	}
	log.Noticef("Vault opened with tpmKeyOnly=%v; recording it as the derivation in use", other)
	return other, nil
}

// resolveUnlock opens the vault through unlock and leaves TpmKeyOnlyMode at
// the derivation that worked, so a caller reading the options back persists
// what the vault is actually keyed with. See resolveKeyMode.
func (o *HandlerOptions) resolveUnlock(log *base.LogObject,
	unlock func(tpmKeyOnlyMode bool) error) error {
	mode, err := resolveKeyMode(log, o.TpmKeyOnlyMode, unlock)
	if err != nil {
		return err
	}
	o.TpmKeyOnlyMode = mode
	return nil
}
