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
// preferred is tried first. When it fails and it was only inferred, the other
// derivation is tried before giving up: vaultmgr infers the mode from whether
// the vault exists, which cannot tell a vault created TPM-key-only from one
// created with the merged key, and at the point of failure an inferred-wrong
// mode looks exactly like a bad seal — the TPM unseal succeeds and only the
// filesystem's own key check refuses. A key that does not match the vault
// changes nothing on disk, so trying the second one is safe. If neither opens
// the vault, both errors are reported, because attributing the failure to
// either mode alone would be a guess.
func resolveKeyMode(log *base.LogObject, preferred, inferred bool,
	unlock func(tpmKeyOnlyMode bool) error) (bool, error) {
	err := unlock(preferred)
	if err == nil || !inferred {
		return preferred, err
	}
	other := !preferred
	log.Noticef("Vault did not open with inferred tpmKeyOnly=%v (%v); trying tpmKeyOnly=%v",
		preferred, err, other)
	if otherErr := unlock(other); otherErr != nil {
		return preferred, fmt.Errorf("vault key derivation unresolved: tpmKeyOnly=%v: %v; tpmKeyOnly=%v: %w",
			preferred, err, other, otherErr)
	}
	log.Noticef("Vault opened with tpmKeyOnly=%v; recording it as the derivation in use", other)
	return other, nil
}
