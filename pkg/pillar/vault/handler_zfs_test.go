// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFstrimBinaryExists verifies that fstrim is present on PATH. TrimVault
// depends on it; a missing binary would silently fail at runtime on first boot.
func TestFstrimBinaryExists(t *testing.T) {
	_, err := exec.LookPath("fstrim")
	assert.NoError(t, err, "fstrim must be present on PATH; TrimVault will fail without it")
}

// TestVaultNeedsZvolMigration covers the decision that drives whether a
// just-unlocked ZFS vault is migrated from the EVE-kvm filesystem layout to
// the EVE-k zvol layout. Migration is needed only on EVE-k when the existing
// vault is still a filesystem dataset.
func TestVaultNeedsZvolMigration(t *testing.T) {
	tests := []struct {
		name        string
		isKube      bool
		vaultIsZvol bool
		want        bool
	}{
		{name: "kvm fs vault", isKube: false, vaultIsZvol: false, want: false},
		{name: "kvm zvol (n/a)", isKube: false, vaultIsZvol: true, want: false},
		{name: "k carried-over fs vault", isKube: true, vaultIsZvol: false, want: true},
		{name: "k native zvol vault", isKube: true, vaultIsZvol: true, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := vaultNeedsZvolMigration(tc.isKube, tc.vaultIsZvol); got != tc.want {
				t.Errorf("vaultNeedsZvolMigration(%t, %t) = %t, want %t",
					tc.isKube, tc.vaultIsZvol, got, tc.want)
			}
		})
	}
}
