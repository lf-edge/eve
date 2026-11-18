// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"errors"
	"os"
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/stretchr/testify/assert"
)

var errTPMRead = errors.New("injected TPM read failure")

func setPCRBankProbe(t *testing.T, supported bool, err error) {
	t.Helper()
	saved := pcrBankSupported
	pcrBankSupported = func(*base.LogObject) (bool, error) { return supported, err }
	t.Cleanup(func() { pcrBankSupported = saved })
}

func TestVaultStatusPCRStatus(t *testing.T) {
	cases := []struct {
		name      string
		supported bool
		err       error
		want      info.PCRStatus
	}{
		{"bank present", true, nil, info.PCRStatus_PCR_ENABLED},
		{"bank absent", false, nil, info.PCRStatus_PCR_DISABLED},
		{"TPM unreadable", false, errTPMRead, info.PCRStatus_PCR_UNKNOWN},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setPCRBankProbe(t, tc.supported, tc.err)

			ext4 := &Ext4Handler{log: testLog()}
			status := ext4.getVaultStatus("vault", t.TempDir(),
				info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED, "fscrypt is not in use")
			assert.Equal(t, tc.want, status.PCRStatus, "ext4")

			zfs := testZFSHandler(nil)
			status = zfs.getVaultStatus("vault", t.TempDir())
			assert.Equal(t, tc.want, status.PCRStatus, "zfs")
		})
	}
}

// When fscrypt status fails, an unreadable TPM must surface as an error, not as
// a missing SHA-256 bank.
func TestExt4VaultStatusFscryptFailureWithUnreadableTPM(t *testing.T) {
	if _, err := os.Stat(fsCryptPath); err == nil {
		t.Skipf("%s exists, so fscrypt status would run", fsCryptPath)
	}
	h := &Ext4Handler{log: testLog()}

	setPCRBankProbe(t, false, errTPMRead)
	status := h.getVaultStatus("vault", t.TempDir(),
		info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED, "")
	assert.Equal(t, info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR, status.Status)
	assert.Contains(t, status.Error, errTPMRead.Error())
	assert.NotContains(t, status.Error, "No PCR-SHA256 bank")

	setPCRBankProbe(t, false, nil)
	status = h.getVaultStatus("vault", t.TempDir(),
		info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED, "")
	assert.Equal(t, info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED, status.Status)
	assert.Equal(t, "No PCR-SHA256 bank available", status.Error)
}
