// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build faultinjection

package evetpm

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// Fault injection for the disk-key presence check, compiled in only under the
// faultinjection build tag (FAULT_INJECTION=y). Production images get the
// pass-through in faultinjection_keypresence_disabled.go instead.
//
// It stands in for a TPM that cannot say whether a disk key exists while the
// rest of it works: the state in which taking the error for an absent key
// seals a fresh key over the one the vault is encrypted with. The marker holds
// the number of presence checks to fail, or "always". It lives on /persist
// because the checks it targets run during boot, before the vault is unlocked,
// and anything under /config is measured into the PCRs the key is sealed to.
var keyPresenceFaultFile = types.PersistStatusDir + "/tpm-key-presence-fault"

var errInjectedKeyPresenceFault = errors.New("injected TPM fault")

func checkDiskKeyPresence(handle tpmutil.Handle) (bool, error) {
	if takeKeyPresenceFault() {
		return false, fmt.Errorf("NVReadPublic(%#x): %w", handle, errInjectedKeyPresenceFault)
	}
	return nvIndexWritten(handle)
}

// takeKeyPresenceFault reports whether this check is to fail. A count is
// decremented durably before the failure is returned, so a reboot neither
// repeats an injected failure nor loses one.
func takeKeyPresenceFault() bool {
	data, err := os.ReadFile(keyPresenceFaultFile)
	if err != nil {
		return false
	}
	armed := strings.TrimSpace(string(data))
	if armed == "always" {
		return true
	}
	n, err := strconv.Atoi(armed)
	if err != nil || n <= 0 {
		return false
	}
	if err := fileutils.WriteRename(keyPresenceFaultFile, []byte(strconv.Itoa(n-1))); err != nil {
		return false
	}
	return true
}
