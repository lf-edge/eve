// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
)

// SimTpmPath is the path to the SWTPM socket, this path is hardcoded in
// tests/tpm/prep-and-test.sh, so if you change this, make sure to update
// the script as well.
const SimTpmPath = "/tmp/eve-tpm/srv.sock"

// SimTpmWaitForTpmReadyState waits for the SWTPM to be ready
func SimTpmWaitForTpmReadyState() error {
	for i := 0; i < 10; i++ {
		rw, err := tpm2.OpenTPM(SimTpmPath)
		if err != nil {
			return fmt.Errorf("failed to open TPM: %w", err)
		}

		_, _, err = tpm2.GetCapability(rw, tpm2.CapabilityHandles, 1, uint32(tpm2.HandleTypeTransient)<<24)
		if err != nil {
			// this is RCRetry, so retry
			if strings.Contains(err.Error(), "code 0x22") {
				time.Sleep(100 * time.Millisecond)
				continue
			} else {
				return fmt.Errorf("something is wrong with the TPM : %w", err)
			}
		} else {
			return nil
		}
	}

	return fmt.Errorf("TPM did't become ready after 10 attempts, failing the test")
}

// SimTpmAvailable checks if the SWTPM socket is available
func SimTpmAvailable() bool {
	_, err := os.Stat(SimTpmPath)
	return err == nil
}
