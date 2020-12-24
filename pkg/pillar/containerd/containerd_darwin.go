// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import "fmt"

// bind mount a namespace file
func bindNS(ns string, path string, pid int) error {
	return fmt.Errorf("bindNS is not implemented on Mac OS X")
}
