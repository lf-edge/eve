// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"syscall"
)

// filePathFor returns the volume-relative path of a file, scattering files across
// a bounded two-level tree derived from the fileID alone. Writer and verifier
// both use it so a file always lands at the same place.
func filePathFor(cfg Config, fileID uint64) string {
	fan := uint64(cfg.DirFanout)
	top := fileID % fan
	sub := (fileID / fan) % fan
	return fmt.Sprintf("d%02d/d%02d/f%d.blk", top, sub, fileID)
}

// isNotEmpty reports whether err is a "directory not empty" error.
func isNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST)
}
