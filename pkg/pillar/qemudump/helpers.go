// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// dirBytes returns the total size of all regular files under root (the running
// on-disk cost of every dump), used to enforce the global cap. A missing root
// counts as zero.
func dirBytes(root string) (uint64, error) {
	var total uint64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode().IsRegular() {
			total += uint64(info.Size())
		}
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("qemudump: size %s: %w", root, err)
	}
	return total, nil
}

// kindBytes returns the total size of files in dir whose name ends with suffix
// (the retained bytes of one (domain, kind) ring), used for the per-domain
// quota. A missing dir counts as zero.
func kindBytes(dir, suffix string) (uint64, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("qemudump: readdir %s: %w", dir, err)
	}
	var total uint64
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		if info, err := e.Info(); err == nil {
			total += uint64(info.Size())
		}
	}
	return total, nil
}

// hostSpace reports free (available to unprivileged callers) and total bytes of
// the filesystem containing path.
func hostSpace(path string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, fmt.Errorf("qemudump: statfs %s: %w", path, err)
	}
	bs := uint64(st.Bsize)
	return st.Bavail * bs, st.Blocks * bs, nil
}
