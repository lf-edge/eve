// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// pruneToNewest keeps the `keep` newest files in dir whose name ends with
// suffix and removes the rest. Recency is taken from the filename, not mtime:
// dump names embed a fixed-width UTC timestamp and a monotonic sequence
// (uniqueDumpPath), so lexicographic order is recency order and eviction is
// deterministic even for many dumps written in the same second — where mtime
// resolution would tie and pick arbitrarily. Files that do not match the
// suffix are left untouched, so the guest-core and qemu-core rings rotate
// independently. A non-existent dir is not an error. This is the rotation half
// of the per-domain ring; it runs before a new dump starts so
// eviction makes room up front.
func pruneToNewest(dir, suffix string, keep int) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("qemudump: readdir %s: %w", dir, err)
	}

	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) <= keep {
		return nil
	}

	// Oldest first (lexicographic == recency), then remove all but the newest.
	sort.Strings(names)
	var firstErr error
	for _, name := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("qemudump: evict %s: %w", filepath.Join(dir, name), err)
		}
	}
	return firstErr
}
