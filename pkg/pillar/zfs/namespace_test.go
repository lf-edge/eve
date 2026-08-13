// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoDirectEnumeration fails when pillar calls a libzfs enumeration outside
// the wrappers in namespace.go. The serialization those wrappers provide is
// process-wide, so a single caller reaching the binding directly defeats it for
// every agent, and nothing else in the build reports that.
func TestNoDirectEnumeration(t *testing.T) {
	banned := []string{"libzfs.PoolOpenAll(", "libzfs.DatasetOpenAll("}
	exempt := map[string]bool{"namespace.go": true, "namespace_test.go": true}

	var offenders []string
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || exempt[d.Name()] {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, call := range banned {
			if strings.Contains(string(content), call) {
				offenders = append(offenders, path+": "+call)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking pillar sources: %v", err)
	}
	for _, offender := range offenders {
		t.Errorf("%s must go through the zfs package wrapper so enumerations serialize", offender)
	}
}
