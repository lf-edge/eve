// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinkBlobSymlinksAndIsIdempotent(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	srcBlob := filepath.Join(src, "abc")
	if err := os.WriteFile(srcBlob, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	dstBlob := filepath.Join(dst, "blobs", "sha256", "abc")

	linked, err := linkBlob(srcBlob, dstBlob)
	if err != nil || !linked {
		t.Fatalf("first: linked=%v err=%v", linked, err)
	}
	fi, err := os.Lstat(dstBlob)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("dst not a symlink: %v", err)
	}

	// Second call is a no-op: dst already present.
	linked, err = linkBlob(srcBlob, dstBlob)
	if err != nil || linked {
		t.Fatalf("second: linked=%v err=%v", linked, err)
	}
}
