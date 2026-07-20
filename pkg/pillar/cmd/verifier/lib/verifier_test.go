// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

// escapesDir reports whether resolved is outside dir (i.e. path traversal).
func escapesDir(dir, resolved string) bool {
	rel, err := filepath.Rel(dir, resolved)
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// TestImageVerifierFilenamesRejectsInvalidSha256 verifies that ImageVerifierFilenames
// rejects a controller-supplied sha256 that is not a strict 64-character hex digest.
// The digest is joined (unescaped) into the on-disk verifier/verified filenames, so a
// crafted value with parent-directory segments would, after path.Join cleaned it,
// resolve outside the verifier tree (path traversal). A valid digest must be accepted
// and stay contained.
func TestImageVerifierFilenamesRejectsInvalidSha256(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "verifier_test", 0)
	v, err := NewVerifier(t.TempDir(), log)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	mediaType := "application/vnd.oci.image.manifest.v1+json"
	badDigests := []string{
		"../../../../../../persist/secret", // traversal into a sibling of the verifier dir
		"../../../pwned",                   // traversal, fewer segments
		"..",
		"foo/bar",
		"",
		"9f86d081884c7d659a2feaa0c55ad015", // too short (32 hex chars)
		"zzzz6d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  // non-hex
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08ff", // too long (66)
	}
	for _, bad := range badDigests {
		if _, _, _, err := v.ImageVerifierFilenames("infile", bad, "tmpID", mediaType); err == nil {
			t.Errorf("ImageVerifierFilenames accepted invalid sha256 %q, expected error", bad)
		}
	}

	// A valid digest must be accepted and stay inside the verifier/verified dirs.
	goodDigest := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	_, verifierFilename, verifiedFilename, err := v.ImageVerifierFilenames(
		"infile", goodDigest, "tmpID", mediaType)
	if err != nil {
		t.Fatalf("ImageVerifierFilenames rejected valid sha256: %v", err)
	}
	if escapesDir(v.GetVerifierDir(), verifierFilename) {
		t.Errorf("verifierFilename %q escaped verifier dir %q",
			verifierFilename, v.GetVerifierDir())
	}
	if escapesDir(v.GetVerifiedDir(), verifiedFilename) {
		t.Errorf("verifiedFilename %q escaped verified dir %q",
			verifiedFilename, v.GetVerifiedDir())
	}
}
