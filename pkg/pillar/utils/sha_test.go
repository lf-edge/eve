// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import "testing"

func TestIsValidSHA256(t *testing.T) {
	valid := []string{
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", // upper-case hex
	}
	for _, s := range valid {
		if !IsValidSHA256(s) {
			t.Errorf("IsValidSHA256(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"..",
		"foo/bar",
		"../../../../../../persist/secret", // path traversal
		"9f86d081884c7d659a2feaa0c55ad015", // too short (32)
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08f", // too long (65)
		"zzzz6d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // non-hex
		"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0", // prefixed
	}
	for _, s := range invalid {
		if IsValidSHA256(s) {
			t.Errorf("IsValidSHA256(%q) = true, want false", s)
		}
	}
}
