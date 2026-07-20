// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import "regexp"

// sha256Regexp matches a valid SHA-256 digest: exactly 64 hexadecimal characters.
var sha256Regexp = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// IsValidSHA256 reports whether s is a syntactically valid SHA-256 digest, i.e.
// exactly 64 hexadecimal characters. It does not verify that the digest matches
// any content; it only guards against malformed values (e.g. controller-supplied
// digests that contain path separators or "..") before they are used to build
// file paths or looked up as content-addressable identifiers.
func IsValidSHA256(s string) bool {
	return sha256Regexp.MatchString(s)
}
