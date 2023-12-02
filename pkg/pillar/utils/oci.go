// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"strings"
)

// MaybeInsertSha Check if the OCI name does not include an explicit sha and if not
// return the name with the sha inserted.
// Note that the sha must be lower case in the OCI reference.
func MaybeInsertSha(name string, sha string) string {
	if strings.Index(name, "@") != -1 {
		// Already has a sha
		return name
	}

	sha = strings.ToLower(sha)
	last := strings.LastIndex(name, ":")
	if last == -1 {
		return name + "@sha256:" + sha
	}
	return name[:last] + "@sha256:" + sha
}
