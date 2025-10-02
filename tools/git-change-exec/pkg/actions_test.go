// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import "testing"

func TestID(t *testing.T) {
	p := LintSpdx{}

	id := ID(p)
	if id != "LintSpdx" {
		t.Fatalf("wrong id: %s\n", id)
	}
}
