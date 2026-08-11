// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := []struct {
		name    string
		content *string
		want    Role
	}{
		{"absent file is kube", nil, Kube},
		{"witness marker", ptr("witness"), Witness},
		{"trailing newline", ptr("witness\n"), Witness},
		{"surrounding space", ptr("  witness \n"), Witness},
		{"empty file is kube", ptr(""), Kube},
		{"unknown content is kube", ptr("something-else"), Kube},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kube-init-role")
			if c.content != nil {
				if err := os.WriteFile(path, []byte(*c.content), 0644); err != nil {
					t.Fatal(err)
				}
			}
			prev := roleFile
			roleFile = path
			t.Cleanup(func() { roleFile = prev })

			if got := readRole(); got != c.want {
				t.Errorf("readRole() = %v, want %v", got, c.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// TestAgentNamesDiffer guards the pubsub identity: a shared agent name
// would make the two containers clobber each other under /run.
func TestAgentNamesDiffer(t *testing.T) {
	if Kube.String() == Witness.String() {
		t.Fatal("roles must not share a pubsub agent name")
	}
}
