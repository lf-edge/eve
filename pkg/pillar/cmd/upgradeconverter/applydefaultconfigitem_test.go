// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Test_ReadAuthorizedKeys verifies that multiple keys in authorized_keys are
// preserved as separate newline-separated lines. sshd requires one key per
// line, so concatenating them without a separator produces a single invalid
// line. Also exercises comment/blank-line skipping and a final key with no
// trailing newline, which the previous ReadString-based loop silently dropped.
func Test_ReadAuthorizedKeys(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)

	const firstKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@example.com"
	const secondKey = "ssh-rsa AAAAB3NzaC1yc2ESecondTestKey second@example.com"

	type readTestEntry struct {
		contents string
		expected string
		expectOK bool
	}

	testMatrix := map[string]readTestEntry{
		"single key with trailing newline": {
			contents: firstKey + "\n",
			expected: firstKey,
			expectOK: true,
		},
		"multiple keys stay newline-separated": {
			contents: firstKey + "\n" + secondKey + "\n",
			expected: firstKey + "\n" + secondKey,
			expectOK: true,
		},
		"comments and blank lines skipped, last key has no newline": {
			contents: "# a comment\n" + firstKey + "\n\n" + secondKey,
			expected: firstKey + "\n" + secondKey,
			expectOK: true,
		},
		"only comments yields nothing": {
			contents: "# just a comment\n",
			expected: "",
			expectOK: false,
		},
		"empty file yields nothing": {
			contents: "",
			expected: "",
			expectOK: false,
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		authKeysFile := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(authKeysFile, []byte(test.contents), 0644); err != nil {
			t.Fatalf("cannot write %s: %s", authKeysFile, err)
		}
		keyData, keyDataValid := readAuthorizedKeys(authKeysFile)
		assert.Equal(t, test.expected, keyData)
		assert.Equal(t, test.expectOK, keyDataValid)
	}

	// A missing file must not be reported as valid key data.
	keyData, keyDataValid := readAuthorizedKeys(
		filepath.Join(t.TempDir(), "absent"))
	assert.Equal(t, "", keyData)
	assert.False(t, keyDataValid)
}
