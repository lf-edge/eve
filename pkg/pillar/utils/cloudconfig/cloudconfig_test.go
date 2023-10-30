package cloudconfig_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils/cloudconfig"
	"github.com/sirupsen/logrus"
)

func TestCloudConfig(t *testing.T) {
	t.Parallel()

	log := base.NewSourceLogObject(logrus.StandardLogger(), "cloudconfig", 0)
	// create a temporary directory to write files to
	rootPath, err := os.MkdirTemp("", "cloudconfig_test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(rootPath) })

	// define the test cases
	testCases := []struct {
		name     string
		input    string
		expected []cloudconfig.WritableFile
		errParse error
		errWrite error
	}{
		{
			name: "single file",
			input: `#cloud-config
write_files:
- path: /tmp/test.txt
  content: SGVsbG8gV29ybGQhCg==
  permissions: "0644"
  encoding: b64`,
			expected: []cloudconfig.WritableFile{
				{
					Path:        "/tmp/test.txt",
					Content:     "Hello World!\n",
					Permissions: "0644",
					Encoding:    "b64",
				},
			},
			errParse: nil,
			errWrite: nil,
		},
		{
			name: "multiple files",
			input: `#cloud-config
write_files:
- path: /tmp/test1.txt
  content: SGVsbG8gV29ybGQhCg==
  permissions: "0644"
  encoding: b64
- path: /tmp/test2.txt
  content: world
  permissions: "0644"
  encoding: plain`,
			expected: []cloudconfig.WritableFile{
				{
					Path:        "/tmp/test1.txt",
					Content:     "Hello World!\n",
					Permissions: "0644",
					Encoding:    "b64",
				},
				{
					Path:        "/tmp/test2.txt",
					Content:     "world",
					Permissions: "0644",
					Encoding:    "plain",
				},
			},
			errParse: nil,
			errWrite: nil,
		},
		{
			name: "unsupported encoding type",
			input: `#cloud-config
write_files:
- path: /tmp/unsupported_encoding_type.txt
  content: SGVsbG8gV29ybGQhCg==
  permissions: "0644"
  encoding: unsupported`,
			errParse: nil,
			errWrite: errors.New("unsupported encoding type. Only base64 and plain are supported"),
		},
		{
			name: "invalid permissions",
			input: `#cloud-config
write_files:
- path: /tmp/invalid_permissions.txt
  content: SGVsbG8gV29ybGQhCg==
  permissions: "invalid"
  encoding: b64`,
			expected: []cloudconfig.WritableFile{},
			errParse: nil,
			errWrite: errors.New("strconv.ParseUint: parsing \"invalid\": invalid syntax"),
		},
		{
			name: "invalid path",
			input: `#cloud-config
write_files:
- path: ../../etc/passwd
  content: SGVsbG8gV29ybGQhCg==
  permissions: "0644"
  encoding: b64`,
			expected: []cloudconfig.WritableFile{},
			errParse: nil,
			errWrite: fmt.Errorf("detected possible attempt to write file outside of root path. invalid path %s", "../../etc/passwd"),
		},
	}

	// run the test cases
	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cc, err := cloudconfig.ParseCloudConfig(tc.input)
			checkError(t, err, tc.errParse)

			// write the files specified in the config
			for _, wf := range cc.WriteFiles {
				err := cloudconfig.WriteFile(log, wf, rootPath)
				checkError(t, err, tc.errWrite)
			}

			// compare the content of the written files with the expected content
			for _, expected := range tc.expected {
				path := filepath.Join(rootPath, expected.Path)
				actualBytes, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("failed to read file %s: %v", expected.Path, err)
				}
				actual := string(actualBytes)
				if actual != expected.Content {
					t.Errorf("content of file %s does not match expected content:\nactual:   %q\nexpected: %q", expected.Path, actual, expected.Content)
				}
			}
		})
	}
}

func checkError(t *testing.T, err error, expected error) {
	t.Helper()
	if err != nil {
		if expected == nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err.Error() != expected.Error() {
			t.Fatalf("expected error %v, but got %v", expected, err)
		}
		return
	}
	if expected != nil {
		t.Fatalf("expected error %v, but got nil", expected)
	}
}
