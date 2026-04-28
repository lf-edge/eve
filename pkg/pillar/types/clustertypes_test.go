// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ENClusterAppStatus.Equal

func TestENClusterAppStatusEqual(t *testing.T) {
	s1 := ENClusterAppStatus{
		ScheduledOnThisNode: true,
		AppIsVMI:            true,
		VMIName:             "myapp",
		VNCPort:             5901,
	}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	s2.ScheduledOnThisNode = false
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.VMIName = "otherapp"
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.VNCPort = 5902
	assert.False(t, s1.Equal(s2))
}

// EdgeNodeClusterConfig.Key

func TestEdgeNodeClusterConfigKey(t *testing.T) {
	cfg := EdgeNodeClusterConfig{}
	assert.Equal(t, cfg.ClusterID.UUID.String(), cfg.Key())
}

func TestVmiVNCConfig_JSONRoundTrip(t *testing.T) {
	cases := []struct {
		name        string
		in          VmiVNCConfig
		mustContain string // substring that must appear
		mustExclude string // substring that must NOT appear
	}{
		{
			name:        "edgeview writer includes CallerPID and AppUUID",
			in:          VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, AppUUID: "app-uuid", CallerPID: 1234},
			mustContain: `"CallerPID":1234`,
		},
		{
			name:        "remote-console writer omits CallerPID",
			in:          VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, AppUUID: "app-uuid"},
			mustExclude: "CallerPID",
		},
		{
			name:        "legacy writer omits AppUUID",
			in:          VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, CallerPID: 1234},
			mustExclude: "AppUUID",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			s := string(buf)
			if tc.mustContain != "" && !strings.Contains(s, tc.mustContain) {
				t.Errorf("missing %q in %s", tc.mustContain, s)
			}
			if tc.mustExclude != "" && strings.Contains(s, tc.mustExclude) {
				t.Errorf("unexpected %q in %s", tc.mustExclude, s)
			}

			var back VmiVNCConfig
			if err := json.Unmarshal(buf, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back != tc.in {
				t.Errorf("round-trip mismatch: got %+v want %+v", back, tc.in)
			}
		})
	}
}

// withProcPath swaps procPath to a tmpdir for the duration of one test.
func withProcPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := procPath
	procPath = dir
	t.Cleanup(func() { procPath = orig })
	return dir
}

// writeComm writes a fake /proc/<pid>/comm file.
func writeComm(t *testing.T, root string, pid int, comm string) {
	t.Helper()
	procDir := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte(comm+"\n"), 0644); err != nil {
		t.Fatalf("write comm: %v", err)
	}
}

func TestOwnerAlive(t *testing.T) {
	cases := []struct {
		name string
		cfg  VmiVNCConfig
		comm string // "" means no comm file at that PID (dead/absent)
		want bool
	}{
		{
			name: "CallerPID unset",
			cfg:  VmiVNCConfig{CallerPID: 0},
			want: false,
		},
		{
			name: "negative CallerPID",
			cfg:  VmiVNCConfig{CallerPID: -1},
			want: false,
		},
		{
			name: "PID dead (no /proc entry)",
			cfg:  VmiVNCConfig{CallerPID: 99999},
			want: false,
		},
		{
			name: "PID live but reused by another program",
			cfg:  VmiVNCConfig{CallerPID: 12345},
			comm: "bash",
			want: false,
		},
		{
			name: "PID live and still edge-view",
			cfg:  VmiVNCConfig{CallerPID: 12345},
			comm: "edge-view",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := withProcPath(t)
			if tc.comm != "" {
				writeComm(t, root, tc.cfg.CallerPID, tc.comm)
			}
			if got := tc.cfg.OwnerAlive(); got != tc.want {
				t.Errorf("OwnerAlive() = %v, want %v", got, tc.want)
			}
		})
	}
}
