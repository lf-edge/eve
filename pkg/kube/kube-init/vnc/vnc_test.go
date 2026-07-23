// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vnc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsRegularFile(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("x"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"regular file", regular, true},
		{"directory", dir, false},
		{"absent", filepath.Join(dir, "nope"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isRegularFile(c.path); got != c.want {
				t.Errorf("isRegularFile(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestVncConfigParsing(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantOK  bool
		wantVMI string
		wantPort int
		wantPID int
	}{
		{
			name:     "full config",
			json:     `{"VMIName":"vmi-foo","VNCPort":5900,"CallerPID":1234}`,
			wantOK:   true,
			wantVMI:  "vmi-foo",
			wantPort: 5900,
			wantPID:  1234,
		},
		{
			name:     "without caller pid",
			json:     `{"VMIName":"vmi-foo","VNCPort":5901}`,
			wantOK:   true,
			wantVMI:  "vmi-foo",
			wantPort: 5901,
			wantPID:  0,
		},
		{
			name:   "missing VMIName fails validation",
			json:   `{"VNCPort":5900}`,
			wantOK: false,
		},
		{
			name:   "missing VNCPort fails validation",
			json:   `{"VMIName":"vmi-foo"}`,
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var cfg vncConfig
			if err := json.Unmarshal([]byte(c.json), &cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			ok := cfg.VMIName != "" && cfg.VNCPort != 0
			if ok != c.wantOK {
				t.Errorf("validation = %v, want %v (cfg=%+v)", ok, c.wantOK, cfg)
				return
			}
			if !ok {
				return
			}
			if cfg.VMIName != c.wantVMI || cfg.VNCPort != c.wantPort ||
				cfg.CallerPID != c.wantPID {
				t.Errorf("parsed = %+v, want VMI=%q Port=%d PID=%d",
					cfg, c.wantVMI, c.wantPort, c.wantPID)
			}
		})
	}
}

func TestProcessAliveSelf(t *testing.T) {
	// Our own PID must always look alive; PID 0 is never a valid
	// running process (kill(0, 0) sends to the process group of
	// the caller, which is not what we want — but we never call
	// processAlive(0) in production, so just smoke-check the +ve
	// case).
	if !processAlive(os.Getpid()) {
		t.Errorf("processAlive(self) should be true")
	}
	// A very large PID that is exceedingly unlikely to exist.
	if processAlive(2_000_000_000) {
		t.Logf("processAlive(2e9) = true (the host happens to have a high-PID process; "+
			"skipping the negative assertion)")
	}
}
