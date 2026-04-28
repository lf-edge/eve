// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// ensureTestLog initializes the package-level log so removeStaleVNCFile's
// Noticef calls don't nil-deref. Safe to call multiple times.
func ensureTestLog() {
	if log != nil {
		return
	}
	lg := logrus.StandardLogger()
	lg.SetLevel(logrus.PanicLevel)
	log = base.NewSourceLogObject(lg, "edgeview-test", os.Getpid())
}

// setupVNCTestFile writes cfg to a tmp file (or a raw string) and points
// vncFilePath at it. Returns the path.
func setupVNCTestFile(t *testing.T, cfg *types.VmiVNCConfig, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vmiVNC.run")
	switch {
	case raw != "":
		if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
			t.Fatalf("write raw: %v", err)
		}
	case cfg != nil:
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	orig := vncFilePath
	vncFilePath = path
	t.Cleanup(func() { vncFilePath = orig })
	return path
}

// swapEdgeviewStubs swaps ownerAlive and isPortListening with canned replies.
func swapEdgeviewStubs(t *testing.T, alive, listening bool) {
	t.Helper()
	origAlive := ownerAlive
	origPort := isPortListening
	ownerAlive = func(types.VmiVNCConfig) bool { return alive }
	isPortListening = func(int) bool { return listening }
	t.Cleanup(func() {
		ownerAlive = origAlive
		isPortListening = origPort
	})
}

func TestRemoveStaleVNCFile(t *testing.T) {
	ensureTestLog()

	cases := []struct {
		name       string
		existing   *types.VmiVNCConfig
		raw        string
		evictIdle  bool
		ownerAlive bool
		listening  bool
		wantOK     bool // canonical return value (can caller proceed)
		wantFile   bool // file remains after the call
	}{
		{
			name:      "no file - proceed",
			evictIdle: true,
			wantOK:    true,
			wantFile:  false,
		},
		{
			name:      "unparsable file removed",
			raw:       "garbage",
			evictIdle: true,
			wantOK:    true,
			wantFile:  false,
		},
		{
			name:      "missing VNCPort treated as unreadable",
			existing:  &types.VmiVNCConfig{VMIName: "vmi", CallerPID: 10},
			evictIdle: true,
			wantOK:    true,
			wantFile:  false,
		},
		{
			name:       "live edgeview blocks",
			existing:   &types.VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, CallerPID: 10},
			evictIdle:  true,
			ownerAlive: true,
			listening:  true,
			wantOK:     false,
			wantFile:   true,
		},
		{
			name:       "live edgeview pid alive but port idle is evicted",
			existing:   &types.VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, CallerPID: 10},
			evictIdle:  true,
			ownerAlive: true,
			listening:  false,
			wantOK:     true,
			wantFile:   false,
		},
		{
			name:      "dead edgeview evicted",
			existing:  &types.VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, CallerPID: 10},
			evictIdle: true,
			wantOK:    true,
			wantFile:  false,
		},
		{
			name:      "startup leaves remote-console file alone",
			existing:  &types.VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, AppUUID: "app"},
			evictIdle: false, // startup mode
			listening: false, // shouldn't even be consulted
			wantOK:    true,
			wantFile:  true,
		},
		{
			name:      "request path blocked by live remote-console",
			existing:  &types.VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, AppUUID: "app"},
			evictIdle: true,
			listening: true,
			wantOK:    false,
			wantFile:  true,
		},
		{
			name:      "request path evicts idle remote-console",
			existing:  &types.VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, AppUUID: "app"},
			evictIdle: true,
			listening: false,
			wantOK:    true,
			wantFile:  false,
		},
		{
			// evictIdle is only consulted on the CallerPID==0 branch; a live
			// edgeview file must always block and be kept, regardless of mode.
			name:       "live edgeview blocks even at startup",
			existing:   &types.VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, CallerPID: 10},
			evictIdle:  false,
			ownerAlive: true,
			listening:  true,
			wantOK:     false,
			wantFile:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := setupVNCTestFile(t, tc.existing, tc.raw)
			swapEdgeviewStubs(t, tc.ownerAlive, tc.listening)

			got := removeStaleVNCFile(tc.evictIdle)
			if got != tc.wantOK {
				t.Errorf("removeStaleVNCFile(%v) = %v, want %v", tc.evictIdle, got, tc.wantOK)
			}
			_, err := os.Stat(path)
			fileRemains := err == nil
			if fileRemains != tc.wantFile {
				t.Errorf("file present = %v, want %v", fileRemains, tc.wantFile)
			}
		})
	}
}
