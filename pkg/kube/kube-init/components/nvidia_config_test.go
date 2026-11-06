// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNvidiaConfigHash(t *testing.T) {
	eve := map[string]string{"default": "version: v1\n"}
	base := nvidiaConfigHash(eve, nil)

	if got := nvidiaConfigHash(eve, map[string]string{}); got != base {
		t.Errorf("empty user ConfigMap changed the hash")
	}
	if got := nvidiaConfigHash(eve, map[string]string{"default": "version: v1\n"}); got != base {
		t.Errorf("user override identical to EVE's changed the hash")
	}
	override := nvidiaConfigHash(eve, map[string]string{"default": "sharing: {}\n"})
	if override == base {
		t.Errorf("user override of default did not change the hash")
	}
	named := nvidiaConfigHash(eve, map[string]string{"timeslice-4": "sharing: {}\n"})
	if named == base || named == override {
		t.Errorf("named user config not reflected in the hash")
	}
	if a, b := nvidiaConfigHash(map[string]string{"ab": "c"}, nil),
		nvidiaConfigHash(map[string]string{"a": "bc"}, nil); a == b {
		t.Errorf("key/value boundary not part of the hash")
	}
}

func TestNvidiaConfigPatch(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

	t.Run("current", func(t *testing.T) {
		patch, restart, err := nvidiaConfigPatch("abc", "abc", "7", now)
		if err != nil || patch != nil || restart {
			t.Errorf("got patch=%s restart=%v err=%v, want no-op", patch, restart, err)
		}
	})

	t.Run("unrecorded", func(t *testing.T) {
		patch, restart, err := nvidiaConfigPatch("", "abc", "7", now)
		if err != nil {
			t.Fatal(err)
		}
		if restart {
			t.Errorf("restart on first record")
		}
		var body map[string]any
		if err := json.Unmarshal(patch, &body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body["spec"]; ok {
			t.Errorf("first record touches the pod template: %s", patch)
		}
	})

	t.Run("changed", func(t *testing.T) {
		patch, restart, err := nvidiaConfigPatch("old", "new", "7", now)
		if err != nil {
			t.Fatal(err)
		}
		if !restart {
			t.Errorf("no restart on config change")
		}
		want := `{"metadata":{"annotations":{"` + nvidiaConfigHashAnnotation + `":"new"},"resourceVersion":"7"},` +
			`"spec":{"template":{"metadata":{"annotations":{"` + restartedAtAnnotation + `":"2026-10-16T12:00:00Z"}}}}}`
		if string(patch) != want {
			t.Errorf("patch =\n%s\nwant\n%s", patch, want)
		}
	})
}
