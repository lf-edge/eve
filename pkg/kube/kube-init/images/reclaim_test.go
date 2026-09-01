// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The guard is the only thing standing between a config revert and the
// deletion of live snapshots, so its failure modes matter more than its
// happy path: every case that is not unambiguously "some other
// snapshotter" must read as "do not touch anything".
func TestConfiguredCRISnapshotter(t *testing.T) {
	const criTable = `[plugins."io.containerd.grpc.v1.cri".containerd]`

	tests := []struct {
		name string
		toml string
		want string
	}{
		{
			name: "erofs under the cri table",
			toml: criTable + "\n  snapshotter = \"erofs\"\n",
			want: "erofs",
		},
		{
			name: "overlayfs under the cri table",
			toml: criTable + "\n  snapshotter = \"overlayfs\"\n",
			want: "overlayfs",
		},
		{
			// The transfer service declares a snapshotter too. Matching
			// it would invert the guard: a config whose CRI snapshotter
			// is overlayfs would look like erofs and the live snapshots
			// would be deleted.
			name: "snapshotter in another table is ignored",
			toml: "[[plugins.\"io.containerd.transfer.v1.local\".unpack_config]]\n" +
				"  snapshotter = \"erofs\"\n",
			want: "",
		},
		{
			// Same trap in the other direction: the CRI table's value
			// must win over a later unrelated one.
			name: "cri table wins over a later table",
			toml: criTable + "\n  snapshotter = \"erofs\"\n" +
				"[plugins.\"io.containerd.service.v1.diff-service\"]\n" +
				"  snapshotter = \"overlayfs\"\n",
			want: "erofs",
		},
		{
			name: "no snapshotter set at all",
			toml: criTable + "\n  disable_snapshot_annotations = true\n",
			want: "",
		},
		{
			name: "leading whitespace and no indentation both parse",
			toml: criTable + "\nsnapshotter=\"erofs\"\n",
			want: "erofs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config-k3s.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatalf("writing config: %v", err)
			}
			if got := configuredCRISnapshotter(path); got != tc.want {
				t.Errorf("configuredCRISnapshotter() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A missing config must not read as "no snapshotter configured, safe to
// proceed" -- it has to be indistinguishable from any other unreadable
// state so the caller refuses.
func TestConfiguredCRISnapshotterMissingFile(t *testing.T) {
	got := configuredCRISnapshotter(filepath.Join(t.TempDir(), "absent.toml"))
	if got != "" {
		t.Errorf("configuredCRISnapshotter(missing) = %q, want \"\"", got)
	}
}

// ReclaimStaleSnapshots must refuse before it opens a containerd
// connection when the config says overlayfs is live, and when the config
// cannot be read at all. Both are checked by passing an unreachable
// socket: if the guard let execution through, the call would fail with a
// connection error instead of the expected refusal.
func TestReclaimRefusesWhenUnsafe(t *testing.T) {
	dir := t.TempDir()
	unreachable := filepath.Join(dir, "no-such.sock")

	t.Run("overlayfs is the configured snapshotter", func(t *testing.T) {
		path := filepath.Join(dir, "live.toml")
		body := "[plugins.\"io.containerd.grpc.v1.cri\".containerd]\n" +
			"  snapshotter = \"overlayfs\"\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("writing config: %v", err)
		}
		_, err := ReclaimStaleSnapshots(t.Context(), unreachable, path)
		if err == nil {
			t.Fatal("expected a refusal, got nil error")
		}
		if !strings.Contains(err.Error(), "refusing to reclaim") {
			t.Errorf("expected a refusal, got %v", err)
		}
	})

	t.Run("config cannot be read", func(t *testing.T) {
		_, err := ReclaimStaleSnapshots(
			t.Context(), unreachable, filepath.Join(dir, "absent.toml"))
		if err == nil {
			t.Fatal("expected a refusal, got nil error")
		}
		if !strings.Contains(err.Error(), "cannot determine the CRI snapshotter") {
			t.Errorf("expected a refusal, got %v", err)
		}
	})
}
