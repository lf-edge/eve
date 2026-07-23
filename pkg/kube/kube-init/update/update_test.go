// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kcus"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestParseHashFile covers the sha256sum-style parser used to
// authenticate the downloaded k3s binary. Non-trivial logic we
// own:
//
//   - Two-field-and-hex-shaped is required; lines that have the
//     filename in the *hash* column must not match.
//   - Multi-entry files (the upstream sha256sum-amd64.txt lists
//     k3s and k3s-airgap-... together) must not cross-contaminate.
//   - A corrupt download (HTML error page, partial transfer) with
//     zero valid lines must surface a distinct "corrupt" error
//     rather than the generic "not found" one.
//   - BSD-style "SHA256 (name) = hex" lines are silently skipped.
func TestParseHashFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name        string
		body        string
		filename    string
		wantHash    string
		wantErr     bool
		wantCorrupt bool
	}{
		{
			name:     "single line match",
			body:     "0000000000000000000000000000000000000000000000000000000000000abc  k3s\n",
			filename: "k3s",
			wantHash: "0000000000000000000000000000000000000000000000000000000000000abc",
		},
		{
			name:     "second of two entries matches",
			body:     "1111111111111111111111111111111111111111111111111111111111111111  k3s-airgap.tar.zst\n2222222222222222222222222222222222222222222222222222222222222222  k3s\n",
			filename: "k3s",
			wantHash: "2222222222222222222222222222222222222222222222222222222222222222",
		},
		{
			name:     "trailing blank line tolerated",
			body:     "3333333333333333333333333333333333333333333333333333333333333333  k3s\n\n",
			filename: "k3s",
			wantHash: "3333333333333333333333333333333333333333333333333333333333333333",
		},
		{
			name:     "filename only in hash column does not match",
			body:     "k3s  k3s-not-the-target\n4444444444444444444444444444444444444444444444444444444444444444  k3s-airgap\n",
			filename: "k3s",
			wantErr:  true,
		},
		{
			name:     "arm64 variant matches its own filename",
			body:     "5555555555555555555555555555555555555555555555555555555555555555  k3s\n6666666666666666666666666666666666666666666666666666666666666666  k3s-arm64\n",
			filename: "k3s-arm64",
			wantHash: "6666666666666666666666666666666666666666666666666666666666666666",
		},
		{
			name:        "BSD-style three-field line is skipped",
			body:        "SHA256 (k3s) = 7777777777777777777777777777777777777777777777777777777777777777\n",
			filename:    "k3s",
			wantErr:     true,
			wantCorrupt: true,
		},
		{
			name:        "HTML error page produces a corrupt-download error",
			body:        "<html><body><h1>404</h1></body></html>\n",
			filename:    "k3s",
			wantErr:     true,
			wantCorrupt: true,
		},
		{
			name:        "empty file is corrupt, not missing",
			body:        "",
			filename:    "k3s",
			wantErr:     true,
			wantCorrupt: true,
		},
		{
			name:     "non-hex digest column is skipped",
			body:     "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG  k3s\n",
			filename: "k3s",
			wantErr:  true,
		},
		{
			name:     "63-character digest is rejected (off-by-one)",
			body:     "000000000000000000000000000000000000000000000000000000000000000  k3s\n",
			filename: "k3s",
			wantErr:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, "hash")
			if err := os.WriteFile(path, []byte(c.body), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			got, err := parseHashFile(path, c.filename)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if c.wantErr {
				if c.wantCorrupt && err != nil &&
					!contains(err.Error(), "corrupt download") {
					t.Errorf("expected corrupt-download phrasing, got %v", err)
				}
				return
			}
			if got != c.wantHash {
				t.Errorf("got %q, want %q", got, c.wantHash)
			}
		})
	}
}

// TestParseK3sVersion covers the version-string parser. The
// version line may appear in either order relative to the
// `go version …` line; empty output must map to "" so
// k3sGetVersion can substitute k3sZeroVersion.
func TestParseK3sVersion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"k3s line first", "k3s version v1.34.2+k3s1 (abc1234)\ngo version go1.22.0\n", "v1.34.2+k3s1"},
		{"go line first", "go version go1.22.0\nk3s version v1.34.2+k3s1 (abc1234)\n", "v1.34.2+k3s1"},
		{"empty", "", ""},
		{"wrong prefix", "rancher version v1.34.2+k3s1 (abc1234)\n", ""},
		{"single field", "k3s\n", ""},
		{"two fields", "k3s version\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseK3sVersion(c.in); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestUpdateFailed pins the retry-gate semantics. The cached
// KubeClusterUpdateStatus is staged via kcus.SetForTest so the
// test exercises updateFailed's logic without touching the
// pubsub layer.
//
// The load-bearing case is "Status==failed for a DIFFERENT
// destination version" — that must NOT block the current
// generation. Equally important: no cached status (subscription
// hasn't delivered, or delete) must NOT block convergence either
// — we err on the side of retrying rather than stranding the
// device.
func TestUpdateFailed(t *testing.T) {
	cases := []struct {
		name string
		seed *types.KubeClusterUpdateStatus // nil = no delivery yet
		want bool
	}{
		{
			name: "no delivery -> not failed",
			seed: nil,
			want: false,
		},
		{
			name: "Status=failed and version matches -> failed",
			seed: &types.KubeClusterUpdateStatus{
				Status:                       types.CompStatusFailed,
				DestinationKubeUpdateVersion: uint32(KubeVersion),
			},
			want: true,
		},
		{
			name: "Status=failed but version is for a previous generation -> not failed",
			seed: &types.KubeClusterUpdateStatus{
				Status:                       types.CompStatusFailed,
				DestinationKubeUpdateVersion: uint32(KubeVersion + 1),
			},
			want: false,
		},
		{
			name: "Status=success for our version -> not failed",
			seed: &types.KubeClusterUpdateStatus{
				Status:                       types.CompStatusCompleted,
				DestinationKubeUpdateVersion: uint32(KubeVersion),
			},
			want: false,
		},
		{
			name: "Status=in-progress for our version -> not failed",
			seed: &types.KubeClusterUpdateStatus{
				Status:                       types.CompStatusInProgress,
				DestinationKubeUpdateVersion: uint32(KubeVersion),
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kcus.ResetForTest()
			t.Cleanup(kcus.ResetForTest)
			if c.seed != nil {
				kcus.SetForTest(*c.seed)
			}
			if got := updateFailed(); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}


// TestK3sArchSuffixRejectsUnsupportedArch pins the upgrade-time
// safety net: silently substituting amd64 for an unsupported arch
// would have downloaded a binary that the kernel cannot exec, with
// the resulting "exec format error" surfacing far from the actual
// fault.
func TestK3sArchSuffixOnlyAcceptsKnownArches(t *testing.T) {
	// We can't easily flip runtime.GOARCH from a test, but the
	// behaviour we can pin: whatever the test host returns must
	// itself be in the supported set (test is run on amd64 or
	// arm64 only).
	arch, err := k3sArchSuffix()
	if err != nil {
		t.Fatalf("expected amd64 or arm64 host, got err=%v", err)
	}
	if arch != "amd64" && arch != "arm64" {
		t.Errorf("got %q, want one of amd64/arm64", arch)
	}
	if suffix := k3sBinarySuffix("arm64"); suffix != "-arm64" {
		t.Errorf("k3sBinarySuffix(arm64) = %q, want -arm64", suffix)
	}
	if suffix := k3sBinarySuffix("amd64"); suffix != "" {
		t.Errorf("k3sBinarySuffix(amd64) = %q, want empty", suffix)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
