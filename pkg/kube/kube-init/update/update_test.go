// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

// TestUpdateStatusUnfinished pins the condition that decides whether a
// converged pass retroactively finishes a status an earlier step left
// open. A k3s update parks the status on "k3s completed" across its
// reboot, and an interrupted pass leaves an in-flight step. A failed
// status is terminal and must be kept, and a completed component other
// than k3s is the pass's own last word.
func TestUpdateStatusUnfinished(t *testing.T) {
	cases := []struct {
		name string
		seed types.KubeClusterUpdateStatus
		want bool
	}{
		{
			name: "k3s completed -> unfinished",
			seed: types.KubeClusterUpdateStatus{
				Component: types.CompK3s,
				Status:    types.CompStatusCompleted,
			},
			want: true,
		},
		{
			name: "k3s download -> unfinished",
			seed: types.KubeClusterUpdateStatus{
				Component: types.CompK3s,
				Status:    types.CompStatusDownload,
			},
			want: true,
		},
		{
			name: "longhorn in progress -> unfinished",
			seed: types.KubeClusterUpdateStatus{
				Component: types.CompLonghorn,
				Status:    types.CompStatusInProgress,
			},
			want: true,
		},
		{
			name: "k3s failed -> kept",
			seed: types.KubeClusterUpdateStatus{
				Component: types.CompK3s,
				Status:    types.CompStatusFailed,
			},
			want: false,
		},
		{
			name: "longhorn failed -> kept",
			seed: types.KubeClusterUpdateStatus{
				Component: types.CompLonghorn,
				Status:    types.CompStatusFailed,
			},
			want: false,
		},
		{
			name: "longhorn completed -> finished",
			seed: types.KubeClusterUpdateStatus{
				Component: types.CompLonghorn,
				Status:    types.CompStatusCompleted,
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := updateStatusUnfinished(c.seed); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// fakeUpdateComponent installs a stand-in for the update-component
// helper that logs each invocation's action and exits with the code
// the test assigns to that action, printing the given text first.
type fakeUpdateComponent struct {
	dir string
}

func newFakeUpdateComponent(t *testing.T) *fakeUpdateComponent {
	t.Helper()
	f := &fakeUpdateComponent{dir: t.TempDir()}
	script := `#!/bin/sh
action=""
for arg in "$@"; do
	case "$arg" in
	--compare|--upgrade|--check-comp-ready|--finalize) action="${arg#--}" ;;
	esac
done
echo "$action" >> "` + f.dir + `/calls"
[ -f "` + f.dir + `/$action.out" ] && cat "` + f.dir + `/$action.out" >&2
[ -f "` + f.dir + `/$action.rc" ] && exit "$(cat "` + f.dir + `/$action.rc")"
exit 0
`
	path := filepath.Join(f.dir, "update-component")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake update-component: %v", err)
	}

	oldPath, oldApplied := compUpdatePath, AppliedKubeVersion
	oldInterval, oldTimeout := readyPollInterval, readyPollTimeout
	compUpdatePath = path
	// No applied version: PublishUpdateStatus stays a no-op.
	AppliedKubeVersion = filepath.Join(f.dir, "applied-kube-version")
	readyPollInterval = 10 * time.Millisecond
	readyPollTimeout = 200 * time.Millisecond
	passFailed.Store(false)
	kcus.ResetForTest()
	t.Cleanup(func() {
		compUpdatePath, AppliedKubeVersion = oldPath, oldApplied
		readyPollInterval, readyPollTimeout = oldInterval, oldTimeout
		passFailed.Store(false)
		kcus.ResetForTest()
	})
	return f
}

// set makes the helper exit with rc on action, after printing out.
func (f *fakeUpdateComponent) set(t *testing.T, action string, rc int, out string) {
	t.Helper()
	for name, body := range map[string]string{
		action + ".rc":  strconv.Itoa(rc),
		action + ".out": out,
	} {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// calls returns the actions the helper was invoked with, consecutive
// repeats collapsed, since the ready poll may run more than once.
func (f *fakeUpdateComponent) calls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	var seq []string
	for _, c := range strings.Fields(string(data)) {
		if len(seq) == 0 || seq[len(seq)-1] != c {
			seq = append(seq, c)
		}
	}
	return strings.Join(seq, " ")
}

// TestUpgradeComponent drives one component through the pass against a
// fake helper. Multus is used because it needs no cluster to decide
// whether it is installed.
func TestUpgradeComponent(t *testing.T) {
	t.Run("already at version runs the owed finalize only", func(t *testing.T) {
		f := newFakeUpdateComponent(t)
		if err := upgradeComponent(context.Background(), CompMultus); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := f.calls(t); got != "compare finalize" {
			t.Errorf("helper calls = %q", got)
		}
	})

	t.Run("drift upgrades, waits ready, then finalizes", func(t *testing.T) {
		f := newFakeUpdateComponent(t)
		f.set(t, "compare", 1, "")
		if err := upgradeComponent(context.Background(), CompMultus); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := f.calls(t); got != "compare upgrade check-comp-ready finalize" {
			t.Errorf("helper calls = %q", got)
		}
		if passFailed.Load() {
			t.Error("a successful upgrade latched the pass as failed")
		}
	})

	t.Run("denied upgrade is terminal and carries the reason", func(t *testing.T) {
		f := newFakeUpdateComponent(t)
		f.set(t, "compare", 1, "")
		f.set(t, "upgrade", 1, "denied upgrade srcVer:v1.9.1 dstVer:v1.13.0")
		err := upgradeComponent(context.Background(), CompMultus)
		if !errors.Is(err, ErrUpdateFailed) {
			t.Fatalf("err = %v, want ErrUpdateFailed", err)
		}
		if !contains(err.Error(), "denied upgrade srcVer:v1.9.1") {
			t.Errorf("err = %v, want the helper's reason", err)
		}
		if got := f.calls(t); got != "compare upgrade" {
			t.Errorf("helper calls = %q", got)
		}
		if !passFailed.Load() {
			t.Error("a failed upgrade did not latch the pass as failed")
		}
	})

	t.Run("never ready is terminal and names what is not ready", func(t *testing.T) {
		f := newFakeUpdateComponent(t)
		f.set(t, "compare", 1, "")
		f.set(t, "check-comp-ready", 1, "volumes not yet on engine v1.13.0: pvc-1")
		err := upgradeComponent(context.Background(), CompMultus)
		if !errors.Is(err, ErrUpdateFailed) {
			t.Fatalf("err = %v, want ErrUpdateFailed", err)
		}
		if !contains(err.Error(), "pvc-1") {
			t.Errorf("err = %v, want the helper's detail", err)
		}
		if got := f.calls(t); got != "compare upgrade check-comp-ready" {
			t.Errorf("helper calls = %q", got)
		}
	})

	t.Run("finalize failure is terminal", func(t *testing.T) {
		f := newFakeUpdateComponent(t)
		f.set(t, "compare", 1, "")
		f.set(t, "finalize", 1, "longhorn-manager not ready")
		err := upgradeComponent(context.Background(), CompMultus)
		if !errors.Is(err, ErrUpdateFailed) {
			t.Fatalf("err = %v, want ErrUpdateFailed", err)
		}
		if got := f.calls(t); got != "compare upgrade check-comp-ready finalize" {
			t.Errorf("helper calls = %q", got)
		}
	})

	t.Run("an upgrade that did not start is deferred, not terminal", func(t *testing.T) {
		f := newFakeUpdateComponent(t)
		f.set(t, "compare", 1, "")
		f.set(t, "upgrade", compUpdateExitNotStarted, "not ready at version:v1.9.1")
		err := upgradeComponent(context.Background(), CompMultus)
		if !errors.Is(err, ErrUpdateDeferred) || errors.Is(err, ErrUpdateFailed) {
			t.Fatalf("err = %v, want ErrUpdateDeferred only", err)
		}
		if passFailed.Load() {
			t.Error("a deferred upgrade latched the pass as failed")
		}
	})

	interrupted := func() {
		kcus.SetForTest(types.KubeClusterUpdateStatus{
			Component:                    types.CompMultus,
			Status:                       types.CompStatusInProgress,
			DestinationKubeUpdateVersion: uint32(KubeVersion),
		})
	}

	t.Run("an interrupted update waits for ready before finalizing", func(t *testing.T) {
		f := newFakeUpdateComponent(t)
		interrupted()
		if err := upgradeComponent(context.Background(), CompMultus); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := f.calls(t); got != "compare check-comp-ready finalize" {
			t.Errorf("helper calls = %q", got)
		}
	})

	t.Run("an interrupted update that never gets ready is terminal", func(t *testing.T) {
		f := newFakeUpdateComponent(t)
		interrupted()
		f.set(t, "check-comp-ready", 1, "volumes not yet on engine v1.13.0: pvc-1")
		err := upgradeComponent(context.Background(), CompMultus)
		if !errors.Is(err, ErrUpdateFailed) {
			t.Fatalf("err = %v, want ErrUpdateFailed", err)
		}
		if got := f.calls(t); got != "compare check-comp-ready" {
			t.Errorf("helper calls = %q", got)
		}
	})

	t.Run("a cancelled pass is not terminal", func(t *testing.T) {
		newFakeUpdateComponent(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := failUpdate(ctx, CompMultus, "wait ready", ctx.Err())
		if errors.Is(err, ErrUpdateFailed) || passFailed.Load() {
			t.Fatalf("err = %v, passFailed = %v: cancellation latched a failure",
				err, passFailed.Load())
		}
	})

	t.Run("an unusable helper is not terminal", func(t *testing.T) {
		newFakeUpdateComponent(t)
		compUpdatePath = filepath.Join(t.TempDir(), "missing")
		err := upgradeComponent(context.Background(), CompMultus)
		if err == nil || errors.Is(err, ErrUpdateFailed) {
			t.Fatalf("err = %v, want a transient error", err)
		}
		if passFailed.Load() {
			t.Error("a helper that could not run latched the pass as failed")
		}
	})
}

// TestCompPostUpgrade covers the step between a component being
// finalized and its update being reported complete.
func TestCompPostUpgrade(t *testing.T) {
	stub := func(t *testing.T, applied bool, err error) *int {
		t.Helper()
		calls := 0
		old := reapplyTieBreakerLonghorn
		reapplyTieBreakerLonghorn = func(context.Context) (bool, error) {
			calls++
			return applied, err
		}
		t.Cleanup(func() { reapplyTieBreakerLonghorn = old })
		return &calls
	}

	t.Run("longhorn re-applies the tie-breaker config", func(t *testing.T) {
		calls := stub(t, true, nil)
		compPostUpgrade(context.Background(), CompLonghorn)
		if *calls != 1 {
			t.Errorf("re-apply calls = %d, want 1", *calls)
		}
	})

	t.Run("other components do not", func(t *testing.T) {
		calls := stub(t, true, nil)
		for _, comp := range []string{CompMultus, CompKubevirt, CompCDI} {
			compPostUpgrade(context.Background(), comp)
		}
		if *calls != 0 {
			t.Errorf("re-apply calls = %d, want 0", *calls)
		}
	})

	t.Run("a re-apply failure does not fail the pass", func(t *testing.T) {
		stub(t, false, errors.New("api down"))
		compPostUpgrade(context.Background(), CompLonghorn)
		if passFailed.Load() {
			t.Error("pass latched as failed")
		}
	})
}

// TestCheckClusterComponentsAfterFailure pins that a failed pass is not
// run again in the same process, and says so with ErrUpdateFailed.
func TestCheckClusterComponentsAfterFailure(t *testing.T) {
	f := newFakeUpdateComponent(t)
	kcus.ResetForTest()
	t.Cleanup(kcus.ResetForTest)
	if !ComponentPassPending() {
		t.Fatal("a node without an applied version must have a pass pending")
	}
	passFailed.Store(true)
	err := CheckClusterComponents(context.Background())
	if !errors.Is(err, ErrUpdateFailed) {
		t.Fatalf("err = %v, want ErrUpdateFailed", err)
	}
	if _, statErr := os.Stat(filepath.Join(f.dir, "calls")); statErr == nil {
		t.Error("the helper was invoked although the pass had failed")
	}
}

// TestCurlDownloadUsesMgmtProxy pins the regression this fixes: curlDownload
// must route through pillar's cost-aware mgmtproxy (HTTPS_PROXY/NO_PROXY on
// the child's env) exactly like the other one-shot download subprocesses in
// kube-init (e.g. StartContainerd). Without this, the k3s binary download
// goes out via table main directly, which breaks exactly when mgmtproxy
// exists to route around a bad table-main default route.
func TestCurlDownloadUsesMgmtProxy(t *testing.T) {
	dir := t.TempDir()
	envOut := filepath.Join(dir, "env.out")
	fakeCurl := filepath.Join(dir, "curl")
	script := "#!/bin/sh\n" +
		"echo \"HTTPS_PROXY=$HTTPS_PROXY\" > " + envOut + "\n" +
		"echo \"NO_PROXY=$NO_PROXY\" >> " + envOut + "\n"
	if err := os.WriteFile(fakeCurl, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake curl: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)

	if err := curlDownload(context.Background(), "https://example.com/x", filepath.Join(dir, "out")); err != nil {
		t.Fatalf("curlDownload: %v", err)
	}

	got, err := os.ReadFile(envOut)
	if err != nil {
		t.Fatalf("read %s: %v", envOut, err)
	}
	if !strings.Contains(string(got), "HTTPS_PROXY=http://127.0.0.1:5443") {
		t.Errorf("fake curl's env = %q, want HTTPS_PROXY=http://127.0.0.1:5443", got)
	}
	if strings.Contains(string(got), "HTTPS_PROXY=\n") {
		t.Errorf("HTTPS_PROXY was empty: %q", got)
	}
}
