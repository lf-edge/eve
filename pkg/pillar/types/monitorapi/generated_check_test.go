// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// rustOutRel is the committed generated Rust file, relative to this package
// (pkg/pillar/types/monitorapi -> pkg/monitor/src/ipc).
var rustOutRel = filepath.Join("..", "..", "..", "monitor", "src", "ipc", "monitorapi.gen.rs")

// TestGeneratedUpToDate is the CI drift-gate: it regenerates both the Go codec
// and the Rust contract into a temp dir and fails if they differ from the
// committed files. CI never writes generated code — developers run
// `go generate ./types/monitorapi/...` and commit the result; this test
// enforces that they did.
func TestGeneratedUpToDate(t *testing.T) {
	tmp := t.TempDir()
	gotRust := filepath.Join(tmp, "monitorapi.gen.rs")

	cmd := exec.Command("go", "run", "./internal/gen", "-src", ".", "-goout", tmp, "-rust", gotRust)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running generator failed: %v\n%s", err, out)
	}

	assertSame(t, filepath.Join(tmp, "union_json.gen.go"), "union_json.gen.go")

	// The Rust comparison needs the sibling pkg/monitor checkout. EVE's
	// `make test` builds pillar in isolation without it; there we skip this
	// half — the Rust Tests workflow runs the full gate against a complete
	// checkout (see .github/workflows/rust-tests.yml).
	if _, err := os.Stat(filepath.Dir(rustOutRel)); err != nil {
		t.Logf("skipping Rust drift check: %s not present (isolated pillar test env)", filepath.Dir(rustOutRel))
		return
	}
	assertSame(t, gotRust, rustOutRel)
}

func assertSame(t *testing.T, generated, committed string) {
	t.Helper()
	got, err := os.ReadFile(generated)
	if err != nil {
		t.Fatalf("reading freshly generated %s: %v", generated, err)
	}
	want, err := os.ReadFile(committed)
	if err != nil {
		t.Fatalf("reading committed %s: %v (was it generated/committed?)", committed, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is out of date.\n"+
			"Run `go generate ./types/monitorapi/...` in pkg/pillar and commit the result.",
			committed)
	}
}
