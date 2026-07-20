// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// TestDoUpdateContentTreeRejectsMalformedSha256 verifies that a content tree whose
// (controller-supplied) sha256 is not a strict 64-hex digest is failed with an error
// set on its ContentTreeStatus, rather than being processed. That error is what the
// controller sees reported back (PublishContentInfoToZedCloud copies it into
// ZInfoContentTree.Err), so a malformed digest is signalled instead of silently
// dropped. It also prevents the crafted digest from ever reaching the downloader /
// verifier, where it would otherwise be joined into on-disk paths (path traversal).
func TestDoUpdateContentTreeRejectsMalformedSha256(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-volumemgr", 0)
	ctx := &volumemgrContext{}

	// A malformed digest must be rejected with an error on the status; the top-of-
	// function guard returns before any pubsub/ctx access, so a bare context is enough.
	bad := []string{
		"../../../../../../persist/secret",
		"..",
		"foo/bar",
		"not-hex",
		"9f86d081884c7d659a2feaa0c55ad015", // too short
	}
	for _, sha := range bad {
		status := &types.ContentTreeStatus{
			ContentSha256: sha,
			DisplayName:   "test",
			State:         types.INITIAL,
		}
		changed, _ := doUpdateContentTree(ctx, status)
		if !changed {
			t.Errorf("doUpdateContentTree(%q) reported no change, expected error set", sha)
		}
		if !status.HasError() {
			t.Errorf("doUpdateContentTree(%q) did not set an error on the status", sha)
		}
	}

	// An empty sha256 (unresolved OCI tag) must NOT be rejected by this guard.
	emptyStatus := &types.ContentTreeStatus{
		ContentSha256:         "",
		DisplayName:           "test-empty",
		State:                 types.INITIAL,
		AllDatastoresResolved: false, // defers further processing, so we only exercise the guard
	}
	doUpdateContentTree(ctx, emptyStatus)
	if emptyStatus.HasError() {
		t.Errorf("doUpdateContentTree set an error for an empty (unresolved) sha256: %s",
			emptyStatus.Error)
	}
}
