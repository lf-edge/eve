// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"
)

// handleGlobalConfigImpl rejects any key other than "global". We don't
// drive the agentlog.HandleGlobalConfig branch (that needs a real
// pubsub.Subscription with content); the wrong-key fast path is enough
// to confirm the dispatcher.

func TestHandleGlobalConfigImpl_NonGlobalKeyIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	before := tc.ctx.GCInitialized
	handleGlobalConfigImpl(tc.ctx, "not-global", nil)
	if tc.ctx.GCInitialized != before {
		t.Fatal("non-global key must not flip GCInitialized")
	}
}

func TestHandleGlobalConfigDelete_NonGlobalKeyIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	handleGlobalConfigDelete(tc.ctx, "not-global", nil)
}
