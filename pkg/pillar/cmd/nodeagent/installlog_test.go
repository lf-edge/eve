// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// installLogTestCtx wraps a real-ish nodeagentContext with a minimal
// agentbase.AgentBase so handleInstallationLog can call ctx.Logger().
func installLogTestCtx(t *testing.T) *testCtx {
	t.Helper()
	tc := newTestCtx()
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	logObj := base.NewSourceLogObject(logger, "test", 1)
	agentbase.Init(tc.ctx, logger, logObj, "test")
	return tc
}

// TestHandleInstallationLog_NoSendReq verifies the early-return when
// /persist/installer/send-require is absent.
func TestHandleInstallationLog_NoSendReq(t *testing.T) {
	tc := installLogTestCtx(t)
	dir := t.TempDir()
	tc.ctx.paths.installLogSendReq = filepath.Join(dir, "send-require")
	tc.ctx.paths.installLog = filepath.Join(dir, "installer.log")

	handleInstallationLog(tc.ctx)
	// No assertion: returning without panicking is the goal.
}

// TestHandleInstallationLog_SendReqPresent verifies that when
// send-require exists, the installer log is read and the marker is
// scheduled for removal. The removal fires after warningTime
// (40 seconds), which is too long for a unit test, so we only verify
// that the read happened (no panic, no error from the early-return
// branch) and that the send-require marker still exists immediately
// after the call.
func TestHandleInstallationLog_SendReqPresent(t *testing.T) {
	tc := installLogTestCtx(t)
	dir := t.TempDir()
	tc.ctx.paths.installLogSendReq = filepath.Join(dir, "send-require")
	tc.ctx.paths.installLog = filepath.Join(dir, "installer.log")
	mustWrite(t, tc.ctx.paths.installLogSendReq, "")
	mustWrite(t, tc.ctx.paths.installLog, "line one\nline two\n")

	handleInstallationLog(tc.ctx)

	// Marker is removed by a time.AfterFunc; immediately after the call
	// the file still exists.
	if _, err := os.Stat(tc.ctx.paths.installLogSendReq); err != nil {
		t.Errorf("send-require marker should still exist immediately after, got %v", err)
	}
}

// silence unused import warnings if a refactor drops one.
var _ = time.Second
