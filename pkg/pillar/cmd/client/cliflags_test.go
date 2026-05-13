// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"flag"
	"testing"
)

// withFatalPanic installs a logger ExitFunc that panics rather than exiting,
// so a test can drive log.Fatal paths and recover. Restored on test cleanup.
func withFatalPanic(t *testing.T) {
	t.Helper()
	prev := logger.ExitFunc
	logger.ExitFunc = func(int) { panic("log.Fatal called") }
	t.Cleanup(func() { logger.ExitFunc = prev })
}

func newClientContextForFlags(ops map[string]bool) *clientContext {
	return &clientContext{operations: ops}
}

func TestProcessAgentSpecificCLIFlags_KnownOps(t *testing.T) {
	ctx := newClientContextForFlags(map[string]bool{
		"selfRegister": false,
		"getUuid":      false,
	})
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx.AddAgentSpecificCLIFlags(fs)
	if err := fs.Parse([]string{"selfRegister", "getUuid"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	ctx.ProcessAgentSpecificCLIFlags(fs)

	if !ctx.operations["selfRegister"] || !ctx.operations["getUuid"] {
		t.Errorf("operations = %v, want both true", ctx.operations)
	}
}

func TestProcessAgentSpecificCLIFlags_UnknownOpFatals(t *testing.T) {
	withFatalPanic(t)
	ctx := newClientContextForFlags(map[string]bool{
		"selfRegister": false,
	})
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx.AddAgentSpecificCLIFlags(fs)
	if err := fs.Parse([]string{"bogus"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected log.Fatal to be reached for unknown arg")
		}
	}()
	ctx.ProcessAgentSpecificCLIFlags(fs)
}
