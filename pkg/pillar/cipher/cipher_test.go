// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cipher

import (
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

func testDecryptContext() *DecryptCipherContext {
	return &DecryptCipherContext{
		Log:          base.NewSourceLogObject(logrus.StandardLogger(), "test", 0),
		AgentName:    "test",
		AgentMetrics: NewAgentMetrics("test"),
	}
}

// undecryptableBlock fails inside DecryptCipherBlock on the empty-payload check,
// before any controller/edge-node cert lookup, so no subscriptions are needed.
func undecryptableBlock() types.CipherBlockStatus {
	return types.CipherBlockStatus{
		CipherBlockID:   "test-block",
		CipherContextID: "test-context",
		IsCipher:        true,
	}
}

func TestGetCipherMarshalledDataFailsClosed(t *testing.T) {
	ctx := testDecryptContext()

	status, clearBytes, err := GetCipherMarshalledData(ctx, undecryptableBlock())
	if err == nil {
		t.Fatalf("decryption failure reported as success (clearBytes=%v)", clearBytes)
	}
	if !status.HasError() {
		t.Fatal("decryption failure left the cipher block status un-errored")
	}
}

func TestGetCipherCredentialsFailsClosed(t *testing.T) {
	ctx := testDecryptContext()

	status, decBlock, err := GetCipherCredentials(ctx, undecryptableBlock())
	if err == nil {
		t.Fatalf("decryption failure reported as success (decBlock=%+v)", decBlock)
	}
	if !status.HasError() {
		t.Fatal("decryption failure left the cipher block status un-errored")
	}
	if !reflect.DeepEqual(decBlock, types.EncryptionBlock{}) {
		t.Fatalf("expected no plaintext on failure, got %+v", decBlock)
	}
}

// The !IsCipher branch is a misuse guard, not a decryption failure: callers are
// expected to check IsCipher and supply their own cleartext, so it stays
// non-fatal.
func TestGetCipherMarshalledDataNotCipher(t *testing.T) {
	ctx := testDecryptContext()

	status := types.CipherBlockStatus{CipherBlockID: "test-block"}
	outStatus, _, err := GetCipherMarshalledData(ctx, status)
	if err != nil {
		t.Fatalf("expected no error for a non-cipher block, got %v", err)
	}
	if outStatus.HasError() {
		t.Fatal("non-cipher block should not be marked in-error")
	}
}

// A failed decrypt must be counted once: GetCipherMarshalledData records it and
// GetCipherCredentials only propagates the error.
func TestGetCipherCredentialsCountsFailureOnce(t *testing.T) {
	ctx := testDecryptContext()

	if _, _, err := GetCipherCredentials(ctx, undecryptableBlock()); err == nil {
		t.Fatal("decryption failure reported as success")
	}

	m := ctx.AgentMetrics.metrics
	if m.FailureCount != 1 {
		t.Errorf("FailureCount = %d, want 1", m.FailureCount)
	}
	if m.SuccessCount != 0 {
		t.Errorf("SuccessCount = %d, want 0", m.SuccessCount)
	}
	if got := m.TypeCounters[types.DecryptFailed]; got != 1 {
		t.Errorf("TypeCounters[DecryptFailed] = %d, want 1", got)
	}
	if got := m.TypeCounters[types.Invalid]; got != 0 {
		t.Errorf("TypeCounters[Invalid] = %d, want 0", got)
	}
}

// A block that arrived already in error never reached decryption, so it counts
// as NotReady and not as a decryption failure.
func TestGetCipherCredentialsNotReadyCountedAsNotReady(t *testing.T) {
	ctx := testDecryptContext()
	status := undecryptableBlock()
	status.SetErrorNow("cipher context not found")

	if _, _, err := GetCipherCredentials(ctx, status); err == nil {
		t.Fatal("not-ready cipher block reported as success")
	}

	m := ctx.AgentMetrics.metrics
	if m.FailureCount != 1 {
		t.Errorf("FailureCount = %d, want 1", m.FailureCount)
	}
	if got := m.TypeCounters[types.NotReady]; got != 1 {
		t.Errorf("TypeCounters[NotReady] = %d, want 1", got)
	}
	if got := m.TypeCounters[types.DecryptFailed]; got != 0 {
		t.Errorf("TypeCounters[DecryptFailed] = %d, want 0", got)
	}
}
