// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"errors"
	"testing"

	"github.com/lf-edge/eve/evetest/constants"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestLiveImageChunkWriterReturnsSendError covers the broker's early close on
// an already-staged upload: the underlying send failing must surface as a
// Write error rather than being silently discarded, or the caller (a
// tar.Writer) cannot tell a benign early close from a successful write.
func TestLiveImageChunkWriterReturnsSendError(t *testing.T) {
	wantErr := errors.New("boom")
	w := &liveImageChunkWriter{send: func(data []byte) error {
		return wantErr
	}}
	n, err := w.Write([]byte("data"))
	if n != 0 || err != wantErr {
		t.Fatalf("Write = (%d, %v), want (0, %v)", n, err, wantErr)
	}
}

// TestLiveImageChunkWriterSkipsEmptyWrite verifies that liveImageChunkWriter
// honors the io.Writer contract for a zero-length Write: it must return
// (0, nil) without invoking send, since archive/tar and io.CopyBuffer can
// legitimately produce such a call and the broker should never see an empty
// chunk on the wire.
func TestLiveImageChunkWriterSkipsEmptyWrite(t *testing.T) {
	var sent [][]byte
	w := &liveImageChunkWriter{send: func(data []byte) error {
		sent = append(sent, data)
		return nil
	}}

	for _, p := range [][]byte{nil, {}} {
		n, err := w.Write(p)
		if n != 0 || err != nil {
			t.Fatalf("Write(%#v) = (%d, %v), want (0, nil)", p, n, err)
		}
	}
	if len(sent) != 0 {
		t.Fatalf("send called %d times for empty writes, want 0", len(sent))
	}

	payload := []byte("data")
	n, err := w.Write(payload)
	if n != len(payload) || err != nil {
		t.Fatalf("Write(%q) = (%d, %v), want (%d, nil)", payload, n, err, len(payload))
	}
	if len(sent) != 1 || string(sent[0]) != string(payload) {
		t.Fatalf("send got %v, want one call with %q", sent, payload)
	}
}

func TestIsMissingSDNImageErr(t *testing.T) {
	withInfo := func(code codes.Code, reason, domain string) error {
		st, err := status.New(code, "pull failed").WithDetails(
			&errdetails.ErrorInfo{Reason: reason, Domain: domain})
		if err != nil {
			t.Fatal(err)
		}
		return st.Err()
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("boom"), false},
		{"no details", status.Error(codes.FailedPrecondition, "pull failed"), false},
		{"typed error", withInfo(codes.FailedPrecondition,
			constants.MissingSDNImageErrorReason, constants.BrokerErrorDomain), true},
		{"other reason", withInfo(codes.FailedPrecondition,
			"OTHER", constants.BrokerErrorDomain), false},
		{"other code", withInfo(codes.Internal,
			constants.MissingSDNImageErrorReason, constants.BrokerErrorDomain), false},
	}
	for _, tc := range tests {
		if got := isMissingSDNImageErr(tc.err); got != tc.want {
			t.Errorf("%s: isMissingSDNImageErr = %v, want %v", tc.name, got, tc.want)
		}
	}
}
