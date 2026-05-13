// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"net/http"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func newFetchCtx(sender *fakeControllerSender, store *fakeCertStore) *clientContext {
	return &clientContext{
		sender:            sender,
		certStore:         store,
		led:               &recordingLedNotifier{},
		serverNameAndPort: "test.example:8080",
	}
}

// A valid (empty) cert chain proto marshals to zero bytes, which compares
// equal to itself across calls — the only thing parseKeys cares about is
// that proto.Unmarshal succeeds.
var validCertBytes = []byte{}

func TestFetchCertChain_ServerReturnsV1NotSupportedStatuses(t *testing.T) {
	statuses := []int{
		http.StatusNotFound,
		http.StatusUnauthorized,
		http.StatusNotImplemented,
		http.StatusBadRequest,
	}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			sender := &fakeControllerSender{sends: []sendResponse{
				{rv: controllerconn.SendRetval{HTTPResp: httpResp(status, "application/x-proto-binary")}},
			}}
			store := &fakeCertStore{}
			ctx := newFetchCtx(sender, store)

			ok := ctx.fetchCertChain(&testTLSCfg, 0)
			if ok {
				t.Errorf("fetchCertChain ok = true, want false on %s", http.StatusText(status))
			}
			if len(store.saved) != 0 {
				t.Errorf("certStore.saved = %d entries, want 0", len(store.saved))
			}
		})
	}
}

func TestFetchCertChain_VerifyChainFailureReturnsFalse(t *testing.T) {
	sender := &fakeControllerSender{
		sends: []sendResponse{
			{rv: controllerconn.SendRetval{
				HTTPResp:     httpResp(http.StatusOK, "application/x-proto-binary"),
				RespContents: validCertBytes,
			}},
		},
		verifyChainErr: errors.New("bad signature"),
	}
	store := &fakeCertStore{}
	ctx := newFetchCtx(sender, store)

	ok := ctx.fetchCertChain(&testTLSCfg, 0)
	if ok {
		t.Error("fetchCertChain ok = true, want false on verify failure")
	}
	if len(store.saved) != 0 {
		t.Errorf("certStore.saved = %d, want 0", len(store.saved))
	}
}

func TestFetchCertChain_StoreSigningFailureReturnsFalse(t *testing.T) {
	sender := &fakeControllerSender{
		sends: []sendResponse{
			{rv: controllerconn.SendRetval{
				HTTPResp:     httpResp(http.StatusOK, "application/x-proto-binary"),
				RespContents: validCertBytes,
			}},
		},
		verifyChain:     []byte("signer"),
		storeSigningErr: errors.New("disk full"),
	}
	store := &fakeCertStore{}
	ctx := newFetchCtx(sender, store)

	if ok := ctx.fetchCertChain(&testTLSCfg, 0); ok {
		t.Error("fetchCertChain ok = true, want false on StoreServerSigningCert failure")
	}
}

func TestFetchCertChain_HappyPath_NoPreviousCheckpoint(t *testing.T) {
	sender := &fakeControllerSender{
		sends: []sendResponse{
			{rv: controllerconn.SendRetval{
				HTTPResp:     httpResp(http.StatusOK, "application/x-proto-binary"),
				RespContents: validCertBytes,
			}},
		},
		verifyChain: []byte("signer-cert"),
	}
	store := &fakeCertStore{}
	ctx := newFetchCtx(sender, store)

	if ok := ctx.fetchCertChain(&testTLSCfg, 0); !ok {
		t.Fatal("fetchCertChain ok = false, want true on happy path")
	}
	if len(store.saved) != 1 {
		t.Errorf("certStore.saved = %d, want 1 entry", len(store.saved))
	}
	if string(sender.storedSigningCert) != "signer-cert" {
		t.Errorf("stored signing cert = %q, want %q", sender.storedSigningCert, "signer-cert")
	}
}

func TestFetchCertChain_NoSaveWhenCheckpointMatches(t *testing.T) {
	sender := &fakeControllerSender{
		sends: []sendResponse{
			{rv: controllerconn.SendRetval{
				HTTPResp:     httpResp(http.StatusOK, "application/x-proto-binary"),
				RespContents: validCertBytes,
			}},
		},
		verifyChain: []byte("signer"),
	}
	store := &fakeCertStore{primary: validCertBytes}
	ctx := newFetchCtx(sender, store)

	if ok := ctx.fetchCertChain(&testTLSCfg, 0); !ok {
		t.Fatal("fetchCertChain ok = false, want true when checkpoint matches")
	}
	if len(store.saved) != 0 {
		t.Errorf("certStore.saved = %d, want no save when checkpoint matches", len(store.saved))
	}
}

func TestFetchCertChain_LedSuppressionRestoredAfter(t *testing.T) {
	sender := &fakeControllerSender{
		sends: []sendResponse{
			{rv: controllerconn.SendRetval{HTTPResp: httpResp(http.StatusNotFound, "application/x-proto-binary")}},
		},
	}
	store := &fakeCertStore{}
	ctx := newFetchCtx(sender, store)

	// Caller starts with LED-manager enabled.
	sender.SetLedManagerDisabled(false)
	_ = ctx.fetchCertChain(&testTLSCfg, 0)
	if sender.LedManagerDisabled() {
		t.Error("LED-manager left disabled after fetchCertChain; should be restored")
	}
}

func TestFetchCertChain_NetworkErrorReturnsFalse(t *testing.T) {
	sender := &fakeControllerSender{sends: []sendResponse{
		{rv: controllerconn.SendRetval{Status: types.SenderStatusRefused}, err: errors.New("net err")},
	}}
	store := &fakeCertStore{}
	ctx := newFetchCtx(sender, store)

	if ok := ctx.fetchCertChain(&testTLSCfg, 0); ok {
		t.Error("fetchCertChain ok = true, want false on network error")
	}
}

func TestHaveControllerCertsCheckpoint(t *testing.T) {
	ctx := &clientContext{certStore: &fakeCertStore{}}
	if ctx.haveControllerCertsCheckpoint() {
		t.Error("want false on empty store")
	}
	ctx.certStore = &fakeCertStore{primary: []byte("x")}
	if !ctx.haveControllerCertsCheckpoint() {
		t.Error("want true when primary present")
	}
	ctx.certStore = &fakeCertStore{backup: []byte("x")}
	if !ctx.haveControllerCertsCheckpoint() {
		t.Error("want true when backup present")
	}
}
