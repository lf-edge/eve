// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// fakeControllerSender satisfies controllerSender for unit tests. Each call
// to SendOnAllIntf consumes the next queued response; queue exhaustion fails
// the call so tests reliably catch unexpected requests.
type fakeControllerSender struct {
	// queued sends; first one consumed per SendOnAllIntf call.
	sends []sendResponse
	// canned verify outputs.
	verifyChain     []byte
	verifyChainErr  error
	storeSigningErr error
	updateProxyCert bool
	// When updateProxyCert is true and proxyCertPool is non-nil, the fake
	// installs the pool onto tlsConfig.RootCAs on UpdateTLSProxyCerts to
	// mirror what the real *controllerconn.Client does.
	proxyCertPool *x509.CertPool
	// canned auth-container verify result.
	authVerifyErr error

	// recorded state
	tlsConfig          *tls.Config
	dns                *types.DeviceNetworkStatus
	ledManagerDisabled bool
	sentURLs           []string
	sentBodies         [][]byte
	storedSigningCert  []byte
	authVerifyCalls    int
}

type sendResponse struct {
	rv  controllerconn.SendRetval
	err error
}

func (f *fakeControllerSender) GetContextForAllIntfFunctions() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

func (f *fakeControllerSender) SendOnAllIntf(_ context.Context, url string,
	body *bytes.Buffer, _ controllerconn.RequestOptions) (controllerconn.SendRetval, error) {
	f.sentURLs = append(f.sentURLs, url)
	if body != nil {
		f.sentBodies = append(f.sentBodies, append([]byte(nil), body.Bytes()...))
	} else {
		f.sentBodies = append(f.sentBodies, nil)
	}
	if len(f.sends) == 0 {
		return controllerconn.SendRetval{}, fmt.Errorf("fakeControllerSender: no canned response for %s", url)
	}
	r := f.sends[0]
	f.sends = f.sends[1:]
	return r.rv, r.err
}

func (f *fakeControllerSender) RemoveAndVerifyAuthContainer(_ *controllerconn.SendRetval, _ bool) error {
	f.authVerifyCalls++
	return f.authVerifyErr
}

func (f *fakeControllerSender) VerifyProtoSigningCertChain(_ []byte) ([]byte, error) {
	return f.verifyChain, f.verifyChainErr
}

func (f *fakeControllerSender) StoreServerSigningCert(b []byte) error {
	f.storedSigningCert = append([]byte(nil), b...)
	return f.storeSigningErr
}

func (f *fakeControllerSender) UpdateTLSProxyCerts() bool {
	if f.updateProxyCert && f.tlsConfig != nil && f.proxyCertPool != nil {
		f.tlsConfig.RootCAs = f.proxyCertPool
	}
	return f.updateProxyCert
}

func (f *fakeControllerSender) GetTLSConfig(_ *tls.Certificate) (*tls.Config, error) {
	return &tls.Config{}, nil
}

func (f *fakeControllerSender) TLSConfig() *tls.Config                              { return f.tlsConfig }
func (f *fakeControllerSender) SetTLSConfig(tc *tls.Config)                         { f.tlsConfig = tc }
func (f *fakeControllerSender) SetDeviceNetworkStatus(d *types.DeviceNetworkStatus) { f.dns = d }
func (f *fakeControllerSender) LedManagerDisabled() bool                            { return f.ledManagerDisabled }
func (f *fakeControllerSender) SetLedManagerDisabled(b bool)                        { f.ledManagerDisabled = b }

// fakeCertStore is an in-memory certStore.
type fakeCertStore struct {
	primary, backup []byte
	saved           [][]byte
}

func (f *fakeCertStore) Read(useBackup bool) ([]byte, error) {
	if useBackup {
		return f.backup, nil
	}
	return f.primary, nil
}

func (f *fakeCertStore) MaybeSave(b []byte) {
	f.saved = append(f.saved, append([]byte(nil), b...))
}

// recordingLedNotifier captures every Update call.
type recordingLedNotifier struct {
	patterns []types.LedBlinkCount
}

func (r *recordingLedNotifier) Update(p types.LedBlinkCount) {
	r.patterns = append(r.patterns, p)
}

// fakeHostnameSetter records each Set call and returns an optional error.
type fakeHostnameSetter struct {
	calls []string
	err   error
}

func (f *fakeHostnameSetter) Set(hostname string) error {
	f.calls = append(f.calls, hostname)
	return f.err
}
