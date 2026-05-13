// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/tls"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// controllerSender is the subset of *controllerconn.Client's methods used by cmd/client.
// The real implementation wraps a *controllerconn.Client; tests inject a fake.
type controllerSender interface {
	GetContextForAllIntfFunctions() (context.Context, context.CancelFunc)
	SendOnAllIntf(ctx context.Context, url string, body *bytes.Buffer,
		opts controllerconn.RequestOptions) (controllerconn.SendRetval, error)
	RemoveAndVerifyAuthContainer(rv *controllerconn.SendRetval, skipVerify bool) error
	VerifyProtoSigningCertChain(contents []byte) ([]byte, error)
	StoreServerSigningCert(certBytes []byte) error
	UpdateTLSProxyCerts() bool
	GetTLSConfig(clientCert *tls.Certificate) (*tls.Config, error)
	TLSConfig() *tls.Config
	SetTLSConfig(*tls.Config)
	SetDeviceNetworkStatus(*types.DeviceNetworkStatus)
	LedManagerDisabled() bool
	SetLedManagerDisabled(bool)
}

// certStore wraps the on-disk controller-cert checkpoint store. Tests inject
// an in-memory impl.
type certStore interface {
	Read(useBackup bool) ([]byte, error)
	MaybeSave(certBytes []byte)
}

// ledNotifier abstracts ledmanager pattern updates so tests can record them.
type ledNotifier interface {
	Update(pattern types.LedBlinkCount)
}

// hostnameSetter abstracts the /bin/hostname call made after onboarding.
type hostnameSetter interface {
	Set(hostname string) error
}
