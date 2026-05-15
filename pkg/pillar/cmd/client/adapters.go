// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/tls"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
)

// realControllerSender wraps *controllerconn.Client and satisfies controllerSender.
type realControllerSender struct {
	c *controllerconn.Client
}

func newRealControllerSender(c *controllerconn.Client) *realControllerSender {
	return &realControllerSender{c: c}
}

func (r *realControllerSender) GetContextForAllIntfFunctions() (context.Context, context.CancelFunc) {
	return r.c.GetContextForAllIntfFunctions()
}

func (r *realControllerSender) SendOnAllIntf(ctx context.Context, url string,
	body *bytes.Buffer, opts controllerconn.RequestOptions) (controllerconn.SendRetval, error) {
	return r.c.SendOnAllIntf(ctx, url, body, opts)
}

func (r *realControllerSender) RemoveAndVerifyAuthContainer(rv *controllerconn.SendRetval, skipVerify bool) error {
	return r.c.RemoveAndVerifyAuthContainer(rv, skipVerify)
}

func (r *realControllerSender) VerifyProtoSigningCertChain(contents []byte) ([]byte, error) {
	return r.c.VerifyProtoSigningCertChain(contents)
}

func (r *realControllerSender) StoreServerSigningCert(certBytes []byte) error {
	return r.c.StoreServerSigningCert(certBytes)
}

func (r *realControllerSender) UpdateTLSProxyCerts() bool { return r.c.UpdateTLSProxyCerts() }

func (r *realControllerSender) GetTLSConfig(clientCert *tls.Certificate) (*tls.Config, error) {
	return r.c.GetTLSConfig(clientCert)
}

func (r *realControllerSender) TLSConfig() *tls.Config       { return r.c.TLSConfig }
func (r *realControllerSender) SetTLSConfig(tc *tls.Config)  { r.c.TLSConfig = tc }
func (r *realControllerSender) LedManagerDisabled() bool     { return r.c.NoLedManager }
func (r *realControllerSender) SetLedManagerDisabled(b bool) { r.c.NoLedManager = b }
func (r *realControllerSender) SetDeviceNetworkStatus(d *types.DeviceNetworkStatus) {
	r.c.DeviceNetworkStatus = d
}

// realCertStore reads and writes the persistent controller-cert checkpoint.
type realCertStore struct{ log *base.LogObject }

func (r *realCertStore) Read(useBackup bool) ([]byte, error) {
	b, _, err := persist.ReadControllerCerts(r.log, useBackup)
	return b, err
}

func (r *realCertStore) MaybeSave(certBytes []byte) {
	persist.MaybeSaveControllerCerts(r.log, certBytes)
}

// realLedNotifier proxies to ledmanager via utils.UpdateLedManagerConfig.
type realLedNotifier struct{ log *base.LogObject }

func (r *realLedNotifier) Update(pattern types.LedBlinkCount) {
	utils.UpdateLedManagerConfig(r.log, pattern)
}

// nullLedNotifier discards all updates; used when LED suppression is needed
// (currently during fetchCertChain so the cert prefetch does not look like
// the device just came online).
type nullLedNotifier struct{}

func (nullLedNotifier) Update(pattern types.LedBlinkCount) {}

// realHostnameSetter calls /bin/hostname via base.Exec.
type realHostnameSetter struct{ log *base.LogObject }

func (r *realHostnameSetter) Set(hostname string) error {
	out, err := base.Exec(r.log, "/bin/hostname", hostname).CombinedOutput()
	if err != nil {
		r.log.Errorf("hostname command %s failed %s output %s", hostname, err, out)
		return err
	}
	return nil
}
