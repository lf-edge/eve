// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// ControllerCert.Key / LogKey

func TestControllerCertLogKey(t *testing.T) {
	hash := []byte{0xde, 0xad, 0xbe, 0xef}
	cert := ControllerCert{CertHash: hash}
	assert.Equal(t, hex.EncodeToString(hash), cert.Key())
	assert.Contains(t, cert.LogKey(), hex.EncodeToString(hash))
}

// ControllerCert LogCreate / LogModify / LogDelete

func TestControllerCertLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	cert := ControllerCert{CertHash: []byte{0x01, 0x02}}
	cert.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	cert.LogModify(log, cert)
	cert.LogDelete(log)
}
