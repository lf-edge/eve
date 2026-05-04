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

// CipherContext.Key / ControllerCertKey / EdgeNodeCertKey / LogKey

func TestCipherContextLogKey(t *testing.T) {
	ctrlHash := []byte{0x01, 0x02}
	devHash := []byte{0x03, 0x04}
	ctx := CipherContext{
		ContextID:          "ctx-123",
		ControllerCertHash: ctrlHash,
		DeviceCertHash:     devHash,
	}
	assert.Equal(t, "ctx-123", ctx.Key())
	assert.Equal(t, hex.EncodeToString(ctrlHash), ctx.ControllerCertKey())
	assert.Equal(t, hex.EncodeToString(devHash), ctx.EdgeNodeCertKey())
	assert.Contains(t, ctx.LogKey(), "ctx-123")
}

// CipherBlockStatus.Key / LogKey

func TestCipherBlockStatusLogKey(t *testing.T) {
	status := CipherBlockStatus{CipherBlockID: "block-abc"}
	assert.Equal(t, "block-abc", status.Key())
	assert.Contains(t, status.LogKey(), "block-abc")
}

// CipherContext / CipherBlockStatus LogCreate / LogModify / LogDelete

func TestCipherContextLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	ctx := CipherContext{ContextID: "ctx-test"}
	ctx.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	ctx.LogModify(log, ctx)
	ctx.LogDelete(log)
}

func TestCipherBlockStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	s := CipherBlockStatus{CipherBlockID: "block-test"}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}
