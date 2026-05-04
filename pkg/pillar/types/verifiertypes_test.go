// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// VerifyImageConfig.Key / LogKey

func TestVerifyImageConfigLogKey(t *testing.T) {
	cfg := VerifyImageConfig{ImageSha256: "abc123"}
	assert.Equal(t, "abc123", cfg.Key())
	assert.Contains(t, cfg.LogKey(), "abc123")
}

// VerifyImageStatus.Key / LogKey

func TestVerifyImageStatusLogKey(t *testing.T) {
	status := VerifyImageStatus{ImageSha256: "def456"}
	assert.Equal(t, "def456", status.Key())
	assert.Contains(t, status.LogKey(), "def456")
}

// VerifyImageConfig / VerifyImageStatus LogCreate / LogModify / LogDelete

func TestVerifyImageConfigLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	cfg := VerifyImageConfig{ImageSha256: "sha256cfg"}
	cfg.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	cfg.LogModify(log, cfg)
	cfg.LogDelete(log)
}

func TestVerifyImageStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	s := VerifyImageStatus{ImageSha256: "sha256status"}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}
