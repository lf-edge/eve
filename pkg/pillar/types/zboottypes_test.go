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

// ZbootConfig.Key / LogKey

func TestZbootConfigLogKey(t *testing.T) {
	cfg := ZbootConfig{PartitionLabel: "IMGA"}
	assert.Equal(t, "IMGA", cfg.Key())
	assert.Contains(t, cfg.LogKey(), "IMGA")
}

// ZbootStatus.Key / LogKey

func TestZbootStatusLogKey(t *testing.T) {
	status := ZbootStatus{PartitionLabel: "IMGB", ShortVersion: "1.0.0"}
	assert.Equal(t, "IMGB", status.Key())
	assert.Contains(t, status.LogKey(), "IMGB")
}

// ZbootConfig / ZbootStatus LogCreate / LogModify / LogDelete

func TestZbootConfigLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	cfg := ZbootConfig{PartitionLabel: "IMGA"}
	cfg.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	cfg.LogModify(log, cfg)
	cfg.LogDelete(log)
}

func TestZbootStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	status := ZbootStatus{PartitionLabel: "IMGB"}
	status.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	status.LogModify(log, status)
	status.LogDelete(log)
}
