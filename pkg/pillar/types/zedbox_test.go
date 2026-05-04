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

// ServiceInitStatus.Key / LogKey

func TestServiceInitStatusLogKey(t *testing.T) {
	s := ServiceInitStatus{ServiceName: "zedagent"}
	assert.Equal(t, "zedagent", s.Key())
	assert.Contains(t, s.LogKey(), "zedagent")
}

// ServiceInitStatus LogCreate / LogModify / LogDelete

func TestServiceInitStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	s := ServiceInitStatus{ServiceName: "zedagent"}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}
