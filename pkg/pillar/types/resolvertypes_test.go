// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// ResolveConfig.Key / LogKey

func TestResolveConfigLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	cfg := ResolveConfig{DatastoreID: id, Name: "img.tar", Counter: 3}
	expected := fmt.Sprintf("%s+%s+%v", id.String(), "img.tar", 3)
	assert.Equal(t, expected, cfg.Key())
	assert.Contains(t, cfg.LogKey(), expected)
}

// ResolveStatus.Key / LogKey

func TestResolveStatusLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := ResolveStatus{DatastoreID: id, Name: "img.tar", Counter: 5}
	expected := fmt.Sprintf("%s+%s+%v", id.String(), "img.tar", 5)
	assert.Equal(t, expected, status.Key())
	assert.Contains(t, status.LogKey(), expected)
}

// ResolveConfig / ResolveStatus LogCreate / LogModify / LogDelete

func TestResolveConfigLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	cfg := ResolveConfig{DatastoreID: id, Name: "img.tar", Counter: 1}
	cfg.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	cfg.LogModify(log, cfg)
	cfg.LogDelete(log)
}

func TestResolveStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	s := ResolveStatus{DatastoreID: id, Name: "img.tar", Counter: 1}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}
