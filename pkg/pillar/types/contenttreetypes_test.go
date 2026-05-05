// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"testing"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ContentTreeStatus.IsContainer

func TestContentTreeStatusIsContainer(t *testing.T) {
	s := ContentTreeStatus{Format: zconfig.Format_CONTAINER}
	assert.True(t, s.IsContainer())

	s.Format = zconfig.Format_RAW
	assert.False(t, s.IsContainer())
}

// ContentTreeStatus.ReferenceID

func TestContentTreeStatusReferenceID(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	s := ContentTreeStatus{
		ContentID:   id,
		RelativeURL: "docker.io/library/alpine:latest",
		Format:      zconfig.Format_CONTAINER,
	}

	// Non-kube: "<uuid>-<relativeURL>"
	ref := s.ReferenceID()
	assert.Equal(t, id.String()+"-docker.io/library/alpine:latest", ref)

	// Kube+container: "<prefix><uuid>-<relativeURL>"
	s.HVTypeKube = true
	ref = s.ReferenceID()
	assert.Contains(t, ref, KubeContainerImagePrefix)
	assert.Contains(t, ref, id.String())
	assert.Contains(t, ref, "docker.io/library/alpine:latest")

	// Kube+non-container: no prefix
	s.Format = zconfig.Format_RAW
	ref = s.ReferenceID()
	assert.Equal(t, id.String()+"-docker.io/library/alpine:latest", ref)
}

// ContentTreeStatus.UpdateFromContentTreeConfig

func TestContentTreeStatusUpdateFromContentTreeConfig(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	config := ContentTreeConfig{
		ContentID:         id,
		RelativeURL:       "some/url",
		Format:            zconfig.Format_CONTAINER,
		ContentSha256:     "abc123",
		MaxDownloadSize:   1024,
		GenerationCounter: 5,
		DisplayName:       "test-content",
	}
	var status ContentTreeStatus
	status.UpdateFromContentTreeConfig(config)

	assert.Equal(t, id, status.ContentID)
	assert.Equal(t, "some/url", status.RelativeURL)
	assert.Equal(t, zconfig.Format_CONTAINER, status.Format)
	assert.Equal(t, "abc123", status.ContentSha256)
	assert.Equal(t, uint64(1024), status.MaxDownloadSize)
	assert.Equal(t, int64(5), status.GenerationCounter)
	assert.Equal(t, "test-content", status.DisplayName)
}

// VerifyImageStatus.Pending

func TestVerifyImageStatusPending(t *testing.T) {
	require.False(t, VerifyImageStatus{}.Pending())
	require.True(t, VerifyImageStatus{PendingAdd: true}.Pending())
	require.True(t, VerifyImageStatus{PendingModify: true}.Pending())
	require.True(t, VerifyImageStatus{PendingDelete: true}.Pending())
}

// ContentTreeConfig.Key / LogKey

func TestContentTreeConfigLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	cfg := ContentTreeConfig{ContentID: id}
	assert.Equal(t, id.String(), cfg.Key())
	assert.Contains(t, cfg.LogKey(), id.String())
}

// ContentTreeStatus.Key / LogKey / ResolveKey

func TestContentTreeStatusLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	dsID := uuid.Must(uuid.NewV4())
	status := ContentTreeStatus{
		ContentID:         id,
		DatastoreIDList:   []uuid.UUID{dsID},
		RelativeURL:       "img.tar",
		GenerationCounter: 1,
		Format:            zconfig.Format_RAW,
	}
	assert.Equal(t, id.String(), status.Key())
	assert.Contains(t, status.LogKey(), id.String())
	rk := status.ResolveKey()
	assert.Contains(t, rk, dsID.String())
}

// ContentTreeConfig / ContentTreeStatus LogCreate / LogModify / LogDelete

func TestContentTreeConfigLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	cfg := ContentTreeConfig{ContentID: id}
	cfg.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	cfg.LogModify(log, cfg)
	cfg.LogDelete(log)
}

func TestContentTreeStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	s := ContentTreeStatus{ContentID: id}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}
