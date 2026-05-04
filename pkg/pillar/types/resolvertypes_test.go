// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	uuid "github.com/satori/go.uuid"
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
