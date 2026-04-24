// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// PathToKey

func TestPathToKey(t *testing.T) {
	assert.Equal(t, "a-b-c", PathToKey("/a/b/c"))
	assert.Equal(t, "a-b-c", PathToKey("a/b/c"))
	assert.Equal(t, "foo", PathToKey("/foo"))
	assert.Equal(t, "foo", PathToKey("foo"))
	assert.Equal(t, "", PathToKey("/"))
	assert.Equal(t, "", PathToKey(""))
}
