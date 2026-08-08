// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWorkloadID(t *testing.T) {
	t.Run("deterministic per UID", func(t *testing.T) {
		id1 := workloadID("11111111-1111-1111-1111-111111111111", "myapp-a1b2c-1")
		id2 := workloadID("11111111-1111-1111-1111-111111111111", "myapp-a1b2c-1")
		assert.Equal(t, id1, id2)
	})

	t.Run("differs across UIDs", func(t *testing.T) {
		id1 := workloadID("11111111-1111-1111-1111-111111111111", "myapp-a1b2c-1")
		id2 := workloadID("22222222-2222-2222-2222-222222222222", "myapp-a1b2c-1")
		assert.NotEqual(t, id1, id2)
	})

	t.Run("never zero", func(t *testing.T) {
		// A broad sweep of inputs, including ones hand-picked to be more
		// likely to collide with a masking edge case, none of which may
		// ever produce exactly 0.
		inputs := []string{"", "0", "a", "myapp-a1b2c-1", "11111111-1111-1111-1111-111111111111"}
		for _, in := range inputs {
			assert.NotZero(t, workloadID(in, "fallback-name"))
			assert.NotZero(t, workloadID("", in))
		}
	})

	t.Run("falls back to kubeName when UID is unavailable", func(t *testing.T) {
		idFromUID := workloadID("11111111-1111-1111-1111-111111111111", "myapp-a1b2c-1")
		idFromNameAsUID := workloadID("myapp-a1b2c-1", "unused")
		idFromFallback := workloadID("", "myapp-a1b2c-1")
		assert.NotEqual(t, idFromUID, idFromNameAsUID,
			"a UID and an unrelated kubeName must not coincidentally hash the same input")
		assert.Equal(t, idFromNameAsUID, idFromFallback,
			"an empty UID must fall back to hashing kubeName, i.e. the exact same input "+
				"as passing kubeName in the UID slot")
	})
}
