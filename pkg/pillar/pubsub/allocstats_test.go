// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"runtime"
	"testing"
)

var allocSink []byte

// TestAllocSizeMatchesRuntime holds AllocSize, a copy of the Go allocator's
// size classes, against the bytes the runtime accounts for allocations of
// those sizes, so that a Go upgrade changing the classes fails here.
func TestAllocSizeMatchesRuntime(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	const runs = 100
	// 16 bytes and up: smaller allocations without pointers share 16-byte
	// blocks, which the runtime accounts per block.
	for _, n := range []int{16, 17, 33, 100, 1000, 1025, 4097, 20000, 32768, 32769, 65536, 100000, 1 << 20} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := 0; i < runs; i++ {
			allocSink = make([]byte, n)
		}
		runtime.ReadMemStats(&after)
		got := int((after.TotalAlloc - before.TotalAlloc) / runs)
		if want := AllocSize(n); got != want {
			t.Errorf("%d bytes: the runtime accounts %d, AllocSize says %d", n, got, want)
		}
	}
}
