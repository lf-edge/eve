// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"sort"
	"sync/atomic"
)

// Alloc counts heap allocations pubsub makes at one kind of call site: how
// many, the bytes asked for, and the bytes the Go allocator reserves for
// them, which is the request rounded up to its size class.
type Alloc struct {
	Count    atomic.Int64
	Bytes    atomic.Int64
	Reserved atomic.Int64
}

// Add counts one allocation of n bytes.
func (a *Alloc) Add(n int) {
	if a == nil || n <= 0 {
		return
	}
	a.Count.Add(1)
	a.Bytes.Add(int64(n))
	a.Reserved.Add(int64(AllocSize(n)))
}

// AddTemp counts a []byte(s) or string(b) conversion of n bytes passed to
// a function which does not keep it: Go converts up to 32 bytes on the
// stack.
func (a *Alloc) AddTemp(n int) {
	if n > 32 {
		a.Add(n)
	}
}

func (a *Alloc) snapshot(kind string, m map[string]int64) {
	m["alloc_"+kind+"_count"] = a.Count.Load()
	m["alloc_"+kind+"_bytes"] = a.Bytes.Load()
	m["alloc_"+kind+"_reserved"] = a.Reserved.Load()
}

// sizeClasses are the object sizes of the Go allocator up to 32 KiB
// (class_to_size in runtime/sizeclasses.go); larger objects take whole
// 8 KiB pages.
var sizeClasses = [...]int{8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160,
	176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512, 576,
	640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688,
	3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472,
	9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480,
	21760, 24576, 27264, 28672, 32768}

// AllocSize returns the bytes the Go allocator reserves for n bytes.
func AllocSize(n int) int {
	if n > sizeClasses[len(sizeClasses)-1] {
		const page = 8 << 10
		return (n + page - 1) &^ (page - 1)
	}
	return sizeClasses[sort.SearchInts(sizeClasses[:], n)]
}

// deepCopyAlloc counts the JSON DeepCopy goes through; DeepCopy does not
// know the topic.
var deepCopyAlloc Alloc
