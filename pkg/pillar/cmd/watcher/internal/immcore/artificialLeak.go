// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build artificialleak

package immcore

import (
	"math/rand"
	"time"
)

// LeakLinear creates an artificial memory leak by allocating blocks of memory at regular intervals.
// It allocates 'block' bytes every 'every' duration and returns a slice of all allocated chunks.
// This function is only compiled when the 'artificialleak' build tag is set.
func LeakLinear(block int, every time.Duration) [][]byte {
	var chunks [][]byte
	ticker := time.NewTicker(every)
	for range ticker.C {
		b := make([]byte, block)
		for i := range b {
			b[i] = byte(rand.Intn(256))
		}
		chunks = append(chunks, b)
	}
	return chunks
}

func init() {
	go LeakLinear(1024*2, 10*time.Second) // 2KB every 10s
}
