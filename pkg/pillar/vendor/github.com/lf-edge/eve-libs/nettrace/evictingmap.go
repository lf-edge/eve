// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import "sync"

// evictingMap is a bounded, insertion-ordered in-memory store for recent
// trace metadata (connections, dials, HTTP requests, etc.).
//
// Purpose:
//   - Cap memory use by keeping only the most recent N items.
//   - Preserve insertion order so the oldest item is evicted first.
//
// Behavior:
//   - When capacity is reached, the oldest item is evicted.
//   - Optionally, evicted items are batched and passed to a caller-provided
//     flush function once a threshold is met. If no flush is configured,
//     evicted items are simply dropped.
//
// How it’s used here (two modes):
//   - In-memory mode (no WithBatchOffload):
//     Everything stays in memory up to the set capacity.
//     Evictions are dropped.
//     GetTrace() reads directly from these in-memory structures.
//   - Offload mode (WithBatchOffload enabled):
//     The HTTP client offloads batches via a callback; this map is configured
//     to avoid doing its own flushes.
//     Any persistence (e.g., to BoltDB) is handled by the offload callback.

type evictingMap struct {
	store       map[TraceID]interface{}
	order       []TraceID
	limit       int
	bucket      string
	batchBuffer []finalizedTrace
	mutex       sync.Mutex

	flushThreshold int
	flushFn        func(batch []finalizedTrace)
}

func newEvictingMap(limit int, bucket string, flushThreshold int, flushFn func([]finalizedTrace)) *evictingMap {
	return &evictingMap{
		store:          make(map[TraceID]interface{}),
		order:          make([]TraceID, 0, limit),
		limit:          limit,
		bucket:         bucket,
		flushThreshold: flushThreshold,
		flushFn:        flushFn,
	}
}

// Set inserts or updates a key. If capacity is exceeded, the oldest entry
// is evicted. If a flushFn is configured, evicted items are batched and
// flushed asynchronously once the flushThreshold is reached.
func (m *evictingMap) Set(key TraceID, value interface{}) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.store[key]; exists {
		m.store[key] = value
		return
	}

	// Evict if over limit
	if m.limit > 0 && len(m.order) >= m.limit {
		oldest := m.order[0]
		m.order = m.order[1:]

		oldVal := m.store[oldest]
		delete(m.store, oldest)

		// Only build/flush a batch if a flusher is actually configured.
		if m.flushFn != nil {
			m.batchBuffer = append(m.batchBuffer, finalizedTrace{
				Bucket: m.bucket,
				Key:    oldest,
				Value:  oldVal,
			})
			// Flush if enough evictions accumulated
			if m.flushThreshold > 0 && len(m.batchBuffer) >= m.flushThreshold {
				batch := m.batchBuffer
				m.batchBuffer = nil // clear before flushing
				go m.flushFn(batch) // async flush
			}
		}
	}

	m.order = append(m.order, key)
	m.store[key] = value
}

func (m *evictingMap) Len() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return len(m.store)
}

func (m *evictingMap) Get(key TraceID) (interface{}, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	val, ok := m.store[key]
	return val, ok
}

func (m *evictingMap) Delete(key TraceID) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.store[key]; !exists {
		return
	}
	delete(m.store, key)

	for i, id := range m.order {
		if id == key {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}
