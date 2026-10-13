// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
)

// PubStats counts what a publication sent, over all its subscribers.
type PubStats struct {
	Connections   atomic.Int64 // subscriber connections being served
	Messages      atomic.Int64
	Bytes         atomic.Int64
	MaxMessage    atomic.Int64
	LargeWarnings atomic.Int64 // messages above the warning size

	CompressedMessages atomic.Int64 // messages above the frame size, sent compressed
	CompressedBytes    atomic.Int64 // their size on the wire
	Refused            atomic.Int64 // values too large even compressed

	AllocMarshal Alloc // JSON of published items
	AllocMessage Alloc // wire messages built for subscribers
	AllocLarge   Alloc // fields tagged pubsub-large moved out to files
}

// SubStats counts what the subscriptions to a publication received, over
// all subscriptions in this process.
type SubStats struct {
	Subscribers      atomic.Int64 // connected subscriptions
	Frames           atomic.Int64
	Bytes            atomic.Int64
	MaxFrame         atomic.Int64
	RetainedBufBytes atomic.Int64 // read buffers held while frames are read
	OversizedFrames  atomic.Int64 // frames read into a one-off buffer
	BufTakenBytes    atomic.Int64 // read buffer bytes handed out, over all reads

	CompressedFrames  atomic.Int64 // compressed frames received
	DecompressedBytes atomic.Int64 // the size of their messages

	AllocReadBuf Alloc // read buffers: pool misses, one-off and decompressed buffers
	AllocDecode  Alloc // copies and decoding of received messages
	AllocLarge   Alloc // fields tagged pubsub-large read back from files
}

var (
	pubStats sync.Map // publication name -> *PubStats
	subStats sync.Map // publication name -> *SubStats
)

// PublicationStats returns the counters of the named publication.
func PublicationStats(name string) *PubStats {
	s, _ := pubStats.LoadOrStore(name, &PubStats{})
	return s.(*PubStats)
}

// SubscriptionStats returns the counters of the subscriptions to the named
// publication.
func SubscriptionStats(name string) *SubStats {
	s, _ := subStats.LoadOrStore(name, &SubStats{})
	return s.(*SubStats)
}

// AddMessage counts a sent message of the given size.
func (s *PubStats) AddMessage(size int) {
	s.Messages.Add(1)
	s.Bytes.Add(int64(size))
	storeMax(&s.MaxMessage, int64(size))
}

// AddFrame counts a received frame of the given size.
func (s *SubStats) AddFrame(size int) {
	s.Frames.Add(1)
	s.Bytes.Add(int64(size))
	storeMax(&s.MaxFrame, int64(size))
}

func storeMax(max *atomic.Int64, v int64) {
	for {
		cur := max.Load()
		if v <= cur || max.CompareAndSwap(cur, v) {
			return
		}
	}
}

func (s *PubStats) snapshot() map[string]int64 {
	m := map[string]int64{
		"connections":    s.Connections.Load(),
		"messages":       s.Messages.Load(),
		"bytes":          s.Bytes.Load(),
		"max_message":    s.MaxMessage.Load(),
		"large_warnings": s.LargeWarnings.Load(),

		"compressed_messages": s.CompressedMessages.Load(),
		"compressed_bytes":    s.CompressedBytes.Load(),
		"refused":             s.Refused.Load(),
	}
	s.AllocMarshal.snapshot("marshal", m)
	s.AllocMessage.snapshot("message", m)
	s.AllocLarge.snapshot("large", m)
	return m
}

func (s *SubStats) snapshot() map[string]int64 {
	m := map[string]int64{
		"subscribers":        s.Subscribers.Load(),
		"frames":             s.Frames.Load(),
		"bytes":              s.Bytes.Load(),
		"max_frame":          s.MaxFrame.Load(),
		"retained_buf_bytes": s.RetainedBufBytes.Load(),
		"oversized_frames":   s.OversizedFrames.Load(),
		"compressed_frames":  s.CompressedFrames.Load(),
		"decompressed_bytes": s.DecompressedBytes.Load(),
		"buf_taken_bytes":    s.BufTakenBytes.Load(),
	}
	s.AllocReadBuf.snapshot("readbuf", m)
	s.AllocDecode.snapshot("decode", m)
	s.AllocLarge.snapshot("large", m)
	return m
}

// StatsJSON returns all counters as one line of JSON:
// {"publications": {name: {counter: n}}, "subscriptions": {...}}.
func StatsJSON() []byte {
	collect := func(m *sync.Map) map[string]map[string]int64 {
		out := make(map[string]map[string]int64)
		m.Range(func(k, v any) bool {
			switch s := v.(type) {
			case *PubStats:
				out[k.(string)] = s.snapshot()
			case *SubStats:
				out[k.(string)] = s.snapshot()
			}
			return true
		})
		return out
	}
	pubs := collect(&pubStats)
	deepCopy := make(map[string]int64)
	deepCopyAlloc.snapshot("deepcopy", deepCopy)
	pubs["(DeepCopy)"] = deepCopy
	b, _ := json.Marshal(map[string]map[string]map[string]int64{
		"publications":  pubs,
		"subscriptions": collect(&subStats),
	})
	return b
}

// StatsHandler serves StatsJSON.
func StatsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(StatsJSON(), '\n'))
}
