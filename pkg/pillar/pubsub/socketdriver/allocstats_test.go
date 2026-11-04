// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"bytes"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

// The allocation counters encode which conversions and buffers escape to
// the heap, which is up to the compiler and the standard library. These
// tests hold them against the runtime's own count of allocations, so that
// a code change or a Go upgrade that changes what is allocated fails here
// instead of making the counters drift.

const allocRuns = 200

// countedAllocs returns the allocations per run of f the runtime counts,
// and those counted in a. AllocsPerRun truncates its average to a whole
// number, so callers compare it with the counted one rounded down: an
// occasional pool miss, after a GC empties the pool, adds a fraction. f runs once before, so that pooled buffers are
// taken from the pool as they are once a subscription is going.
func countedAllocs(a *pubsub.Alloc, f func()) (runtime, counted float64) {
	f()
	before := a.Count.Load()
	runtime = testing.AllocsPerRun(allocRuns, f)
	// AllocsPerRun runs f once more to warm up.
	counted = float64(a.Count.Load()-before) / (allocRuns + 1)
	return runtime, counted
}

func TestAllocCountsSend(t *testing.T) {
	for _, tt := range []struct {
		name, key string
		size      int
	}{
		{"short key", "global", 100},
		{"uuid key", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", 100},
		{"large value", "global", 200 << 10},
	} {
		s := &Publisher{topic: "DevicePortConfig", stats: &pubsub.PubStats{}}
		val := []byte(`"` + strings.Repeat("x", tt.size) + `"`)
		runtime, counted := countedAllocs(&s.stats.AllocMessage, func() {
			msg := s.updateMessage(tt.key, val)
			_ = writeFrame(io.Discard, msg, false, &s.stats.AllocMessage)
		})
		if runtime != math.Floor(counted) {
			t.Errorf("%s: %v allocations per message, %v counted", tt.name, runtime, counted)
		}
	}
}

func TestAllocCountsReceive(t *testing.T) {
	if raceEnabled {
		// The race detector turns off the optimisation of
		// append(s, make([]T, n)...), so base64 AppendDecode allocates
		// twice for keys above 32 bytes.
		t.Skip("the race detector changes what is allocated")
	}
	logger := logrus.New()
	log := base.NewSourceLogObject(logger, "test", 1)
	for _, tt := range []struct {
		name, key string
		size      int
	}{
		{"short key", "global", 100},
		{"uuid key", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", 100},
		{"pooled buffer", "global", 30 << 10},
		{"buffer of its own", "global", 200 << 10},
	} {
		pub := &Publisher{topic: "DevicePortConfig", stats: &pubsub.PubStats{}}
		var frame bytes.Buffer
		val := []byte(`"` + strings.Repeat("x", tt.size) + `"`)
		if err := WriteFrame(&frame, pub.updateMessage(tt.key, val)); err != nil {
			t.Fatal(err)
		}
		s := &Subscriber{topic: "DevicePortConfig", name: "test/DevicePortConfig",
			stats: &pubsub.SubStats{}, logger: logger, log: log}
		stream := bytes.NewReader(frame.Bytes())
		s.reader = NewFrameReaderWithStats(stream, s.stats)
		read := func() {
			stream.Reset(frame.Bytes())
			if msg, _, _ := s.read(); msg != "update" {
				t.Fatalf("read %q", msg)
			}
		}
		read()
		decode, readbuf := &s.stats.AllocDecode, &s.stats.AllocReadBuf
		beforeDecode, beforeBuf := decode.Count.Load(), readbuf.Count.Load()
		runtime := testing.AllocsPerRun(allocRuns, read)
		counted := float64(decode.Count.Load()-beforeDecode+readbuf.Count.Load()-beforeBuf) /
			(allocRuns + 1)
		if runtime != math.Floor(counted) {
			t.Errorf("%s: %v allocations per message, %v counted", tt.name, runtime, counted)
		}
	}
}
