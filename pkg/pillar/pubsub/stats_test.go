// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// statsTestID keeps the counters of repeated runs (-count) apart: they are
// kept per name for the life of the process.
var statsTestID atomic.Int32

func uniqueName(base string) string {
	return fmt.Sprintf("%s%d", base, statsTestID.Add(1))
}

func TestStatsGetOrCreate(t *testing.T) {
	if PublicationStats("statstest/a") != PublicationStats("statstest/a") {
		t.Fatal("same name must give the same publication counters")
	}
	if SubscriptionStats("statstest/a") != SubscriptionStats("statstest/a") {
		t.Fatal("same name must give the same subscription counters")
	}
	if PublicationStats("statstest/a") == PublicationStats("statstest/b") {
		t.Fatal("different names must give different counters")
	}
}

func TestStatsConcurrentMax(t *testing.T) {
	name := uniqueName("statstest/concurrent")
	pub := PublicationStats(name)
	sub := SubscriptionStats(name)
	var wg sync.WaitGroup
	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				pub.AddMessage(g*100 + i)
				sub.AddFrame(g*100 + i)
			}
		}(g)
	}
	wg.Wait()
	if pub.Messages.Load() != 10000 || sub.Frames.Load() != 10000 {
		t.Fatalf("messages %d frames %d, want 10000 each",
			pub.Messages.Load(), sub.Frames.Load())
	}
	if pub.MaxMessage.Load() != 9999 || sub.MaxFrame.Load() != 9999 {
		t.Fatalf("max message %d max frame %d, want 9999",
			pub.MaxMessage.Load(), sub.MaxFrame.Load())
	}
	if want := int64(9999 * 10000 / 2); pub.Bytes.Load() != want || sub.Bytes.Load() != want {
		t.Fatalf("bytes %d / %d, want %d", pub.Bytes.Load(), sub.Bytes.Load(), want)
	}
}

func TestStatsJSON(t *testing.T) {
	name := uniqueName("statstest/json")
	PublicationStats(name).AddMessage(42)
	SubscriptionStats(name).RetainedBufBytes.Add(1024)

	rec := httptest.NewRecorder()
	StatsHandler(rec, httptest.NewRequest("GET", "/debug/pubsub/stats", nil))
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	var stats map[string]map[string]map[string]int64
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("invalid JSON %q: %v", rec.Body.String(), err)
	}
	pub := stats["publications"][name]
	if pub["messages"] != 1 || pub["bytes"] != 42 || pub["max_message"] != 42 {
		t.Fatalf("publication counters %v", pub)
	}
	for _, field := range []string{"connections", "large_warnings"} {
		if _, ok := pub[field]; !ok {
			t.Errorf("publication counters lack %q", field)
		}
	}
	sub := stats["subscriptions"][name]
	if sub["retained_buf_bytes"] != 1024 {
		t.Fatalf("subscription counters %v", sub)
	}
	for _, field := range []string{"subscribers", "frames", "bytes", "max_frame",
		"oversized_frames"} {
		if _, ok := sub[field]; !ok {
			t.Errorf("subscription counters lack %q", field)
		}
	}
	if body := rec.Body.Bytes(); body[len(body)-1] == '\n' && json.Valid(body[:len(body)-1]) {
		// A trailing newline is fine; the JSON itself must be on one line.
		if n := countNewlines(body[:len(body)-1]); n != 0 {
			t.Fatalf("JSON spans %d lines, want one", n+1)
		}
	}
}

func countNewlines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}
