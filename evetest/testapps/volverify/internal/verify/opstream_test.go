// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import "testing"

func testConfig() Config {
	return Config{
		Seed:            1234,
		BlockSize:       testBlockSize,
		Ops:             300,
		CommitEvery:     8,
		DirFanout:       4,
		SmallBlocks:     2,
		MedBlocks:       4,
		MaxBlocks:       8,
		ExpectCommitted: -1,
	}
}

// replayOps drives the generator against a fresh model, returning the full stream.
func replayOps(cfg Config, n uint64) []op {
	gen := newGenerator(cfg)
	m := newModel(cfg)
	ops := make([]op, 0, n)
	for i := uint64(0); i < n; i++ {
		o := gen.next(m, i)
		ops = append(ops, o)
		m.apply(o)
	}
	return ops
}

func TestOpStreamDeterministic(t *testing.T) {
	cfg := testConfig()
	a := replayOps(cfg, cfg.Ops)
	b := replayOps(cfg, cfg.Ops)
	if len(a) != len(b) {
		t.Fatalf("length mismatch %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("op %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestOpStreamSeedSensitive(t *testing.T) {
	cfg := testConfig()
	a := replayOps(cfg, cfg.Ops)
	cfg.Seed++
	b := replayOps(cfg, cfg.Ops)
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different seeds produced identical op streams")
	}
}

func TestOpStreamHasMix(t *testing.T) {
	cfg := testConfig()
	var counts [4]int
	for _, o := range replayOps(cfg, cfg.Ops) {
		counts[o.typ]++
	}
	if counts[opCreate] == 0 || counts[opDelete] == 0 {
		t.Fatalf("expected creates and deletes, got %+v", counts)
	}
}
