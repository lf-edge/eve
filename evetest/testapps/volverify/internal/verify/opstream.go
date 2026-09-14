// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import "fmt"

// opType is the kind of filesystem mutation an op performs.
type opType int

const (
	opCreate opType = iota
	opDelete
	opMkdir
	opRmdir
)

// op is one entry in the deterministic op stream (design §4.2). fileID equals the
// op index for a create.
type op struct {
	n       uint64
	typ     opType
	fileID  uint64
	nblocks int
	dir     string
}

// generator produces the op stream. Given the same seed it yields the same ops,
// provided it is driven against a model advanced by those same ops — the two
// selection ops (delete/rmdir) consult the model, so the writer and verifier must
// both replay from op 0 to stay in lockstep.
type generator struct {
	rng *prng
	cfg Config
}

func newGenerator(cfg Config) *generator {
	return &generator{rng: newPRNG(cfg.Seed), cfg: cfg}
}

// scratchDir names one of a bounded set of churn directories, kept disjoint from
// the file-placement tree so mkdir/rmdir churn never removes a live file's parent.
func scratchDir(k int) string {
	return fmt.Sprintf("scratch/s%03d", k)
}

// pickNBlocks draws a file length from a heavy-tailed distribution: mostly small,
// occasionally medium, rarely large.
func (g *generator) pickNBlocks() int {
	r := g.rng.next() % 1000
	switch {
	case r < 850:
		return 1 + g.rng.intn(g.cfg.SmallBlocks)
	case r < 990:
		return 1 + g.rng.intn(g.cfg.MedBlocks)
	default:
		return 1 + g.rng.intn(g.cfg.MaxBlocks)
	}
}

// next returns op n for the current model state and advances the generator.
func (g *generator) next(m *model, n uint64) op {
	choice := g.rng.next() % 100
	switch {
	case choice < 65:
		return op{n: n, typ: opCreate, fileID: n, nblocks: g.pickNBlocks()}
	case choice < 85:
		if len(m.liveIDs) == 0 {
			return op{n: n, typ: opCreate, fileID: n, nblocks: g.pickNBlocks()}
		}
		id := m.liveIDs[g.rng.intn(len(m.liveIDs))]
		return op{n: n, typ: opDelete, fileID: id}
	case choice < 93:
		return op{n: n, typ: opMkdir, dir: scratchDir(g.rng.intn(g.cfg.DirFanout * g.cfg.DirFanout))}
	default:
		if len(m.dirList) == 0 {
			return op{n: n, typ: opCreate, fileID: n, nblocks: g.pickNBlocks()}
		}
		return op{n: n, typ: opRmdir, dir: m.dirList[g.rng.intn(len(m.dirList))]}
	}
}
