// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

// prng is a splitmix64 stream. It is deterministic given its seed, so the writer
// and verifier reproduce the identical op stream by seeding from the same
// masterSeed and drawing in the same order (design §4.2).
type prng struct {
	state uint64
}

func newPRNG(seed uint64) *prng {
	return &prng{state: seed}
}

func (p *prng) next() uint64 {
	p.state += 0x9E3779B97F4A7C15
	z := p.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// intn returns a value in [0,n). n must be positive.
func (p *prng) intn(n int) int {
	return int(p.next() % uint64(n))
}
