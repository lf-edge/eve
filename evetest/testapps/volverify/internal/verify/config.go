// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

// Config parameterizes an op stream. The same Config (and Seed) must be supplied
// to the writer and to the later verifier, since both replay the identical stream.
type Config struct {
	Seed        uint64 // master seed for the deterministic op stream
	BlockSize   int    // on-disk block size in bytes (must be > headerLen)
	Ops         uint64 // total number of ops the writer applies
	CommitEvery uint64 // fsync + advance the committed index every this many ops
	DirFanout   int    // per-level fan-out of the file placement tree
	SmallBlocks int    // upper bound (inclusive) on a "small" file, in blocks
	MedBlocks   int    // upper bound on a "medium" file, in blocks
	MaxBlocks   int    // upper bound on a "large" file, in blocks

	// ExpectCommitted is an off-volume floor on the committed op index for the
	// verifier: the effective committed index is max(on-volume commit,
	// ExpectCommitted). It closes the blind spot where fsck clears both the last
	// files' data and the on-volume commit slots — the harness, which ran the
	// writer to completion, supplies the true high-water mark so the verifier
	// still expects (and thus flags loss of) the last work. -1 means "trust the
	// on-volume commit only". Authoritative only when the caller knows the writer
	// finished; a value above reality would over-expect. Ignored by the writer.
	ExpectCommitted int64
}

// DefaultConfig returns a Config sized for on-device churn against a large blank
// volume: 4 KiB blocks and a heavy-tailed size mix (mostly KB, occasional
// MB/hundreds-MB) so allocated blocks scatter through the shrink evacuation zone.
func DefaultConfig() Config {
	return Config{
		Seed:            1,
		BlockSize:       4096,
		Ops:             100000,
		CommitEvery:     64,
		DirFanout:       16,
		SmallBlocks:     4,     // <= 16 KiB
		MedBlocks:       256,   // <= 1 MiB
		MaxBlocks:       65536, // <= 256 MiB
		ExpectCommitted: -1,
	}
}

// valid reports whether the Config is self-consistent enough to run.
func (c Config) valid() bool {
	return c.BlockSize > headerLen &&
		c.CommitEvery > 0 &&
		c.DirFanout > 0 &&
		c.SmallBlocks >= 1 &&
		c.MedBlocks >= c.SmallBlocks &&
		c.MaxBlocks >= c.MedBlocks
}
