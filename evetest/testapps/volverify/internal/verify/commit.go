// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"syscall"
)

// commitDirName holds the two ping-pong committed-index slots on the volume.
const commitDirName = ".vv-commit"

const (
	commitMagic  = 0x56564349 // "VVCI" little-endian
	commitRecLen = 24         // magic(4) + generation(8) + index(8) + crc(4)
)

// commitRecord is the durable "everything through op Index is fsynced" marker.
// generation strictly increases so recovery can pick the newest valid slot even
// when a crash tore the most recent write (design §4.2).
type commitRecord struct {
	generation uint64
	index      int64
}

func slotPath(volDir string, slot int) string {
	return filepath.Join(volDir, commitDirName, fmt.Sprintf("commit.%d", slot))
}

// writeCommit atomically publishes rec into the ping-pong slot chosen by its
// generation parity, fsyncing the file and its directory before returning.
func writeCommit(volDir string, rec commitRecord) error {
	dir := filepath.Join(volDir, commitDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var buf [commitRecLen]byte
	binary.LittleEndian.PutUint32(buf[0:4], commitMagic)
	binary.LittleEndian.PutUint64(buf[4:12], rec.generation)
	binary.LittleEndian.PutUint64(buf[12:20], uint64(rec.index))
	binary.LittleEndian.PutUint32(buf[20:24], crc32.Checksum(buf[0:20], castagnoli))

	path := slotPath(volDir, int(rec.generation%2))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf[:]); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsyncDir(dir)
}

// readCommit returns the highest-generation valid slot's index, or -1 when no
// valid slot exists (fresh volume, or both slots torn).
func readCommit(volDir string) int64 {
	best := int64(-1)
	bestGen := int64(-1)
	for slot := 0; slot < 2; slot++ {
		rec, ok := readSlot(slotPath(volDir, slot))
		if !ok {
			continue
		}
		if int64(rec.generation) > bestGen {
			bestGen = int64(rec.generation)
			best = rec.index
		}
	}
	return best
}

func readSlot(path string) (commitRecord, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) != commitRecLen {
		return commitRecord{}, false
	}
	if binary.LittleEndian.Uint32(data[0:4]) != commitMagic {
		return commitRecord{}, false
	}
	if binary.LittleEndian.Uint32(data[20:24]) != crc32.Checksum(data[0:20], castagnoli) {
		return commitRecord{}, false
	}
	return commitRecord{
		generation: binary.LittleEndian.Uint64(data[4:12]),
		index:      int64(binary.LittleEndian.Uint64(data[12:20])),
	}, true
}

// nextGeneration returns the generation to use for the next commit write.
func nextGeneration(volDir string) uint64 {
	var maxGen int64 = -1
	for slot := 0; slot < 2; slot++ {
		if rec, ok := readSlot(slotPath(volDir, slot)); ok {
			if int64(rec.generation) > maxGen {
				maxGen = int64(rec.generation)
			}
		}
	}
	return uint64(maxGen + 1)
}

// fsyncDir flushes a directory entry so a rename/create is durable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	err = d.Sync()
	// Some filesystems reject fsync on a directory; that is not fatal here.
	if err != nil && (errors.Is(err, os.ErrInvalid) || errors.Is(err, syscall.EINVAL)) {
		return nil
	}
	return err
}
