//go:build chaos

package partitionresizer

import (
	"os"
	"time"

	"github.com/diskfs/go-diskfs/backend"
)

// maybeWrapBackend, in -tags chaos builds, wraps the backend so that a write
// touching a GPT metadata sector is followed by a delay
// (RESIZER_GPT_WRITE_DELAY, e.g. "10s"). go-diskfs writes the table as several
// WriteAt calls (backup entries, backup header, primary entries, primary
// header, protective MBR); the delay widens the window between them so a
// crash-injection test can land between the backup and primary writes -- in
// particular inside updatePartitions, which is otherwise a single fast table
// write that random-timed kills almost never catch.
func maybeWrapBackend(b backend.Storage) backend.Storage {
	s := os.Getenv("RESIZER_GPT_WRITE_DELAY")
	if s == "" {
		return b
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return b
	}
	var sectors int64
	if fi, serr := b.Stat(); serr == nil {
		sectors = fi.Size() / 512
	}
	return &delayBackend{Storage: b, delay: d, diskSectors: sectors}
}

type delayBackend struct {
	backend.Storage
	delay       time.Duration
	diskSectors int64
}

func (d *delayBackend) Writable() (backend.WritableFile, error) {
	wf, err := d.Storage.Writable()
	if err != nil {
		return nil, err
	}
	return &delayWritable{WritableFile: wf, delay: d.delay, diskSectors: d.diskSectors}, nil
}

type delayWritable struct {
	backend.WritableFile
	delay       time.Duration
	diskSectors int64
}

func (d *delayWritable) WriteAt(p []byte, off int64) (int, error) {
	n, err := d.WritableFile.WriteAt(p, off)
	if err == nil && isGPTWrite(off, len(p), d.diskSectors) {
		time.Sleep(d.delay)
	}
	return n, err
}

// isGPTWrite reports whether a write at byte offset off of the given length
// touches a GPT metadata sector (512-byte LBAs): the protective MBR + primary
// header + primary entry array (LBA 0..33), or the backup entry array + backup
// header (the last 33 sectors).
func isGPTWrite(off int64, length int, diskSectors int64) bool {
	const sec = 512
	start := off / sec
	end := (off + int64(length) - 1) / sec
	if start <= 33 { // overlaps the primary region (LBA 0..33)
		return true
	}
	if diskSectors > 0 && end >= diskSectors-33 { // overlaps the backup region
		return true
	}
	return false
}
