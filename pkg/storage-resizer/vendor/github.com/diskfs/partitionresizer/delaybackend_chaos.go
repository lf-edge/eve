//go:build chaos

package partitionresizer

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/diskfs/go-diskfs/backend"
)

// pausePetMarker couples this chaos delay to storage-resizer's run-watchdog
// feeder: while the file exists the feeder withholds pets, so a hardware
// watchdog reset lands INSIDE the delayed GPT write below -- deterministic,
// rather than at a wall-clock timeout that only probabilistically overlaps a
// write. Keep this path in sync with pkg/storage-resizer/watchdog.go.
const pausePetMarker = "/run/storage-resizer-pause-pet"

// gptWriteSeq counts GPT-metadata writes within one partitionresizer process so
// each log line (and the RESIZER_GPT_DELAY_NTH selector) can name the exact
// block write in flight. One pr.Run per process, so a package var suffices.
var gptWriteSeq int64

// maybeWrapBackend, in -tags chaos builds, wraps the backend so that a write
// touching a GPT metadata sector is followed by a delay (RESIZER_GPT_WRITE_DELAY,
// e.g. "20s"). go-diskfs writes the table as several WriteAt calls (backup
// entries, backup header, primary entries, primary header, protective MBR); the
// delay widens the window between them so a crash- or watchdog-injection test can
// land inside updatePartitions, which is otherwise a single fast table write that
// random-timed kills almost never catch. It also emits an ordered, per-block
// STORAGE_RESIZER_GPT_WRITE log so a test can determine WHERE a reset hit.
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
	// A real block device (/dev/sda) reports Size()==0 via Stat(); without the
	// real size, isGPTWrite/gptRegion cannot recognize the backup-GPT region (the
	// last 33 sectors), so only primary-region writes would be instrumented. Fall
	// back to the underlying fd's end offset. go-diskfs uses pread/pwrite
	// (offset-independent), so seeking this fd does not perturb its writes; restore
	// the offset anyway for hygiene.
	if sectors == 0 {
		if f, ferr := b.Sys(); ferr == nil && f != nil {
			if sz, serr := f.Seek(0, io.SeekEnd); serr == nil && sz > 0 {
				sectors = sz / 512
			}
			_, _ = f.Seek(0, io.SeekStart)
		}
	}
	// RESIZER_GPT_DELAY_NTH (optional, 1-based): delay+starve only the Nth GPT
	// write, so a test can steer the watchdog reset onto a specific block
	// (protective-MBR / primary-header / primary-entries / backup-entries /
	// backup-header) instead of always the first. 0/unset = delay every write.
	nth, _ := strconv.ParseInt(os.Getenv("RESIZER_GPT_DELAY_NTH"), 10, 64)
	fmt.Fprintf(os.Stderr, "STORAGE_RESIZER_CHAOS: GPT-write delay=%s nth=%d disk_sectors=%d\n", d, nth, sectors)
	return &delayBackend{Storage: b, delay: d, diskSectors: sectors, nth: nth}
}

type delayBackend struct {
	backend.Storage
	delay       time.Duration
	diskSectors int64
	nth         int64
}

func (d *delayBackend) Writable() (backend.WritableFile, error) {
	wf, err := d.Storage.Writable()
	if err != nil {
		return nil, err
	}
	return &delayWritable{WritableFile: wf, delay: d.delay, diskSectors: d.diskSectors, nth: d.nth}, nil
}

type delayWritable struct {
	backend.WritableFile
	delay       time.Duration
	diskSectors int64
	nth         int64
}

func (d *delayWritable) WriteAt(p []byte, off int64) (int, error) {
	n, err := d.WritableFile.WriteAt(p, off)
	if err != nil || !isGPTWrite(off, len(p), d.diskSectors) {
		return n, err
	}
	seq := atomic.AddInt64(&gptWriteSeq, 1)
	region := gptRegion(off, d.diskSectors)
	if d.nth > 0 && seq != d.nth {
		// Not the targeted write: record it (so the analyzer sees the full
		// ordered sequence) but neither delay nor starve the feeder.
		fmt.Fprintf(os.Stderr, "STORAGE_RESIZER_GPT_WRITE seq=%d region=%s lba=%d len=%d no-delay\n",
			seq, region, off/512, len(p))
		return n, err
	}
	// Log BEFORE sleeping so the console record shows exactly which GPT block is
	// in flight if a reset lands during the delay; a missing END line for that
	// seq marks where the fire hit.
	fmt.Fprintf(os.Stderr, "STORAGE_RESIZER_GPT_WRITE seq=%d region=%s lba=%d len=%d delay=%s BEGIN-SLEEP\n",
		seq, region, off/512, len(p), d.delay)
	pausePet(true)
	time.Sleep(d.delay)
	pausePet(false)
	fmt.Fprintf(os.Stderr, "STORAGE_RESIZER_GPT_WRITE seq=%d region=%s lba=%d END-SLEEP survived\n",
		seq, region, off/512)
	return n, err
}

// pausePet creates/removes the marker the run-watchdog feeder polls to decide
// whether to withhold pets.
func pausePet(on bool) {
	if on {
		_ = os.WriteFile(pausePetMarker, []byte("1"), 0o644)
		return
	}
	_ = os.Remove(pausePetMarker)
}

// gptRegion names the GPT metadata region that a byte offset (512-byte LBAs)
// falls in, for the ordered write log.
func gptRegion(off, diskSectors int64) string {
	lba := off / 512
	switch {
	case lba == 0:
		return "protective-MBR"
	case lba == 1:
		return "primary-header"
	case lba >= 2 && lba <= 33:
		return "primary-entries"
	case diskSectors > 0 && lba == diskSectors-1:
		return "backup-header"
	case diskSectors > 0 && lba >= diskSectors-33:
		return "backup-entries"
	default:
		return "gpt-other"
	}
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
