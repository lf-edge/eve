// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// benchCtx is cancelled on ^C so in-flight child processes (mkfs/resize2fs/…)
// and the fill loop abort promptly, letting cleanup run sequentially in the
// main path rather than racing the writers.
var benchCtx = context.Background()

// timed runs fn, records its wall-clock duration, and fatals on error.
func timed(name string, bytes int64, fn func() error) step {
	start := time.Now()
	err := fn()
	d := time.Since(start)
	if err != nil {
		fatal(fmt.Errorf("%s: %w", name, err))
	}
	return step{Name: name, Bytes: bytes, Duration: d}
}

// runOK runs a command and fatals (via returned error) on any non-zero exit.
func runOK(name string, args ...string) error {
	out, err := exec.CommandContext(benchCtx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return nil
}

// runFsck runs e2fsck, accepting exit codes 0 (clean) and 1 (errors corrected).
func runFsck(name string, args ...string) error {
	cmd := exec.CommandContext(benchCtx, name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() <= 1 {
		return nil
	}
	return fmt.Errorf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
}

// runResize2fs shrinks the fs and turns the cryptic "New size smaller than
// minimum" failure into an actionable message (the fs is too full to shrink
// that far).
func runResize2fs(img, sizeArg string) error {
	out, err := exec.CommandContext(benchCtx, "resize2fs", img, sizeArg).CombinedOutput()
	if err == nil {
		return nil
	}
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "smaller than minimum") {
		return fmt.Errorf("filesystem is too full to shrink to %s — lower --fill or --shrink, or raise --persist-size\n(%s)", sizeArg, s)
	}
	return fmt.Errorf("resize2fs %s %s: %v\n%s", img, sizeArg, err, s)
}

// resize2fsEstimate parses `resize2fs -P`, whose last line is
// "Estimated minimum size of the filesystem: N" with N in fs blocks. Returns the
// estimate in bytes.
func resize2fsEstimate(img string, blockSize int64) (int64, error) {
	out, err := exec.CommandContext(benchCtx, "resize2fs", "-P", img).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("resize2fs -P %s: %v\n%s", img, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "minimum size") {
			continue
		}
		fields := strings.Fields(line)
		blocks, perr := strconv.ParseInt(fields[len(fields)-1], 10, 64)
		if perr != nil {
			return 0, fmt.Errorf("parse resize2fs -P output %q: %w", line, perr)
		}
		return blocks * blockSize, nil
	}
	return 0, fmt.Errorf("resize2fs -P: no minimum-size line in output:\n%s", out)
}

// runResize2fsMinimize shrinks the fs to its minimum size (resize2fs -M). The
// flag precedes the device. Turns the too-full failure into an actionable error.
func runResize2fsMinimize(img string) error {
	out, err := exec.CommandContext(benchCtx, "resize2fs", "-M", img).CombinedOutput()
	if err == nil {
		return nil
	}
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "smaller than minimum") {
		return fmt.Errorf("filesystem is too full/fragmented to minimize\n(%s)", s)
	}
	return fmt.Errorf("resize2fs -M %s: %v\n%s", img, err, s)
}

// splitFields splits a flag value like "-O encrypt,quota" into args, dropping
// empty tokens. Returns nil for an empty string.
func splitFields(s string) []string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return nil
	}
	return f
}

// runFat runs mkfs.fat (or mkfs.vfat) on the image.
func runFat(img string) error {
	if _, err := exec.LookPath("mkfs.fat"); err == nil {
		return runOK("mkfs.fat", "-F", "32", img)
	}
	return runOK("mkfs.vfat", "-F", "32", img)
}

// truncateFile creates/zeroes path to size bytes (sparse).
func truncateFile(path string, size int64) {
	f, err := os.Create(path)
	if err != nil {
		fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		fatal(err)
	}
	_ = f.Close()
}

// randBuf returns n bytes of random data (so nothing along the path can dedup
// or zero-optimize the writes).
func randBuf(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fatal(err)
	}
	return b
}

// writeFile writes exactly n bytes to path, repeating buf, then fsyncs.
func writeFile(path string, n int64, buf []byte) {
	f, err := os.Create(path)
	if err != nil {
		fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := writeN(f, n, buf); err != nil {
		fatal(err)
	}
	if err := f.Sync(); err != nil {
		fatal(err)
	}
}

func writeN(f *os.File, n int64, buf []byte) error {
	for n > 0 {
		chunk := int64(len(buf))
		if chunk > n {
			chunk = n
		}
		if _, err := f.Write(buf[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

// fillDir writes files totaling ~bytes into dir, using a size mix that resembles
// a real /persist rather than a few identical blobs: a bounded number of small
// files (4 KiB–1 MiB: logs, configs, certs) for realistic inode/extent pressure,
// then the remaining bytes in large files (64–512 MiB: volume images, container
// blobs). Sizes are drawn from a fixed-seed PRNG so runs are comparable.
func fillDir(dir string, bytes int64, smallFiles int, buf []byte, label string) error {
	rng := mrand.New(mrand.NewSource(1))
	prog := newProgress(label, bytes)
	var written int64
	idx := 0
	// Tier 1: many small files (bounded count, small total).
	for n := 0; n < smallFiles && written < bytes; n++ {
		if err := benchCtx.Err(); err != nil {
			return err // ^C: stop writing so cleanup can remove the dir
		}
		sz := int64(4<<10) + rng.Int63n(1<<20-4<<10) // 4 KiB .. 1 MiB
		if sz > bytes-written {
			sz = bytes - written
		}
		if err := writeFillFile(dir, idx, sz, buf); err != nil {
			return err
		}
		written += sz
		idx++
		prog.update(written)
	}
	// Tier 2: the bulk of the bytes in large files.
	for written < bytes {
		if err := benchCtx.Err(); err != nil {
			return err
		}
		sz := int64(64<<20) + rng.Int63n(448<<20) // 64 .. 512 MiB
		if sz > bytes-written {
			sz = bytes - written
		}
		if err := writeFillFile(dir, idx, sz, buf); err != nil {
			return err
		}
		written += sz
		idx++
		prog.update(written)
	}
	return nil
}

func writeFillFile(dir string, idx int, n int64, buf []byte) error {
	f, err := os.Create(filepath.Join(dir, fmt.Sprintf("fill-%06d.dat", idx)))
	if err != nil {
		return err
	}
	if err := writeN(f, n, buf); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// ageFilesystem fragments an already-filled fs: each cycle deletes a scattered
// set of files and refills the freed space with small files, so the final layout
// is scattered across the address space (which raises the relocatable-block count
// and the resize2fs floor). The churn per cycle is bounded (min of capacity/20
// and 4 GiB): a few GB of scattered delete+refill fragments free space without
// rewriting tens of GB as tiny files — the all-of-30%-then-refill-as-small-files
// approach was pathologically slow (~50k fsync'd files per cycle at 100 GB/85%)
// and ballooned the backing image toward full. Refill writes are not fsync'd per
// file (one sync per cycle); the floor is measured after e2fsck, so per-file
// durability is unnecessary here. Fixed-seed PRNG so runs are comparable.
func ageFilesystem(dir string, cycles int, capacity int64, buf []byte) error {
	rng := mrand.New(mrand.NewSource(2))
	idx := 1 << 24 // start aging indices well above the fill indices
	churnCap := capacity / 20
	if max := int64(4) << 30; churnCap > max {
		churnCap = max
	}
	for c := 0; c < cycles; c++ {
		if err := benchCtx.Err(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "  aging cycle %d/%d (churn ~%s)...\n", c+1, cycles, human(churnCap))
		ents, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		// Delete files in shuffled order until ~churnCap is freed, scattering the
		// holes across the address space.
		rng.Shuffle(len(ents), func(i, j int) { ents[i], ents[j] = ents[j], ents[i] })
		var freed int64
		for _, e := range ents {
			if freed >= churnCap || e.IsDir() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			if err := os.Remove(p); err != nil {
				return err
			}
			freed += info.Size()
		}
		// Refill the freed bytes as small files (4 KiB–1 MiB) into the holes.
		for freed > 0 {
			if err := benchCtx.Err(); err != nil {
				return err
			}
			sz := int64(4<<10) + rng.Int63n(1<<20-4<<10)
			if sz > freed {
				sz = freed
			}
			if err := writeFileNoSync(dir, idx, sz, buf); err != nil {
				return err
			}
			freed -= sz
			idx++
		}
		if err := runOK("sync"); err != nil {
			return err
		}
	}
	return nil
}

// writeFileNoSync writes a fill file without an fsync (the caller syncs once at
// the end). Used by aging, where per-file durability is not needed.
func writeFileNoSync(dir string, idx int, n int64, buf []byte) error {
	f, err := os.Create(filepath.Join(dir, fmt.Sprintf("frag-%08d.dat", idx)))
	if err != nil {
		return err
	}
	if err := writeN(f, n, buf); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// copyFileSync copies src to dst and fsyncs dst (a raw image copy, as the grow
// does for the squashfs IMGx content).
func copyFileSync(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// fsyncFile flushes a file's dirty pages to the medium.
func fsyncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// readExt4SB parses the ext4 superblock (1024 bytes in) of an image file.
func readExt4SB(img string) (blockSize, blockCount, freeBlocks int64, err error) {
	f, err := os.Open(img)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 1024)
	if _, err := f.ReadAt(b, 1024); err != nil {
		return 0, 0, 0, err
	}
	if binary.LittleEndian.Uint16(b[0x38:0x3a]) != 0xEF53 {
		return 0, 0, 0, fmt.Errorf("not an ext4 filesystem (bad magic)")
	}
	logBS := binary.LittleEndian.Uint32(b[0x18:0x1c])
	bc := uint64(binary.LittleEndian.Uint32(b[0x04:0x08])) | uint64(binary.LittleEndian.Uint32(b[0x150:0x154]))<<32
	fb := uint64(binary.LittleEndian.Uint32(b[0x0c:0x10])) | uint64(binary.LittleEndian.Uint32(b[0x158:0x15c]))<<32
	return int64(1024) << logBS, int64(bc), int64(fb), nil
}

// readExt4Inodes reads the inode geometry from the ext4 superblock: the total
// inode count, free inodes, and inode size. The inode table (count × size) is
// fixed at mkfs time and is NOT reclaimed by resize2fs, so it is the prime
// suspect for the size-proportional part of the shrink floor.
func readExt4Inodes(img string) (inodesCount, freeInodes, inodeSize int64, err error) {
	f, err := os.Open(img)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 1024)
	if _, err := f.ReadAt(b, 1024); err != nil {
		return 0, 0, 0, err
	}
	if binary.LittleEndian.Uint16(b[0x38:0x3a]) != 0xEF53 {
		return 0, 0, 0, fmt.Errorf("not an ext4 filesystem (bad magic)")
	}
	inodesCount = int64(binary.LittleEndian.Uint32(b[0x00:0x04]))
	freeInodes = int64(binary.LittleEndian.Uint32(b[0x10:0x14]))
	inodeSize = int64(binary.LittleEndian.Uint16(b[0x58:0x5a]))
	return inodesCount, freeInodes, inodeSize, nil
}

// progress prints a throttled "done / total" line to stderr during a long write
// loop, so a multi-minute fill or aging pass reports forward motion instead of
// going dark. It prints at most every ~15s (and once at completion).
type progress struct {
	label string
	total int64
	start time.Time
	last  time.Time
}

func newProgress(label string, total int64) *progress {
	now := time.Now()
	fmt.Fprintf(os.Stderr, "  %s: 0 / %s ...\n", label, human(total))
	return &progress{label: label, total: total, start: now, last: now}
}

func (p *progress) update(done int64) {
	now := time.Now()
	if done < p.total && now.Sub(p.last) < 15*time.Second {
		return
	}
	p.last = now
	elapsed := now.Sub(p.start).Seconds()
	var rate float64
	if elapsed > 0 {
		rate = float64(done) / (1 << 20) / elapsed
	}
	pct := float64(0)
	if p.total > 0 {
		pct = float64(done) * 100 / float64(p.total)
	}
	fmt.Fprintf(os.Stderr, "  %s: %s / %s (%.0f%%, %.0f MiB/s)\n",
		p.label, human(done), human(p.total), pct, rate)
}

// availableBytes returns the space available to a non-privileged writer at path
// (statfs Bavail*Bsize). Root can write into the reserved blocks too, so this is
// a conservative floor.
func availableBytes(path string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * st.Bsize
}

// dirEmptyOrAbsent reports whether path does not exist or is an empty directory.
func dirEmptyOrAbsent(path string) bool {
	ents, err := os.ReadDir(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	return len(ents) == 0
}

// fsTypeOf returns a human label and the statfs magic for the filesystem at path.
func fsTypeOf(path string) (string, int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return "unknown", 0
	}
	magic := int64(st.Type)
	names := map[int64]string{
		tmpfsMagic: "tmpfs", ramfsMagic: "ramfs",
		0xEF53: "ext2/3/4", 0x9123683E: "btrfs", 0x58465342: "xfs",
		0x2fc12fc1: "zfs", 0x65735546: "fuse", 0x794c7630: "overlayfs",
		0x6969: "nfs", 0x01021997: "v9fs",
	}
	if n, ok := names[magic]; ok {
		return n, magic
	}
	return fmt.Sprintf("magic 0x%x", magic), magic
}

// maybeDropCaches drops the page cache if requested and root; reports whether it did.
func maybeDropCaches(want, root bool) bool {
	if !want || !root {
		return false
	}
	_ = exec.Command("sync").Run()
	if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0o644); err != nil {
		return false
	}
	return true
}

// toolPackage maps each external tool to the Alpine package that provides it,
// so a missing-tool error tells the operator exactly what to install. Note that
// resize2fs lives in e2fsprogs-extra, not the base e2fsprogs package.
var toolPackage = map[string]string{
	"mkfs.ext4": "e2fsprogs",
	"e2fsck":    "e2fsprogs",
	"resize2fs": "e2fsprogs-extra",
	"mcopy":     "mtools",
	"mkfs.fat":  "dosfstools",
	"mkfs.vfat": "dosfstools",
}

func checkRequiredTools() error {
	required := []string{"mkfs.ext4", "e2fsck", "resize2fs", "mcopy"}
	var missing []string
	pkgs := map[string]bool{}
	for _, t := range required {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
			pkgs[toolPackage[t]] = true
		}
	}
	if _, e1 := exec.LookPath("mkfs.fat"); e1 != nil {
		if _, e2 := exec.LookPath("mkfs.vfat"); e2 != nil {
			missing = append(missing, "mkfs.fat/mkfs.vfat")
			pkgs[toolPackage["mkfs.fat"]] = true
		}
	}
	if len(missing) > 0 {
		var names []string
		for p := range pkgs {
			names = append(names, p)
		}
		sort.Strings(names)
		return fmt.Errorf("missing required tools: %s (Alpine: apk add %s)",
			strings.Join(missing, ", "), strings.Join(names, " "))
	}
	return nil
}

func mustSize(s string) int64 {
	n, err := parseSize(s)
	if err != nil {
		fatal(fmt.Errorf("bad size %q: %w", s, err))
	}
	return n
}

// parseSize parses sizes like "22G", "300M", "512" with binary K/M/G/T suffixes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult = 1 << 10
	case 'M', 'm':
		mult = 1 << 20
	case 'G', 'g':
		mult = 1 << 30
	case 'T', 't':
		mult = 1 << 40
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

func human(b int64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGT"[exp])
}

func round(d time.Duration) string {
	if d >= time.Second {
		return d.Round(10 * time.Millisecond).String()
	}
	return d.Round(time.Millisecond).String()
}

var (
	scratchDir  string // the scratch dir we created; cleaned on exit/signal/fatal
	mountPoint  string // set while a loop mount is active, cleared after umount
	keepScratch bool
)

// cleanupScratch umounts any loop mount we left active and removes the scratch
// dir we created. It is safe to call repeatedly and from a signal handler. It
// always umounts (even with --keep) so a leaked loop mount can never block the
// directory.
func cleanupScratch() {
	if mountPoint != "" {
		_ = exec.Command("umount", mountPoint).Run()
		mountPoint = ""
	}
	if scratchDir != "" && !keepScratch {
		_ = os.RemoveAll(scratchDir)
	}
}

// installSignalCleanup umounts + removes the scratch on SIGINT/SIGTERM (^C),
// which would otherwise skip the deferred cleanup and leak the loop mount.
func installSignalCleanup(cancel context.CancelFunc) {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigc
		fmt.Fprintf(os.Stderr, "\nresize-bench: interrupted (%v); aborting\n", s)
		// Cancel in-flight work; the main path's op returns an error and runs
		// cleanupScratch() via fatal(), sequentially (no race with the writers).
		cancel()
		// Fallback: if the main path is stuck or in a non-cancellable gap, clean
		// up and exit ourselves after a grace period.
		time.Sleep(5 * time.Second)
		cleanupScratch()
		os.Exit(130)
	}()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "resize-bench:", err)
	cleanupScratch()
	os.Exit(1)
}
