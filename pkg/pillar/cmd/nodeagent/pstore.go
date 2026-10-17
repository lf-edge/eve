// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
)

const (
	// pillar's own /sys is a fresh sysfs without the pstore mount.
	pstoreDir   = "/hostfs/sys/fs/pstore"
	kcrashesDir = types.PersistDir + "/kcrashes"
	// maxKcrashes is the number of dumps kept in kcrashesDir, one file each.
	maxKcrashes = 10
	// encryptedSuffix marks a record the running kernel cannot decompress.
	encryptedSuffix = ".enc.z"
)

// pstoreHeader is the first line pstore_dump() writes in each record:
// "<reason>#<oops count> Part<n>", where Part1 holds the newest log.
var pstoreHeader = regexp.MustCompile(`^(\w+)#(\d+) Part(\d+)$`)

// pstoreRecord is one dmesg-* file in pstorefs.
type pstoreRecord struct {
	name   string
	reason string
	count  int
	part   int
	time   time.Time // zero when the backend recorded no time
	body   string    // the log text, without the header line
}

// pstoreDump is the set of records one kmsg_dump() wrote.
type pstoreDump struct {
	records []pstoreRecord // in write order, Part1 first
	current bool           // from the previous boot or later, not stale
}

func (d *pstoreDump) reason() string    { return d.records[0].reason }
func (d *pstoreDump) count() int        { return d.records[0].count }
func (d *pstoreDump) time() time.Time   { return d.records[0].time }
func (d *pstoreDump) isCrash() bool     { return d.reason() == "Panic" || d.reason() == "Oops" }
func (d *pstoreDump) firstName() string { return d.records[0].name }

// text returns the dumped log in order, oldest part first.
func (d *pstoreDump) text() string {
	var sb strings.Builder
	for i := len(d.records) - 1; i >= 0; i-- {
		sb.WriteString(d.records[i].body)
	}
	return sb.String()
}

// panicLine returns the "Kernel panic - not syncing" message of the dump, or
// its reason and count when the dump holds none.
func (d *pstoreDump) panicLine() string {
	text := d.text()
	if i := strings.LastIndex(text, "Kernel panic - not syncing"); i >= 0 {
		line, _, _ := strings.Cut(text[i:], "\n")
		return strings.TrimSpace(line)
	}
	return fmt.Sprintf("%s#%d", d.reason(), d.count())
}

// rebootStack returns the dump from its last "Kernel panic - not syncing"
// line onward, cut after the last whole line within maxRebootStackSize
// runes with "..." appended, so the controller sees the panic message and
// the innermost frames. A dump without a panic line yields its tail, as for
// other reboot stacks.
func (d *pstoreDump) rebootStack() string {
	text := d.text()
	i := strings.LastIndex(text, "Kernel panic - not syncing")
	if i < 0 {
		return truncateRebootStack(text)
	}
	if j := strings.LastIndex(text[:i], "\n"); j >= 0 {
		i = j + 1
	}
	runes := []rune(text[i:])
	if len(runes) <= maxRebootStackSize {
		return string(runes)
	}
	head := string(runes[:maxRebootStackSize])
	if k := strings.LastIndex(head, "\n"); k >= 0 {
		head = head[:k+1]
	}
	return head + "..."
}

// readPstoreRecords reads the dmesg-* files in dir. Records the running
// kernel could not decompress are returned separately by name, since their
// content cannot be parsed. A missing dir yields nothing.
func readPstoreRecords(dir string) (records []pstoreRecord, encrypted []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("pstore: %v", err)
		}
		return nil, nil
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "dmesg-") {
			continue
		}
		if strings.HasSuffix(name, encryptedSuffix) {
			encrypted = append(encrypted, name)
			continue
		}
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			log.Errorf("pstore: %v", err)
			continue
		}
		info, err := e.Info()
		if err != nil {
			log.Errorf("pstore: %v", err)
			continue
		}
		records = append(records, parsePstoreRecord(name, string(b), info.ModTime()))
	}
	return records, encrypted
}

// parsePstoreRecord splits a record into its header fields and body. A
// record without a recognizable header becomes a single-part dump with an
// empty reason. An mtime of the epoch means the backend kept no time.
func parsePstoreRecord(name, content string, mtime time.Time) pstoreRecord {
	rec := pstoreRecord{name: name, part: 1, body: content}
	if mtime.Unix() > 0 {
		rec.time = mtime
	}
	header, body, _ := strings.Cut(content, "\n")
	if m := pstoreHeader.FindStringSubmatch(header); m != nil {
		rec.reason = m[1]
		rec.count, _ = strconv.Atoi(m[2])
		rec.part, _ = strconv.Atoi(m[3])
		rec.body = body
	}
	return rec
}

// groupPstoreRecords sorts records by (time, part) and splits them into
// dumps wherever the part number stops increasing or the header changes.
// A dump's records are written within a second or two, so this holds even
// across a second boundary. Dumps are returned oldest first.
func groupPstoreRecords(records []pstoreRecord) []*pstoreDump {
	sort.SliceStable(records, func(i, j int) bool {
		if !records[i].time.Equal(records[j].time) {
			return records[i].time.Before(records[j].time)
		}
		return records[i].part < records[j].part
	})
	var dumps []*pstoreDump
	var cur *pstoreDump
	for _, rec := range records {
		if cur != nil {
			last := cur.records[len(cur.records)-1]
			if rec.part > last.part && rec.reason == last.reason &&
				rec.count == last.count {
				cur.records = append(cur.records, rec)
				continue
			}
		}
		cur = &pstoreDump{records: []pstoreRecord{rec}}
		dumps = append(dumps, cur)
	}
	return dumps
}

// classifyPstoreDumps marks the dumps written since prevBoot, the start of
// the previous boot that reached nodeagent, as current. Without prevBoot
// every timed dump is stale. A dump with no time counts as current.
func classifyPstoreDumps(dumps []*pstoreDump, prevBoot time.Time) {
	for _, d := range dumps {
		switch {
		case d.time().IsZero():
			d.current = true
		case prevBoot.IsZero():
			d.current = false
		default:
			d.current = d.time().After(prevBoot)
		}
	}
}

// pstoreRebootReason decides whether the newest current crash dump becomes
// the reboot reason, given the reason, boot reason and reason-file time
// stored in /persist. It returns the deciding dump (nil if none), the reason
// to write, which is empty when the stored reason stands, and the boot reason
// to write with it. A panic while EVE was already rebooting keeps the stored
// boot reason: zedagent chooses the config to start from by it, so a reboot
// from the watchdog must not turn into a normal one.
func pstoreRebootReason(dumps []*pstoreDump, storedReason string,
	storedBoot types.BootReason, storedTime time.Time) (*pstoreDump, string, types.BootReason) {

	var crashes []*pstoreDump
	for _, d := range dumps {
		if d.current && d.isCrash() {
			crashes = append(crashes, d)
		}
	}
	if len(crashes) == 0 {
		return nil, "", types.BootReasonNone
	}
	newest := crashes[len(crashes)-1]
	suffix := ""
	if len(crashes) > 1 {
		suffix = fmt.Sprintf(" (%d panics)", len(crashes))
	}
	storedReason = strings.TrimSpace(storedReason)
	switch {
	case storedReason == "":
		return newest, "kernel panic, pstore: " + newest.panicLine() + suffix,
			types.BootReasonKernel
	case storedBoot == types.BootReasonKernel:
		// Written by kdump in an older EVE, or by an earlier run of this code.
		return newest, "", types.BootReasonNone
	case newest.time().IsZero() || storedTime.Before(newest.time()):
		// EVE decided to reboot and the kernel panicked on the way down.
		br := storedBoot
		if br == types.BootReasonNone {
			br = types.BootReasonKernel
		}
		return newest, "kernel panic after " + storedReason + suffix, br
	default:
		return newest, "", types.BootReasonNone
	}
}

// logPstoreDump logs a dump the way agentlog logs a Go fatal stack trace: a
// header and an end marker from nodeagent, and each line of the kernel log,
// tagged "[kernel panic #N]", on a kernel_panic_stacks log object.
func logPstoreDump(d *pstoreDump) {
	what := "Kernel panic stack trace"
	logf := log.Errorf
	if !d.isCrash() {
		what = "Kernel log dump"
		logf = log.Warnf
	}
	state := "from the previous boot or later"
	if !d.current {
		state = "stale, from before the previous boot"
	}
	lines := strings.Split(strings.TrimRight(d.text(), "\n"), "\n")
	logf("%s from pstore (%s#%d at %s, %s) with %d lines: %s", what,
		d.reason(), d.count(), d.time().Format(time.RFC3339), state,
		len(lines), d.panicLine())
	stackLog := base.EnsureLogObject(log, base.KernelPanicStacksType,
		"", uuid.UUID{}, string(base.KernelPanicStacksType))
	for i, l := range lines {
		stackLog.Warnf("[kernel panic #%d]: %s", i, l)
	}
	logf("%s: end of stack", what)
}

// kcrashFile is a file to save under kcrashesDir.
type kcrashFile struct {
	name    string
	content []byte
	time    time.Time
	records []string // pstore files it holds, erased once it is saved
	saved   bool
}

// handlePstoreRecords turns the pstore records of earlier boots into
// /persist/kcrashes copies and, for the newest current crash, the reboot
// reason files read by handleLastRebootReason. It erases a record only
// after its copy is durable. Must run before handleLastRebootReason, which
// rewrites the restart counter whose mtime marks the previous boot.
func handlePstoreRecords(ctx *nodeagentContext) {
	dir := ctx.paths.pstoreDir
	records, encrypted := readPstoreRecords(dir)
	if len(records) == 0 && len(encrypted) == 0 {
		return
	}
	dumps := groupPstoreRecords(records)
	var prevBoot time.Time
	if info, err := os.Stat(ctx.paths.restartCounterFile); err == nil {
		prevBoot = info.ModTime()
	}
	classifyPstoreDumps(dumps, prevBoot)

	var files []*kcrashFile
	dumpFile := make(map[*pstoreDump]*kcrashFile)
	used := make(map[string]bool)
	for _, d := range dumps {
		name := "pstore-" + d.firstName()
		if !d.time().IsZero() {
			name = "pstore-" + d.time().UTC().Format(time.RFC3339)
		}
		stem := name
		for i := 1; used[name]; i++ {
			name = fmt.Sprintf("%s-%d", stem, i)
		}
		used[name] = true
		f := &kcrashFile{name: name + ".log", content: []byte(d.text()), time: d.time()}
		for _, r := range d.records {
			f.records = append(f.records, r.name)
		}
		files = append(files, f)
		dumpFile[d] = f
		logPstoreDump(d)
	}
	for _, name := range encrypted {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			log.Errorf("pstore: %v", err)
			continue
		}
		var mtime time.Time
		if info, err := os.Stat(path); err == nil && info.ModTime().Unix() > 0 {
			mtime = info.ModTime()
		}
		log.Warnf("pstore: compressed record %s, %d bytes", name, len(b))
		files = append(files, &kcrashFile{name: name, content: b,
			time: mtime, records: []string{name}})
	}
	saveKcrashFiles(ctx.paths.kcrashesDir, files)

	storedReason, storedTime, _ := ctx.rebootStore.GetRebootReason()
	storedBoot, _ := ctx.rebootStore.GetBootReason()
	deciding, reason, br := pstoreRebootReason(dumps, storedReason, storedBoot, storedTime)
	if deciding != nil {
		if reason == "" {
			log.Warnf("pstore: kernel panic at %s not used as reboot reason, stored %s: %s",
				deciding.time().Format(time.RFC3339), storedBoot,
				strings.TrimSpace(storedReason))
		} else if err := ctx.rebootStore.WriteKernelRebootReason(reason,
			deciding.rebootStack(), br, deciding.time()); err != nil {
			log.Errorf("pstore: keeping records, writing reboot reason failed: %v", err)
			dumpFile[deciding].saved = false
		} else {
			dumpFile[deciding].saved = true
			ctx.pstoreLoggedStack = deciding.rebootStack()
		}
	}

	for _, f := range files {
		if !f.saved {
			continue
		}
		for _, name := range f.records {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				log.Errorf("pstore: erase: %v", err)
			}
		}
	}
}

// saveKcrashFiles writes files to dir. Dumps are limited to the newest
// maxKcrashes, removing older dumps there so at most maxKcrashes remain;
// dumps that do not fit are marked saved too, since rotation would discard
// them. Compressed records are not limited, since they cannot be grouped
// into dumps and one panic leaves many of them.
func saveKcrashFiles(dir string, files []*kcrashFile) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Errorf("pstore: %v", err)
		return
	}
	var keep, encrypted []*kcrashFile
	for _, f := range files {
		if strings.HasSuffix(f.name, encryptedSuffix) {
			encrypted = append(encrypted, f)
		} else {
			keep = append(keep, f)
		}
	}
	sort.SliceStable(keep, func(i, j int) bool {
		return keep[i].time.After(keep[j].time)
	})
	if len(keep) > maxKcrashes {
		for _, f := range keep[maxKcrashes:] {
			log.Warnf("pstore: not saving %s, more than %d dumps", f.name, maxKcrashes)
			f.saved = true
		}
		keep = keep[:maxKcrashes]
	}
	pruneKcrashes(dir, maxKcrashes-len(keep), keep)
	for _, f := range slices.Concat(keep, encrypted) {
		err := fileutils.WriteRenameWithMtime(filepath.Join(dir, f.name), f.content, f.time)
		if err != nil {
			log.Errorf("pstore: %v", err)
			continue
		}
		f.saved = true
	}
}

// pruneKcrashes removes the oldest files in dir until at most room remain,
// not counting compressed records or files about to be rewritten by name.
func pruneKcrashes(dir string, room int, rewrite []*kcrashFile) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Errorf("pstore: %v", err)
		return
	}
	skip := make(map[string]bool)
	for _, f := range rewrite {
		skip[f.name] = true
	}
	type existing struct {
		name  string
		mtime time.Time
	}
	var old []existing
	for _, e := range entries {
		if skip[e.Name()] || e.IsDir() ||
			strings.HasSuffix(e.Name(), encryptedSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		old = append(old, existing{e.Name(), info.ModTime()})
	}
	sort.Slice(old, func(i, j int) bool { return old[i].mtime.After(old[j].mtime) })
	for i := room; i < len(old); i++ {
		if err := os.Remove(filepath.Join(dir, old[i].name)); err != nil {
			log.Errorf("pstore: %v", err)
		}
	}
}
