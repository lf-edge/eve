// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/framed"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

// Protocol over AF_UNIX or other IPC mechanism
// "request" from client after connect to sanity check subject.
// Server sends the other messages; "update" for initial values.
// "complete" once all initial keys/values in collection have been sent.
// "restarted" if/when pub.km.restartCounter is set.
// Ongoing we send "update" and "delete" messages.
// They keys and values are base64-encoded since they might contain spaces.
// We include typeName after command word for sanity checks.
// Hence the message format is
//	"request" topic
//	"hello"  topic
//	"update" topic key json-val
//	"delete" topic key
//	"complete" topic (aka synchronized)
//	"restarted" topic count

// We always publish to our collection.
// We always write to a file in order to have a checkpoint on restart
// The special agent name "" implies always reading from the /run/global/
// directory.
const (
	publishToSock     = true  // XXX
	subscribeFromDir  = false // XXX
	subscribeFromSock = true  // XXX

	// For a subscription, if the agentName is empty we interpret that as
	// being directory in /run/global
	fixedName = "global"
	fixedDir  = "/run/" + fixedName
	// maxsize is the application-level limit on framed message size.
	// Messages are base64-encoded before this check, so the effective raw JSON
	// payload limit is approximately maxsize * 3/4 ≈ 7.5 MB.
	maxsize = 10 * 1024 * 1024
)

// SocketDriver driver for pubsub using local unix-domain socket and files
type SocketDriver struct {
	Logger  *logrus.Logger
	Log     *base.LogObject
	RootDir string // Default is "/"; tests can override
}

// Publisher return an implementation of `pubsub.DriverPublisher` for
// `SocketDriver`
func (s *SocketDriver) Publisher(global bool, name, topic string, persistent bool, updaterList *pubsub.Updaters, restarted pubsub.Restarted, differ pubsub.Differ) (pubsub.DriverPublisher, error) {
	var (
		dirName, sockName string
		publishToDir      bool
		listener          net.Listener
		err               error
	)
	shouldPopulate := false

	// We always write to the directory as a checkpoint for process restart
	// That directory could be persistent in which case it will survive
	// a reboot.

	// if the agentName is "", signal that we publish to dir, rather than
	// to sock
	if global {
		publishToDir = true
	}

	// the dirName depends on if we are persistent, and if it is the global config
	switch {
	case persistent && publishToDir:
		// No longer supported
		return nil, errors.New("Persistent not supported for empty agentname")
	case persistent && !publishToDir:
		dirName = s.persistentDirName(name)
	case !persistent && publishToDir:
		// Special case for /run/global
		dirName = s.fixedDirName(name)
	default:
		dirName = s.pubDirName(name)
	}

	if _, err := os.Stat(dirName); err != nil {
		s.Log.Functionf("Publish Create %s\n", dirName)
		if err := os.MkdirAll(dirName, 0700); err != nil {
			errStr := fmt.Sprintf("Publish(%s): %s",
				name, err)
			return nil, errors.New(errStr)
		}
	} else {
		// Read existing status from dir
		shouldPopulate = true
	}

	if !publishToDir && publishToSock {
		sockName = s.sockName(name)
		dir := path.Dir(sockName)
		if _, err := os.Stat(dir); err != nil {
			s.Log.Functionf("Publish Create %s\n", dir)
			if err := os.MkdirAll(dir, 0700); err != nil {
				errStr := fmt.Sprintf("Publish(%s): %s",
					name, err)
				return nil, errors.New(errStr)
			}
		}
		if _, err := os.Stat(sockName); err == nil {
			// This could either be a left-over in the filesystem
			// or some other process (or ourselves) using the same
			// name to publish. Try connect to see if it is the latter.
			sock, err := net.Dial("unix", sockName)
			if err == nil {
				sock.Close()
				s.Log.Fatalf("Cannot publish %s since it is already used",
					sockName)
			}
			if err := os.Remove(sockName); err != nil {
				errStr := fmt.Sprintf("Publish(%s): %s",
					name, err)
				return nil, errors.New(errStr)
			}
		}
		listener, err = net.Listen("unix", sockName)
		if err != nil {
			errStr := fmt.Sprintf("Publish(%s): failed %s",
				name, err)
			return nil, errors.New(errStr)
		}
	}
	doneChan := make(chan struct{})
	return &Publisher{
		persistent:     persistent,
		sockName:       sockName,
		listener:       listener,
		dirName:        dirName,
		shouldPopulate: shouldPopulate,
		name:           name,
		topic:          topic,
		updaters:       updaterList,
		differ:         differ,
		restarted:      restarted,
		logger:         s.Logger,
		log:            s.Log,
		doneChan:       doneChan,
		rootDir:        s.RootDir,
	}, nil
}

// Subscriber return an implementation of `pubsub.DriverSubscriber` for
// `SocketDriver`
func (s *SocketDriver) Subscriber(global bool, name, topic string, persistent bool, C chan pubsub.Change) (pubsub.DriverSubscriber, error) {
	var (
		sockName   = s.sockName(name)
		dirName    string
		subFromDir bool
	)

	// Special case for files in /run/global/ and also
	// for zedclient going away yet metrics being read after it
	// is gone.
	var agentName string
	names := strings.Split(name, "/")
	if len(names) > 0 {
		agentName = names[0]
	}

	if global {
		subFromDir = true
		if persistent {
			// No longer supported
			return nil, errors.New("Persistent not supported for empty agentname")
		}
		dirName = s.fixedDirName(name)
	} else if agentName == "zedclient" {
		subFromDir = true
		if persistent {
			dirName = s.persistentDirName(name)
		} else {
			dirName = s.pubDirName(name)
		}
	} else if persistent {
		// We do the initial Load from the directory if it
		// exists, but subsequent updates come over IPC
		subFromDir = false
		dirName = s.persistentDirName(name)
	} else {
		subFromDir = subscribeFromDir
		dirName = s.pubDirName(name)
	}
	doneChan := make(chan struct{})
	return &Subscriber{
		subscribeFromDir: subFromDir,
		dirName:          dirName,
		name:             name,
		topic:            topic,
		sockName:         sockName,
		C:                C,
		logger:           s.Logger,
		log:              s.Log,
		doneChan:         doneChan,
		rootDir:          s.RootDir,
	}, nil
}

// DefaultName default name for an agent when none is provided
func (s *SocketDriver) DefaultName() string {
	return fixedName
}

func (s *SocketDriver) sockName(name string) string {
	return fmt.Sprintf("%s/var/run/%s.sock", s.RootDir, name)
}

func (s *SocketDriver) pubDirName(name string) string {
	return fmt.Sprintf("%s/var/run/%s", s.RootDir, name)
}

func (s *SocketDriver) fixedDirName(name string) string {
	return fmt.Sprintf("%s/%s/%s", s.RootDir, fixedDir, name)
}

func (s *SocketDriver) persistentDirName(name string) string {
	return fmt.Sprintf("%s/%s/status/%s", s.RootDir, "/persist", name)
}

// NewFramedWriter wraps a net.Conn with a framed.Writer that uses big frames
// (32-bit length prefix), supporting messages up to maxsize.
// The actual application-level limit is enforced by the send* methods.
func NewFramedWriter(conn net.Conn) *framed.Writer {
	w := framed.NewWriter(conn)
	w.EnableBigFrames()
	return w
}

// initialBufSize is the initial size of the reusable read buffer.
// It will grow as needed up to maxsize.
const initialBufSize = 1024

// Size buckets for frame statistics. Each bucket counts frames with size
// up to the bucket boundary. The last bucket catches everything above.
var frameSizeBuckets = []int{
	256,
	1024,
	4 * 1024,
	16 * 1024,
	64 * 1024,
	256 * 1024,
	1024 * 1024,
	10 * 1024 * 1024,
}

// frameSizeBucketLabels are human-readable labels matching frameSizeBuckets.
var frameSizeBucketLabels = []string{
	"<=256B",
	"<=1KB",
	"<=4KB",
	"<=16KB",
	"<=64KB",
	"<=256KB",
	"<=1MB",
	"<=10MB",
	">10MB",
}

// readerStats holds per-FrameReader accumulated statistics.
type readerStats struct {
	framesRead   uint64 // total frames read
	bytesRead    uint64 // total payload bytes read
	grows        uint64 // number of buffer grow events
	maxFrameSize uint64 // largest frame seen
	bufSize      uint64 // current buffer capacity
	buckets      [9]uint64
}

// classifyFrame increments the appropriate size bucket counter.
func (s *readerStats) classifyFrame(n int) {
	for i, boundary := range frameSizeBuckets {
		if n <= boundary {
			atomic.AddUint64(&s.buckets[i], 1)
			return
		}
	}
	atomic.AddUint64(&s.buckets[len(frameSizeBuckets)], 1)
}

// globalReaderStats provides a system-wide aggregate view.
// Protected by globalStatsMu.
var (
	globalStatsMu     sync.Mutex
	globalReaderStats = make(map[string]*readerStats) // key is topic name
)

// registerReader registers a FrameReader's stats under the given topic.
func registerReader(topic string, stats *readerStats) {
	globalStatsMu.Lock()
	defer globalStatsMu.Unlock()
	globalReaderStats[topic] = stats
}

// unregisterReader removes a FrameReader's stats.
func unregisterReader(topic string) {
	globalStatsMu.Lock()
	defer globalStatsMu.Unlock()
	delete(globalReaderStats, topic)
}

// ReaderStatsEntry is a snapshot of one FrameReader's statistics.
type ReaderStatsEntry struct {
	Topic        string
	FramesRead   uint64
	BytesRead    uint64
	Grows        uint64
	MaxFrameSize uint64
	BufSize      uint64
	Buckets      [9]uint64
}

// GetAllReaderStats returns a snapshot of per-topic reader statistics.
// Safe to call from any goroutine.
func GetAllReaderStats() []ReaderStatsEntry {
	globalStatsMu.Lock()
	defer globalStatsMu.Unlock()
	entries := make([]ReaderStatsEntry, 0, len(globalReaderStats))
	for topic, s := range globalReaderStats {
		var buckets [9]uint64
		for i := range buckets {
			buckets[i] = atomic.LoadUint64(&s.buckets[i])
		}
		entries = append(entries, ReaderStatsEntry{
			Topic:        topic,
			FramesRead:   atomic.LoadUint64(&s.framesRead),
			BytesRead:    atomic.LoadUint64(&s.bytesRead),
			Grows:        atomic.LoadUint64(&s.grows),
			MaxFrameSize: atomic.LoadUint64(&s.maxFrameSize),
			BufSize:      atomic.LoadUint64(&s.bufSize),
			Buckets:      buckets,
		})
	}
	return entries
}

// LogReaderStats logs a summary of all reader stats using size buckets.
// Includes a comparison line showing old pool memory vs current arena memory.
func LogReaderStats(log *base.LogObject) {
	entries := GetAllReaderStats()
	if len(entries) == 0 {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Topic < entries[j].Topic
	})
	var totalOldPoolMem, totalArenaMem, totalFrames, totalBytes, totalGrows uint64
	var totalReaders int
	for _, e := range entries {
		totalReaders++
		totalFrames += e.FramesRead
		totalBytes += e.BytesRead
		totalGrows += e.Grows
		// Old pool: every reader used a fixed 65536-byte buffer
		totalOldPoolMem += 65536
		totalArenaMem += e.BufSize

		log.Functionf("FrameReader[%s]: frames=%d bytes=%d grows=%d maxFrame=%d buf=%d",
			e.Topic, e.FramesRead, e.BytesRead, e.Grows, e.MaxFrameSize, e.BufSize)
		for i, label := range frameSizeBucketLabels {
			if e.Buckets[i] > 0 {
				log.Functionf("  %s: %d", label, e.Buckets[i])
			}
		}
	}
	// Arena allocs = initial make per reader + grows. After warmup, grows stop.
	// Old sync.Pool: best case 0 allocs after warmup, worst case 1 per read
	// when GC reclaims idle buffers between Get/Put cycles.
	totalArenaAllocs := uint64(totalReaders) + totalGrows
	log.Functionf("FrameReader totals: readers=%d frames=%d bytes=%d "+
		"oldPoolMem=%d arenaMem=%d savedBytes=%d "+
		"arenaAllocs=%d grows=%d",
		totalReaders, totalFrames, totalBytes,
		totalOldPoolMem, totalArenaMem,
		int64(totalOldPoolMem)-int64(totalArenaMem),
		totalArenaAllocs, totalGrows)
}

// writeStatsCSV appends one row per topic plus a "__totals__" row to the given
// CSV file. The file is created with a header on first call.
// CSV columns:
//
//	timestamp, topic, frames, bytes, grows, max_frame, buf_size,
//	old_pool_mem, arena_mem, saved_bytes, arena_allocs,
//	bucket_<=256B, bucket_<=1KB, bucket_<=4KB, bucket_<=16KB,
//	bucket_<=64KB, bucket_<=256KB, bucket_<=1MB, bucket_<=10MB, bucket_>10MB
func writeStatsCSV(filePath string) error {
	entries := GetAllReaderStats()
	if len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Topic < entries[j].Topic
	})

	needHeader := false
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		needHeader = true
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("writeStatsCSV: open %s: %w", filePath, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if needHeader {
		header := []string{
			"timestamp", "topic", "frames", "bytes", "grows",
			"max_frame", "buf_size", "old_pool_mem", "arena_mem",
			"saved_bytes", "arena_allocs",
		}
		for _, label := range frameSizeBucketLabels {
			header = append(header, "bucket_"+label)
		}
		if err := w.Write(header); err != nil {
			return err
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	u := strconv.FormatUint

	var totalOldPoolMem, totalArenaMem, totalFrames, totalBytes, totalGrows uint64
	for _, e := range entries {
		totalFrames += e.FramesRead
		totalBytes += e.BytesRead
		totalGrows += e.Grows
		oldPool := uint64(65536)
		totalOldPoolMem += oldPool
		totalArenaMem += e.BufSize

		row := []string{
			now, e.Topic,
			u(e.FramesRead, 10), u(e.BytesRead, 10), u(e.Grows, 10),
			u(e.MaxFrameSize, 10), u(e.BufSize, 10),
			u(oldPool, 10), u(e.BufSize, 10),
			strconv.FormatInt(int64(oldPool)-int64(e.BufSize), 10),
			u(1+e.Grows, 10),
		}
		for _, b := range e.Buckets {
			row = append(row, u(b, 10))
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	// Totals row
	totalArenaAllocs := uint64(len(entries)) + totalGrows
	totRow := []string{
		now, "__totals__",
		u(totalFrames, 10), u(totalBytes, 10), u(totalGrows, 10),
		"0", u(totalArenaMem, 10),
		u(totalOldPoolMem, 10), u(totalArenaMem, 10),
		strconv.FormatInt(int64(totalOldPoolMem)-int64(totalArenaMem), 10),
		u(totalArenaAllocs, 10),
	}
	for range frameSizeBucketLabels {
		totRow = append(totRow, "0")
	}
	return w.Write(totRow)
}

// StartStatsLogger starts a goroutine that periodically writes FrameReader
// statistics to a CSV file and optionally also logs them.
// csvPath is the output CSV file (e.g. "/persist/pubsub-frame-stats.csv").
// Returns a stop function to cancel the logging goroutine.
// If interval is <= 0 a no-op stop function is returned.
func StartStatsLogger(log *base.LogObject, interval time.Duration, csvPath string) func() {
	if interval <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := writeStatsCSV(csvPath); err != nil {
					log.Errorf("FrameReader stats CSV: %v", err)
				}
				LogReaderStats(log)
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

// FrameReader reads length-prefixed frames from a stream using a reusable
// buffer that grows as needed up to maxsize. This avoids per-read allocations
// (unlike framed.ReadFrame) and avoids wasting memory with fixed large buffers.
// The wire format is identical to framed with EnableBigFrames: 4-byte
// little-endian length prefix followed by payload.
type FrameReader struct {
	r     io.Reader
	hdr   [4]byte
	buf   []byte
	topic string
	stats readerStats
}

// NewFrameReader creates a FrameReader over conn with an initial buffer of
// initialBufSize bytes. The buffer grows on demand up to maxsize.
// The topic is used for stats reporting; the reader is registered in the
// global stats map. Call Close when done to unregister.
func NewFrameReader(conn net.Conn, topic string) *FrameReader {
	fr := &FrameReader{
		r:     conn,
		buf:   make([]byte, initialBufSize),
		topic: topic,
		stats: readerStats{bufSize: initialBufSize},
	}
	registerReader(topic, &fr.stats)
	return fr
}

// NewFrameReaderInternal creates a FrameReader without registering it in the
// global stats map. Use this for short-lived readers that read only a single
// handshake frame (e.g. the publisher-side reader in serveConnection).
func NewFrameReaderInternal(conn net.Conn) *FrameReader {
	return &FrameReader{
		r:   conn,
		buf: make([]byte, initialBufSize),
	}
}

// Close unregisters this reader's stats. Should be called when the
// connection is done. No-op if the reader was created with NewFrameReaderInternal.
func (fr *FrameReader) Close() {
	if fr.topic != "" {
		unregisterReader(fr.topic)
	}
}

// ReadFrame reads a single frame. The returned slice is valid only until the
// next call to ReadFrame (it aliases the internal buffer).
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	// Read 4-byte length header
	if _, err := io.ReadFull(fr.r, fr.hdr[:]); err != nil {
		return nil, err
	}
	nraw := binary.LittleEndian.Uint32(fr.hdr[:])
	// Validate as uint32 before converting to int: on 32-bit platforms a large
	// prefix would wrap negative, bypass the check, and panic on buf[:n].
	if nraw > uint32(maxsize) {
		return nil, fmt.Errorf("received frame of %d bytes exceeds max %d",
			nraw, maxsize)
	}
	n := int(nraw)
	// Grow buffer if needed with 25% headroom to reduce future
	// re-allocations; never shrink.
	if n > len(fr.buf) {
		newSize := n + n/4
		if newSize > maxsize {
			newSize = maxsize
		}
		fr.buf = make([]byte, newSize)
		atomic.AddUint64(&fr.stats.grows, 1)
		atomic.StoreUint64(&fr.stats.bufSize, uint64(newSize))
	}
	if _, err := io.ReadFull(fr.r, fr.buf[:n]); err != nil {
		return nil, err
	}
	// Update stats
	atomic.AddUint64(&fr.stats.framesRead, 1)
	atomic.AddUint64(&fr.stats.bytesRead, uint64(n))
	un := uint64(n)
	for {
		old := atomic.LoadUint64(&fr.stats.maxFrameSize)
		if un <= old || atomic.CompareAndSwapUint64(&fr.stats.maxFrameSize, old, un) {
			break
		}
	}
	fr.stats.classifyFrame(n)
	return fr.buf[:n], nil
}

// Poll to check if we should go away
func areWeDone(log *base.LogObject, doneChan <-chan struct{}) bool {
	select {
	case _, ok := <-doneChan:
		if !ok {
			return true
		} else {
			log.Fatal("Received message on doneChan")
		}
	default:
	}
	return false
}
