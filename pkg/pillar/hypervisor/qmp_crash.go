// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"golang.org/x/sys/unix"
)

// dumpStreamTimeout bounds how long we wait for qemu to stream a guest core
// through the FIFO. The capture runs in domainmgr's per-domain goroutine (never
// the main loop), so a hang here cannot stall the watchdog; the bound just
// stops a stuck dump from holding the domain frozen forever.
const dumpStreamTimeout = 15 * time.Minute

// The crash-channel registry lets the per-domain QMP monitor goroutine (a
// translator, not an actor) hand mode-A crash notifications to domainmgr, which
// owns crash policy. Keyed by domain name; created lazily by WatchCrash and
// dropped by the KVM Cleanup. We never close the channels — a closed channel
// would busy-loop domainmgr's select; dropping the map entry is enough because
// emitCrash only sends to a still-registered channel.
var crashRegistry = newCrashRegistry()

type crashRegistryT struct {
	mu    sync.Mutex
	chans map[string]chan types.DomainCrashEvent
}

func newCrashRegistry() *crashRegistryT {
	return &crashRegistryT{chans: map[string]chan types.DomainCrashEvent{}}
}

// watch returns the receive end of the domain's crash channel, creating it on
// first use. Buffered (1) so a crash notification is never lost if domainmgr is
// momentarily busy.
func (r *crashRegistryT) watch(domainName string) <-chan types.DomainCrashEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.chans[domainName]
	if !ok {
		ch = make(chan types.DomainCrashEvent, 1)
		r.chans[domainName] = ch
	}
	return ch
}

// emit delivers a crash notification if domainmgr is watching this domain. The
// non-blocking send collapses repeated internal-error events into the single
// buffered slot.
func (r *crashRegistryT) emit(domainName, runState string) {
	r.mu.Lock()
	ch := r.chans[domainName]
	r.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- types.DomainCrashEvent{RunState: runState, When: time.Now()}:
	default:
	}
}

// forget drops the domain's channel (on Cleanup / VM teardown) so a later
// WatchCrash for a restarted VM gets a fresh channel.
func (r *crashRegistryT) forget(domainName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.chans, domainName)
}

// readQemuRunState returns the raw QMP run-state string ("running",
// "internal-error", "paused", …). Unlike getQemuStatus it does not map to
// SwState, so it can surface internal-error — the mode-A crash signal that has
// no SwState of its own.
func readQemuRunState(socket string) (string, error) {
	raw, err := execRawCmd(socket, `{ "execute": "query-status" }`, false)
	if err != nil {
		return "", err
	}
	var resp struct {
		Return struct {
			Status string `json:"status"`
		} `json:"return"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("parse query-status: %w", err)
	}
	return resp.Return.Status, nil
}

// execDumpGuestMemoryStream dumps the guest's physical RAM as an ELF core and
// streams it to w, so the caller can compress and quota it on the fly with no
// full-size intermediate on disk. It uses a FIFO plus
// dump-guest-memory protocol=file:<fifo>,detach=true — the vendored go-qemu QMP
// client cannot pass an fd (no SCM_RIGHTS), and detach keeps the QMP call from
// blocking for the whole (possibly minutes-long) dump. If w returns an error
// mid-stream (e.g. quota exceeded), closing the read end makes qemu's dump
// thread see EPIPE and abort.
func execDumpGuestMemoryStream(socket string, w io.Writer) error {
	fifo := filepath.Join(filepath.Dir(socket), fmt.Sprintf("guestmem-%d.fifo", time.Now().UnixNano()))
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		return fmt.Errorf("mkfifo %s: %w", fifo, err)
	}
	defer os.Remove(fifo)

	// Start the reader BEFORE issuing the dump command. dump-guest-memory opens
	// the FIFO for writing, which blocks until a reader is present; issuing the
	// command first would wedge qemu opening the FIFO — the QMP call never
	// returns and we never open the reader (a deadlock). Opening the read end
	// here (also blocking) rendezvous with qemu's write open, in the handler or
	// the detached thread.
	// readerFile lets the timeout path close the read end so the reader
	// goroutine's io.Copy unblocks and stops writing to w before we return
	// (w is closed by the caller; concurrent Write/Close on the zstd encoder
	// would be a data race).
	var readerMu sync.Mutex
	var readerFile *os.File
	done := make(chan error, 1)
	go func() {
		f, err := os.Open(fifo) // blocks until a writer (qemu) opens the FIFO
		if err != nil {
			done <- fmt.Errorf("open guest-core FIFO: %w", err)
			return
		}
		readerMu.Lock()
		readerFile = f
		readerMu.Unlock()
		defer f.Close()
		_, err = io.Copy(w, f)
		done <- err
	}()

	cmd := fmt.Sprintf(`{ "execute": "dump-guest-memory", "arguments": { "paging": false, "detach": true, "protocol": "file:%s" } }`, fifo)
	if _, err := execRawCmd(socket, cmd, true); err != nil {
		// The command failed, so qemu will never open the write end; unblock the
		// waiting reader by opening (and closing) the write end ourselves.
		if wf, oerr := os.OpenFile(fifo, os.O_WRONLY, 0); oerr == nil {
			_ = wf.Close()
		}
		<-done
		return fmt.Errorf("dump-guest-memory: %w", err)
	}

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("streaming guest core: %w", err)
		}
		return nil
	case <-time.After(dumpStreamTimeout):
		// If the goroutine actually finished right at the deadline, honor its
		// result instead of forcing anything.
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("streaming guest core: %w", err)
			}
			return nil
		default:
		}
		// Still blocked — stop it before returning so it can no longer write to
		// w (the caller closes w; concurrent Write/Close on the zstd encoder is a
		// data race). It is either in io.Copy (readerFile set — close the read
		// end) or still in os.Open waiting for qemu to open the write end
		// (readerFile nil — rendezvous by opening the write end ourselves, as the
		// command-error path above does, so the read open returns and the
		// goroutine can exit). Then drain it.
		readerMu.Lock()
		rf := readerFile
		readerMu.Unlock()
		if rf != nil {
			_ = rf.Close()
		} else if wf, oerr := os.OpenFile(fifo, os.O_WRONLY, 0); oerr == nil {
			_ = wf.Close()
		}
		<-done
		return fmt.Errorf("timed out after %s streaming guest core", dumpStreamTimeout)
	}
}
