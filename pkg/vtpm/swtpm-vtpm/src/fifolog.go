// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

type logForwarder struct {
	fifoPath      string
	logPath       string
	logFileHandle *os.File
	logSize       int64
	mu            sync.Mutex
	cancel        context.CancelFunc
	done          chan struct{}
}

func newLogForwarder(fifoPath, logPath string) (*logForwarder, error) {
	// remove stale FIFO from a previous run, if any
	os.Remove(fifoPath)

	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		return nil, fmt.Errorf("failed to create log FIFO: %w", err)
	}

	logFileHandle, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		os.Remove(fifoPath)
		return nil, fmt.Errorf("failed to open swtpm log file: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	lf := &logForwarder{
		fifoPath:      fifoPath,
		logPath:       logPath,
		logFileHandle: logFileHandle,
		cancel:        cancel,
		done:          make(chan struct{}),
	}
	go lf.run(ctx)
	return lf, nil
}

// openFIFO polls until a writer opens the FIFO
func (lf *logForwarder) openFIFO(ctx context.Context) (*os.File, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		f, err := os.OpenFile(lf.fifoPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			return f, nil
		}
		// if no writer yet, OK, otherswise report error.
		if !errors.Is(err, syscall.ENXIO) {
			return nil, fmt.Errorf("failed to open log FIFO: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (lf *logForwarder) run(ctx context.Context) {
	defer close(lf.done)
	defer func() {
		lf.mu.Lock()
		if lf.logFileHandle != nil {
			lf.logFileHandle.Close()
			lf.logFileHandle = nil
		}
		lf.mu.Unlock()
	}()

	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return
		}
		fifo, err := lf.openFIFO(ctx)
		if err != nil {
			return
		}
		// drain FIFO until EOF (writer closed).
		for {
			n, readErr := fifo.Read(buf)
			if n > 0 {
				lf.writeToLog(buf[:n])
			}
			if readErr != nil {
				break
			}
		}
		fifo.Close()
	}
}

func (lf *logForwarder) writeToLog(data []byte) {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if lf.logFileHandle == nil {
		return
	}
	n, err := lf.logFileHandle.Write(data)
	if err != nil {
		log.Errorf("swtpm log write error: %v", err)
		return
	}
	lf.logSize += int64(n)
	if lf.logSize >= swtpmLogMaxSize {
		lf.rotate()
	}
}

func (lf *logForwarder) rotate() {
	for i := swtpmLogMaxBackups - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d.gz", lf.logPath, i),
			fmt.Sprintf("%s.%d.gz", lf.logPath, i+1))
	}
	if err := compressFile(lf.logPath, lf.logPath+".1.gz"); err != nil {
		log.Errorf("log compress error: %v", err)
		return
	}
	if err := lf.logFileHandle.Truncate(0); err != nil {
		log.Errorf("log truncate error: %v", err)
		return
	}
	if _, err := lf.logFileHandle.Seek(0, io.SeekStart); err != nil {
		log.Errorf("log seek error: %v", err)
		return
	}
	lf.logSize = 0
}

func (lf *logForwarder) stop() {
	lf.cancel()
	<-lf.done
	os.Remove(lf.fifoPath)
}

// compressFile gzip-compresses src into dst.
func compressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}
