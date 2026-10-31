// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"fmt"
	"sync"

	units "github.com/docker/go-units"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kernelcmdline"
)

// The largest frame and the largest message can be set on the kernel command
// line, e.g. eve_pubsub_max_message=64M. Every process reads them before it
// sends or receives its first frame, so all ends of a connection agree.
const (
	// frameSizeParam sets the largest frame payload, which is also the
	// largest message sent as it is: a larger one is compressed and must
	// compress into a frame.
	frameSizeParam = "eve_pubsub_max_frame"
	// messageSizeParam sets the largest message, decompressed.
	messageSizeParam = "eve_pubsub_max_message"

	defaultMaxFrameSize   = 1 << 20
	defaultMaxMessageSize = 30 << 20
	// minFrameSize is the smallest frame size that can be set: below it, a
	// message would be compressed only to be read into a pooled buffer.
	minFrameSize = poolMaxSize
	// maxSizeLimit is the largest either size can be set to. A frame length
	// must stay below compressedFlag.
	maxSizeLimit = 1 << 30
)

// sizeLimits are the largest frame and message of this process.
type sizeLimits struct {
	frame   int
	message int
	errs    []error // parameters which could not be used as given
}

var (
	limitsOnce    sync.Once
	limits        sizeLimits
	logLimitsOnce sync.Once
)

func currentLimits() *sizeLimits {
	limitsOnce.Do(func() {
		cmdline, err := kernelcmdline.Current()
		limits = limitsFrom(cmdline)
		if err != nil {
			limits.errs = append(limits.errs, fmt.Errorf(
				"reading the kernel command line: %w; using the default sizes", err))
		}
	})
	return &limits
}

// maxFrameSize returns the largest frame payload, and the largest message
// sent as it is.
func maxFrameSize() int {
	return currentLimits().frame
}

// maxMessageSize returns the largest message, decompressed.
func maxMessageSize() int {
	return currentLimits().message
}

// limitsFrom returns the sizes the command line sets, and the defaults for
// those it does not. A size that does not parse is replaced by its default
// and one out of range is clamped, each with an error.
func limitsFrom(cmdline kernelcmdline.Cmdline) sizeLimits {
	var l sizeLimits
	l.frame = l.size(cmdline, frameSizeParam, defaultMaxFrameSize, minFrameSize)
	l.message = l.size(cmdline, messageSizeParam,
		max(defaultMaxMessageSize, l.frame), l.frame)
	return l
}

func (l *sizeLimits) size(cmdline kernelcmdline.Cmdline, name string, def, minSize int) int {
	value, ok := cmdline.Value(name)
	if !ok {
		return def
	}
	n, err := units.RAMInBytes(value)
	switch {
	case err != nil:
		l.errs = append(l.errs, fmt.Errorf("%s=%s: %w; using %d", name, value, err, def))
		return def
	case n < int64(minSize):
		l.errs = append(l.errs, fmt.Errorf("%s=%s is below %d; using %d",
			name, value, minSize, minSize))
		return minSize
	case n > maxSizeLimit:
		l.errs = append(l.errs, fmt.Errorf("%s=%s is above %d; using %d",
			name, value, maxSizeLimit, maxSizeLimit))
		return maxSizeLimit
	}
	return int(n)
}

// logLimits logs, once per process, the sizes set on the kernel command line
// and the parameters which could not be used as given.
func logLimits(log *base.LogObject) {
	logLimitsOnce.Do(func() {
		l := currentLimits()
		for _, err := range l.errs {
			log.Errorf("pubsub: %v", err)
		}
		if l.frame != defaultMaxFrameSize || l.message != defaultMaxMessageSize {
			log.Noticef("pubsub: frames up to %d bytes, messages up to %d bytes",
				l.frame, l.message)
		}
	})
}
