// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/kernelcmdline"
)

func TestLimitsFromKernelCmdline(t *testing.T) {
	tests := []struct {
		cmdline        string
		frame, message int
		errs           int
	}{
		{"console=ttyS0", defaultMaxFrameSize, defaultMaxMessageSize, 0},
		{"eve_pubsub_max_frame=4M eve_pubsub_max_message=64M", 4 << 20, 64 << 20, 0},
		{"eve_pubsub_max_message=1048576", defaultMaxFrameSize, 1 << 20, 0},
		{"eve_pubsub_max_message=512KiB", defaultMaxFrameSize, defaultMaxFrameSize, 1},
		{"eve_pubsub_max_frame=40M", 40 << 20, 40 << 20, 0},
		{"eve_pubsub_max_frame=1k", minFrameSize, defaultMaxMessageSize, 1},
		{"eve_pubsub_max_message=4G", defaultMaxFrameSize, maxSizeLimit, 1},
		{"eve_pubsub_max_frame=lots eve_pubsub_max_message", defaultMaxFrameSize, defaultMaxMessageSize, 2},
		{"eve_pubsub_max_message=16M eve_pubsub_max_message=48m", defaultMaxFrameSize, 48 << 20, 0},
	}
	for _, tt := range tests {
		l := limitsFrom(kernelcmdline.Parse(tt.cmdline))
		if l.frame != tt.frame || l.message != tt.message || len(l.errs) != tt.errs {
			t.Errorf("%q: frame %d, message %d, errors %v; want %d, %d and %d errors",
				tt.cmdline, l.frame, l.message, l.errs, tt.frame, tt.message, tt.errs)
		}
	}
}
