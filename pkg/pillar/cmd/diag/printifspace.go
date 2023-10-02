// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// PrintHandle is returned by PrintIfSpaceInit()
// The assumption is that the caller calls Flush() when done with one set of
// output so it can be written to a file and the counters reset.
type PrintHandle struct {
	curLines      int // Number used in current iteration
	maxRows       int
	maxColumns    int
	exceeded      bool
	exceededCount int
	outfile       *os.File
	stateFilename string
	allBytes      bytes.Buffer
}

// PrintIfSpaceInit sets up the limits and initializes current lines to zero
func PrintIfSpaceInit(outfile *os.File, stateFilename string,
	maxRows int, maxColumns int) *PrintHandle {
	h := PrintHandle{
		curLines:      0,
		maxRows:       maxRows - 1, // Save one line for an "exceeded" message
		maxColumns:    maxColumns,
		exceeded:      false,
		outfile:       outfile,
		stateFilename: stateFilename,
		exceededCount: 0,
	}
	return &h
}

// Flush writes all the output to statefilename and resets to zero.
// It prints a line if exceeded
func (h *PrintHandle) Flush() {
	if h.exceededCount > 0 {
		h.Print("WARNING: screen exceeded size by %d\n",
			h.exceededCount)
	}
	if h.stateFilename != "" {
		fileutils.WriteRename(h.stateFilename,
			[]byte(h.allBytes.String()))
	}
	h.Reset()
}

// Reset forgets about what has been printed
func (h *PrintHandle) Reset() {
	h.curLines = 0
	h.exceeded = false
	h.exceededCount = 0
	h.allBytes.Reset()
}

// Print checks the number of lines since last PrintIfSpaceInit taking
// into account the number of columns.
// A terminating non-empty line counts as a line.
// Returns true if it was printed.
// In addition it always saves to allBytes
func (h *PrintHandle) Print(format string, a ...any) (bool, error) {
	// Determine how many lines this will take based on \n plus the
	// line wrap past maxColumns
	out := fmt.Sprintf(format, a...)
	if h.exceeded {
		h.exceededCount++
		h.allBytes.WriteString(out)
		return false, fmt.Errorf("already exceeded. count %d",
			h.exceededCount-1)
	}
	lineCnt := 0
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		// Round up to determine wrap
		cnt := 1 + (len(line)-1)/h.maxColumns
		lineCnt += cnt
	}
	// lines has at least one element; check length of last line
	if len(lines[len(lines)-1]) == 0 {
		lineCnt--
	}
	if h.curLines+lineCnt > h.maxRows {
		h.exceeded = true
		h.exceededCount++
		h.allBytes.WriteString(out)
		return false, fmt.Errorf("had %d lines, added %d, exceeded %d",
			h.curLines, lineCnt, h.maxRows)
	}
	h.curLines += lineCnt
	fmt.Fprint(h.outfile, out)
	h.allBytes.WriteString(out)
	return true, nil
}
