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
	ctx := PrintHandle{
		curLines:      0,
		maxRows:       maxRows - 1, // Save one line for an "exceeded" message
		maxColumns:    maxColumns,
		exceeded:      false,
		outfile:       outfile,
		stateFilename: stateFilename,
		exceededCount: 0,
	}
	return &ctx
}

// Flush writes all the output to statefilename and resets to zero.
// It prints a line if exceeded
func (ctx *PrintHandle) Flush() {
	if ctx.exceededCount > 0 {
		ctx.Print("WARNING: screen exceeded size by %d\n",
			ctx.exceededCount)
	}
	if ctx.stateFilename != "" {
		fileutils.WriteRename(ctx.stateFilename,
			[]byte(ctx.allBytes.String()))
	}
	ctx.Reset()
}

// Reset forgets about what has been printed
func (ctx *PrintHandle) Reset() {
	ctx.curLines = 0
	ctx.exceeded = false
	ctx.exceededCount = 0
	ctx.allBytes.Reset()
}

// Print checks the number of lines since last PrintIfSpaceInit taking
// into account the number of columns.
// A terminating non-empty line counts as a line.
// Returns true if it was printed.
// In addition it always saves to allBytes
func (ctx *PrintHandle) Print(format string, a ...any) (bool, error) {
	// Determine how many lines this will take based on \n plus the
	// line wrap past maxColumns
	out := fmt.Sprintf(format, a...)
	if ctx.exceeded {
		ctx.exceededCount++
		ctx.allBytes.WriteString(out)
		return false, fmt.Errorf("already exceeded. count %d",
			ctx.exceededCount-1)
	}
	lineCnt := 0
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		// Round up to determine wrap
		cnt := 1 + (len(line)-1)/ctx.maxColumns
		lineCnt += cnt
	}
	// lines has at least one element; check length of last line
	if len(lines[len(lines)-1]) == 0 {
		lineCnt--
	}
	if ctx.curLines+lineCnt > ctx.maxRows {
		ctx.exceeded = true
		ctx.exceededCount++
		ctx.allBytes.WriteString(out)
		return false, fmt.Errorf("had %d lines, added %d, exceeded %d",
			ctx.curLines, lineCnt, ctx.maxRows)
	}
	ctx.curLines += lineCnt
	fmt.Fprint(ctx.outfile, out)
	ctx.allBytes.WriteString(out)
	return true, nil
}
