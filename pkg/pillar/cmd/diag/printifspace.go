// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// The directory might not be available when we start so this gets called
// until it succeeds.
func tryOpenStatefile(ctx *diagContext) *os.File {
	// XXX tmpfile plus rename at end ... where is end?
	// Want open+defer close instead of Init() call?
	// XXX have close function do the rename and log.
	// XXX make level an arg to PrintIfSpace so we can determine max
	// level and use that for log.
	statefile, err := os.OpenFile(ctx.stateFilename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NONBLOCK, 0644)
	if err != nil {
		log.Warn(err)
		return nil
	}
	log.Noticef("Created %s", ctx.stateFilename)
	return statefile
}

// PrintIfSpaceInit sets up the limits and initializes lines to zero
// ignorePrevious needed for unit test
func PrintIfSpaceInit(ctx *diagContext, outfile *os.File, stateFilename string,
	maxRows int, maxColumns int, ignorePrevious bool) {
	// Save then (re)set everything
	exceededCount := ctx.exceededCount

	ctx.curLines = 0
	ctx.maxRows = maxRows
	ctx.maxColumns = maxColumns
	ctx.exceeded = false
	ctx.outfile = outfile
	ctx.stateFilename = stateFilename
	ctx.exceededCount = 0
	if ctx.stateFilename != "" && ctx.statefile == nil {
		ctx.statefile = tryOpenStatefile(ctx)
	}
	if ctx.statefile != nil {
		ctx.statefile.Truncate(0)
		ctx.statefile.Seek(0, 0)
	}
	if exceededCount > 0 {
		if ignorePrevious {
			log.Warnf("WARNING: previous screen exceeded size by %d",
				exceededCount)
		} else {
			PrintIfSpace(ctx, "WARNING: previous screen exceeded size by %d\n",
				exceededCount)
		}
	}
}

// XXX
func PrintIfSpaceClose(ctx *diagContext) {
	if ctx.stateFilename != "" {
		// XXX tmpfilename? Read it to write?
		fileutils.WriteRename(ctx.stateFilename, nil)
	}
}

// PrintIfSpace checks the number of lines since last PrintIfSpaceInit taking
// into account the number of columns.
// A terminating non-empty line counts as a line.
// Returns true if it was printed.
// In addition it always prints to ctx.statefile if set.
func PrintIfSpace(ctx *diagContext, format string, a ...any) (bool, error) {
	// Determine how many lines this will take based on \n plus the
	// line wrap past maxColumns
	out := fmt.Sprintf(format, a...)
	if ctx.exceeded {
		ctx.exceededCount++
		if ctx.statefile != nil {
			fmt.Fprint(ctx.statefile, out)
		}
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
		if ctx.statefile != nil {
			fmt.Fprint(ctx.statefile, out)
		}
		return false, fmt.Errorf("had %d lines, added %d, exceeded %d",
			ctx.curLines, lineCnt, ctx.maxRows)
	}
	ctx.curLines += lineCnt
	fmt.Fprint(ctx.outfile, out)
	if ctx.statefile != nil {
		fmt.Fprint(ctx.statefile, out)
	}
	return true, nil
}
