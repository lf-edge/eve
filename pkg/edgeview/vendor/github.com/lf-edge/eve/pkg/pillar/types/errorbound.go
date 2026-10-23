// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxErrorLen is the longest error string an ErrorDescription carries;
// SetErrorDescription cuts longer ones down with TruncateError. The bound is
// what keeps a status publishable: a pubsub message carries 64 KiB, and an
// AppInstanceStatus embeds one error per volume reference on top of its own,
// so an error that grows with what went wrong (one entry per source address,
// per blob, per volume) has to be bounded somewhere every status passes.
const MaxErrorLen = 4096

// OversizedStatusErrorLen is what the error strings of a status are cut down
// to when the status still does not fit a pubsub message: short enough for
// a status with many volumes to fit, long enough to still say what failed.
const OversizedStatusErrorLen = 256

// truncatedNoteFmt replaces the bytes TruncateError drops from the middle.
const truncatedNoteFmt = " [... %d bytes dropped ...] "

// TruncateError returns s when it is at most maxLen bytes long. Otherwise it
// keeps the head and the tail of s with a note in between saying how many
// bytes were dropped: the head because that is where the cause usually is,
// the tail because that is where a wrapped error or a command's output ends.
// Cuts land on rune boundaries.
func TruncateError(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 0 {
		return ""
	}
	// The note is longest with the whole length in it, so the result stays
	// within maxLen whatever the dropped count turns out to be.
	keep := maxLen - len(fmt.Sprintf(truncatedNoteFmt, len(s)))
	if keep < 2 {
		return s[:runeStartBefore(s, maxLen)]
	}
	head := runeStartBefore(s, keep*2/3)
	tailStart := runeStartAfter(s, len(s)-(keep-head))
	return s[:head] + fmt.Sprintf(truncatedNoteFmt, tailStart-head) + s[tailStart:]
}

// JoinMaxErrorStrings joins errs with sep like strings.Join, as far as the result
// stays within maxLen bytes: the errors that do not fit are left out and
// replaced by a note of how many they were. The first error is always
// included, cut down with TruncateError when it alone does not fit.
func JoinMaxErrorStrings(errs []string, sep string, maxLen int) string {
	if len(errs) == 0 {
		return ""
	}
	if joined := strings.Join(errs, sep); len(joined) <= maxLen {
		return joined
	}
	note := func(n int) string { return fmt.Sprintf("... and %d more", n) }
	var b strings.Builder
	for i, e := range errs {
		after := len(errs) - i - 1
		if i == 0 {
			budget := maxLen
			if after > 0 {
				budget -= len(sep) + len(note(after))
			}
			b.WriteString(TruncateError(e, budget))
			continue
		}
		need := b.Len() + len(sep) + len(e)
		if after > 0 {
			need += len(sep) + len(note(after))
		}
		if need > maxLen {
			b.WriteString(sep)
			b.WriteString(note(after + 1))
			break
		}
		b.WriteString(sep)
		b.WriteString(e)
	}
	return b.String()
}

// runeStartBefore moves i back to the start of the rune it falls into.
func runeStartBefore(s string, i int) int {
	for i > 0 && i < len(s) && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

// runeStartAfter moves i forward to the start of the next rune.
func runeStartAfter(s string, i int) int {
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return i
}
