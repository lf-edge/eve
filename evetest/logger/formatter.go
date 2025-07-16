// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"time"

	"github.com/sirupsen/logrus"
)

// PrefixColor defines the ANSI color to apply to the log prefix.
type PrefixColor int

// PrefixColor named-value constants.
const (
	// No color (default)

	// PrefixColorNone specifies no color for the log prefix (default).
	PrefixColorNone PrefixColor = iota

	// Standard ANSI colors

	PrefixColorBlack
	PrefixColorRed
	PrefixColorGreen
	PrefixColorYellow
	PrefixColorBlue
	PrefixColorPurple
	PrefixColorCyan
	PrefixColorWhite

	// Bright ANSI colors

	PrefixColorBrightBlack
	PrefixColorBrightRed
	PrefixColorBrightGreen
	PrefixColorBrightYellow
	PrefixColorBrightBlue
	PrefixColorBrightPurple
	PrefixColorBrightCyan
	PrefixColorBrightWhite
)

const (
	colorReset = "\033[0m"

	ansiBlack        = "\033[30m"
	ansiRed          = "\033[31m"
	ansiGreen        = "\033[32m"
	ansiYellow       = "\033[33m"
	ansiBlue         = "\033[34m"
	ansiPurple       = "\033[35m"
	ansiCyan         = "\033[36m"
	ansiWhite        = "\033[37m"
	ansiBrightBlack  = "\033[90m"
	ansiBrightRed    = "\033[91m"
	ansiBrightGreen  = "\033[92m"
	ansiBrightYellow = "\033[93m"
	ansiBrightBlue   = "\033[94m"
	ansiBrightPurple = "\033[95m"
	ansiBrightCyan   = "\033[96m"
	ansiBrightWhite  = "\033[97m"
)

func colorSeq(c PrefixColor) string {
	switch c {
	case PrefixColorBlack:
		return ansiBlack
	case PrefixColorRed:
		return ansiRed
	case PrefixColorGreen:
		return ansiGreen
	case PrefixColorYellow:
		return ansiYellow
	case PrefixColorBlue:
		return ansiBlue
	case PrefixColorPurple:
		return ansiPurple
	case PrefixColorCyan:
		return ansiCyan
	case PrefixColorWhite:
		return ansiWhite
	case PrefixColorBrightBlack:
		return ansiBrightBlack
	case PrefixColorBrightRed:
		return ansiBrightRed
	case PrefixColorBrightGreen:
		return ansiBrightGreen
	case PrefixColorBrightYellow:
		return ansiBrightYellow
	case PrefixColorBrightBlue:
		return ansiBrightBlue
	case PrefixColorBrightPurple:
		return ansiBrightPurple
	case PrefixColorBrightCyan:
		return ansiBrightCyan
	case PrefixColorBrightWhite:
		return ansiBrightWhite
	default:
		return ""
	}
}

// PrefixedFormatter is a logrus formatter that prepends a colored prefix to each log line.
type PrefixedFormatter struct {
	Prefix string
	Color  PrefixColor
}

// Format formats a logrus log entry with an optional colored prefix.
func (f *PrefixedFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var buf bytes.Buffer

	// Prefix (optionally colored)
	if f.Prefix != "" {
		if seq := colorSeq(f.Color); seq != "" {
			buf.WriteString(seq)
			buf.WriteString(f.Prefix)
			buf.WriteString(colorReset)
		} else {
			buf.WriteString(f.Prefix)
		}
		buf.WriteByte(' ')
	}

	// time="..."
	buf.WriteString(`time="`)
	buf.WriteString(entry.Time.UTC().Format(time.RFC3339))
	buf.WriteString(`" `)

	// level=...
	buf.WriteString(`level=`)
	buf.WriteString(entry.Level.String())
	buf.WriteByte(' ')

	// msg="..."
	buf.WriteString(`msg="`)
	buf.WriteString(entry.Message)
	buf.WriteString(`"`)

	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
