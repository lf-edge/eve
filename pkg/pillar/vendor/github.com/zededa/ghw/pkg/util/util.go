//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package util

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/zededa/ghw/internal/log"
)

const (
	UNKNOWN = "unknown"
)

type closer interface {
	Close() error
}

func SafeClose(c closer) {
	err := c.Close()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to close: %s", err)
	}
}

// Reads a supplied filepath and converts the contents to an integer. Returns
// -1 if there were file permissions or existence errors or if the contents
// could not be successfully converted to an integer. In any error, a warning
// message is printed to STDERR and -1 is returned.
func SafeIntFromFile(ctx context.Context, path string) int {
	msg := "failed to read int from file: %s\n"
	buf, err := os.ReadFile(path)
	if err != nil {
		log.Warn(ctx, msg, err)
		return -1
	}
	contents := strings.TrimSpace(string(buf))
	res, err := strconv.Atoi(contents)
	if err != nil {
		log.Warn(ctx, msg, err)
		return -1
	}
	return res
}

// ConcatStrings concatenate strings in a larger one. This function
// addresses a very specific ghw use case. For a more general approach,
// just use strings.Join()
func ConcatStrings(items ...string) string {
	return strings.Join(items, "")
}

// Convert strings to bool using strconv.ParseBool() when recognized, otherwise
// use map lookup to convert strings like "Yes" "No" "On" "Off" to bool
// `ethtool` uses on, off, yes, no (upper and lower case) rather than true and
// false.
func ParseBool(str string) (bool, error) {
	if b, err := strconv.ParseBool(str); err == nil {
		return b, err
	} else {
		ExtraBools := map[string]bool{
			"on":  true,
			"off": false,
			"yes": true,
			"no":  false,
			// Return false instead of an error on empty strings
			// For example from empty files in SysClassNet/Device
			"": false,
		}
		if b, ok := ExtraBools[strings.ToLower(str)]; ok {
			return b, nil
		} else {
			// Return strconv.ParseBool's error here
			return b, err
		}
	}
}

// maxCPUID bounds the logical processor IDs ParseCPUList accepts, far above any
// kernel's CPU limit, so that a corrupt list, from a snapshot say, cannot make it
// allocate gigabytes.
const maxCPUID = 1 << 16

// ParseCPUList parses a list of logical processor IDs in the kernel's CPU-list
// format, such as "0-3,7", the format of sysfs files like
// /sys/devices/system/cpu/online. Surrounding whitespace is ignored, and an
// empty list or "(null)", which the kernel prints for a mask it never set, is
// nil. An ID of maxCPUID or more is an error.
func ParseCPUList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "(null)" {
		return nil, nil
	}
	var ids []int
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.ParseUint(lo, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("invalid CPU list %q: %w", s, err)
		}
		last := first
		if isRange {
			if last, err = strconv.ParseUint(hi, 10, 31); err != nil {
				return nil, fmt.Errorf("invalid CPU list %q: %w", s, err)
			}
			if last < first {
				return nil, fmt.Errorf("invalid CPU list %q: range %s is reversed", s, part)
			}
		}
		if last >= maxCPUID {
			return nil, fmt.Errorf("invalid CPU list %q: CPU %d is out of range", s, last)
		}
		for id := first; id <= last; id++ {
			ids = append(ids, int(id))
		}
	}
	return ids, nil
}

// ReadCPUList reads a sysfs file holding a CPU list (see ParseCPUList). The
// error wraps os.ErrNotExist when the file does not exist.
func ReadCPUList(path string) ([]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCPUList(string(data))
}

// ReadInt reads a sysfs file holding one integer. Unlike SafeIntFromFile it
// tells a missing or malformed file (an error, wrapping os.ErrNotExist when the
// file does not exist) from a value of -1, and it does not warn.
func ReadInt(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}
